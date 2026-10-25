"""Publication-window discovery, bounded evidence staging and incremental admission."""
import contextlib
import hashlib
import json
import logging
import shutil
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
from sqlalchemy import func, or_, select

from .collector import FILE_LIMIT, error_details, failure_schedule
from .config import settings
from .db import (Alias, DateEvidenceCache, Job, MetadataState, RecentCandidate, RecentSource, Revision,
                 Source, SourceRecord, Vulnerability, now, session)
from .identity import record_aliases
from .publication import VERIFIED, cache_key, cached_evidence, cve_ids, date_in_window, resolve_publication
from .recent_reset import KEY
from .service import digest, ingest
from .sources import Upstream, ghsa_record, nvd_record, osv_record
from .timeline import derive_revision, iso, stamp

BYTE_LIMIT = 2_000_000
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
_touch_lock = threading.Lock()
_last_touch = 0.0
log = logging.getLogger("vulintel.recent")


def enabled(db):
    row = db.get(MetadataState, KEY)
    return row and row.value.get("complete") and not row.value.get("superseded_by")


def progress(db):
    row = db.get(MetadataState, KEY)
    if row is None:
        return None
    value = row.value
    run_id = value["run_id"]
    stages = list(db.scalars(select(RecentSource).where(RecentSource.run_id == run_id)))
    sources = {source.id: source for source in db.scalars(select(Source))}
    counts = dict(db.execute(select(RecentCandidate.status, func.count()).where(
        RecentCandidate.run_id == run_id).group_by(RecentCandidate.status)).all())
    oversized_by_source = dict(db.execute(select(RecentCandidate.source_id, func.count()).where(
        RecentCandidate.run_id == run_id, RecentCandidate.status == "oversized")
        .group_by(RecentCandidate.source_id)).all())
    active_sources = [stage for stage in stages if sources[stage.source_id].enabled and stage.mode == "published"]
    scan_complete = bool(value.get("complete") and all(not stage.initial for stage in active_sources))
    candidates = sum(counts.values())
    pending = sum(counts.get(key, 0) for key in ("pending", "lookup"))
    processed = candidates - pending
    elapsed = max(0, (now() - stamp(value["started_at"])).total_seconds())
    rate = processed / elapsed if elapsed and processed else None
    candidate_updated = db.scalar(select(func.max(RecentCandidate.updated_at)).where(RecentCandidate.run_id == run_id))
    latest = max([stage.updated_at for stage in stages] + [stamp(value.get("updated_at") or value["started_at"])]
                 + ([candidate_updated] if candidate_updated else []))
    job = db.scalar(select(Job).where(Job.kind == "bootstrap", Job.source_id == run_id).order_by(Job.created_at.desc()).limit(1))
    heartbeat = job.lease_until - timedelta(minutes=5) if job and job.lease_until else None
    return {"run_id": run_id, "window_start": value["window_start"], "window_end": value["window_end"],
            "phase": "cleanup" if not value.get("complete") else "discovering" if not scan_complete else "verifying" if pending else "scan_complete",
            "scan_complete": scan_complete, "network_blocks_reports": False,
            "candidates": candidates, "processed": processed, "verified_candidates": counts.get("admitted", 0),
            "admitted_vulnerabilities": db.scalar(select(func.count()).select_from(Vulnerability)),
            "excluded_old": counts.get("excluded", 0), "unverified": counts.get("unverified", 0),
            "oversized": counts.get("oversized", 0),
            "conflicts": counts.get("conflict", 0), "pending": pending, "errors": counts.get("error", 0),
            "updated_at": iso(latest), "heartbeat_at": iso(heartbeat),
            "status": ("interrupted" if job and job.status == "running" and job.lease_until and job.lease_until < now() else job.status if job else "queued"),
            "items_per_hour": round(rate * 3600, 2) if rate else None,
            "percent": round(processed / candidates * 100, 2) if scan_complete and candidates else None,
            "estimated_remaining_seconds": round(pending / rate) if scan_complete and rate and pending else None,
            "sources": [{"id": stage.source_id, "enabled": sources[stage.source_id].enabled,
                         "mode": stage.mode, "status": stage.status, "initial_complete": not stage.initial,
                         "processed": stage.processed, "total": stage.total, "error": stage.error,
                         "oversized": oversized_by_source.get(stage.source_id, 0),
                         "coverage": "定向补充／首次覆盖有限" if stage.mode == "targeted" else "按发布窗口发现候选；真实披露日期另行核实"}
                        for stage in stages]}


def touch(run_id, heartbeat=None):
    global _last_touch
    if heartbeat:
        heartbeat()
    with _touch_lock:
        if time.monotonic() - _last_touch < 30:
            return
        _last_touch = time.monotonic()
    with session() as db:
        job = db.scalar(select(Job).where(Job.kind == "bootstrap", Job.source_id == run_id).limit(1))
        if job:
            job.status, job.error, job.lease_until = "running", None, now() + timedelta(minutes=5)
            db.commit()


def _prior(db, source_id, record):
    linked = db.scalar(select(SourceRecord.vulnerability_id).where(SourceRecord.source_id == source_id,
                       SourceRecord.source_key == record["source_key"][:240]))
    if not linked and record_aliases(record):
        linked = db.scalar(select(Alias.vulnerability_id).where(Alias.alias.in_(record_aliases(record))).limit(1))
    return db.get(Vulnerability, linked) if linked else None


def _facts(db, source_id, record):
    prior = _prior(db, source_id, record)
    records = {(item["source"], item["source_key"]): item for item in (prior.data.get("source_records", []) if prior else [])}
    records[(source_id, record["source_key"])] = {"source": source_id, **record}
    values = list(records.values())
    return {**record, "source_records": values,
            "aliases": sorted({alias for item in values for alias in record_aliases(item)}),
            "references": sorted({url for item in values for url in item.get("references", [])})}, prior


def offer(db, stage, record):
    if not isinstance(record, dict) or not record.get("source_key"):
        raise ValueError("初始化来源缺少稳定编号")
    encoded = json.dumps(record, ensure_ascii=False).encode()
    key = str(record["source_key"])[:240]
    if len(encoded) > MAX_CANDIDATE_BYTES:
        quarantine(db, stage, record, encoded)
        return
    fingerprint = digest({k: v for k, v in record.items() if k != "modified"})
    row = db.scalar(select(RecentCandidate).where(RecentCandidate.run_id == stage.run_id,
                    RecentCandidate.source_id == stage.source_id, RecentCandidate.source_key == key))
    if row and row.fingerprint == fingerprint:
        return
    start = stage.start_at if stage.initial else max(stage.end_at - timedelta(days=7), now() - timedelta(days=7))
    facts, prior = _facts(db, stage.source_id, record)
    timeline = derive_revision(SimpleNamespace(id="candidate", data=facts), observed=now()).snapshot["timeline"]
    # A public record already present before the window disproves "new this week"
    # even when an exact earliest disclosure is not known. Do this before HTTP.
    old = any(stamp(item["end_at"]) < start for item in timeline["date_evidence"])
    important = stamp(timeline.get("material_changed_at"))
    important_end = stamp(timeline.get("important_end_at"))
    recent_update = bool(not stage.initial and important and start <= important <= stage.end_at
                         and important_end and important_end <= stage.end_at)
    status, reason = ("excluded", "已知公开记录早于初始化窗口") if old and not recent_update and not prior else ("pending", None)
    if row is None:
        row = RecentCandidate(run_id=stage.run_id, source_id=stage.source_id, source_key=key,
                              fingerprint=fingerprint, data=record, start_at=start, end_at=stage.end_at)
        db.add(row)
    row.fingerprint, row.data, row.status, row.reason = fingerprint, record, status, reason
    row.initial = stage.initial
    if status == "excluded":
        row.data = {key: record.get(key) for key in ("source_key", "title", "aliases", "published")}
    row.collected_at, row.updated_at, row.start_at, row.end_at = now(), now(), start, stage.end_at
    row.annotation, row.evidence_cursor, row.retry_at = {}, {}, None
    row.vulnerability_id = prior.id if prior else None


def quarantine(db, stage, record, encoded):
    """Save every byte before advancing; isolated rows never become analyses."""
    fingerprint = hashlib.sha256(encoded).hexdigest()
    root = _snapshot_root(stage.run_id, stage.id, stage.cursor.get("cycle", 0)) / "quarantine"
    if root.is_symlink() or root.resolve().parent != root.parent.resolve():
        raise ValueError("隔离目录超出受控范围")
    root.mkdir(parents=True, exist_ok=True)
    path, temporary = root / (fingerprint + ".json"), root / (fingerprint + ".part")
    if path.is_symlink() or temporary.is_symlink():
        raise ValueError("隔离文件不可为符号链接")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    key = str(record["source_key"])[:240]
    row = db.scalar(select(RecentCandidate).where(RecentCandidate.run_id == stage.run_id,
        RecentCandidate.source_id == stage.source_id, RecentCandidate.source_key == key))
    if row is None:
        row = RecentCandidate(run_id=stage.run_id, source_id=stage.source_id, source_key=key,
                              fingerprint=fingerprint, data={}, start_at=stage.start_at, end_at=stage.end_at)
        db.add(row)
    row.fingerprint, row.status, row.initial = fingerprint, "oversized", stage.initial
    row.data = {"source_key": key, "title": str(record.get("title", key))[:500],
                "aliases": record.get("aliases", [])[:30], "references": record.get("references", [])[:30],
                "evidence_complete": False, "title_complete": len(str(record.get("title", key))) <= 500,
                "aliases_complete": len(record.get("aliases", [])) <= 30,
                "references_complete": len(record.get("references", [])) <= 30,
                "raw_artifact": {"relative_path": path.relative_to(settings().data_dir).as_posix(),
                                 "sha256": fingerprint, "bytes": len(encoded)}}
    row.annotation, row.evidence_cursor, row.retry_at = {}, {}, None
    row.reason = f"单条候选{len(encoded)}字节超过8MiB上限；已隔离完整原文，待核查，未入库或分析"
    row.collected_at, row.updated_at = now(), now()
    row.start_at, row.end_at = stage.start_at, stage.end_at
    log.warning("recent_candidate_quarantined source=%s key=%s bytes=%s", stage.source_id, key[:80], len(encoded))


def raw_candidate_path(row):
    """Only managed, intact quarantine artifacts can be served to an admin."""
    from pathlib import Path
    metadata = row.data.get("raw_artifact", {})
    relative = Path(metadata.get("relative_path", ""))
    root = settings().data_dir / "recent-snapshots" / row.run_id
    path = settings().data_dir / relative
    if relative.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("候选原文路径超出受控范围")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("候选原文路径包含符号链接")
        if parent == settings().data_dir:
            break
    if not path.is_file() or path.stat().st_size != metadata.get("bytes"):
        raise ValueError("候选原文缺失或大小校验失败")
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            checksum.update(chunk)
    if checksum.hexdigest() != metadata.get("sha256"):
        raise ValueError("候选原文校验失败")
    return path


def github_date_range(start, end):
    # GitHub rejects fractional seconds. Expand the query to enclosing seconds;
    # candidate admission still uses the original precise stored boundaries.
    lower = start.replace(microsecond=0)
    upper = end.replace(microsecond=0) + (timedelta(seconds=1) if end.microsecond else timedelta())
    return iso(lower) + ".." + iso(upper)


class SnapshotUpstream(Upstream):
    """Freeze non-paginated feeds/documents on disk; never persist credentials."""
    def __init__(self, root, **kwargs):
        super().__init__(**kwargs)
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def path(self, url, kwargs):
        key = hashlib.sha256(json.dumps([url, kwargs.get("params")], sort_keys=True).encode()).hexdigest()
        path = self.root / key
        if path.is_symlink() or path.resolve().parent != self.root.resolve():
            raise ValueError("初始化快照路径超出受控范围")
        return path

    def get(self, url, **kwargs):
        path = self.path(url, kwargs)
        if not path.exists():
            response = super().get(url, **kwargs)
            temporary = path.with_suffix(".part")
            temporary.write_bytes(response.content)
            temporary.replace(path)
        return httpx.Response(200, content=path.read_bytes(), request=httpx.Request("GET", url))

    @contextlib.contextmanager
    def downloaded(self, url, *, limit=FILE_LIMIT, **kwargs):
        path = self.path(url, kwargs)
        if not path.exists():
            temporary = path.with_suffix(".part")
            with super().downloaded(url, limit=limit, **kwargs) as stream, temporary.open("wb") as output:
                shutil.copyfileobj(stream, output, length=65536)
            temporary.replace(path)
        if path.stat().st_size > limit:
            raise ValueError("初始化快照超过容量限制")
        with path.open("rb") as stream:
            yield stream


def _snapshot_root(run_id, stage_id, cycle):
    from uuid import UUID
    UUID(run_id)
    UUID(stage_id)
    base = settings().data_dir / "recent-snapshots"
    root = base / run_id / stage_id / str(int(cycle))
    # Every existing component must be ordinary, contained directories.
    for part in [base, base / run_id, base / run_id / stage_id, root]:
        if part.is_symlink() or not part.resolve().is_relative_to(settings().data_dir.resolve()):
            raise ValueError("初始化快照目录超出受控范围")
    return root


def page(source, stage, transport=None, heartbeat=None):
    cursor = stage.cursor
    def callback():
        touch(stage.run_id, heartbeat)
    if source.kind in {"nvd", "ghsa"}:
        upstream = Upstream(transport=transport, heartbeat=callback)
        try:
            if source.kind == "nvd":
                params = {"pubStartDate": iso(stage.start_at), "pubEndDate": iso(stage.end_at),
                          "startIndex": cursor.get("offset", 0), "resultsPerPage": 200}
                key = settings().nvd_api_key.get_secret_value()
                data = upstream.get(source.url, params=params, headers={"apiKey": key} if key else {}).json()
                rows = [nvd_record(item["cve"]) for item in data["vulnerabilities"]]
                offset = cursor.get("offset", 0) + len(rows)
                if not rows and offset < data["totalResults"]:
                    raise ValueError("NVD初始化分页提前结束")
                # Keep NVD's own stricter request interval, separate from date enrichment.
                upstream.pause(0.7 if key else 6)
                return rows, {**cursor, "offset": offset}, offset >= data["totalResults"], data["totalResults"]
            target = cursor.get("url") or source.url
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.port not in (None, 443) or parsed.username or parsed.password:
                raise ValueError("GitHub初始化分页地址不属于官方HTTPS来源")
            date_range = github_date_range(stage.start_at, stage.end_at)
            if cursor.get("url"):
                pairs = [(key, date_range if key in {"published", "modified", "updated"} else value)
                         for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
                target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment))
            params = None if cursor.get("url") else {"published" if stage.initial else "modified": date_range,
                                                   "sort": "published", "direction": "asc", "per_page": 100}
            token = settings().github_token.get_secret_value()
            headers = {"Accept": "application/vnd.github+json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            response = upstream.get(target, params=params, headers=headers)
            next_url = response.links.get("next", {}).get("url")
            return [ghsa_record(item) for item in response.json()], {**cursor, "url": next_url}, not next_url, None
        finally:
            upstream.close()
    root = _snapshot_root(stage.run_id, stage.id, cursor.get("cycle", 0))
    upstream = SnapshotUpstream(root, transport=transport, heartbeat=callback)
    records, used, consumed, exhausted = [], 0, 0, False
    stream = upstream.records(source, stage.start_at, stage.end_at)
    try:
        for index, record in enumerate(stream):
            if index < cursor.get("offset", 0):
                continue
            size = len(json.dumps(record, ensure_ascii=False).encode())
            if records and used + size > BYTE_LIMIT:
                break
            records.append(record)
            used += size
            consumed += 1
            if consumed >= 100:
                break
        else:
            exhausted = True
    finally:
        stream.close()
        upstream.close()
    return records, {**cursor, "offset": cursor.get("offset", 0) + consumed}, exhausted, None


def discover_once(transport=None, heartbeat=None):
    from .maintenance import active
    with session() as db:
        if active(db) or not enabled(db):
            return False
        run = db.get(MetadataState, KEY).value
        for request in db.scalars(select(Job).where(Job.kind == "collect", Job.status == "pending")):
            manual_stage = db.scalar(select(RecentSource).where(RecentSource.run_id == run["run_id"],
                                     RecentSource.source_id == request.source_id))
            if manual_stage:
                manual_stage.next_run = now()
                if manual_stage.mode == "targeted":
                    request.status, request.error = "done", "该来源仅按已发现精确编号补充，不回灌历史索引"
        db.commit()
        initial_done = not db.scalar(select(RecentSource.id).join(Source, Source.id == RecentSource.source_id).where(
            RecentSource.run_id == run["run_id"], RecentSource.mode == "published", RecentSource.initial.is_(True),
            Source.enabled.is_(True)).limit(1))
        if initial_done:
            kev = db.scalar(select(RecentSource).join(Source, Source.id == RecentSource.source_id).where(
                RecentSource.run_id == run["run_id"], Source.kind == "kev", RecentSource.mode == "targeted"))
            if kev:
                kev.mode, kev.status, kev.initial = "events", "pending", False
                kev.start_at, kev.end_at = stamp(run["window_start"]), now()
                db.commit()
        stages = list(db.scalars(select(RecentSource).join(Source, Source.id == RecentSource.source_id).where(
            RecentSource.run_id == run["run_id"], RecentSource.mode.in_(["published", "events"]), Source.enabled.is_(True),
            RecentSource.next_run <= now()).order_by(RecentSource.updated_at)))
        if not stages:
            return False
        stage = stages[0]
        source = db.get(Source, stage.source_id)
        if not stage.initial and stage.status == "idle":
            floor = stamp(run["window_start"])
            stage.start_at = max(floor, (source.last_success or stage.end_at) - timedelta(hours=48))
            stage.end_at = now()
            if source.kind == "nvd":
                stage.end_at = min(stage.end_at, stage.start_at + timedelta(days=100))
            stage.cursor = {"cycle": stage.cursor.get("cycle", 0) + 1}
            stage.total = None
        stage.status, stage.error, stage.updated_at = "running", None, now()
        source.last_attempt = now()
        _running(db, stage.run_id)
        db.commit()
        stage_id = stage.id
    try:
        rows, cursor, complete, total = page(source, stage, transport, heartbeat)
        with session() as db:
            stage, source = db.get(RecentSource, stage_id), db.get(Source, stage.source_id)
            for record in rows:
                if source.kind == "kev" and (not stamp(record.get("kev_added_at")) or
                        not stage.start_at.date() <= stamp(record["kev_added_at"]).date() <= stage.end_at.date()):
                    continue
                offer(db, stage, record)
            stage.cursor, stage.total = cursor, total
            stage.processed += len(rows)
            stage.updated_at, stage.error = now(), None
            if complete:
                stage.status, stage.initial = "idle", False
                interval = timedelta(seconds=settings().source_interval_seconds)
                stage.next_run = now() if now() - stage.end_at >= interval else now() + interval
                source.last_success, source.next_run, source.error = stage.end_at, stage.next_run, None
                for job in db.scalars(select(Job).where(Job.kind == "collect", Job.source_id == source.id, Job.status == "pending")):
                    job.status = "done"
            else:
                stage.status, stage.next_run = "pending", now()
            _settle(db, stage.run_id)
            db.commit()
    except (KeyboardInterrupt, SystemExit, InterruptedError):
        raise
    except Exception as exc:
        log.exception("recent_discovery_failed stage=%s", stage_id)
        with session() as db:
            stage = db.get(RecentSource, stage_id)
            details = error_details(exc)
            reason = details["reason"] + (f"（HTTP {details['status']}）" if details.get("status") else "")
            stage.status, stage.error, stage.updated_at = "failed", reason, now()
            stage.next_run = max(now() + timedelta(seconds=60), failure_schedule(exc))
            source = db.get(Source, stage.source_id)
            source.error, source.next_run = stage.error, stage.next_run
            _settle(db, stage.run_id)
            db.commit()
    return True


def _target_osv(db, row, identity):
    """Known precise IDs and ecosystem only; never sweep modified_id.csv."""
    identifiers = ["GHSA-" + alias[5:].lower() if alias.startswith("GHSA-") else alias
                   for alias in record_aliases(row.data) if alias.startswith(("GHSA-", "PYSEC-", "GO-", "RUSTSEC-"))]
    ecosystems = set()
    for item in row.data.get("affected", []):
        if isinstance(item, dict):
            package = item.get("package", {})
            ecosystems.add(str(package.get("ecosystem", "")).lower())
    aliases = {"pip": "pypi", "rust": "crates.io", "composer": "packagist", "rubygems": "rubygems"}
    ecosystems = {aliases.get(eco, eco) for eco in ecosystems}
    if not identifiers or not ecosystems:
        return
    for stage in db.scalars(select(RecentSource).join(Source, Source.id == RecentSource.source_id).where(
            RecentSource.run_id == row.run_id, RecentSource.mode == "targeted", Source.kind == "osv", Source.enabled.is_(True))):
        source = db.get(Source, stage.source_id)
        if str(source.config.get("ecosystem", "")).lower() not in ecosystems:
            continue
        for identifier in identifiers:
            existing = db.scalar(select(RecentCandidate.id).where(RecentCandidate.run_id == row.run_id,
                RecentCandidate.source_id == source.id, RecentCandidate.source_key == identifier))
            if existing:
                continue
            db.add(RecentCandidate(run_id=row.run_id, source_id=source.id, source_key=identifier,
                fingerprint="lookup", status="lookup", data={}, start_at=row.start_at, end_at=row.end_at,
                vulnerability_id=identity))


def verify_once(transport=None, heartbeat=None):
    from .date_enrichment import allowed_reference, fetch_group
    from .maintenance import active
    with session() as db:
        if active(db) or not enabled(db):
            return False
        run_id = db.get(MetadataState, KEY).value["run_id"]
        row = db.scalar(select(RecentCandidate).join(Source, Source.id == RecentCandidate.source_id).where(
            RecentCandidate.run_id == run_id, Source.enabled.is_(True),
            RecentCandidate.status.in_(["pending", "lookup", "unverified", "conflict", "error"]),
            or_(RecentCandidate.retry_at.is_(None), RecentCandidate.retry_at <= now()))
            .order_by(RecentCandidate.updated_at, RecentCandidate.id).limit(1))
        if not row:
            _settle(db, run_id)
            db.commit()
            return False
        candidate_id, source = row.id, db.get(Source, row.source_id)
        def callback():
            touch(run_id, heartbeat)
        lookup = row.status == "lookup" or row.fingerprint == "lookup"
        facts, prior = _facts(db, row.source_id, row.data) if not lookup else ({}, None)
        done = set(row.evidence_cursor.get("done", []))
        requests = [("https://cveawg.mitre.org/api/cve/" + cve, cve) for cve in cve_ids(facts)]
        refs = {url for url in facts.get("references", []) if allowed_reference(url)}
        for url, _ in requests:
            cached = db.get(DateEvidenceCache, cache_key(url))
            if cached:
                refs.update(cached.data.get("references", []))
        requests.extend((url, None) for url in sorted(refs))
        requests = [(url, identifier) for url, identifier in requests if url not in done][:4]
        _running(db, run_id)
        db.commit()
    try:
        if lookup:
            url = source.url.rsplit("/", 1)[0] + "/" + quote(row.source_key, safe="") + ".json"
            upstream = Upstream(transport=transport, heartbeat=callback)
            try:
                payload = upstream.get(url).json()
            finally:
                upstream.close()
            with session() as db:
                row = db.get(RecentCandidate, candidate_id)
                vuln = db.get(Vulnerability, row.vulnerability_id)
                record = osv_record(payload)
                if payload.get("id") != row.source_key or not vuln or not set(record_aliases(record)) & set(vuln.data.get("aliases", [])):
                    raise ValueError("OSV定向详情编号或漏洞关联不一致")
                stage = db.scalar(select(RecentSource).where(RecentSource.run_id == run_id, RecentSource.source_id == row.source_id))
                offer(db, stage, record)
                _settle(db, run_id)
                db.commit()
            return True
        if requests:
            fetch_group(requests, transport=transport, heartbeat=callback)
            with session() as db:
                row = db.get(RecentCandidate, candidate_id)
                row.evidence_cursor = {"done": sorted(done | {url for url, _ in requests})}
                row.updated_at = now()
                _settle(db, run_id)
                db.commit()
            return True
        with session() as db:
            row = db.get(RecentCandidate, candidate_id)
            facts, prior = _facts(db, row.source_id, row.data)
            extra, diagnostics = cached_evidence(db, facts)
            annotation = resolve_publication(facts, extra)
            annotation["date_fetches"] = diagnostics
            row.annotation, row.updated_at = annotation, now()
            previous = db.scalar(select(Revision).where(Revision.vulnerability_id == prior.id).order_by(Revision.id.desc()).limit(1)) if prior else None
            derived = derive_revision(SimpleNamespace(id="candidate", data=facts), latest=previous, observed=now())
            new = date_in_window(SimpleNamespace(status=annotation["publication_status"],
                start_at=stamp(annotation["publication_start_at"]), end_at=stamp(annotation["publication_end_at"])), row.start_at, row.end_at)
            stage = db.scalar(select(RecentSource).where(RecentSource.run_id == run_id, RecentSource.source_id == row.source_id))
            important_end = stamp(derived.snapshot["timeline"].get("important_end_at"))
            important = (not row.initial and derived.important_at and row.start_at <= derived.important_at <= row.end_at
                         and important_end and important_end <= row.end_at)
            uncertain = (annotation["publication_status"] == "day" and annotation["publication_start_at"]
                         and stamp(annotation["publication_start_at"]) <= row.end_at
                         and stamp(annotation["publication_end_at"]) >= row.start_at and not new)
            if prior and annotation["publication_status"] not in VERIFIED:
                # New contradictory source evidence must invalidate the current
                # date too, rather than leaving a disproved date reportable.
                ingest(db, row.source_id, row.data, observed=max(row.collected_at, previous.observed_at) if previous else row.collected_at)
            if annotation["publication_status"] in VERIFIED and (new or important or prior):
                observed = max(row.collected_at, previous.observed_at) if previous else row.collected_at
                identity = ingest(db, row.source_id, row.data, observed=observed)
                row.vulnerability_id, row.status, row.reason = identity, "admitted", None
                row.retry_at = None
                _target_osv(db, row, identity)
            elif annotation["publication_status"] in VERIFIED and not uncertain:
                row.status, row.reason, row.retry_at = "excluded", "规范公开日期不在窗口且无近期重要事件", None
            else:
                row.status = "conflict" if annotation["publication_status"] == "conflict" else "unverified"
                row.reason = "日期精度不足以确认窗口归属" if uncertain else "日期冲突" if row.status == "conflict" else "公开日期或窗口归属尚未确认"
                row.evidence_cursor, row.retry_at = {}, now() + timedelta(hours=24)
            _settle(db, run_id)
            db.commit()
    except (KeyboardInterrupt, SystemExit, InterruptedError):
        raise
    except Exception as exc:
        log.exception("recent_candidate_failed candidate=%s", candidate_id)
        with session() as db:
            row = db.get(RecentCandidate, candidate_id)
            row.status, row.reason, row.updated_at = "error", error_details(exc)["reason"], now()
            row.retry_at = max(now() + timedelta(seconds=60), failure_schedule(exc))
            _settle(db, run_id)
            db.commit()
    return True


def _running(db, run_id):
    job = db.scalar(select(Job).where(Job.kind == "bootstrap", Job.source_id == run_id).limit(1))
    if job:
        job.status, job.error, job.lease_until = "running", None, now() + timedelta(minutes=5)


def _settle(db, run_id):
    db.flush()
    remaining = db.scalar(select(RecentSource.id).join(Source, Source.id == RecentSource.source_id).where(
        RecentSource.run_id == run_id, RecentSource.mode == "published", RecentSource.initial.is_(True),
        Source.enabled.is_(True)).limit(1))
    pending = db.scalar(select(RecentCandidate.id).where(RecentCandidate.run_id == run_id,
        RecentCandidate.status.in_(["pending", "lookup"])).limit(1))
    job = db.scalar(select(Job).where(Job.kind == "bootstrap", Job.source_id == run_id).limit(1))
    if job:
        job.status, job.lease_until = "pending" if remaining or pending else "done", None
