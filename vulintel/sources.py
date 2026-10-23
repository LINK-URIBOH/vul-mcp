"""Fixed, auditable upstream adapters. No model-supplied URLs are fetched."""
import csv
import hashlib
import html
import io
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urljoin, urlsplit

import feedparser
import ijson
from bs4 import BeautifulSoup
from sqlalchemy import select

from .config import settings
from .collector import (CollectorHTTP, CollectionError, MANIFEST_LIMIT, error_details,
                        failure_schedule, log_event)
from .db import Source, now
from .timeline import explicit_publication, stamp as parse_stamp

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def date(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollectionError("invalid_source_date", "来源日期格式无效") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def iso(value):
    return value.isoformat(timespec="seconds") + "Z"


def text(value):
    if isinstance(value, str) and "<" not in value:
        return html.unescape(value)
    return BeautifulSoup(value or "", "html.parser").get_text(" ", strip=True)


def entry(key, title, description, aliases=None, references=None, affected=None,
          severity="unknown", score=None, exploited=False, modified=None, published=None, **extra):
    return {"source_key": str(key), "title": str(title or key), "description": str(description or ""),
            "aliases": sorted(set(aliases or [])), "references": sorted(set(references or [])),
            "affected": affected or [], "severity": severity if severity in RANK else "unknown",
            "score": score, "exploited": exploited, "modified": modified, "published": published, **extra}


def nvd_record(cve):
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve.get("metrics", {})
    metric = next(iter(metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31")
                       or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [{}]))
    cvss = metric.get("cvssData", {})
    severity = str(cvss.get("baseSeverity", metric.get("baseSeverity", "unknown"))).lower()
    return entry(cve["id"], desc[:180], desc, [cve["id"]],
                 [r["url"] for r in cve.get("references", [])],
                 cve.get("configurations", []), severity, cvss.get("baseScore"),
                 "cisaExploitAdd" in cve, cve.get("lastModified"), cve.get("published"),
                 cvss=cvss, status=cve.get("vulnStatus"), source_authority="NVD", exploitation_added_at=cve.get("cisaExploitAdd"))


def ghsa_record(record):
    aliases = [item["value"] for item in record.get("identifiers", [])]
    return entry(record["ghsa_id"], record.get("summary"), record.get("description"), aliases,
                 record.get("references", []) + [record["html_url"]], record.get("vulnerabilities", []),
                 record.get("severity", "unknown"), (record.get("cvss") or {}).get("score"),
                 modified=record.get("updated_at"), published=record.get("published_at"),
                 withdrawn=record.get("withdrawn_at"), source_authority="GitHub Advisory")


def osv_record(record):
    severity = str(record.get("database_specific", {}).get("severity", "unknown")).lower()
    return entry(record["id"], record.get("summary"), record.get("details"),
                 [record["id"], *record.get("aliases", [])],
                 [r["url"] for r in record.get("references", [])], record.get("affected", []),
                 severity, modified=record.get("modified"), published=record.get("published"),
                 withdrawn=record.get("withdrawn"), cvss=record.get("severity", []), source_authority="OSV")


def kev_record(record):
    return entry(record["cveID"], record.get("vulnerabilityName"), record.get("shortDescription"),
                 [record["cveID"]], [record.get("notes", "")] if record.get("notes", "").startswith("https://") else [],
                 [{"vendor": record.get("vendorProject"), "product": record.get("product")}],
                 exploited=True, kev_added_at=record.get("dateAdded"),
                 remediation=record.get("requiredAction"), ransomware=record.get("knownRansomwareCampaignUse"),
                 source_authority="CISA KEV")


def catalog():
    values = [
        ("nvd", "NVD / CVE 全产品", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", {}),
        ("kev", "CISA 已利用漏洞", "kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {}),
        ("ghsa", "GitHub Advisory", "ghsa", "https://api.github.com/advisories", {}),
        ("msrc", "微软安全公告", "msrc", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", {}),
        ("apple", "Apple 安全更新", "bulletin", "https://support.apple.com/en-us/100100",
         {"pattern": r"https://support\.apple\.com/en-us/\d+", "exclude": "100100", "product": "macOS / Apple"}),
        ("android", "Android 安全公告", "bulletin", "https://source.android.com/docs/security/bulletin/asb-overview",
         {"pattern": r"https://source\.android\.com/docs/security/bulletin/\d{4}-\d{2}-\d{2}", "product": "Android"}),
        ("nodejs", "Node.js 安全公告", "rss", "https://nodejs.org/en/feed/vulnerability.xml", {"product": "Node.js"}),
        ("go-blog", "Go 安全发布", "rss", "https://go.dev/blog/feed.atom", {"security_only": True, "product": "Go"}),
        ("python", "Python 官方 PSF 公告库", "psf", "https://codeload.github.com/psf/advisory-database/tar.gz/refs/heads/main", {}),
        ("php", "PHP 发布公告", "rss", "https://www.php.net/releases/feed.php", {"security_only": True, "product": "PHP"}),
        ("debian", "Debian 安全公告", "rss", "https://www.debian.org/security/dsa-long", {"product": "Debian Linux"}),
        ("ubuntu", "Ubuntu 安全公告", "rss", "https://ubuntu.com/security/notices/rss.xml", {"product": "Ubuntu Linux"}),
        ("cisco", "Cisco 网络设备", "rss", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", {"product": "Cisco"}),
        ("fortinet", "Fortinet 网络设备", "rss", "https://filestore.fortinet.com/fortiguard/rss/ir.xml", {"product": "Fortinet"}),
        ("cisa-advisories", "CISA 基础设施公告", "rss", "https://www.cisa.gov/cybersecurity-advisories/all.xml", {"product": "基础设施"}),
    ]
    for eco in ["npm", "Packagist", "Maven", "PyPI", "Go", "Linux", "Android",
                "Debian", "Ubuntu", "Alpine", "NuGet", "crates.io", "RubyGems", "OSS-Fuzz"]:
        values.append(("osv-" + re.sub(r"[^a-z0-9]+", "-", eco.lower()), "OSV · " + eco, "osv",
                       "https://storage.googleapis.com/osv-vulnerabilities/" + quote(eco, safe="") + "/modified_id.csv",
                       {"ecosystem": eco}))
    return values


def seed_sources(db):
    for sid, name, kind, url, config in catalog():
        if not db.get(Source, sid):
            db.add(Source(id=sid, name=name, kind=kind, url=url, config=config))
    db.commit()


class Upstream(CollectorHTTP):
    def records(self, source, start, end):
        cfg = settings()
        self.context.update(source=source.id, phase=source.kind + "_fetch", document=None)
        self.heartbeat()
        if source.kind == "nvd":
            offset = 0
            while True:
                params = {"lastModStartDate": iso(start), "lastModEndDate": iso(end),
                          "startIndex": offset, "resultsPerPage": 200}
                key = cfg.nvd_api_key.get_secret_value()
                data = self.get(source.url, params=params, headers={"apiKey": key} if key else {}).json()
                for raw in data["vulnerabilities"]:
                    yield nvd_record(raw["cve"])
                offset += len(data["vulnerabilities"])
                if offset >= data["totalResults"]:
                    break
                if not data["vulnerabilities"]:
                    raise CollectionError("incomplete_nvd_pagination", "NVD 分页在返回全部记录前中断")
                self.pause(0.7 if key else 6)
        elif source.kind == "ghsa":
            url, params = source.url, {"modified": f">={iso(start)}", "per_page": 100, "sort": "updated", "direction": "asc"}
            token = cfg.github_token.get_secret_value()
            headers = {"Accept": "application/vnd.github+json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            while url:
                response = self.get(url, params=params, headers=headers)
                for raw in response.json():
                    yield ghsa_record(raw)
                target = response.links.get("next", {}).get("url")
                if target:
                    parsed = urlsplit(target)
                    if (parsed.scheme != "https" or parsed.hostname != "api.github.com"
                            or parsed.port not in (None, 443) or parsed.username or parsed.password):
                        raise CollectionError("invalid_github_page", "GitHub 下一页不属于官方 HTTPS 来源")
                url, params = target, None
        elif source.kind == "kev":
            # The full catalog is small; compare content on every pass, including old CVEs newly exploited.
            for raw in self.get(source.url).json()["vulnerabilities"]:
                yield kev_record(raw)
        elif source.kind == "osv":
            # Finish and close the index network response before requesting any detail records.
            with self.temporary() as manifest:
                self.context["phase"] = "osv_index_download"
                with self.downloaded(source.url) as index:
                    self.context["phase"] = "osv_index_parse"
                    seen, total = set(), 0
                    with io.TextIOWrapper(index, encoding="utf-8-sig", newline="") as lines:
                        for row in csv.reader(lines):
                            self.heartbeat()
                            if len(row) != 2:
                                raise CollectionError("invalid_osv_index", "OSV 索引结构无效")
                            modified = date(row[0])
                            if modified is None:
                                raise CollectionError("invalid_osv_date", "OSV 索引缺少修改时间")
                            if modified < start:
                                break
                            if modified > end:
                                continue
                            vid = row[1]
                            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,240}", vid):
                                raise CollectionError("invalid_osv_id", "OSV 索引编号无效")
                            if vid in seen:
                                continue
                            encoded = (vid + "\n").encode("ascii")
                            total += len(encoded)
                            if total > MANIFEST_LIMIT:
                                raise CollectionError("manifest_too_large", "OSV 编号清单超过 16 MiB 限制")
                            manifest.write(encoded)
                            seen.add(vid)
                    del seen
                manifest.seek(0)
                for line in manifest:
                    self.context["phase"] = "osv_detail"
                    vid = line.decode("ascii").strip()
                    url = source.url.rsplit("/", 1)[0] + "/" + quote(vid, safe="") + ".json"
                    payload = self.get(url).json()
                    if not isinstance(payload, dict) or payload.get("id") != vid:
                        raise CollectionError("invalid_osv_record", "OSV 详情编号与索引不一致")
                    yield osv_record(payload)
        elif source.kind == "msrc":
            raw = self.get(source.url, headers={"Accept": "application/json"}).json()
            if not isinstance(raw, dict) or not isinstance(raw.get("value"), list):
                raise CollectionError("invalid_msrc_index", "微软更新列表结构无效")
            for update in raw["value"]:
                self.heartbeat()
                if not isinstance(update, dict):
                    raise CollectionError("invalid_msrc_index", "微软更新列表条目必须为对象")
                modified = date(update.get("CurrentReleaseDate"))
                if modified is None:
                    raise CollectionError("invalid_msrc_date", "微软更新列表缺少修改时间")
                if modified < start or modified > end:
                    continue
                url = update.get("CvrfUrl", "")
                if not isinstance(url, str):
                    raise CollectionError("invalid_msrc_host", "微软文档地址格式无效")
                parsed = urlsplit(url)
                if (parsed.scheme != "https" or parsed.hostname != "api.msrc.microsoft.com"
                        or parsed.port not in (None, 443) or parsed.username or parsed.password):
                    raise CollectionError("invalid_msrc_host", "微软文档不属于官方 HTTPS 来源")
                document = update.get("ID", "")
                if not isinstance(document, str) or not re.fullmatch(
                        r"\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", document):
                    raise CollectionError("invalid_msrc_id", "微软文档月份编号无效")
                self.context.update(phase="msrc_document_download", document=document)
                with self.downloaded(url, headers={"Accept": "application/json"}) as doc:
                    self.context["phase"] = "msrc_document_parse"
                    for item in self.msrc_items(doc):
                        if not isinstance(item, dict) or not isinstance(item.get("CVE"), str):
                            raise CollectionError("invalid_msrc_record", "微软漏洞条目缺少 CVE 编号")
                        identifier = item["CVE"]
                        notes = "\n".join(text(x.get("Value", "")) for x in item.get("Notes", []))
                        title = item.get("Title", {})
                        title = title.get("Value", identifier) if isinstance(title, dict) else title
                        severity = next((str(t.get("Description", {}).get("Value", "unknown")).lower()
                                         for t in item.get("Threats", []) if t.get("Type") == 3), "unknown")
                        severity = {"important": "high", "moderate": "medium"}.get(severity, severity)
                        history = item.get("RevisionHistory", {})
                        history = history.get("Revision", []) if isinstance(history, dict) else history
                        history = history if isinstance(history, list) else [history]
                        dates = [(parse_stamp(r.get("Date")), r.get("Date")) for r in history if isinstance(r, dict)]
                        published = min((d for d in dates if d[0]), default=(None, None))[1]
                        yield entry(identifier, title, notes, [identifier],
                                    [f"https://msrc.microsoft.com/update-guide/vulnerability/{identifier}"],
                                    item.get("ProductStatuses", []), severity,
                                    modified=update.get("CurrentReleaseDate"),
                                    published=published, publication_basis="微软条目最早公开修订时间",
                                    remediations=item.get("Remediations", []), source_authority="Microsoft")
        elif source.kind == "psf":
            import json
            import tarfile
            with self.downloaded(source.url) as archive:
                with tarfile.open(fileobj=archive, mode="r|gz") as entries:
                    found = False
                    for member in entries:
                        self.heartbeat()
                        if not member.isfile() or not member.name.endswith(".json") or "/advisories/" not in member.name:
                            continue
                        if member.size > 2_000_000:
                            raise CollectionError("psf_record_too_large", "PSF 单条公告超过容量限制")
                        record = json.load(entries.extractfile(member))
                        found = True
                        if date(record.get("modified")) and date(record["modified"]) >= start:
                            yield osv_record(record)
                    if not found:
                        raise CollectionError("invalid_psf_archive", "PSF 公告归档缺少预期记录")
        elif source.kind == "rss":
            # 2026-10-23: CISA returned 403 for our default UA; curl/8.0 passed two full-feed checks.
            # Override this request only, so a reused client keeps other sources' default headers.
            headers = {"User-Agent": "curl/8.0"} if source.id == "cisa-advisories" else {}
            parsed = feedparser.parse(self.get(source.url, headers=headers).content)
            if not parsed.entries:
                raise CollectionError("empty_feed", "官方订阅未包含公告条目，请核对来源或解析格式")
            for raw in parsed.entries:
                self.heartbeat()
                stamp = raw["updated_parsed"] if "updated_parsed" in raw else raw.get("published_parsed")
                modified = datetime(*stamp[:6]) if stamp else None
                if modified and modified < start:
                    continue
                description = text(raw.get("summary", ""))
                title = raw.get("title", "")
                if source.config.get("security_only") and not re.search(r"security|CVE-|vulnerab", title + description, re.I):
                    continue
                link = raw.get("link", source.url)
                aliases = CVE.findall(title + " " + description)
                # Feeds grouping several CVEs are bulletins, not claims that those CVEs are aliases.
                key = raw.get("id") or link
                yield entry(hashlib.sha256(key.encode()).hexdigest(), title, description,
                            aliases if len(set(aliases)) == 1 else [], [link],
                            [{"product": source.config.get("product", source.name)}],
                            modified=iso(modified) if modified else None,
                            published=iso(datetime(*raw["published_parsed"][:6])) if raw.get("published_parsed") else None,
                            publication_basis="订阅公告公开时间",
                            mentioned_cves=sorted(set(aliases)), source_authority=source.name,
                            record_type="bulletin")
        elif source.kind == "bulletin":
            soup = BeautifulSoup(self.get(source.url).text, "html.parser")
            links = sorted({urljoin(source.url, a["href"]).split("#")[0].split("?")[0].rstrip("/")
                            for a in soup.select("a[href]")})
            matched = [url for url in links if re.fullmatch(source.config["pattern"], url)
                       and source.config.get("exclude", "never-match") not in url]
            if not matched:
                raise CollectionError("missing_bulletin_links", "官方页面未找到公告链接，页面结构可能已改变")
            for link in matched:
                self.heartbeat()
                if source.id == "android":
                    stamp = date(link.rsplit("/", 1)[1])
                    if stamp and stamp < start - timedelta(days=40):
                        continue
                page = BeautifulSoup(self.get(link).text, "html.parser")
                main = page.select_one("main, article") or page
                description = main.get_text(" ", strip=True)
                title = page.title.get_text() if page.title else link
                identifiers = sorted(set(CVE.findall(description)))
                if not identifiers:
                    continue
                published, basis = explicit_publication(str(page), source.id, link)
                yield entry(hashlib.sha256(link.encode()).hexdigest(), title, description, [], [link],
                            [{"product": source.config["product"]}], mentioned_cves=identifiers,
                            published=published, publication_basis=basis,
                            source_authority=source.name, record_type="bulletin")
        else:
            raise CollectionError("unsupported_source", "来源适配器类型不受支持")

    def msrc_items(self, document):
        def checked_events():
            found, started = False, False
            for prefix, event, value in ijson.parse(document, use_float=True):
                self.heartbeat()
                if not started:
                    if (prefix, event) != ("", "start_map"):
                        raise CollectionError("invalid_msrc_document", "微软文档根节点必须为对象")
                    started = True
                if prefix == "Vulnerability":
                    if event == "start_array" and not found:
                        found = True
                    elif event != "end_array":
                        raise CollectionError("invalid_msrc_document", "微软文档漏洞列表结构无效")
                yield prefix, event, value
            if not found:
                raise CollectionError("invalid_msrc_document", "微软文档缺少漏洞列表")
        try:
            yield from ijson.items(checked_events(), "Vulnerability.item", use_float=True)
        except (ijson.JSONError, UnicodeError) as exc:
            raise CollectionError("invalid_msrc_json", "微软文档 JSON 不完整或编码无效") from exc


def collect_one(source_id, force=False, upstream=None, heartbeat=None, delivery_tick=None, job_id=None):
    from .db import session
    from .service import ingest
    from .db import MetadataState
    def update_progress(db, **values):
        key = "source-progress:" + source_id
        state = db.get(MetadataState, key)
        if state is None:
            state = MetadataState(key=key, value={})
            db.add(state)
        state.value = {**state.value, **values}
    own_client = upstream is None
    started = time.monotonic()
    next_progress = started + 15
    cutoff = now()
    with session() as db:
        source = db.get(Source, source_id)
        if source is None or (not source.enabled and not force):
            return
        source.last_attempt = cutoff
        update_progress(db, status="running", started_at=iso(cutoff), processed=0, job_id=job_id)
        start = (source.last_success - timedelta(hours=48)) if source.last_success else cutoff - timedelta(days=7)
        # NVD limits date ranges; split long outages into <=100-day windows, advancing only fully fetched windows.
        end = min(cutoff, start + timedelta(days=100)) if source.kind == "nvd" else cutoff
        db.commit()
        log_event("collection_started", source=source_id, job=job_id, start=iso(start), end=iso(end))
        count, records = 0, None
        try:
            upstream = upstream or Upstream(heartbeat=heartbeat)
            if isinstance(upstream, CollectorHTTP):
                upstream.context.update(source=source_id, job=job_id)
                if heartbeat:
                    upstream.heartbeat_callback = heartbeat
            records = upstream.records(source, start, end)
            for record in records:
                if heartbeat:
                    if isinstance(upstream, CollectorHTTP):
                        upstream.heartbeat()
                    else:
                        heartbeat()
                context = getattr(upstream, "context", {})
                phase = context.get("phase")
                context["phase"] = "ingest"
                if source.kind == "kev" and date(record.get("kev_added_at")) and date(record["kev_added_at"]) < start:
                    from .db import Alias, SourceRecord
                    known = db.scalar(select(SourceRecord).where(SourceRecord.source_id == source.id,
                                                               SourceRecord.source_key == record["source_key"]))
                    if not known and not db.get(Alias, record["source_key"].upper()):
                        context["phase"] = phase
                        continue
                ingest(db, source.id, record)
                db.commit()
                count += 1
                if count % 20 == 0:
                    update_progress(db, status="running", processed=count, heartbeat_at=iso(now()))
                    db.commit()
                context["phase"] = phase
                if time.monotonic() >= next_progress:
                    progress = dict(context)
                    progress.update(source=source_id, job=job_id, processed=count,
                                    elapsed=round(time.monotonic() - started, 3))
                    log_event("collection_progress", **progress)
                    next_progress = time.monotonic() + 15
                if delivery_tick and count % 20 == 0:
                    delivery_tick()
            source.last_success = end
            source.error = None
            update_progress(db, status="done", processed=count, completed_at=iso(now()))
            source.next_run = cutoff + timedelta(seconds=settings().source_interval_seconds)
            if end < cutoff:
                source.next_run = cutoff
            db.commit()
            completed = dict(getattr(upstream, "context", {}))
            completed.update(source=source_id, job=job_id, processed=count,
                             elapsed=round(time.monotonic() - started, 3), end=iso(end))
            log_event("collection_completed", **completed)
            return count
        except Exception as exc:
            db.rollback()
            source = db.get(Source, source_id)
            update_progress(db, status="failed", processed=count, failed_at=iso(now()))
            details = error_details(exc, getattr(upstream, "context", {}))
            source.next_run = failure_schedule(exc)
            source.error = (f"{details['code']} · {details['reason']}"
                            + (f" · HTTP {details['status']}" if details["status"] else "")
                            + f" · 下次重试 {iso(source.next_run)}")
            db.commit()
            details.update(source=source_id, job=job_id, processed=count,
                           elapsed=round(time.monotonic() - started, 3), next_run=iso(source.next_run))
            log_event("collection_failed", level=logging.WARNING, **details)
            raise
        finally:
            if records is not None and hasattr(records, "close"):
                records.close()
            if own_client and upstream is not None:
                upstream.close()
