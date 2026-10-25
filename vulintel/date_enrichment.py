"""Bounded, cached public date evidence. Upstream JSON/HTML is data, never code."""
import json
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from sqlalchemy import or_, select

from .collector import CollectionError, CollectorHTTP, error_details
from .config import settings
from .db import DateEvidenceCache, Job, Vulnerability, now, session
from .identity import CVE_ID
from .publication import VERIFIED, annotate, cache_key, cve_ids, https_url, proof

LIMIT = 2_000_000
_last_request = 0.0
_request_lock = threading.Lock()
_flights_lock = threading.Lock()
_flights = {}
_network_slots = threading.BoundedSemaphore(4)


def fetch_group(requests, transport=None, heartbeat=None):
    """At most four in-flight requests across candidate and legacy evidence jobs."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fetch_cached, url, identifier=identifier, transport=transport, heartbeat=heartbeat)
                   for url, identifier in requests]
        return [future.result() for future in futures]


def allowed_reference(url):
    if not https_url(url):
        return False
    host = urlsplit(url).hostname.lower()
    return host in {name.strip().lower() for name in settings().publication_reference_hosts.split(",") if name.strip()}


def cve_facts(payload, identifier, url):
    metadata = payload.get("cveMetadata", {})
    if metadata.get("cveId", "").upper() != identifier:
        raise CollectionError("date_identity_mismatch", "官方日期证据的CVE编号不一致")
    evidence = []
    if metadata.get("datePublished"):
        evidence.append(proof("cve", identifier, "cveMetadata.datePublished", metadata["datePublished"],
                              "record_publication", url))
    cna = payload.get("containers", {}).get("cna", {})
    if metadata.get("state") == "PUBLISHED" and cna.get("datePublic"):
        evidence.append(proof("cna", identifier, "containers.cna.datePublic", cna["datePublic"], "disclosure", url))
    references = sorted({ref["url"] for ref in cna.get("references", []) if isinstance(ref, dict)
                         and allowed_reference(ref.get("url"))})
    return {"evidence": evidence, "references": references, "record_state": metadata.get("state"),
            "reason": "cna_disclosure_missing" if not cna.get("datePublic") else None}


def page_facts(content, url):
    soup = BeautifulSoup(content, "html.parser")
    for tag in soup(["script", "style"]):
        if tag.name == "style":
            tag.decompose()
    plain = soup.get_text(" ", strip=True)
    identifiers = set(CVE_ID.findall(plain.upper()))
    evidence = {}
    # Only a page/section unambiguously about this CVE supplies a date. A date
    # on a multi-CVE bulletin is not copied to every CVE it happens to mention.
    from .timeline import explicit_publication
    if len(identifiers) == 1:
        identifier = next(iter(identifiers))
        value, _ = explicit_publication(str(soup), "evidence", url)
        if value:
            evidence[identifier] = [proof("original_advisory", identifier, "datePublished", value,
                                          "advisory_publication", url)]
    for section in soup.find_all(id=True):
        identifier = str(section.get("id", "")).upper()
        if CVE_ID.fullmatch(identifier) and set(CVE_ID.findall(section.get_text(" ").upper())) <= {identifier}:
            value, _ = explicit_publication(str(section), "evidence", url)
            if value:
                evidence.setdefault(identifier, []).append(proof("original_advisory", identifier,
                    "cve_section.datePublished", value, "advisory_publication", url))
    return {"evidence_by_cve": evidence, "reason": None if evidence else "no_cve_specific_publication_date"}


def fetch_cached(url, *, identifier=None, transport=None, heartbeat=None):
    key = (url, identifier)
    with _flights_lock:
        future = _flights.get(key)
        owner = future is None
        if owner:
            future = Future()
            _flights[key] = future
    if not owner:
        return future.result()
    try:
        with _network_slots:
            data = _fetch_cached(url, identifier=identifier, transport=transport, heartbeat=heartbeat)
        future.set_result(data)
        return data
    except BaseException as exc:
        future.set_exception(exc)
        raise
    finally:
        with _flights_lock:
            _flights.pop(key, None)


def _fetch_cached(url, *, identifier=None, transport=None, heartbeat=None):
    global _last_request
    if identifier is None and not allowed_reference(url):
        raise ValueError("日期补证地址未通过官方或研究者域名白名单")
    if identifier is not None and (not CVE_ID.fullmatch(identifier)
            or url != "https://cveawg.mitre.org/api/cve/" + identifier):
        raise ValueError("无效的官方CVE补证地址")
    with session() as db:
        cached = db.get(DateEvidenceCache, cache_key(url))
        if cached and cached.retry_at > now():
            return cached.data
    client = CollectorHTTP(transport=transport, heartbeat=heartbeat)
    try:
        def pace(_request):
            global _last_request
            # Pace actual request starts, not reservations. A delayed thread must
            # not compress the next interval to catch up with an old reservation.
            with _request_lock:
                client.pause(max(0, _last_request + settings().publication_request_interval - time.monotonic()))
                _last_request = time.monotonic()
        client.client.event_hooks["request"].append(pace)
        with client.downloaded(url, limit=LIMIT) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise CollectionError("date_evidence_too_large", "单份日期证据超过容量限制")
        data = cve_facts(json.loads(raw), identifier, url) if identifier else page_facts(raw, url)
        status = "ok"
        retry_at = now() + timedelta(hours=settings().publication_cache_hours)
    except (KeyboardInterrupt, SystemExit, InterruptedError):
        raise
    except Exception as exc:
        details = error_details(exc)
        data, status = {"reason": details["code"]}, "error"
        retry_at = max(now() + timedelta(minutes=15), getattr(exc, "retry_at", None) or now())
    finally:
        client.close()
    with session() as db:
        row = db.get(DateEvidenceCache, cache_key(url))
        if row is None:
            row = DateEvidenceCache(key=cache_key(url), url=url)
            db.add(row)
        # A temporary network failure does not erase previously verified facts.
        if status == "error" and row.data:
            data = {**row.data, **data}
        row.status, row.data, row.checked_at, row.retry_at = status, data, now(), retry_at
        db.commit()
    return data


def enrich(vulnerability_id, transport=None, heartbeat=None):
    with session() as db:
        vuln = db.get(Vulnerability, vulnerability_id)
        if not vuln:
            return
        data = dict(vuln.data)
    references = {url for url in data.get("references", []) if allowed_reference(url)}
    requests = [("https://cveawg.mitre.org/api/cve/" + identifier, identifier) for identifier in cve_ids(data)]
    for facts in fetch_group(requests, transport=transport, heartbeat=heartbeat):
        references.update(facts.get("references", []))
    fetch_group([(reference, None) for reference in sorted(references)], transport=transport, heartbeat=heartbeat)
    with session() as db:
        vuln = db.get(Vulnerability, vulnerability_id)
        if vuln:
            annotation, diagnostics = annotate(db, vuln, enqueue=False)
            db.commit()
            return {"status": annotation.status, "diagnostics": diagnostics}


def unresolved(result):
    return bool(result and (result["status"] not in VERIFIED
                or any(item["status"] == "error" for item in result.get("diagnostics", []))))


def schedule_retry(db, identity, result):
    if not unresolved(result):
        return
    row = db.scalar(select(Job).where(Job.kind == "publication", Job.source_id == identity,
                                     Job.status.in_(["pending", "running", "failed"])).limit(1))
    if row is None:
        row = Job(kind="publication", source_id=identity)
        db.add(row)
    row.status, row.error = "pending", "公开日期仍有待核实或补证缺口，结果见漏洞详情"
    row.lease_until = now() + timedelta(hours=24)


def run_once(heartbeat=None, transport=None):
    from .maintenance import active
    with session() as db:
        if active(db):
            return False
        for stale in db.scalars(select(Job).where(Job.kind == "publication", Job.status == "running", Job.lease_until < now())):
            stale.status = "pending"
        row = db.scalar(select(Job).where(Job.kind == "publication", Job.status == "pending",
                        or_(Job.lease_until.is_(None), Job.lease_until <= now()))
                        .order_by(Job.created_at).with_for_update(skip_locked=True).limit(1))
        if not row:
            db.commit()
            return False
        job_id, identity = row.id, row.source_id
        row.status, row.lease_until = "running", now() + timedelta(minutes=10)
        db.commit()
    try:
        result = enrich(identity, transport=transport, heartbeat=heartbeat)
        with session() as db:
            row = db.get(Job, job_id)
            if row:
                retry = unresolved(result)
                row.status, row.error = ("pending", "公开日期仍有待核实或补证缺口，结果见漏洞详情") if retry else ("done", None)
                row.lease_until = now() + timedelta(hours=24) if retry else None
                db.commit()
    except (KeyboardInterrupt, SystemExit, InterruptedError):
        raise
    except Exception as exc:
        with session() as db:
            row = db.get(Job, job_id)
            if row:
                row.status, row.error, row.lease_until = "failed", error_details(exc)["reason"], None
                db.commit()
    return True
