"""Fixed, auditable upstream adapters. No model-supplied URLs are fetched."""
import csv
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urljoin, urlsplit

import feedparser
import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from .config import settings
from .db import Source, now

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def date(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def iso(value):
    return value.isoformat(timespec="seconds") + "Z"


def text(value):
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
                 cvss=cvss, status=cve.get("vulnStatus"), source_authority="NVD")


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
                 exploited=True, published=record.get("dateAdded"),
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


class Upstream:
    def __init__(self, transport=None):
        self.client = httpx.Client(timeout=45, follow_redirects=False, transport=transport,
                                   headers={"User-Agent": "VulIntel/1.0 (vulnerability advisory monitor)"})

    def close(self):
        self.client.close()

    def get(self, url, **kwargs):
        # All callers use registry or same-origin validated upstream links.
        for _ in range(4):
            with self.client.stream("GET", url, **kwargs) as streamed:
                chunks, size = [], 0
                for chunk in streamed.iter_bytes():
                    size += len(chunk)
                    if size > 24 * 1024 * 1024:
                        raise ValueError("Upstream response exceeds 24 MiB; no cursor advanced")
                    chunks.append(chunk)
                response = httpx.Response(streamed.status_code, headers=streamed.headers,
                                          content=b"".join(chunks), request=streamed.request)
            if response.status_code in (301, 302, 307, 308):
                target = urljoin(url, response.headers["location"])
                if urlsplit(target).scheme != "https" or urlsplit(target).hostname != urlsplit(url).hostname:
                    raise ValueError("Upstream cross-origin redirect refused")
                url = target
                continue
            response.raise_for_status()
            return response
        raise ValueError("Too many redirects")

    def records(self, source, start, end):
        cfg = settings()
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
                    raise ValueError("NVD pagination stopped before totalResults")
                time.sleep(0.7 if key else 6)
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
                if target and urlsplit(target).hostname != "api.github.com":
                    raise ValueError("Invalid GitHub next page")
                url, params = target, None
        elif source.kind == "kev":
            # The full catalog is small; compare content on every pass, including old CVEs newly exploited.
            for raw in self.get(source.url).json()["vulnerabilities"]:
                yield kev_record(raw)
        elif source.kind == "osv":
            with self.client.stream("GET", source.url) as response:
                response.raise_for_status()
                for row in csv.reader(response.iter_lines()):
                    if len(row) != 2:
                        raise ValueError("OSV modified index schema changed")
                    modified = date(row[0])
                    if modified < start:
                        break
                    if modified > end:
                        continue
                    vid = row[1]
                    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", vid):
                        raise ValueError("Invalid OSV record identifier")
                    url = source.url.rsplit("/", 1)[0] + "/" + quote(vid, safe="") + ".json"
                    yield osv_record(self.get(url).json())
        elif source.kind == "msrc":
            raw = self.get(source.url, headers={"Accept": "application/json"}).json()
            for update in raw["value"]:
                modified = date(update.get("CurrentReleaseDate"))
                if modified and modified < start:
                    continue
                url = update.get("CvrfUrl", "")
                if urlsplit(url).hostname != "api.msrc.microsoft.com":
                    raise ValueError("Unexpected MSRC document host")
                doc = self.get(url, headers={"Accept": "application/json"}).json()
                for item in doc.get("Vulnerability", []):
                    identifier = item["CVE"]
                    notes = "\n".join(text(x.get("Value", "")) for x in item.get("Notes", []))
                    title = item.get("Title", {})
                    title = title.get("Value", identifier) if isinstance(title, dict) else title
                    severity = next((str(t.get("Description", {}).get("Value", "unknown")).lower()
                                     for t in item.get("Threats", []) if t.get("Type") == 3), "unknown")
                    severity = {"important": "high", "moderate": "medium"}.get(severity, severity)
                    yield entry(identifier, title, notes, [identifier],
                                [f"https://msrc.microsoft.com/update-guide/vulnerability/{identifier}"],
                                item.get("ProductStatuses", []), severity,
                                modified=update.get("CurrentReleaseDate"),
                                remediations=item.get("Remediations", []), source_authority="Microsoft")
        elif source.kind == "psf":
            import json
            import tarfile
            import tempfile
            with tempfile.TemporaryFile() as archive:
                with self.client.stream("GET", source.url) as response:
                    response.raise_for_status()
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > 64 * 1024 * 1024:
                            raise ValueError("PSF archive exceeds expected size")
                        archive.write(chunk)
                archive.seek(0)
                with tarfile.open(fileobj=archive, mode="r|gz") as entries:
                    found = False
                    for member in entries:
                        if not member.isfile() or not member.name.endswith(".json") or "/advisories/" not in member.name:
                            continue
                        if member.size > 2_000_000:
                            raise ValueError("Unexpectedly large PSF advisory")
                        record = json.load(entries.extractfile(member))
                        found = True
                        if date(record.get("modified")) and date(record["modified"]) >= start:
                            yield osv_record(record)
                    if not found:
                        raise ValueError("PSF archive schema changed")
        elif source.kind == "rss":
            parsed = feedparser.parse(self.get(source.url).content)
            if not parsed.entries:
                raise ValueError("Feed has no entries; check source endpoint/parser")
            for raw in parsed.entries:
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
                            mentioned_cves=sorted(set(aliases)), source_authority=source.name,
                            record_type="bulletin")
        elif source.kind == "bulletin":
            soup = BeautifulSoup(self.get(source.url).text, "html.parser")
            links = sorted({urljoin(source.url, a["href"]).split("#")[0].split("?")[0].rstrip("/")
                            for a in soup.select("a[href]")})
            matched = [url for url in links if re.fullmatch(source.config["pattern"], url)
                       and source.config.get("exclude", "never-match") not in url]
            if not matched:
                raise ValueError("No bulletin links found; upstream layout may have changed")
            for link in matched:
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
                yield entry(hashlib.sha256(link.encode()).hexdigest(), title, description, [], [link],
                            [{"product": source.config["product"]}], mentioned_cves=identifiers,
                            source_authority=source.name, record_type="bulletin")
        else:
            raise ValueError("Unsupported source adapter")


def collect_one(source_id, force=False, upstream=None, heartbeat=None):
    from .db import session
    from .service import ingest
    own_client = upstream is None
    upstream = upstream or Upstream()
    cutoff = now()
    with session() as db:
        source = db.get(Source, source_id)
        if source is None or (not source.enabled and not force):
            return
        source.last_attempt = cutoff
        start = (source.last_success - timedelta(hours=48)) if source.last_success else cutoff - timedelta(days=7)
        # NVD limits date ranges; split long outages into <=100-day windows, advancing only fully fetched windows.
        end = min(cutoff, start + timedelta(days=100)) if source.kind == "nvd" else cutoff
        db.commit()
        try:
            count = 0
            for record in upstream.records(source, start, end):
                if source.kind == "kev" and date(record.get("published")) and date(record["published"]) < start:
                    from .db import Alias, SourceRecord
                    known = db.scalar(select(SourceRecord).where(SourceRecord.source_id == source.id,
                                                               SourceRecord.source_key == record["source_key"]))
                    if not known and not db.get(Alias, record["source_key"].upper()):
                        continue
                ingest(db, source.id, record)
                db.commit()
                count += 1
                if heartbeat and count % 20 == 0:
                    heartbeat()
            source.last_success = end
            source.error = None
            source.next_run = cutoff + timedelta(seconds=settings().source_interval_seconds)
            if end < cutoff:
                source.next_run = cutoff
            db.commit()
            return count
        except Exception as exc:
            db.rollback()
            source = db.get(Source, source_id)
            # Deliberately omit exception strings: HTTP URLs/headers may contain upstream credentials.
            status = getattr(getattr(exc, "response", None), "status_code", None)
            source.error = f"{type(exc).__name__}" + (f" · HTTP {status}" if status else " · 采集失败，请检查来源与日志")
            source.next_run = cutoff + timedelta(minutes=15)
            db.commit()
            raise
        finally:
            if own_client:
                upstream.close()
