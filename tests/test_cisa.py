from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select

from vulintel.db import Alias, Source, SourceRecord, Vulnerability
from vulintel.sources import Upstream, catalog, collect_one


def source(sid):
    sid, name, kind, url, config = next(row for row in catalog() if row[0] == sid)
    return Source(id=sid, name=name, kind=kind, url=url, config=config)


def feed():
    return b'''<?xml version="1.0"?><rss version="2.0"><channel><title>All CISA Advisories</title>
    <item><title>Two vulnerabilities</title>
    <link>https://www.cisa.gov/news-events/ics-advisories/test-advisory</link>
    <description>CVE-2026-12345 and CVE-2026-67890</description>
    <pubDate>Fri, 23 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>'''


def test_cisa_request_override_and_shared_client_isolation():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=feed())

    upstream = Upstream(httpx.MockTransport(handler))
    default_ua = upstream.client.headers["user-agent"]
    try:
        for sid in ("cisa-advisories", "debian", "cisa-advisories", "ubuntu"):
            rows = list(upstream.records(source(sid), datetime(2026, 10, 16), datetime(2026, 10, 24)))
            assert len(rows) == 1
            assert rows[0]["mentioned_cves"] == ["CVE-2026-12345", "CVE-2026-67890"]
            assert rows[0]["aliases"] == []
        assert [request.headers["user-agent"] for request in requests] == [
            "curl/8.0", default_ua, "curl/8.0", default_ua,
        ]
        assert upstream.client.headers["user-agent"] == default_ua
    finally:
        upstream.close()


@pytest.mark.parametrize("first_response", ["redirect", "retry"])
def test_cisa_override_survives_redirect_or_retry(first_response, monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            if first_response == "redirect":
                return httpx.Response(302, headers={"Location": "/cybersecurity-advisories/redirected.xml"})
            return httpx.Response(503)
        return httpx.Response(200, content=feed())

    upstream = Upstream(httpx.MockTransport(handler))
    monkeypatch.setattr(upstream, "pause", lambda _: None)
    try:
        rows = list(upstream.records(source("cisa-advisories"),
                                     datetime(2026, 10, 16), datetime(2026, 10, 24)))
        assert len(rows) == 1 and len(requests) == 2
        assert all(request.headers["user-agent"] == "curl/8.0" for request in requests)
        assert all(request.url.scheme == "https" and request.url.host == "www.cisa.gov"
                   for request in requests)
    finally:
        upstream.close()


def test_cisa_repeat_collection_clears_error_without_duplicate_or_cve_aliases(store, monkeypatch):
    cutoff = datetime(2026, 10, 23, 2, 0)
    monkeypatch.setattr("vulintel.sources.now", lambda: cutoff)
    with store() as db:
        row = db.get(Source, "cisa-advisories")
        row.last_success = cutoff - timedelta(days=1)
        row.error = "upstream_forbidden"
        db.commit()

    upstream = Upstream(httpx.MockTransport(lambda _: httpx.Response(200, content=feed())))
    try:
        for _ in range(2):
            assert collect_one("cisa-advisories", upstream=upstream) == 1
        with store() as db:
            row = db.get(Source, "cisa-advisories")
            assert row.last_success == cutoff and row.error is None
            assert row.next_run > cutoff
            assert db.scalar(select(func.count()).select_from(SourceRecord)) == 1
            assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
            assert db.scalar(select(func.count()).select_from(Alias).where(Alias.alias.like("CVE-%"))) == 0
    finally:
        upstream.close()
