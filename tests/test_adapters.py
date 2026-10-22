from datetime import datetime

import httpx

from vulintel.db import Source
from vulintel.sources import CVE, Upstream, catalog, date


def source(sid):
    sid, name, kind, url, config = next(row for row in catalog() if row[0] == sid)
    return Source(id=sid, name=name, kind=kind, url=url, config=config)


def test_cve_regex_and_utc():
    assert CVE.findall("fix CVE-2026-12345") == ["CVE-2026-12345"]
    assert date("2026-10-22T04:00:00") == datetime(2026, 10, 22, 4)
    assert date("2026-10-22T12:00:00+08:00") == datetime(2026, 10, 22, 4)


def test_nvd_pagination():
    seen = []
    def response(request):
        start = int(request.url.params["startIndex"])
        seen.append(start)
        return httpx.Response(200, json={"totalResults": 2, "vulnerabilities": [{"cve": {"id": f"CVE-2026-{10000 + start}"}}]})
    upstream = Upstream(httpx.MockTransport(response))
    import unittest.mock
    with unittest.mock.patch("vulintel.sources.time.sleep"):
        rows = list(upstream.records(source("nvd"), datetime(2026, 10, 15), datetime(2026, 10, 22)))
    assert seen == [0, 1] and len(rows) == 2
    upstream.close()


def test_osv_stream_window_and_record():
    def response(request):
        if str(request.url).endswith("modified_id.csv"):
            return httpx.Response(200, text="2026-10-21T00:00:00Z,GO-2026-1234\n2020-01-01T00:00:00Z,GO-2020-1\n")
        assert str(request.url).endswith("GO-2026-1234.json")
        return httpx.Response(200, json={"id": "GO-2026-1234", "aliases": ["CVE-2026-12345"]})
    upstream = Upstream(httpx.MockTransport(response))
    rows = list(upstream.records(source("osv-go"), datetime(2026, 10, 15), datetime(2026, 10, 22)))
    assert len(rows) == 1 and "CVE-2026-12345" in rows[0]["aliases"]
    upstream.close()


def test_rss_does_not_merge_different_cves():
    feed = b'''<?xml version="1.0"?><rss version="2.0"><channel><title>Security</title>
    <item><title>CVE-2026-12345 and CVE-2026-67890</title><link>https://nodejs.org/advisory</link>
    <description>Two vulnerabilities</description><pubDate>Wed, 21 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>'''
    upstream = Upstream(httpx.MockTransport(lambda request: httpx.Response(200, content=feed)))
    rows = list(upstream.records(source("nodejs"), datetime(2026, 10, 15), datetime(2026, 10, 22)))
    assert rows[0]["aliases"] == []
    assert rows[0]["mentioned_cves"] == ["CVE-2026-12345", "CVE-2026-67890"]
    upstream.close()
