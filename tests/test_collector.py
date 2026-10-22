import gzip
import errno
import json
import logging
import zlib
from contextlib import contextmanager
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from scripts import check_sources
from vulintel import collector
from vulintel.collector import CollectionError, error_details
from vulintel.db import Source, SourceRecord, now
from vulintel.sources import Upstream, catalog, collect_one, iso


def source(sid):
    sid, name, kind, url, config = next(row for row in catalog() if row[0] == sid)
    return Source(id=sid, name=name, kind=kind, url=url, config=config)


@pytest.fixture(autouse=True)
def fast_backoff(monkeypatch):
    monkeypatch.setattr(collector.time, "sleep", lambda _: None)
    monkeypatch.setattr(collector.random, "uniform", lambda *_: 0)


@pytest.mark.parametrize("encoding", [None, "gzip", "deflate"])
def test_response_is_decoded_once_and_headers_describe_decoded_body(encoding):
    raw = json.dumps({"message": "中文 compressed data"}, ensure_ascii=False).encode()
    body = gzip.compress(raw) if encoding == "gzip" else zlib.compress(raw) if encoding else raw
    headers = {"Content-Length": str(len(body)), "Transfer-Encoding": "chunked"}
    if encoding:
        headers["Content-Encoding"] = encoding
    client = Upstream(httpx.MockTransport(lambda _: httpx.Response(
        200, headers=headers, stream=httpx.ByteStream(body))))
    try:
        result = client.get("https://example.org/feed")
        assert result.content == raw
        assert result.json()["message"].startswith("中文")
        assert "content-encoding" not in result.headers
        assert "transfer-encoding" not in result.headers
        assert int(result.headers["content-length"]) == len(raw)
    finally:
        client.close()


def test_corrupt_compression_and_expanded_size_limit_are_failures(monkeypatch):
    monkeypatch.setattr(collector, "NORMAL_LIMIT", 1024)
    for body in (b"not gzip", gzip.compress(b"x" * 2048)):
        client = Upstream(httpx.MockTransport(lambda _: httpx.Response(
            200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(body))))
        try:
            with pytest.raises((httpx.DecodingError, CollectionError)):
                client.get("https://example.org/data")
        finally:
            client.close()


@pytest.mark.parametrize("failure", ["status", "disconnect", "timeout"])
def test_transient_get_retries_then_succeeds(failure):
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            if failure == "disconnect":
                raise httpx.RemoteProtocolError("connection lost", request=request)
            if failure == "timeout":
                raise httpx.ReadTimeout("read timeout", request=request)
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        assert upstream.get("https://example.org/feed").json() == {"ok": True}
        assert len(calls) == 3
    finally:
        upstream.close()


def test_short_retry_after_is_observed_and_http_date_defers(monkeypatch):
    from email.utils import format_datetime
    from datetime import timezone
    sleeps, calls = [], []
    monkeypatch.setattr(collector.time, "sleep", sleeps.append)
    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "2"}) if len(calls) == 1 else httpx.Response(200)
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        assert upstream.get("https://example.org/data").status_code == 200
        assert len(calls) == 2 and 1 <= sum(sleeps) <= 2
    finally:
        upstream.close()
    stamp = now().replace(tzinfo=timezone.utc) + timedelta(hours=1)
    assert collector.retry_after(format_datetime(stamp)).replace(tzinfo=timezone.utc) >= stamp - timedelta(seconds=1)


def test_retry_after_long_delay_defers_source_without_advancing_cursor(store):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "1800"})
    upstream = Upstream(httpx.MockTransport(handler))
    started = now()
    try:
        with pytest.raises(CollectionError, match="延期"):
            collect_one("kev", upstream=upstream)
        assert len(calls) == 1
        with store() as db:
            row = db.get(Source, "kev")
            assert row.last_success is None
            assert row.next_run >= started + timedelta(minutes=30)
            assert "retry_deferred" in row.error
    finally:
        upstream.close()


def test_forbidden_is_not_retried_and_has_one_hour_backoff(store):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(403, text="private upstream body")
    upstream = Upstream(httpx.MockTransport(handler))
    started = now()
    try:
        with pytest.raises(httpx.HTTPStatusError):
            collect_one("cisa-advisories", upstream=upstream)
        assert len(calls) == 1
        with store() as db:
            row = db.get(Source, "cisa-advisories")
            assert row.last_success is None
            assert row.next_run >= started + timedelta(hours=1)
            assert "官方来源拒绝访问" in row.error
            assert "private" not in row.error
    finally:
        upstream.close()


def test_logs_never_include_exception_text_headers_or_query_secrets(store, caplog):
    secret = "PRIVATE-TOKEN-NOT-FOR-LOGS"
    def handler(request):
        raise httpx.ReadTimeout(f"{secret} https://user:pass@example.org/?apiKey={secret}", request=request)
    upstream = Upstream(httpx.MockTransport(handler))
    caplog.set_level(logging.INFO, logger="vulintel.collector")
    try:
        with pytest.raises(httpx.ReadTimeout):
            collect_one("nvd", upstream=upstream, job_id="test-job")
        assert secret not in caplog.text and "user:pass" not in caplog.text
        events = [json.loads(record.message) for record in caplog.records]
        failed = next(row for row in events if row["event"] == "collection_failed")
        assert failed["job"] == "test-job" and failed["source"] == "nvd"
        assert failed["attempt"] == 3 and failed["stack"]
        assert failed["phase"] == "nvd_fetch" and failed["processed"] == 0
    finally:
        upstream.close()


def test_only_same_origin_https_redirects_are_followed():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/end"})
        return httpx.Response(200, text="done")
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        assert upstream.get("https://example.org/start").text == "done"
    finally:
        upstream.close()
    for target in ("http://example.org/end", "https://other.example/end", "https://example.org:444/end"):
        upstream = Upstream(httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": target})))
        try:
            with pytest.raises(CollectionError, match="HTTPS"):
                upstream.get("https://example.org/start")
        finally:
            upstream.close()


class TrackedStream(httpx.SyncByteStream):
    def __init__(self, body, *, fail=False):
        self.body, self.fail, self.closed = body, fail, False

    def __iter__(self):
        yield self.body
        if self.fail:
            raise httpx.RemoteProtocolError("partial index lost")

    def close(self):
        self.closed = True


def test_osv_closes_index_before_details_retries_and_deduplicates(store):
    streams, details = [], []
    def handler(request):
        if request.url.path.endswith("modified_id.csv"):
            fail = not streams
            vid = "SHOULD-NOT-BE-PROCESSED" if fail else "GO-2026-1234"
            line = f"{iso(now())},{vid}\n".encode()
            stream = TrackedStream(line + line, fail=fail)
            streams.append(stream)
            return httpx.Response(200, stream=stream)
        assert all(stream.closed for stream in streams)
        details.append(request.url.path)
        return httpx.Response(200, json={"id": "GO-2026-1234"})
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        rows = list(upstream.records(source("osv-go"), now() - timedelta(days=7), now() + timedelta(seconds=1)))
        assert [row["source_key"] for row in rows] == ["GO-2026-1234"]
        assert len(streams) == 2 and len(details) == 1
        assert list((collector.settings().data_dir / ".collector").iterdir()) == []
    finally:
        upstream.close()


def test_osv_manifest_limit_and_generator_cancel_release_files(store, monkeypatch):
    body = (iso(now()) + ",GO-2026-1234\n").encode()
    upstream = Upstream(httpx.MockTransport(lambda request: httpx.Response(
        200, stream=httpx.ByteStream(body)) if str(request.url).endswith("csv")
        else httpx.Response(200, json={"id": "GO-2026-1234"})))
    try:
        monkeypatch.setattr("vulintel.sources.MANIFEST_LIMIT", 1)
        with pytest.raises(CollectionError, match="清单"):
            list(upstream.records(source("osv-go"), now() - timedelta(days=7), now() + timedelta(seconds=1)))
        monkeypatch.setattr("vulintel.sources.MANIFEST_LIMIT", collector.MANIFEST_LIMIT)
        generator = upstream.records(source("osv-go"), now() - timedelta(days=7), now() + timedelta(seconds=1))
        assert next(generator)["source_key"] == "GO-2026-1234"
        generator.close()
        assert list((collector.settings().data_dir / ".collector").iterdir()) == []
    finally:
        upstream.close()


def test_osv_detail_disconnect_retries_without_redownloading_index(store):
    index_calls, detail_calls = [], []
    def handler(request):
        if str(request.url).endswith("csv"):
            index_calls.append(request)
            return httpx.Response(200, text=f"{iso(now())},GO-2026-1234\n")
        detail_calls.append(request)
        if len(detail_calls) == 1:
            raise httpx.RemoteProtocolError("detail disconnected", request=request)
        return httpx.Response(200, json={"id": "GO-2026-1234"})
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        assert collect_one("osv-go", upstream=upstream) == 1
        assert len(index_calls) == 1 and len(detail_calls) == 2
    finally:
        upstream.close()


class LargeDocument(httpx.SyncByteStream):
    def __init__(self, mib=25, trailer=b""):
        self.mib, self.trailer, self.closed = mib, trailer, False

    def __iter__(self):
        yield b'{"metadata":['
        for _ in range(self.mib * 1024):
            yield b'"' + b"x" * 1024 + b'",'
        yield b'null],"Vulnerability":[{"CVE":"CVE-2026-12345"},{"CVE":"CVE-2026-67890"}]}'
        yield self.trailer

    def close(self):
        self.closed = True


def msrc_transport(document):
    modified = iso(now() - timedelta(seconds=1))
    def handler(request):
        if request.url.path.endswith("updates"):
            return httpx.Response(200, json={"value": [{"ID": "2026-Oct", "CurrentReleaseDate": modified,
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"}]})
        return httpx.Response(200, stream=document)
    return httpx.MockTransport(handler)


def test_msrc_over_24_mib_streams_into_database_and_replay_is_idempotent(store):
    for _ in range(2):
        document = LargeDocument()
        upstream = Upstream(msrc_transport(document))
        try:
            assert collect_one("msrc", upstream=upstream) == 2
            assert document.closed
        finally:
            upstream.close()
    with store() as db:
        assert db.scalar(select(func.count()).select_from(SourceRecord)) == 2
        assert db.get(Source, "msrc").last_success is not None
        assert db.get(Source, "msrc").error is None
    assert list((collector.settings().data_dir / ".collector").iterdir()) == []


def test_msrc_over_64_mib_is_rejected_and_cleaned_up(store):
    document = LargeDocument(mib=65)
    upstream = Upstream(msrc_transport(document))
    try:
        with pytest.raises(CollectionError, match="容量"):
            collect_one("msrc", upstream=upstream)
        assert document.closed
        with store() as db:
            assert db.get(Source, "msrc").last_success is None
            assert db.scalar(select(func.count()).select_from(SourceRecord)) == 0
        assert list((collector.settings().data_dir / ".collector").iterdir()) == []
    finally:
        upstream.close()


@pytest.mark.parametrize("body", [b'{}', b'{"Vulnerability":{}}', b'[]'])
def test_msrc_invalid_document_schema_is_not_empty_success(store, body):
    upstream = Upstream(msrc_transport(httpx.ByteStream(body)))
    try:
        with pytest.raises(CollectionError):
            collect_one("msrc", upstream=upstream)
        with store() as db:
            assert db.get(Source, "msrc").last_success is None
    finally:
        upstream.close()


def test_msrc_corrupt_tail_retains_partial_data_then_restart_completes(store):
    upstream = Upstream(msrc_transport(LargeDocument(mib=0, trailer=b" INVALID")))
    try:
        with pytest.raises(CollectionError):
            collect_one("msrc", upstream=upstream)
        with store() as db:
            assert db.get(Source, "msrc").last_success is None
    finally:
        upstream.close()
    upstream = Upstream(msrc_transport(LargeDocument(mib=0)))
    try:
        assert collect_one("msrc", upstream=upstream) == 2
        with store() as db:
            assert db.scalar(select(func.count()).select_from(SourceRecord)) == 2
            assert db.get(Source, "msrc").last_success is not None
    finally:
        upstream.close()


def test_msrc_updated_historical_month_is_included_and_future_update_is_skipped(store):
    fetched = []
    current = now()
    def handler(request):
        if request.url.path.endswith("updates"):
            return httpx.Response(200, json={"value": [
                {"ID": "2007-Aug", "CurrentReleaseDate": iso(current - timedelta(days=1)),
                 "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2007-Aug"},
                {"ID": "2026-Oct", "CurrentReleaseDate": iso(current + timedelta(days=1)),
                 "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"}]})
        fetched.append(request.url.path)
        return httpx.Response(200, json={"Vulnerability": [{"CVE": "CVE-2007-1234"}]})
    upstream = Upstream(httpx.MockTransport(handler))
    try:
        assert collect_one("msrc", upstream=upstream) == 1
        assert fetched == ["/cvrf/v3.0/cvrf/2007-Aug"]
    finally:
        upstream.close()


def test_disk_full_keeps_cursor_and_closes_temporary_file(store, monkeypatch):
    closed = []
    original = Upstream.temporary
    class FullDisk:
        def __init__(self, handle):
            self.handle = handle
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def write(self, content):
            raise OSError(errno.ENOSPC, "No space left on device: private filesystem details")
    @contextmanager
    def temporary(self):
        with original(self) as handle:
            try:
                yield FullDisk(handle)
            finally:
                closed.append(handle)
    monkeypatch.setattr(Upstream, "temporary", temporary)
    upstream = Upstream(msrc_transport(LargeDocument(mib=0)))
    try:
        with pytest.raises(OSError):
            collect_one("msrc", upstream=upstream)
        assert closed and all(handle.closed for handle in closed)
        with store() as db:
            row = db.get(Source, "msrc")
            assert row.last_success is None and "private" not in row.error
            assert "temporary_storage_full" in row.error
    finally:
        upstream.close()


def test_heartbeat_runs_during_download_and_backoff_without_delivery(monkeypatch):
    touches, clock = [], [0]
    monkeypatch.setattr(collector.time, "monotonic", lambda: clock[0])
    def sleep(seconds):
        clock[0] += seconds
    monkeypatch.setattr(collector.time, "sleep", sleep)
    upstream = Upstream(heartbeat=lambda: touches.append(clock[0]))
    try:
        upstream.pause(46)
        assert touches == [0, 15, 30, 45]
    finally:
        upstream.close()


def test_download_updates_heartbeat_while_streaming(monkeypatch):
    touches, clock = [], [0]
    monkeypatch.setattr(collector.time, "monotonic", lambda: clock[0])
    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(3):
                clock[0] += 16
                yield b"x" * 65536
    upstream = Upstream(httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowStream())),
                        heartbeat=lambda: touches.append(clock[0]))
    try:
        assert len(upstream.get("https://example.org/slow").content) == 3 * 65536
        assert touches == [0, 16, 32, 48]
    finally:
        upstream.close()


def test_worker_uses_separate_heartbeat_and_delivery_callbacks(store, monkeypatch):
    from vulintel import worker
    from vulintel.db import Job
    sent = []
    monkeypatch.setattr(worker, "deliver_one", lambda db: sent.append(True))
    def collect(source_id, **kwargs):
        kwargs["heartbeat"]()
        assert sent == []
        kwargs["delivery_tick"]()
        assert sent == [True]
        return 1
    monkeypatch.setattr(worker, "collect_one", collect)
    with store() as db:
        job = Job(kind="collect", source_id="kev")
        db.add(job)
        db.commit()
        job_id = job.id
    assert worker.work_once()
    assert (collector.settings().data_dir / "worker.heartbeat").exists()
    with store() as db:
        assert db.get(Job, job_id).status == "done"


def test_check_cli_filters_sources_summarizes_and_fails_full_only(monkeypatch, capsys):
    selected = []
    def fake_check(value, days, full, cancelled=None):
        selected.append((value[0], days, full))
        return {"id": value[0], "result": "failed", "processed": 0}
    monkeypatch.setattr(check_sources, "check", fake_check)
    assert check_sources.main(["--source", "msrc", "--source", "nvd", "--days", "2", "--full"]) == 1
    assert {row[0] for row in selected} == {"msrc", "nvd"}
    assert all(row[1:] == (2, True) for row in selected)
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["failed"] == 2 and summary["sources"] == 2
    assert check_sources.main(["--source", "nvd"]) == 0


def test_error_details_excludes_exception_text():
    details = error_details(ValueError("super-secret query=token"))
    assert "super-secret" not in json.dumps(details)


def test_client_initialization_failure_is_scheduled_and_redacted(store, monkeypatch):
    def broken_client(**kwargs):
        raise ValueError("private proxy username:password")
    monkeypatch.setattr("vulintel.sources.Upstream", broken_client)
    with pytest.raises(ValueError):
        collect_one("kev")
    with store() as db:
        row = db.get(Source, "kev")
        assert row.last_success is None and row.next_run > now()
        assert "private" not in row.error


def test_ingest_failure_closes_live_record_generator_and_temporary_file(store, monkeypatch):
    def broken_ingest(*args):
        raise ValueError("database failure")
    monkeypatch.setattr("vulintel.service.ingest", broken_ingest)
    upstream = Upstream(msrc_transport(LargeDocument(mib=0)))
    try:
        with pytest.raises(ValueError):
            collect_one("msrc", upstream=upstream)
        assert list((collector.settings().data_dir / ".collector").iterdir()) == []
    finally:
        upstream.close()


def test_msrc_floats_remain_json_serializable(store):
    body = json.dumps({"Vulnerability": [{"CVE": "CVE-2026-12345",
                                         "Remediations": [{"value": 1.25}]}]}).encode()
    upstream = Upstream(msrc_transport(httpx.ByteStream(body)))
    try:
        assert collect_one("msrc", upstream=upstream) == 1
        with store() as db:
            row = db.scalar(select(SourceRecord))
            assert row.data["remediations"][0]["value"] == 1.25
    finally:
        upstream.close()


def test_read_only_check_does_not_open_database(monkeypatch):
    def forbidden_database():
        raise AssertionError("Read-only source check must not open the business database")
    monkeypatch.setattr("vulintel.db.engine", forbidden_database)
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"vulnerabilities": [
        {"cveID": "CVE-2026-12345"}, {"cveID": "CVE-2026-67890"}]}))
    monkeypatch.setattr(check_sources, "Upstream", lambda: Upstream(transport))
    result = check_sources.check(next(row for row in catalog() if row[0] == "kev"), full=True)
    assert result["complete"] and result["processed"] == 2
    def broken_client():
        raise ValueError("private proxy credentials")
    monkeypatch.setattr(check_sources, "Upstream", broken_client)
    result = check_sources.check(next(row for row in catalog() if row[0] == "kev"), full=True)
    assert result["result"] == "failed" and "private" not in json.dumps(result)


def test_interrupted_download_cleans_up_without_advancing_source(store):
    class Cancelled(httpx.SyncByteStream):
        def __iter__(self):
            yield b"partial"
            raise KeyboardInterrupt()
    upstream = Upstream(msrc_transport(Cancelled()))
    try:
        with pytest.raises(KeyboardInterrupt):
            collect_one("msrc", upstream=upstream)
        with store() as db:
            assert db.get(Source, "msrc").last_success is None
        assert list((collector.settings().data_dir / ".collector").iterdir()) == []
    finally:
        upstream.close()


def test_cli_cancellation_callback_stops_before_network_request(store, monkeypatch):
    import threading
    cancelled = threading.Event()
    cancelled.set()
    calls = []
    def make_client(**kwargs):
        def handler(request):
            calls.append(request)
            return httpx.Response(200)
        return Upstream(httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(check_sources, "Upstream", make_client)
    result = check_sources.check(next(row for row in catalog() if row[0] == "msrc"), full=True,
                                 cancelled=cancelled)
    assert result["result"] == "failed" and result["error"] == "InterruptedError"
    assert calls == []


def test_collection_progress_reports_committed_count_without_advancing_early(store, monkeypatch, caplog):
    from vulintel.sources import entry
    clock = [0]
    monkeypatch.setattr("vulintel.sources.time.monotonic", lambda: clock[0])
    class SlowRecords:
        def records(self, source, start, end):
            clock[0] = 16
            yield entry("test-progress", "test", "")
            with store() as db:
                assert db.get(Source, "kev").last_success is None
    caplog.set_level(logging.INFO, logger="vulintel.collector")
    assert collect_one("kev", upstream=SlowRecords(), job_id="progress-job") == 1
    events = [json.loads(record.message) for record in caplog.records]
    progress = next(row for row in events if row["event"] == "collection_progress")
    assert progress["processed"] == 1 and progress["job"] == "progress-job"


def test_forbidden_retry_after_later_than_one_hour_is_respected():
    started = now()
    response = httpx.Response(403, headers={"Retry-After": "7200"},
                              request=httpx.Request("GET", "https://example.org/feed"))
    with pytest.raises(httpx.HTTPStatusError) as error:
        response.raise_for_status()
    assert collector.failure_schedule(error.value) >= started + timedelta(hours=2)
