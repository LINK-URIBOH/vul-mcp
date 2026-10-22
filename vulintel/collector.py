"""Bounded HTTP downloads and diagnostics that never log upstream payloads or credentials."""
import contextlib
import errno
import io
import json
import logging
import random
import re
import tempfile
import time
import traceback
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from .config import settings

log = logging.getLogger("vulintel.collector")
NORMAL_LIMIT = 24 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
MANIFEST_LIMIT = 16 * 1024 * 1024
RETRY_STATUSES = {429, 500, 502, 503, 504}
TRANSIENT_ERRORS = (httpx.NetworkError, httpx.TimeoutException, httpx.RemoteProtocolError, httpx.DecodingError)


class CollectionError(ValueError):
    def __init__(self, code, message, *, retry_at=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_at = retry_at


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def retry_after(value):
    if not value:
        return None
    try:
        if re.fullmatch(r"\d+", value.strip()):
            # Untrusted Retry-After must not overflow datetime/timedelta.
            seconds = min(int(value.strip()[:12]), 86400 * 365)
            return utcnow() + timedelta(seconds=seconds)
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OverflowError):
        return None


def error_details(exc, context=None):
    """Allowlisted fields and stack locations only: no exception text, locals, or source lines."""
    result = dict(context or {})
    response = getattr(exc, "response", None)
    status = response.status_code if response is not None else result.get("status")
    code = exc.code if isinstance(exc, CollectionError) else type(exc).__name__
    reason = exc.message if isinstance(exc, CollectionError) else "采集失败，请根据阶段和堆栈位置排查"
    if status == 403:
        code, reason = "upstream_forbidden", "官方来源拒绝访问"
    elif isinstance(exc, httpx.HTTPStatusError):
        code, reason = "upstream_http_error", "官方来源返回 HTTP 错误"
    elif isinstance(exc, httpx.TimeoutException):
        code, reason = "upstream_timeout", "官方来源连接或读取超时"
    elif isinstance(exc, httpx.RemoteProtocolError):
        code, reason = "upstream_disconnected", "官方来源传输中断"
    elif isinstance(exc, httpx.NetworkError):
        code, reason = "upstream_network_error", "官方来源网络连接失败"
    elif isinstance(exc, httpx.DecodingError):
        code, reason = "invalid_compressed_response", "官方来源压缩响应损坏"
    elif isinstance(exc, OSError) and (exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}
                                     or getattr(exc, "winerror", None) == 112):
        code, reason = "temporary_storage_full", "采集临时存储空间不足"
    elif isinstance(exc, PermissionError):
        code, reason = "temporary_storage_denied", "采集临时目录不可写"
    result.update(error=type(exc).__name__, code=code, reason=reason, status=status,
                  stack=[{"file": Path(f.filename).name, "line": f.lineno, "function": f.name}
                         for f in traceback.extract_tb(exc.__traceback__)][-12:])
    return result


def log_event(event, *, level=logging.INFO, **fields):
    log.log(level, json.dumps({"event": event, **fields}, ensure_ascii=False, default=str))


def failure_schedule(exc):
    response = getattr(exc, "response", None)
    forbidden = response is not None and response.status_code == 403
    stamp = utcnow() + timedelta(hours=1) if forbidden else utcnow() + timedelta(minutes=15)
    deferred = getattr(exc, "retry_at", None)
    if deferred:
        stamp = max(stamp, deferred)
    if response is not None:
        hint = retry_after(response.headers.get("retry-after"))
        if hint:
            stamp = max(stamp, hint)
    return stamp


class CollectorHTTP:
    def __init__(self, transport=None, *, heartbeat=None):
        self.client = httpx.Client(timeout=httpx.Timeout(45, connect=10, pool=10),
                                   follow_redirects=False, transport=transport,
                                   headers={"User-Agent": "VulIntel/1.0.1 (vulnerability advisory monitor)"})
        self.heartbeat_callback = heartbeat
        self.last_heartbeat = float("-inf")
        self.context = {"phase": "initialize", "document": None, "attempt": 0, "bytes": 0}

    def close(self):
        self.client.close()

    def heartbeat(self):
        current = time.monotonic()
        if self.heartbeat_callback and current - self.last_heartbeat >= 15:
            self.heartbeat_callback()
            self.last_heartbeat = current

    def pause(self, seconds):
        while seconds > 0:
            self.heartbeat()
            step = min(seconds, 1)
            time.sleep(step)
            seconds -= step
        self.heartbeat()

    @contextlib.contextmanager
    def temporary(self):
        directory = settings().data_dir / ".collector"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(mode="w+b", dir=directory) as handle:
            yield handle

    def _download(self, url, output, limit, **kwargs):
        """Every attempt rewinds its sink; a partial network response is never exposed to a parser."""
        retry_at = None
        for attempt in range(1, 4):
            retry_at = None
            output.seek(0)
            output.truncate()
            self.context.update(attempt=attempt, bytes=0, status=None)
            self.heartbeat()
            current, request_options = url, dict(kwargs)
            try:
                for redirect in range(4):
                    self.context["host"] = urlsplit(current).hostname
                    with self.client.stream("GET", current, **request_options) as response:
                        self.context["status"] = response.status_code
                        if response.status_code in (301, 302, 303, 307, 308):
                            target = urljoin(current, response.headers.get("location", ""))
                            origin, destination = urlsplit(url), urlsplit(target)
                            if (not response.headers.get("location") or destination.scheme != "https"
                                    or destination.hostname != origin.hostname
                                    or destination.port not in (None, 443)
                                    or destination.username or destination.password):
                                raise CollectionError("unsafe_redirect", "来源重定向不符合官方同源 HTTPS 规则")
                            if redirect == 3:
                                raise CollectionError("too_many_redirects", "来源重定向次数超过限制")
                            current = target
                            request_options.pop("params", None)
                            continue
                        retry_at = retry_after(response.headers.get("retry-after"))
                        if response.status_code in RETRY_STATUSES and retry_at:
                            if (retry_at - utcnow()).total_seconds() > 60:
                                raise CollectionError("retry_deferred", "官方来源要求延期重试", retry_at=retry_at)
                        response.raise_for_status()
                        # iter_bytes has already decoded Content-Encoding. Keep the expanded-size guard.
                        for chunk in response.iter_bytes(chunk_size=64 * 1024):
                            self.context["bytes"] += len(chunk)
                            self.heartbeat()
                            if self.context["bytes"] > limit:
                                raise CollectionError("response_too_large", "来源解压后响应超过容量限制")
                            output.write(chunk)
                        headers = response.headers.copy()
                        for name in ("content-encoding", "content-length", "transfer-encoding"):
                            headers.pop(name, None)
                        output.seek(0)
                        return response.status_code, headers, response.request
            except (httpx.HTTPStatusError, *TRANSIENT_ERRORS) as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if isinstance(exc, httpx.HTTPStatusError) and status not in RETRY_STATUSES:
                    raise
                if attempt == 3:
                    if retry_at:
                        raise CollectionError("retry_exhausted", "官方来源重试后仍不可用",
                                              retry_at=retry_at) from exc
                    raise
                delay = max(0, (retry_at - utcnow()).total_seconds()) if retry_at else 2 ** (attempt - 1)
                log_event("request_retry", level=logging.WARNING, **error_details(exc, self.context))
                self.pause(delay + random.uniform(0, 0.25))
        raise CollectionError("download_incomplete", "来源下载未完成")

    def get(self, url, **kwargs):
        with io.BytesIO() as output:
            status, headers, request = self._download(url, output, NORMAL_LIMIT, **kwargs)
            return httpx.Response(status, headers=headers, content=output.getvalue(), request=request)

    @contextlib.contextmanager
    def downloaded(self, url, *, limit=FILE_LIMIT, **kwargs):
        with self.temporary() as output:
            self._download(url, output, limit, **kwargs)
            yield output
