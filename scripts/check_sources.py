"""Read-only upstream checks; sampling by default, complete windows with --full."""
import argparse
import concurrent.futures
import contextlib
import json
import logging
import sys
import threading
import time
from datetime import timedelta

from vulintel.collector import error_details, failure_schedule, log_event
from vulintel.db import Source, now
from vulintel.sources import Upstream, catalog


def check(value, days=7, full=False, cancelled=None):
    sid, name, kind, url, config = value
    source = Source(id=sid, name=name, kind=kind, url=url, config=config)
    upstream = None
    generator = None
    count, sample = 0, None
    started = time.monotonic()
    end = now()
    next_progress = started + 15
    def heartbeat():
        if cancelled is not None and cancelled.is_set():
            raise InterruptedError("Source check cancelled")
    try:
        log_event("source_check_started", source=sid, full=full, days=days)
        upstream = Upstream(heartbeat=heartbeat) if cancelled is not None else Upstream()
        generator = upstream.records(source, end - timedelta(days=days), end)
        for record in generator:
            count += 1
            if sample is None:
                sample = record["source_key"]
            if time.monotonic() >= next_progress:
                log_event("source_check_progress", processed=count,
                          elapsed=round(time.monotonic() - started, 3), **upstream.context)
                next_progress = time.monotonic() + 15
            if not full:
                break
        return {"id": sid, "result": "record" if count else "empty_window", "sample": sample,
                "processed": count, "complete": full or not count,
                "elapsed": round(time.monotonic() - started, 3)}
    except Exception as exc:
        return {"id": sid, "result": "failed", "processed": count, "complete": False,
                "next_retry_utc": failure_schedule(exc).isoformat() + "Z",
                "elapsed": round(time.monotonic() - started, 3),
                **error_details(exc, getattr(upstream, "context", {}))}
    finally:
        if generator:
            generator.close()
        if upstream is not None:
            upstream.close()


@contextlib.contextmanager
def check_logging():
    logger = logging.getLogger("vulintel.collector")
    level, propagate = logger.level, logger.propagate
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(level)
        logger.propagate = propagate


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="只读检查官方来源，不写业务数据库")
    parser.add_argument("--source", action="append", default=[], help="来源 ID；可重复指定")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--full", action="store_true", help="完整处理时间窗口，而非只检查首条")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.days <= 100:
        parser.error("--days 必须为 1..100（NVD 单窗口限制）")
    if not 1 <= args.workers <= 4:
        parser.error("--workers 必须为 1..4")
    values = catalog()
    if set(args.source) - {row[0] for row in values}:
        parser.error("未知来源 ID")
    if args.source:
        values = [row for row in values if row[0] in args.source]
    failed, processed = 0, 0
    cancelled = threading.Event()
    with check_logging(), concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(check, row, args.days, args.full, cancelled) for row in values]
        try:
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                failed += result["result"] == "failed"
                processed += result["processed"]
                print(json.dumps(result, ensure_ascii=False), flush=True)
        except KeyboardInterrupt:
            cancelled.set()
            for future in futures:
                future.cancel()
            print(json.dumps({"event": "summary", "cancelled": True, "full": args.full}), flush=True)
            return 130
    print(json.dumps({"event": "summary", "sources": len(values), "failed": failed,
                      "processed": processed, "full": args.full}, ensure_ascii=False), flush=True)
    return 1 if args.full and failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
