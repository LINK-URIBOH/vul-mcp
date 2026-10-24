"""Synthetic-data benchmark; refuses production database names and never sends network notifications."""
import argparse
import concurrent.futures
import contextlib
import json
import logging
import sys
import time
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from vulintel import __version__
from vulintel.config import settings
from vulintel.db import (Batch, BatchItem, Delivery, MetadataState, PublicationAnnotation, PublicationState,
                         Revision, RevisionDateProjection, Vulnerability,
                         migrate, now, session, uid)
from vulintel.publication import DATE_POLICY, proof, resolve_publication
from vulintel.report_jobs import run_report_once, status
from vulintel.reports import report_dir
from vulintel.service import Analysis, digest, due_slot, finalize, open_batch
from vulintel.timeline import EVENT_POLICY, iso


def memory_mib():
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
    except ImportError:
        return None


def seed(rows):
    cutoff = datetime.fromisoformat(due_slot()).replace(tzinfo=None) - timedelta(hours=8)
    with session() as db:
        if db.scalar(select(func.count()).select_from(Vulnerability)):
            raise ValueError("基准数据库必须为空；已有测试数据请使用 --run-only")
        for offset in range(0, rows, 500):
            vulns, revisions, annotations = [], [], []
            for number in range(offset, min(rows, offset + 500)):
                category = "new" if number < 20 else "update" if number < 30 else "unknown" if number < 40 else "old"
                published = cutoff - timedelta(days=1 if category == "new" else 90)
                if category == "unknown":
                    published = None
                important = cutoff - timedelta(hours=1) if category == "update" else None
                identity = f"00000000-0000-0000-0000-{number:012d}"
                facts = {"id": identity, "title": f"合成漏洞 {number}", "aliases": [f"TEST-{number}"],
                         "severity": "high" if number % 2 else "low", "exploited": category == "update",
                         "description": "synthetic-evidence-" + "x" * 2048, "affected": [{"product": "合成测试系统"}],
                         "source_records": [], "references": ["https://example.org/synthetic-advisory"],
                         "product_group": "合成测试系统", "timeline": {"published_at": iso(published),
                         "publication_source": "synthetic", "publication_basis": "合成测试时间",
                         "material_changed_at": iso(important)}}
                canonical = resolve_publication({}, [proof("synthetic", identity, "disclosed_at", iso(published),
                    "disclosure", "https://example.org/synthetic-advisory")] if published else [], assessed=cutoff)
                facts["timeline"] = {**facts["timeline"], **canonical, "event_policy": EVENT_POLICY,
                                     "important_end_at": iso(important), "important_precision": "datetime" if important else None,
                                     "important_reference": "https://example.org/synthetic-advisory" if important else None}
                annotations.append({"vulnerability_id": identity, "policy": DATE_POLICY, "assessed_at": cutoff,
                                    "status": canonical["publication_status"], "start_at": published, "end_at": published,
                                    "fingerprint": digest(canonical), "data": canonical})
                vulns.append({"id": identity, "data": facts, "title": facts["title"], "product": "合成测试系统",
                              "severity": facts["severity"], "exploited": facts["exploited"],
                              "updated_at": cutoff - timedelta(seconds=1)})
                revisions.append({"vulnerability_id": identity, "snapshot": facts,
                                  "snapshot_bytes": len(json.dumps(facts, ensure_ascii=False).encode()),
                                  "observed_at": cutoff - timedelta(seconds=1), "first_seen_at": cutoff - timedelta(seconds=1),
                                  "published_at": published, "important_at": important, "content_hash": str(number)})
            db.execute(Vulnerability.__table__.insert(), vulns)
            revision_ids = dict(db.execute(Revision.__table__.insert().returning(
                Revision.vulnerability_id, Revision.id), revisions).all())
            annotation_ids = dict(db.execute(PublicationAnnotation.__table__.insert().returning(
                PublicationAnnotation.vulnerability_id, PublicationAnnotation.id), annotations).all())
            db.execute(PublicationState.__table__.insert(), [{"vulnerability_id": row["vulnerability_id"],
                "annotation_id": annotation_ids[row["vulnerability_id"]], "policy": DATE_POLICY,
                "status": row["status"], "start_at": row["start_at"], "end_at": row["end_at"]} for row in annotations])
            db.execute(RevisionDateProjection.__table__.insert(), [{"revision_id": revision_ids[row["vulnerability_id"]],
                "policy": EVENT_POLICY, "important_at": row["important_at"], "important_end_at": row["important_at"],
                "timeline": row["snapshot"]["timeline"]} for row in revisions])
            db.commit()
            if offset % 10000 == 0:
                print(json.dumps({"seeded": offset + len(vulns), "peak_mib": memory_mib()}), flush=True)
        from vulintel.timeline import BACKFILL_KEY
        db.add(MetadataState(key=BACKFILL_KEY, value={"complete": True, "processed": rows}))
        db.add(MetadataState(key="benchmark_data", value={"rows": rows, "cutoff": iso(cutoff)}))
        db.commit()


def legacy_repro():
    """Reproduce the previous all-ORM accumulation on dedicated synthetic data only."""
    with session() as db:
        batch = Batch(id=uid(), slot="2000-01-01T09:00+08:00", cutoff=now(), status="preparing")
        db.add(batch)
        db.flush()
        for number, vuln in enumerate(db.scalars(select(Vulnerability).execution_options(yield_per=50)), start=1):
            db.add(BatchItem(batch_id=batch.id, vulnerability_id=vuln.id, snapshot=vuln.data, priority=True))
            if number % 5000 == 0:
                print(json.dumps({"legacy_pending_items": number, "peak_mib": memory_mib()}), flush=True)
        db.rollback()  # This diagnostic never commits a legacy report.


def wait(batch_id, wanted):
    for _ in range(10000):
        with session() as db:
            batch = db.get(Batch, batch_id)
            if batch.status == wanted:
                return status(db, batch)
            if batch.status == "failed":
                raise ValueError(batch.error)
        if not run_report_once():
            raise ValueError("报告队列未取得进展")
    raise ValueError("报告任务超出基准迭代上限")


@contextlib.contextmanager
def protocol_client():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from starlette.testclient import TestClient
    from vulintel.app import create_app
    cfg = settings()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    app = create_app()
    logging.getLogger("vulintel").setLevel(logging.WARNING)
    app.state.verifier.keys = {"synthetic-key": key.public_key()}
    app.state.verifier.loaded = time.monotonic()
    signed = jwt.encode({"iss": cfg.issuer_url, "sub": "synthetic-admin", "aud": cfg.resource_url,
                        "iat": int(time.time()), "exp": int(time.time()) + 300, "azp": cfg.mcp_client_id,
                        "scope": "vul.read vul.submit vul.deliver", "realm_access": {"roles": ["vul-admin"]}},
                       key, algorithm="RS256", headers={"kid": "synthetic-key"})
    with TestClient(app, base_url=cfg.public_base_url,
                    headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18",
                             "Authorization": "Bearer " + signed}) as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
                               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "synthetic-benchmark", "version": "1"}}})
        assert response.status_code == 200 and response.json()["result"]["serverInfo"]["version"] == __version__
        tools = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()["result"]["tools"]
        assert len(tools) == 9
        assert next(tool for tool in tools if tool["name"] == "open_report_batch")["annotations"]["readOnlyHint"] is False
        def call(name, arguments):
            response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                               "params": {"name": name, "arguments": arguments}})
            result = response.json().get("result", {})
            assert response.status_code == 200 and not result.get("isError"), response.text[:500]
            return result["structuredContent"]
        yield call


def run_protocol(call):
    started = time.monotonic()
    result = call("open_report_batch", {})
    latency = time.monotonic() - started
    assert result["status"] == "preparing" and result["total"] is None
    assert latency < 3, latency
    batch_id = result["batch_id"]
    def parallel_open(_):
        with session() as db:
            return open_batch(db, "synthetic-concurrency")["batch_id"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        assert set(pool.map(parallel_open, range(4))) == {batch_id}
    ready = wait(batch_id, "analyzing")
    assert ready["total"] == 30 and ready["unverified_dates"] == 10, ready
    assert call("get_report_status", {"batch_id": batch_id})["total"] == 30
    page = call("get_batch_page", {"batch_id": batch_id, "limit": 5, "pending_only": True})
    assert page["pending_analysis"] == 30
    evidence = call("get_item_evidence", {"batch_id": batch_id, "item_id": page["items"][0]["item_id"]})
    assert evidence["next_offset"] is None
    with session() as db:
        ids = list(db.scalars(select(BatchItem.id).where(BatchItem.batch_id == batch_id).order_by(BatchItem.id)))
    for offset in range(0, len(ids), 5):
        values = [Analysis(item_id=identity, vulnerability_summary="合成测试记录的中文说明，非真实漏洞情报。",
                      root_cause="合成原理，未执行漏洞代码", trigger_conditions="仅基准测试",
                      impact="合成影响", affected_versions="合成版本", attack_path="未验证，合成路径",
                      remediation="合成修复建议", evidence_level="unknown", evidence_notes="合成数据，不是验证证据",
                      references=["https://example.org/synthetic-advisory"]) for identity in ids[offset:offset + 5]]
        call("submit_batch_analysis", {"batch_id": batch_id, "analyses": [value.model_dump() for value in values]})
    result = call("finalize_report", {"batch_id": batch_id, "summary": "INTERNAL-EXECUTION-TEXT",
                                     "overview": {"risk_summary": ["合成测试报告，不代表真实漏洞风险"]}})
    assert result["status"] == "rendering"
    final = wait(batch_id, "finalized")
    root = report_dir(batch_id)
    data = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert len(data["items"]) == 30 and len(data["unverified"]) == 10
    assert "INTERNAL-EXECUTION-TEXT" not in (root / "report.html").read_text(encoding="utf-8")
    with session() as db:
        before = db.scalar(select(func.count()).select_from(Delivery))
        finalize(db, "synthetic-benchmark", batch_id, "repeat")
        assert before == db.scalar(select(func.count()).select_from(Delivery))
    print(json.dumps({"success": True, "batch_id": batch_id, "selected": final["total"],
                      "unverified": final["unverified_dates"], "open_seconds": round(latency, 4),
                      "peak_mib": memory_mib(), "elapsed_seconds": round(time.monotonic() - started, 2),
                      "deliveries_prepared": before, "report_root": str(root),
                      "signed_jwt_mcp_flow": True, "concurrent_open": 4}, ensure_ascii=False), flush=True)


def run():
    with protocol_client() as call:
        run_protocol(call)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=100000)
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument("--run-only", action="store_true")
    parser.add_argument("--legacy-repro", action="store_true")
    args = parser.parse_args()
    database = make_url(settings().database_url.get_secret_value()).database
    if not database or not (database == "report_benchmark" or database.endswith("report_benchmark.db")):
        raise SystemExit("拒绝操作：仅允许独立 report_benchmark 数据库或 report_benchmark.db 文件")
    if settings().delivery_enabled:
        raise SystemExit("基准测试必须关闭 DELIVERY_ENABLED")
    if args.rows < 100000:
        raise SystemExit("规模验收至少需要 100000 条记录")
    logging.basicConfig(level=logging.WARNING)
    migrate()
    from vulintel.sources import seed_sources
    with session() as db:
        seed_sources(db)
    if not args.run_only:
        seed(args.rows)
    if args.legacy_repro:
        legacy_repro()
    elif not args.seed_only:
        run()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"success": False, "error_type": type(exc).__name__}), file=sys.stderr, flush=True)
        raise SystemExit(1) from None
