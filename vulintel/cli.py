import argparse
import json


from .app import initialize
from .db import Delivery, Job, session
from .service import audit, source_status


def main():
    parser = argparse.ArgumentParser(description="漏洞情报服务管理")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("status")
    backfill = commands.add_parser("backfill", help="分片补齐历史日期元数据，不创建报告或投递")
    backfill.add_argument("--max-steps", type=int, default=10)
    repair = commands.add_parser("repair-history", help="持续修复全部历史数据，清理旧报告；中断后同命令恢复")
    repair.add_argument("--clear-reports", action="store_true", required=True,
                        help="清理首次运行时已有的全部报告、分析、投递队列与归档文件")
    dates = commands.add_parser("repair-publication-dates", help="补证、重标全部历史公开日期并重建未发布批次")
    dates.add_argument("--rebuild-unpublished", action="store_true", required=True)
    recent = commands.add_parser("reset-recent", help="清空漏洞和报告后，后台分阶段初始化近七天公开记录")
    recent.add_argument("--days", type=int, choices=[7], default=7)
    recent.add_argument("--clear-vulnerabilities", action="store_true", required=True)
    recent.add_argument("--clear-reports", action="store_true", required=True)
    recent.add_argument("--new-run", action="store_true", help="显式开始新一轮清理；默认恢复或返回已有结果")
    review = commands.add_parser("audit-report", help="只读审计冻结批次的公开事件与重复标识，不重建或投递")
    review.add_argument("batch_id")
    review.add_argument("--snapshot-json", help="离线审计 get_batch_page 摘要导出；不连接数据库，不代替完整证据核查")
    collect = commands.add_parser("collect")
    collect.add_argument("source")
    retry = commands.add_parser("retry")
    retry.add_argument("kind", choices=["job", "delivery"])
    retry.add_argument("id")
    args = parser.parse_args()
    if args.command == "audit-report":
        from .event_audit import audit_report
        if args.snapshot_json:
            from pathlib import Path
            from .event_audit import audit_items
            from .timeline import stamp
            data = json.loads(Path(args.snapshot_json).read_text(encoding="utf-8"))
            if data.get("batch_id") != args.batch_id or not data.get("complete"):
                raise SystemExit("导出批次编号不一致或分页未完成")
            cutoff = stamp(data.get("status", {}).get("slot"))
            if cutoff is None:
                raise SystemExit("导出缺少有效批次截止时间")
            items = [(item["item_id"], item["snapshot"]) for item in data["items"]]
            result = audit_items(items, cutoff, summary_only=True)
            print(json.dumps({"batch_id": args.batch_id, **result}, ensure_ascii=False, indent=2))
            return
        with session() as db:
            print(json.dumps(audit_report(db, args.batch_id), ensure_ascii=False, indent=2))
        return
    initialize()
    if args.command in {"repair-history", "repair-publication-dates", "reset-recent"}:
        import signal
        from .maintenance import run_repair
        if args.command == "repair-publication-dates":
            from .date_repair import run_repair
        def stopped(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stopped)
        try:
            def emit(value):
                print(value, flush=True)
            if args.command == "reset-recent":
                from .recent_reset import run_reset
                run_reset(days=args.days, new_run=args.new_run, emit=emit)
            else:
                run_repair(emit=emit)
        except KeyboardInterrupt:
            raise SystemExit(130) from None
        return
    if args.command == "init":
        print("数据库迁移及预置采集源初始化完成")
    elif args.command == "collect":
        from .db import Source
        with session() as db:
            if not db.get(Source, args.source):
                raise SystemExit("未知来源")
            db.add(Job(kind="collect", source_id=args.source))
            audit(db, "local-cli", "source.collect", args.source)
            db.commit()
        print("已加入补采队列")
    elif args.command == "status":
        with session() as db:
            from sqlalchemy import select
            from .db import Batch, MetadataState
            from .report_jobs import status as report_status
            from .timeline import BACKFILL_KEY
            from .maintenance import progress
            from .publication import coverage
            from .recent import progress as bootstrap_progress
            metadata = db.get(MetadataState, BACKFILL_KEY)
            print(json.dumps({"sources": source_status(db),
                              "maintenance": progress(db),
                              "date_coverage": coverage(db),
                              "bootstrap": bootstrap_progress(db),
                              "metadata_backfill": metadata.value if metadata else {"complete": False},
                              "reports": [report_status(db, batch) for batch in db.scalars(
                                  select(Batch).order_by(Batch.cutoff.desc()).limit(10))]}, ensure_ascii=False, indent=2))
    elif args.command == "backfill":
        from .timeline import BACKFILL_KEY, backfill_step
        from .db import MetadataState
        from .maintenance import report_write_guard
        if not 1 <= args.max_steps <= 1000:
            raise SystemExit("--max-steps 必须为 1..1000")
        for _ in range(args.max_steps):
            with session() as db:
                report_write_guard(db)
                complete = backfill_step(db)
                db.commit()
                progress = db.get(MetadataState, BACKFILL_KEY).value
            if complete:
                break
        print(json.dumps(progress, ensure_ascii=False))
    else:
        from .db import now
        with session() as db:
            record = db.get(Job if args.kind == "job" else Delivery, args.id)
            if not record or record.status != "failed":
                raise SystemExit("仅可重试失败记录")
            if args.kind == "job" and record.kind == "maintenance":
                from .publication import REPAIR_KEY
                from .recent_reset import KEY as RESET_KEY
                command = ("reset-recent --days 7 --clear-vulnerabilities --clear-reports" if record.source_id == RESET_KEY else
                           "repair-publication-dates --rebuild-unpublished" if record.source_id == REPAIR_KEY else "repair-history --clear-reports")
                raise SystemExit("请使用 " + command + " 恢复维护任务")
            record.status, record.error, record.lease_until = "pending", None, None
            if args.kind == "delivery":
                record.attempts, record.next_run = 0, now()
            audit(db, "local-cli", args.kind + ".retry", args.id)
            db.commit()
        print("已加入重试队列")


if __name__ == "__main__":
    main()
