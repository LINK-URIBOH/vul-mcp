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
    collect = commands.add_parser("collect")
    collect.add_argument("source")
    retry = commands.add_parser("retry")
    retry.add_argument("kind", choices=["job", "delivery"])
    retry.add_argument("id")
    args = parser.parse_args()
    initialize()
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
            metadata = db.get(MetadataState, "publication_backfill_v2")
            print(json.dumps({"sources": source_status(db),
                              "metadata_backfill": metadata.value if metadata else {"complete": False},
                              "reports": [report_status(db, batch) for batch in db.scalars(
                                  select(Batch).order_by(Batch.cutoff.desc()).limit(10))]}, ensure_ascii=False, indent=2))
    elif args.command == "backfill":
        from .timeline import backfill_step
        from .db import MetadataState
        if not 1 <= args.max_steps <= 1000:
            raise SystemExit("--max-steps 必须为 1..1000")
        for _ in range(args.max_steps):
            with session() as db:
                complete = backfill_step(db)
                db.commit()
                progress = db.get(MetadataState, "publication_backfill_v2").value
            if complete:
                break
        print(json.dumps(progress, ensure_ascii=False))
    else:
        from .db import now
        with session() as db:
            record = db.get(Job if args.kind == "job" else Delivery, args.id)
            if not record or record.status != "failed":
                raise SystemExit("仅可重试失败记录")
            record.status, record.error, record.lease_until = "pending", None, None
            if args.kind == "delivery":
                record.attempts, record.next_run = 0, now()
            audit(db, "local-cli", args.kind + ".retry", args.id)
            db.commit()
        print("已加入重试队列")


if __name__ == "__main__":
    main()
