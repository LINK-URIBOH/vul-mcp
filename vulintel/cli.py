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
            print(json.dumps({"sources": source_status(db)}, ensure_ascii=False, indent=2))
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
