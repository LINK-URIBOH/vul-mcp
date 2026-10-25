"""Independent, persistent publisher. Only explicit cloud triggers create slots."""
import logging
import signal
import time

from sqlalchemy import text

from .config import settings
from .db import build_engine, session

stopping = False


def tick():
    from .maintenance import active
    from .publications import coordinate
    from .report_jobs import run_report_once
    from .delivery import deliver_one
    settings().data_dir.mkdir(parents=True, exist_ok=True)
    (settings().data_dir / "publisher.heartbeat").touch()
    with session() as db:
        if active(db):
            return False
        coordinate(db)
        db.commit()
    busy = run_report_once()
    with session() as db:
        delivered = deliver_one(db)
    return busy or delivered


def main():
    global stopping
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    from .app import initialize
    initialize()
    if not settings().publisher_enabled:
        raise RuntimeError("PUBLISHER_ENABLED=true is required")
    engine = build_engine(settings().database_url.get_secret_value())
    with engine.connect() as lock:
        if lock.dialect.name == "postgresql":
            if not lock.execute(text("SELECT pg_try_advisory_lock(86221026)")).scalar():
                raise RuntimeError("Another publisher owns the publication lock")
            lock.commit()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: globals().__setitem__("stopping", True))
        while not stopping:
            try:
                if not tick():
                    time.sleep(2)
            except Exception:
                logging.getLogger(__name__).exception("publisher_iteration_failed")
                time.sleep(5)
    engine.dispose()


if __name__ == "__main__":
    main()
