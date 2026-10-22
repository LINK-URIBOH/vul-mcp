"""Read-only upstream schema smoke check, one record per source, no database writes."""
import concurrent.futures
import json
from datetime import timedelta

from vulintel.db import Source, now
from vulintel.sources import Upstream, catalog


def check(value):
    sid, name, kind, url, config = value
    source = Source(id=sid, name=name, kind=kind, url=url, config=config)
    upstream = Upstream()
    generator = None
    try:
        generator = upstream.records(source, now() - timedelta(days=7), now())
        first = next(generator, None)
        return {"id": sid, "result": "record" if first else "empty_window", "sample": first["source_key"] if first else None}
    except Exception as exc:
        response = getattr(exc, "response", None)
        return {"id": sid, "result": "failed", "error": type(exc).__name__,
                "http_status": response.status_code if response is not None else None}
    finally:
        if generator:
            generator.close()
        upstream.close()


if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(check, catalog()):
            print(json.dumps(result, ensure_ascii=False), flush=True)
