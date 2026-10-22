"""Real loopback HTTP smoke test using the official SDK client."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request


def test_real_http_official_client(tmp_path):
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
    logfile = tmp_path / "server.log"
    with logfile.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:create_app", "--factory",
             "--host", "127.0.0.1", "--port", str(port), "--no-access-log",
             "--no-proxy-headers", "--log-level", "warning"],
            cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 30
            while True:
                try:
                    with opener.open(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                        assert response.status == 200
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(f"Server did not start: {logfile.read_text(encoding='utf-8')}")
                    time.sleep(0.1)
            probe = subprocess.run(
                [sys.executable, "scripts/probe.py", "--url", f"http://127.0.0.1:{port}/mcp",
                 "--marker", "network-regression-01"],
                cwd=root, env=env, capture_output=True, text=True, timeout=40,
            )
            assert probe.returncode == 0, probe.stderr
            result = json.loads(probe.stdout)
            assert result["probe"] == "passed"
            assert result["result"]["marker"] == "network-regression-01"
            assert result["invalid_marker_rejected"] is True
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
