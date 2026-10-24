"""Exercise the HTTP handler on loopback with disposable storage."""
from pathlib import Path
import json
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

# This helper intentionally tests the source checkout. Wheel validation uses
# check_wheel.py and runs from a separate working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artchain.api import ApiHandler
from artchain.cli import Context


def main():
    with tempfile.TemporaryDirectory(prefix="artchain-http-") as data:
        class Handler(ApiHandler):
            pass

        Handler.ctx = Context(data_dir=data, difficulty=1)
        Handler.quiet = True
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_port
        try:
            for path, mime in (
                ("/", "text/html"),
                ("/manifest.webmanifest", "application/manifest+json"),
                ("/sw.js", "javascript"),
                ("/icons/icon-192.png", "image/png"),
                ("/legal/privacy.html", "text/html"),
            ):
                with urlopen(base + path, timeout=10) as response:
                    assert response.status == 200, path
                    assert mime in response.headers["Content-Type"], path
                    assert response.read(), path
            with urlopen(base + "/api/health", timeout=10) as response:
                assert json.load(response)["ok"] is True
            request = Request(base + "/api/init", data=b'{"difficulty":1}',
                              headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=10) as response:
                assert json.load(response)["ok"] is True
            with urlopen(base + "/api/status", timeout=10) as response:
                assert json.load(response)["ok"] is True
            with urlopen(base + "/api/chain", timeout=10) as response:
                payload = json.load(response)
                assert payload["ok"] is True
                assert len(payload["data"]["blocks"]) == 1
            request = Request(base + "/api/verify", data=b"{}",
                              headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=10) as response:
                payload = json.load(response)
                assert payload["ok"] is True
                assert payload["data"]["valid"] is True
            print("PASS: HTTP assets, status, initialization, chain, verification")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
