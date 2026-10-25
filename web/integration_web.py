import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class WebIntegrationTests(unittest.TestCase):
    @contextmanager
    def guard(self, asset, enable_addon=True):
        received = []

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_POST(self):
                self.do_GET()

            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append((self.path, dict(self.headers), body))
                status = 200
                if self.path == "/api/recovery/request":
                    status = 404 if json.loads(body)["identifier"] == "missing" else 200
                data = json.dumps(
                    {
                        "origin_host": self.headers.get("Host"),
                        "forwarded_host": self.headers.get("X-Forwarded-Host"),
                    }
                ).encode()
                if self.path == "/config":
                    data = json.dumps(
                        {
                            "jwt_secret": "fixture-secret",
                            "api_secret": "fixture-api",
                            "db_dsn": "fixture-dsn",
                            "http_addr": ":5002",
                        }
                    ).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header(
                    "Access-Control-Allow-Origin", self.headers.get("Origin", "*")
                )
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                self.wfile.write(data)

        backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        binary = Path(sys.executable).with_name("mitmdump")
        if not binary.is_file():
            raise RuntimeError("Run with a Python environment containing mitmproxy")
        with tempfile.TemporaryDirectory(prefix="hackathon-guard-") as temporary:
            env = dict(
                os.environ,
                GUARD_ASSET=asset,
                GUARD_PUBLIC_HOST="market.local",
                GUARD_ALLOWED_ORIGINS="https://shop.example",
            )
            with open(Path(temporary) / "proxy.log", "w+") as output:
                command = [
                    str(binary),
                    "--mode",
                    f"reverse:http://127.0.0.1:{backend.server_port}",
                    "--listen-host",
                    "127.0.0.1",
                    "--listen-port",
                    str(port),
                    "--set",
                    "block_global=false",
                    "--set",
                    "connection_strategy=lazy",
                    "--set",
                    "flow_detail=0",
                    "--set",
                    "block_list=:~all:403",
                    "--set",
                    "confdir=" + temporary,
                    "-s",
                    str(Path(__file__).with_name("guard_addon.py")),
                ]
                if not enable_addon:
                    command = command[:-2]
                process = subprocess.Popen(
                    command,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    env=env,
                )
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            output.seek(0)
                            self.fail("mitmdump exited: " + output.read())
                        try:
                            with socket.create_connection(
                                ("127.0.0.1", port), timeout=0.1
                            ):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail("mitmdump did not start")
                            time.sleep(0.05)
                    yield port, received
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    backend.shutdown()
                    backend.server_close()
                    thread.join(timeout=2)

    def call(self, port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        result = (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            response.read(),
        )
        conn.close()
        return result

    def test_missing_addon_is_fail_closed(self):
        with self.guard("market", enable_addon=False) as (port, received):
            self.assertEqual(self.call(port, "GET", "/")[0], 403)
            self.assertEqual(received, [])

    def test_bank_block_before_origin_and_legitimate_preview(self):
        with self.guard("vault") as (port, received):
            for amount, expected in (("-100.00", 403), ("100.00", 200)):
                response = self.call(
                    port,
                    "POST",
                    "/api/transfers/preview",
                    json.dumps({"amount": amount}),
                    {"Content-Type": "application/json"},
                )
                self.assertEqual(response[0], expected)
            self.assertEqual(len(received), 1)

    def test_recovery_response_does_not_disclose_user_existence(self):
        with self.guard("vault") as (port, received):
            results = []
            for identifier in ("known", "missing"):
                result = self.call(
                    port,
                    "POST",
                    "/api/recovery/request",
                    json.dumps({"identifier": identifier}),
                    {"Content-Type": "application/json"},
                )
                self.assertEqual(result[0], 200)
                results.append(result[2])
            self.assertEqual(results[0], results[1])
            self.assertEqual(len(received), 2)

    def test_market_header_trust_and_cors(self):
        with self.guard("market") as (port, received):
            status, headers, body = self.call(
                port,
                "GET",
                "/api/admin/panel",
                headers={
                    "Host": "admin.market.local",
                    "X-Forwarded-Host": "admin.market.local",
                    "Forwarded": "host=admin.market.local",
                    "Origin": "https://evil.example",
                },
            )
            self.assertEqual(status, 200)
            reply = json.loads(body)
            self.assertEqual(reply["origin_host"], "market.local")
            self.assertIsNone(reply["forwarded_host"])
            self.assertNotIn("access-control-allow-origin", headers)
            self.assertNotIn("access-control-allow-credentials", headers)
            status, _, _ = self.call(
                port,
                "POST",
                "/api/auth/register",
                '{"username":"test","password":"secret","is_admin":true}',
                {"Content-Type": "application/json"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(len(received), 1)

    def test_market_public_config_has_no_secret_fields(self):
        with self.guard("market") as (port, received):
            status, _, body = self.call(port, "GET", "/config")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"http_addr": ":5002"})
            self.assertEqual(len(received), 1)

    def test_nether_upload_and_static_execution(self):
        with self.guard("nether") as (port, received):
            for filename, expected in (("shell.phtml", 403), ("document.txt", 200)):
                body = (
                    '--fixture\r\nContent-Disposition: form-data; name="file"; filename="'
                    + filename
                    + '"\r\nContent-Type: text/plain\r\n\r\nfixture\r\n--fixture--\r\n'
                ).encode()
                status, _, _ = self.call(
                    port,
                    "POST",
                    "/api/upload",
                    body,
                    {"Content-Type": "multipart/form-data; boundary=fixture"},
                )
                self.assertEqual(status, expected)
            ambiguous = (
                b'--fixture\r\nContent-Disposition: form-data; name="file"; '
                b'filename="document.txt"; filename="shell.phtml"\r\n'
                b"Content-Type: text/plain\r\n\r\nfixture\r\n--fixture--\r\n"
            )
            status, _, _ = self.call(
                port,
                "POST",
                "/api/upload",
                ambiguous,
                {"Content-Type": "multipart/form-data; boundary=fixture"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(self.call(port, "GET", "/uploads/shell.phtml")[0], 403)
            self.assertEqual(self.call(port, "GET", "/config.backup")[0], 403)
            self.assertEqual(len(received), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
