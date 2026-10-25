import argparse
import json
import socketserver
import struct
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path

import sla_smoke


class Stub(BaseHTTPRequestHandler):
    blocked: dict[str, int] = {}
    state = {"balance": 10000, "review": b""}

    def log_message(self, *args):
        pass

    def reply(self, status, document=None, raw=b"ok", headers=()):
        body = json.dumps(document).encode() if document is not None else raw
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in self.blocked:
            return self.reply(self.blocked[path])
        documents = {
            "/api/accounts/1": {"balanceMinor": self.state["balance"], "flag": None},
            "/api/accounts/1/transactions": {"totalElements": 1, "flag": None},
            "/api/catalog/search": {"count": 1, "results": [{"id": 8, "price": 990}]},
            "/api/profile": {"user": {"is_admin": False}},
            "/api/wallet": {"balance": 0},
            "/api/orders/1002": {"order": {"id": 1002}},
        }
        if path in documents:
            return self.reply(200, documents[path])
        if path.endswith("/reviews.html"):
            return self.reply(200, raw=self.state["review"])
        return self.reply(200)

    def do_POST(self):
        path = self.path
        raw = self.body()
        if path in self.blocked:
            return self.reply(self.blocked[path])
        if path == "/api/auth/login":
            return self.reply(
                200,
                {
                    "userId": 1,
                    "role": "CUSTOMER",
                    "token": "t",
                    "user": {"is_admin": False},
                },
                headers=[("Set-Cookie", "BOBASESSION=s; Path=/")],
            )
        if path == "/api/transfers/preview":
            return self.reply(200, {"confirmationId": "c", "amountMinor": 100})
        if path == "/api/transfers":
            self.state["balance"] -= 100
            return self.reply(200, {"status": "COMPLETED", "flag": None})
        if path == "/api/cart":
            return self.reply(201, {"order_id": 1002, "status": "cart"})
        if path.endswith("/checkout"):
            return self.reply(200, {"total": 990})
        if path.endswith("/pay"):
            return self.reply(402, {"error": "insufficient funds"})
        if path.endswith("/reviews"):
            self.state["review"] = json.loads(raw)["body"].encode()
            return self.reply(201, {})
        if path == "/api/upload":
            return self.reply(201, {"ok": b'filename="sla-' in raw, "id": "1"})
        if path in ("/api/auth/register",) or path.endswith("/comments"):
            return self.reply(201, {})
        return self.reply(200, {})


class OffLockerStub(socketserver.BaseRequestHandler):
    def handle(self):
        size = struct.unpack("<I", self.request.recv(4))[0]
        request = self.request.recv(size)
        reply = struct.pack("<HHHH", 9, 119, 1, 1) + request[8:16] + b"\x00"
        self.request.sendall(struct.pack("<I", len(reply)) + reply)


class ModbusStub(socketserver.BaseRequestHandler):
    truncate = False

    def handle(self):
        tid, _, _, unit, fc, _, count = struct.unpack("!HHHBBHH", self.request.recv(12))
        if self.truncate:
            self.request.sendall(struct.pack("!HHHB", tid, 0, 1, unit))
            return
        size = (count + 7) // 8 if fc in (1, 2) else 2 * count
        pdu = bytes([fc, size]) + bytes(size)
        self.request.sendall(struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu)


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [
            serve(ThreadingHTTPServer(("127.0.0.1", 0), Stub)),
            serve(socketserver.ThreadingTCPServer(("127.0.0.1", 0), OffLockerStub)),
            serve(socketserver.ThreadingTCPServer(("127.0.0.1", 0), ModbusStub)),
        ]
        web, offlocker, agro = (s.server_address[1] for s in cls.servers)
        cls.cfg = sla_smoke.load_config(None)
        cls.cfg["vault"].update(username="u", password="p", recipient_account="ACC1")
        cls.cfg["ports"] = {
            "vault": web,
            "market": web,
            "nether": web,
            "nether_php": web,
            "offlocker": offlocker,
            "agro": agro,
        }

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()

    def setUp(self):
        Stub.blocked = {}
        ModbusStub.truncate = False

    def run_smoke(self, full=True, assets=None, cfg=None):
        args = argparse.Namespace(assets=assets, mode="gateway", full=full)
        with redirect_stdout(StringIO()):
            return sla_smoke.run_once(cfg or self.cfg, args)

    def test_malformed_modbus_reply_is_a_failed_check_not_a_crash(self):
        ModbusStub.truncate = True
        results = self.run_smoke(full=False, assets="agro")
        self.assertEqual(len(results), 4)
        self.assertTrue(all(r.status == "FAIL" and "MBAP" in r.detail for r in results))

    def test_config_mismatches_are_reported_as_conf(self):
        cfg = json.loads(json.dumps(self.cfg))
        cfg["agro"]["units"] = []
        results = self.run_smoke(full=False, assets="agro", cfg=cfg)
        self.assertEqual([r.status for r in results], ["CONF"])
        Stub.blocked = {"/api/sellers/3/storefront": 404, "/api/accounts/1": 404}
        results = {r.name: r for r in self.run_smoke(full=False, assets="vault,market")}
        self.assertEqual(results["GET storefront"].status, "CONF")
        self.assertIn("market.seller_id", results["GET storefront"].detail)
        self.assertEqual(results["GET /api/accounts/{id}"].status, "CONF")
        cfg = json.loads(json.dumps(self.cfg))
        cfg["vault"]["password"] = ""
        results = {
            r.name: r for r in self.run_smoke(full=False, assets="vault", cfg=cfg)
        }
        self.assertEqual(results["POST /api/auth/login"].status, "CONF")

    def test_credentials_come_from_environment_not_example_config(self):
        example = json.loads(Path("sla_config.example.json").read_text())
        self.assertEqual(
            (example["vault"]["username"], example["vault"]["password"]), ("", "")
        )
        cfg = sla_smoke.load_config(
            "sla_config.example.json",
            environ={
                "SLA_VAULT_USERNAME": "env-user",
                "SLA_VAULT_PASSWORD": "env-pass",
            },
        )
        self.assertEqual(
            (cfg["vault"]["username"], cfg["vault"]["password"]),
            ("env-user", "env-pass"),
        )

    def test_exit_status_accumulates_across_rounds(self):
        rounds = []

        def sleep(_):
            Stub.blocked = {}
            rounds.append("slept")

        Stub.blocked = {"/health": 403}
        args = argparse.Namespace(
            assets="nether", mode="gateway", full=False, repeat=2, interval=0, json=None
        )
        with redirect_stdout(StringIO()):
            failed = sla_smoke.run_rounds(self.cfg, args, sleep=sleep)
        self.assertTrue(failed)
        self.assertEqual(rounds, ["slept"])
        args.repeat = 1
        with redirect_stdout(StringIO()):
            self.assertFalse(sla_smoke.run_rounds(self.cfg, args, sleep=sleep))

    def test_all_legitimate_flows_pass(self):
        results = self.run_smoke()
        failed = [(r.asset, r.name, r.detail) for r in results if r.status != "PASS"]
        self.assertEqual(failed, [])
        names = {r.name for r in results}
        for expected in (
            "transfer preview -> confirm -> balance",
            "cart -> checkout -> pay",
            "POST /api/upload (.txt)",
            "HealthRequest (tid 19 -> 119)",
            "FC04 unit 1 input registers (telemetry)",
        ):
            self.assertIn(expected, names)

    def test_read_mostly_mode_skips_state_changes(self):
        names = {r.name for r in self.run_smoke(full=False)}
        self.assertNotIn("transfer preview -> confirm -> balance", names)
        self.assertNotIn("POST comment", names)

    def test_false_positive_and_antibot_are_named(self):
        Stub.blocked = {"/api/health": 403, "/static/app.js": 468}
        results = {r.name: r for r in self.run_smoke(full=False)}
        self.assertEqual(results["GET /api/health"].status, "FAIL")
        self.assertIn("false positive", results["GET /api/health"].detail)
        self.assertIn("anti-bot", results["GET /static/app.js"].detail)

    def test_flag_marker_on_normal_response_fails(self):
        with self.assertRaises(sla_smoke.Failure):
            sla_smoke.no_flag({"flag": "marker"})
        self.assertEqual(sla_smoke.no_flag({"flag": None}), {"flag": None})

    def test_unreachable_asset_reported_not_crashing(self):
        cfg = json.loads(json.dumps(self.cfg))
        cfg["ports"]["agro"] = 1
        args = argparse.Namespace(assets="agro", mode="gateway", full=False)
        with redirect_stdout(StringIO()):
            results = sla_smoke.run_once(cfg, args)
        self.assertTrue(results)
        self.assertTrue(all(r.status == "FAIL" for r in results))


if __name__ == "__main__":
    unittest.main()
