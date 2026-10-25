import argparse
import http.cookiejar
import json
import os
import secrets
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ASSETS = ("vault", "market", "nether", "offlocker", "agro")
PORTS = {
    "vault": 5001,
    "market": 5002,
    "nether": 5003,
    "nether_php": 5006,
    "offlocker": 5004,
    "agro": 5005,
}
DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "timeout": 5,
    "slow_ms": 1500,
    "ports": {},
    "vault": {
        "username": "",
        "password": "",
        "account_id": 1,
        "lookup_name": "jdoe",
        "history_query": "transfer",
        "recipient_account": "",
        "transfer_amount": "1.00",
    },
    "market": {"search_query": "phone", "seller_id": 3},
    "nether": {"article": "brewing-basics"},
    "agro": {"units": [1]},
}


class Failure(Exception):
    pass


class Skipped(Exception):
    pass


class ConfigError(Exception):
    pass


STATUS_MARK = {
    "PASS": "  ok ",
    "SKIP": " skip",
    "SLOW": " SLOW",
    "FAIL": " FAIL",
    "CONF": " CONF",
}
BAD_STATUSES = ("FAIL", "SLOW", "CONF")


@dataclass
class Result:
    asset: str
    name: str
    status: str
    detail: str
    ms: int


@dataclass
class Runner:
    slow_ms: int
    results: list[Result] = field(default_factory=list)

    def check(self, asset, name, action):
        started = time.monotonic()
        try:
            detail = action() or "ok"
            status = "PASS"
        except Skipped as exc:
            status, detail = "SKIP", str(exc)
        except ConfigError as exc:
            status, detail = "CONF", str(exc)
        except Failure as exc:
            status, detail = "FAIL", str(exc)
        except Exception as exc:
            status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
        ms = int((time.monotonic() - started) * 1000)
        if status == "PASS" and ms > self.slow_ms:
            status, detail = "SLOW", f"{detail} ({ms} ms > {self.slow_ms} ms)"
        self.results.append(Result(asset, name, status, detail, ms))
        print(
            f"{STATUS_MARK[status]} {asset:<9} {name:<38} {ms:>5} ms  {detail}",
            flush=True,
        )
        return status == "PASS"


@dataclass
class Response:
    status: int
    body: bytes

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError as exc:
            raise Failure(f"HTTP {self.status}: response is not JSON") from exc


def expect(response, *codes, config_key=None):
    if response.status in codes:
        return response
    if response.status == 404 and config_key:
        raise ConfigError(f"HTTP 404: check `{config_key}` in the config")
    if response.status == 403:
        raise Failure("HTTP 403 on legitimate request: false positive")
    if response.status == 468:
        raise Failure("HTTP 468: anti-bot response breaks SLA monitoring")
    raise Failure(f"HTTP {response.status}, expected {'/'.join(map(str, codes))}")


def no_flag(document):
    if isinstance(document, dict) and document.get("flag"):
        raise Failure("response carries a non-empty flag marker on a normal request")
    return document


class Http:
    def __init__(self, base, timeout):
        self.base = base
        self.timeout = timeout
        self.headers = {
            "User-Agent": "sla-smoke/1.0",
            "Accept": "application/json, */*",
        }
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def call(self, method, path, json_body=None, data=None, headers=None):
        merged = dict(self.headers, **(headers or {}))
        if json_body is not None:
            data = json.dumps(json_body).encode()
            merged["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=merged
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as reply:
                return Response(reply.status, reply.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(exc.code, exc.read())

    def get(self, path, *codes, config_key=None):
        return expect(self.call("GET", path), *(codes or (200,)), config_key=config_key)


def multipart(field_name, filename, content, content_type="text/plain"):
    boundary = "sla" + secrets.token_hex(12)
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode()
        + content
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, f"multipart/form-data; boundary={boundary}"


def vault_checks(run, cfg, base, full):
    c = cfg["vault"]
    web = Http(base, cfg["timeout"])
    a = "vault"
    for path in ("/", "/login", "/css/app.css", "/js/common.js", "/js/login.js"):
        run.check(a, f"GET {path}", lambda p=path: web.get(p) and None)
    run.check(a, "GET /api/health", lambda: web.get("/api/health") and None)
    run.check(a, "GET /actuator/health", lambda: web.get("/actuator/health") and None)

    def login():
        if not c["username"] or not c["password"]:
            raise ConfigError(
                "vault credentials missing: sla_config.json or SLA_VAULT_USERNAME/PASSWORD"
            )
        reply = web.call(
            "POST",
            "/api/auth/login",
            {"username": c["username"], "password": c["password"]},
        )
        if reply.status in (401, 403):
            raise ConfigError(f"HTTP {reply.status}: vault credentials rejected")
        reply = expect(reply, 200).json()
        if "userId" not in reply:
            raise Failure("login response has no userId")
        return f"role={reply.get('role')}"

    if not run.check(a, "POST /api/auth/login", login):
        return
    account = f"/api/accounts/{c['account_id']}"

    def balance():
        reply = no_flag(web.get(account, config_key="vault.account_id").json())
        if not isinstance(reply.get("balanceMinor"), int):
            raise Failure("account has no balanceMinor")
        return f"balanceMinor={reply['balanceMinor']}"

    run.check(a, "GET /api/accounts/{id}", balance)

    def history():
        reply = no_flag(web.get(f"{account}/transactions").json())
        found = no_flag(
            web.get(f"{account}/transactions?query={c['history_query']}").json()
        )
        return f"total={reply.get('totalElements')} search={found.get('totalElements')}"

    run.check(a, "GET transactions + search", history)
    run.check(
        a,
        "GET /api/internal/directory (name)",
        lambda: web.get(f"/api/internal/directory?q={c['lookup_name']}") and None,
    )
    run.check(
        a,
        "POST statement/export",
        lambda: (
            expect(
                web.call(
                    "POST",
                    f"{account}/statement/export",
                    {"title": "Monthly statement"},
                ),
                200,
            )
            and None
        ),
    )
    if not full:
        return

    def transfer():
        if not c["recipient_account"]:
            raise Skipped("vault.recipient_account not set in config")
        before = web.get(account).json()["balanceMinor"]
        preview = no_flag(
            expect(
                web.call(
                    "POST",
                    "/api/transfers/preview",
                    {
                        "sourceAccountId": c["account_id"],
                        "recipientAccountNumber": c["recipient_account"],
                        "amount": c["transfer_amount"],
                    },
                ),
                200,
            ).json()
        )
        done = no_flag(
            expect(
                web.call(
                    "POST",
                    "/api/transfers",
                    {"confirmationId": preview["confirmationId"]},
                ),
                200,
            ).json()
        )
        after = web.get(account).json()["balanceMinor"]
        if before - after != preview["amountMinor"]:
            raise Failure(
                f"balance moved by {before - after}, preview said {preview['amountMinor']}"
            )
        return f"status={done.get('status')} amountMinor={preview['amountMinor']}"

    run.check(a, "transfer preview -> confirm -> balance", transfer)
    run.check(
        a,
        "POST /api/profile/preferences",
        lambda: (
            expect(
                web.call(
                    "POST",
                    "/api/profile/preferences",
                    {"displayName": "Mia", "notificationsEnabled": True},
                ),
                200,
            )
            and None
        ),
    )
    run.check(
        a,
        "POST /api/recovery/request",
        lambda: (
            expect(
                web.call(
                    "POST", "/api/recovery/request", {"identifier": c["username"]}
                ),
                200,
            )
            and None
        ),
    )


def market_checks(run, cfg, base, full):
    c = cfg["market"]
    web = Http(base, cfg["timeout"])
    a = "market"
    for path in ("/", "/static/app.js", "/static/app.css"):
        run.check(a, f"GET {path}", lambda p=path: web.get(p) and None)
    user = {
        "username": "sla" + secrets.token_hex(5),
        "password": secrets.token_urlsafe(12),
    }

    def register_and_login():
        expect(web.call("POST", "/api/auth/register", dict(user)), 201)
        reply = expect(web.call("POST", "/api/auth/login", dict(user)), 200).json()
        if not reply.get("token"):
            raise Failure("login response has no token")
        if reply.get("user", {}).get("is_admin"):
            raise Failure("fresh buyer account is admin")
        web.headers["Authorization"] = f"Bearer {reply['token']}"
        return f"user={user['username']}"

    if not run.check(a, "register + login", register_and_login):
        return
    run.check(a, "GET /api/profile", lambda: web.get("/api/profile").json() and None)
    run.check(
        a,
        "GET /api/wallet",
        lambda: f"balance={web.get('/api/wallet').json().get('balance')}",
    )
    products = []

    def search():
        reply = web.get(f"/api/catalog/search?q={c['search_query']}").json()
        listing = web.get("/api/catalog/search").json()
        products.extend(listing.get("results", []))
        return f"q-results={reply.get('count')} catalog={len(products)}"

    run.check(a, "GET /api/catalog/search", search)
    run.check(
        a,
        "GET storefront",
        lambda: (
            web.get(
                f"/api/sellers/{c['seller_id']}/storefront",
                config_key="market.seller_id",
            )
            and None
        ),
    )
    if not full:
        return

    def order():
        if not products:
            raise Skipped("catalog is empty")
        item = min(products, key=lambda p: p.get("price", 0))
        cart = expect(
            web.call(
                "POST",
                "/api/cart",
                {
                    "items": [
                        {
                            "product_id": item["id"],
                            "qty": 1,
                            "unit_price": item["price"],
                        }
                    ]
                },
            ),
            201,
        ).json()
        order_id = cart["order_id"]
        checkout = expect(
            web.call("POST", f"/api/orders/{order_id}/checkout", {}), 200
        ).json()
        if checkout.get("total") != item["price"]:
            raise Failure(
                f"checkout total {checkout.get('total')} != price {item['price']}"
            )
        web.get(f"/api/orders/{order_id}")
        before = web.get("/api/wallet").json().get("balance")
        paid = web.call("POST", f"/api/orders/{order_id}/pay", {})
        expect(paid, 200, 402)
        after = web.get("/api/wallet").json().get("balance")
        if paid.status == 200 and before - after != checkout["total"]:
            raise Failure(
                f"paid 200 but wallet moved by {before - after}, total {checkout['total']}"
            )
        if paid.status == 402 and before != after:
            raise Failure("402 but wallet balance changed")
        return f"order={order_id} pay={paid.status} wallet {before}->{after}"

    run.check(a, "cart -> checkout -> pay", order)

    def review():
        if not products:
            raise Skipped("catalog is empty")
        pid = products[0]["id"]
        expect(
            web.call(
                "POST",
                f"/api/products/{pid}/reviews",
                {
                    "author": "Aziza",
                    "body": "Good quality, fast delivery.",
                    "rating": 5,
                },
            ),
            201,
        )
        page = web.get(f"/api/products/{pid}/reviews.html")
        if b"fast delivery" not in page.body:
            raise Failure("new review not rendered")

    run.check(a, "POST review + reviews.html", review)


def nether_checks(run, cfg, base, php_base, full):
    c = cfg["nether"]
    web = Http(base, cfg["timeout"])
    php = Http(php_base, cfg["timeout"])
    a = "nether"
    article = c["article"]
    for path in (
        "/",
        "/health",
        f"/articles/{article}",
        "/css/styles.css",
        "/js/app.js",
    ):
        run.check(a, f"GET {path}", lambda p=path: web.get(p) and None)
    run.check(a, "GET / (php 5006/6006)", lambda: php.get("/") and None)
    if not full:
        return
    marker = "sla-" + secrets.token_hex(4)

    def comment():
        expect(
            web.call(
                "POST",
                f"/api/articles/{article}/comments",
                {"author": "Dilnoza", "body": f"Thanks for the article {marker}"},
            ),
            201,
        )

    run.check(a, "POST comment", comment)

    def upload():
        body, ctype = multipart(
            "file", f"{marker}.txt", b"Contact request: please call back.\n"
        )
        reply = expect(
            web.call("POST", "/api/upload", data=body, headers={"Content-Type": ctype}),
            201,
        ).json()
        if not reply.get("ok"):
            raise Failure("upload response ok=false")
        return f"id={reply.get('id')}"

    run.check(a, "POST /api/upload (.txt)", upload)


def offlocker_checks(run, cfg, host, port):
    def health():
        request_id = secrets.randbelow(2**31)
        body = struct.pack("<HHHHq", 8, 19, 1, 1, request_id)
        with socket.create_connection((host, port), timeout=cfg["timeout"]) as sock:
            sock.settimeout(cfg["timeout"])
            sock.sendall(struct.pack("<I", len(body)) + body)
            size = struct.unpack("<I", recv_exact(sock, 4))[0]
            if not 8 <= size <= 1 << 20:
                raise Failure(f"bad response frame length {size}")
            reply = recv_exact(sock, size)
        template = struct.unpack_from("<H", reply, 2)[0]
        if template != 119:
            raise Failure(f"response template {template}, expected 119")
        return f"{size} bytes"

    run.check("offlocker", "HealthRequest (tid 19 -> 119)", health)


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise Failure("connection closed mid-frame")
        data += chunk
    return data


def agro_checks(run, cfg, host, port):
    units = cfg["agro"]["units"]
    if not units or not all(isinstance(u, int) and 0 <= u <= 247 for u in units):

        def bad_units():
            raise ConfigError("agro.units must list at least one unit id (0..247)")

        run.check("agro", "config agro.units", bad_units)
        return
    reads = (
        (4, 0, 14, "input registers (telemetry)"),
        (3, 0, 13, "holding registers"),
        (1, 0, 9, "coils"),
        (2, 0, 8, "discrete inputs"),
    )
    for unit in units:
        for fc, start, count, label in reads:
            run.check(
                "agro",
                f"FC{fc:02d} unit {unit} {label}",
                lambda u=unit, f=fc, s=start, n=count: modbus_read(
                    cfg, host, port, u, f, s, n
                ),
            )


def modbus_read(cfg, host, port, unit, fc, start, count):
    tid = secrets.randbelow(65536)
    adu = struct.pack("!HHHBBHH", tid, 0, 6, unit, fc, start, count)
    with socket.create_connection((host, port), timeout=cfg["timeout"]) as sock:
        sock.settimeout(cfg["timeout"])
        sock.sendall(adu)
        header = recv_exact(sock, 7)
        rtid, protocol, length, runit = struct.unpack("!HHHB", header)
        if not 2 <= length <= 254:
            raise Failure(f"bad MBAP length {length}")
        pdu = recv_exact(sock, length - 1)
    if (rtid, protocol, runit) != (tid, 0, unit):
        raise Failure("response MBAP does not match request")
    if len(pdu) < 2:
        raise Failure(f"short PDU ({len(pdu)} bytes)")
    if pdu[0] == fc | 0x80:
        raise Failure(f"Modbus exception {pdu[1]:#04x}")
    expected = (count + 7) // 8 if fc in (1, 2) else 2 * count
    if pdu[0] != fc or pdu[1] != expected:
        raise Failure(f"unexpected PDU fc={pdu[0]} bytes={pdu[1]}")
    return f"{expected} bytes"


def load_config(path, environ=os.environ):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        for key, value in json.loads(Path(path).read_text()).items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(value)
            else:
                cfg[key] = value
    for key in ("username", "password"):
        cfg["vault"][key] = environ.get(f"SLA_VAULT_{key.upper()}", cfg["vault"][key])
    return cfg


def port_for(cfg, name, mode):
    if name in cfg["ports"]:
        return int(cfg["ports"][name])
    return PORTS[name] + (1000 if mode == "gateway" else 0)


def run_once(cfg, args):
    run = Runner(cfg["slow_ms"])
    host = cfg["host"]
    selected = args.assets.split(",") if args.assets else list(ASSETS)

    def url(name):
        return f"http://{host}:{port_for(cfg, name, args.mode)}"

    print(
        f"== SLA smoke {time.strftime('%H:%M:%S')} host={host} mode={args.mode} "
        f"full={args.full} assets={','.join(selected)}"
    )
    if "vault" in selected:
        vault_checks(run, cfg, url("vault"), args.full)
    if "market" in selected:
        market_checks(run, cfg, url("market"), args.full)
    if "nether" in selected:
        nether_checks(run, cfg, url("nether"), url("nether_php"), args.full)
    if "offlocker" in selected:
        offlocker_checks(run, cfg, host, port_for(cfg, "offlocker", args.mode))
    if "agro" in selected:
        agro_checks(run, cfg, host, port_for(cfg, "agro", args.mode))
    counts = {s: sum(r.status == s for r in run.results) for s in STATUS_MARK}
    print("== " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    return run.results


def run_rounds(cfg, args, sleep=time.sleep):
    round_number, failed = 0, False
    while True:
        round_number += 1
        results = run_once(cfg, args)
        failed |= any(r.status in BAD_STATUSES for r in results)
        if args.json:
            with open(args.json, "a") as out:
                out.write(
                    json.dumps(
                        {"ts": time.time(), "results": [r.__dict__ for r in results]}
                    )
                    + "\n"
                )
        if args.repeat and round_number >= args.repeat:
            return failed
        sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", help="JSON config; see sla_config.example.json")
    parser.add_argument("--host")
    parser.add_argument(
        "--mode",
        choices=("gateway", "origin"),
        default="gateway",
        help="gateway = 60xx, origin = 50xx (per-asset override via config ports)",
    )
    parser.add_argument("--assets", help=f"comma list from {','.join(ASSETS)}")
    parser.add_argument(
        "--full", action="store_true", help="include state-changing normal flows"
    )
    parser.add_argument(
        "--repeat", type=int, default=1, help="number of rounds, 0 = forever"
    )
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("--json", help="append each round's results to this JSONL file")
    parser.add_argument(
        "--allow-repeated-full",
        action="store_true",
        help="permit --full together with --repeat != 1 (state-changing flows every round)",
    )
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.full and args.repeat != 1 and not args.allow_repeated_full:
        parser.error(
            "--full changes state on every round (transfer, new user, order, upload); "
            "use --repeat 1, or pass --allow-repeated-full deliberately"
        )
    if args.host:
        cfg["host"] = args.host
    if args.assets and set(args.assets.split(",")) - set(ASSETS):
        parser.error(f"unknown asset; choose from {','.join(ASSETS)}")
    sys.exit(1 if run_rounds(cfg, args) else 0)


if __name__ == "__main__":
    main()
