import argparse
import asyncio
import collections
import contextlib
import logging
import re
import struct
import time
import unicodedata
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

MAX_FRAME = 1336
MAX_RESPONSE = 16_777_216
SCHEMA = {
    1: (9, "ss"),
    2: (44, "s"),
    3: (48, ""),
    4: (49, ""),
    5: (48, "s"),
    6: (40, "s"),
    7: (40, "b"),
    8: (40, "s"),
    9: (44, "s"),
    10: (41, ""),
    11: (48, "s"),
    12: (48, "bs"),
    13: (40, ""),
    14: (44, ""),
    15: (40, ""),
    16: (44, ""),
    17: (44, ""),
    18: (40, ""),
    19: (8, ""),
    20: (48, ""),
}
TOKEN = re.compile(rb"[0-9a-fA-F]{32}")
PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
QUERY = re.compile(r"[A-Za-z0-9._ -]{0,128}")
DIAGNOSTIC_COMMANDS = {"", "echo UNDER"}
PIN_LENGTH = 6
LOGIN_FAILURE_LIMIT = 10
LOGIN_FAILURE_WINDOW = 300.0
LOGIN_DELAY_STEP = 0.1
LOGIN_DELAY_MAX = 1.0
LOGGER = logging.getLogger("offlocker_gateway")


class Rejected(ValueError):
    pass


def variable_fields(body, offset, kinds):
    values = []
    for kind in kinds:
        if offset + 4 > len(body):
            raise Rejected("variable_header")
        size = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        if size > len(body) - offset:
            raise Rejected("variable_length")
        value = body[offset : offset + size]
        offset += size
        if kind == "s":
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise Rejected("utf8") from exc
            if "\x00" in value:
                raise Rejected("nul")
        values.append(value)
    return values, offset


def approved_manifest_url(value):
    if any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        return False
    try:
        url = urlsplit(value)
        return (
            url.scheme == "http"
            and url.netloc.lower() in ("chilonzor-01", "chilonzor-01:80")
            and url.path == "/manifest.xml"
            and not url.query
            and not url.fragment
            and "?" not in value
            and "#" not in value
        )
    except ValueError:
        return False


def ordinary_signature(value):
    return (
        0 < len(value) <= 128
        and unicodedata.category(value[0]).startswith("L")
        and all(
            unicodedata.category(c)[0] in "LMN" or c in " .-\u2019\u02bb\u02bc"
            for c in value
        )
    )


def safe_manifest(value):
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
        return False
    encoding = re.search(
        r'^\ufeff?\s*<\?xml\s+[^?]*encoding\s*=\s*[\'"]([^\'"]+)', text, re.IGNORECASE
    )
    if encoding and encoding[1].lower() not in ("utf-8", "utf8"):
        return False
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        return False
    if root.tag != "manifest":
        return False
    return all(
        isinstance(node.tag, str) and "{" not in node.tag for node in root.iter()
    )


def validate(body):
    if not 8 <= len(body) <= MAX_FRAME:
        raise Rejected("frame_length")
    block, tid, schema, version = struct.unpack_from("<HHHH", body)
    if schema != 1 or version != 1 or tid not in SCHEMA:
        raise Rejected("schema")
    expected, kinds = SCHEMA[tid]
    if block != expected or len(body) < 8 + block:
        raise Rejected("block")
    fixed = body[8 : 8 + block]
    if tid not in (1, 19) and not TOKEN.fullmatch(fixed[8:40]):
        raise Rejected("token")
    fields, end = variable_fields(body, 8 + block, kinds)
    if end != len(body):
        raise Rejected("trailing")
    if tid == 1 and fixed[8] not in (1, 2, 3):
        raise Rejected("role")
    if tid == 2 and not QUERY.fullmatch(fields[0]):
        raise Rejected("tracking_query")
    if tid == 4 and fixed[48] not in (1, 2, 3):
        raise Rejected("action")
    if tid == 6 and (not PATH.fullmatch(fields[0]) or ".." in fields[0]):
        raise Rejected("label_path")
    if tid == 7 and not safe_manifest(fields[0]):
        raise Rejected("xml")
    if tid == 8 and not approved_manifest_url(fields[0]):
        raise Rejected("manifest_url")
    if tid == 10 and fixed[40] not in (1, 2, 3):
        raise Rejected("report")
    if tid == 11 and not ordinary_signature(fields[0]):
        raise Rejected("signature")
    if tid == 12 and fields[1] not in DIAGNOSTIC_COMMANDS:
        raise Rejected("diagnostic_command")
    return tid


def owned_lockers(body, request_id):
    if len(body) < 21:
        raise Rejected("ownership_response")
    block, tid, schema, version = struct.unpack_from("<HHHH", body)
    if (block, tid, schema, version) != (9, 115, 1, 1):
        raise Rejected("ownership_response")
    if struct.unpack_from("<q", body, 8)[0] != request_id or body[16] != 0:
        raise Rejected("ownership_auth")
    group_block, count = struct.unpack_from("<HH", body, 17)
    if group_block != 22:
        raise Rejected("ownership_group")
    offset = 21
    lockers = set()
    for _ in range(count):
        if offset + group_block > len(body):
            raise Rejected("ownership_group")
        locker = struct.unpack_from("<q", body, offset + 12)[0]
        if locker > 0:
            lockers.add(locker)
        offset += group_block
        _, offset = variable_fields(body, offset, "sss")
    if offset != len(body):
        raise Rejected("ownership_trailing")
    return lockers


def framed(body):
    return struct.pack("<I", len(body)) + body


async def read_frame(reader, maximum, timeout):
    header = await asyncio.wait_for(reader.readexactly(4), timeout)
    size = struct.unpack("<I", header)[0]
    if not 8 <= size <= maximum:
        raise Rejected("frame_length")
    return await asyncio.wait_for(reader.readexactly(size), timeout)


async def close(writer):
    if writer is not None:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2)


def login_reply(request_id):
    return (
        struct.pack("<HHHHqBBq", 50, 101, 1, 1, request_id, 3, 1, 0)
        + b"\x00" * 32
        + struct.pack("<I", 0)
        + struct.pack("<I", 19)
        + b"Invalid credentials"
    )


def error_reply(request_id, code, message):
    text = message.encode("utf-8")
    return (
        struct.pack("<HHHHqBi", 13, 120, 1, 1, request_id, 3, code)
        + struct.pack("<I", len(text))
        + text
    )


def pin_shaped(credential):
    return len(credential) == PIN_LENGTH and credential.isdigit()


def short_pin(credential):
    return credential.isdigit() and not pin_shaped(credential)


def login_fields(body):
    block = struct.unpack_from("<H", body)[0]
    offset = 8 + block
    values = []
    for _ in range(2):
        size = struct.unpack_from("<I", body, offset)[0]
        offset += 4
        values.append(body[offset : offset + size].decode("utf-8"))
        offset += size
    return values


class LoginGuard:
    def __init__(
        self,
        limit=LOGIN_FAILURE_LIMIT,
        window=LOGIN_FAILURE_WINDOW,
        step=LOGIN_DELAY_STEP,
        maximum=LOGIN_DELAY_MAX,
    ):
        self.limit = limit
        self.window = window
        self.step = step
        self.maximum = maximum
        self.failures = {}
        self.slots = {}

    def _recent(self, address, now):
        entries = self.failures.get(address)
        if not entries:
            return collections.deque()
        while entries and now - entries[0] > self.window:
            entries.popleft()
        return entries

    def interval(self, address, now):
        excess = len(self._recent(address, now)) - self.limit
        return min(self.maximum, self.step * excess) if excess > 0 else 0.0

    def reserve(self, address, now):
        interval = self.interval(address, now)
        if interval <= 0.0:
            return 0.0
        booked = max(0.0, self.slots.get(address, now) - now)
        wait = max(interval, booked)
        if wait > self.maximum:
            return None
        self.slots[address] = now + wait + interval
        return wait

    def record(self, address, now, success):
        if success:
            self.failures.pop(address, None)
            self.slots.pop(address, None)
            return
        entries = self._recent(address, now)
        entries.append(now)
        self.failures[address] = entries
        for stale in [key for key in self.slots if key not in self.failures]:
            if now - self.slots[stale] > self.window:
                del self.slots[stale]


class Gateway:
    def __init__(
        self,
        upstream,
        io_timeout=10,
        idle_timeout=300,
        max_connections=256,
        login_guard=None,
    ):
        self.upstream = upstream
        self.io_timeout = io_timeout
        self.idle_timeout = idle_timeout
        self.max_connections = max_connections
        self.login_guard = login_guard or LoginGuard()
        self.active = 0

    async def open_upstream(self):
        return await asyncio.wait_for(
            asyncio.open_connection(*self.upstream), self.io_timeout
        )

    async def send(self, writer, body):
        writer.write(framed(body))
        await asyncio.wait_for(writer.drain(), self.io_timeout)

    async def authorize_locker(self, body, reader, writer):
        request_id = struct.unpack_from("<q", body, 8)[0]
        request = struct.pack("<HHHH", 40, 15, 1, 1) + body[8:48]
        await self.send(writer, request)
        reply = await read_frame(reader, MAX_RESPONSE, self.io_timeout)
        locker = struct.unpack_from("<q", body, 48)[0]
        if locker not in owned_lockers(reply, request_id):
            raise Rejected("locker_owner")

    async def handle(self, reader, writer):
        upstream_writer = None
        admitted = self.active < self.max_connections
        if not admitted:
            await close(writer)
            return
        peer = writer.get_extra_info("peername")
        address = peer[0] if peer else ""
        self.active += 1
        try:
            while True:
                header = await asyncio.wait_for(
                    reader.readexactly(4), self.idle_timeout
                )
                size = struct.unpack("<I", header)[0]
                if not 8 <= size <= MAX_FRAME:
                    raise Rejected("frame_length")
                body = await asyncio.wait_for(reader.readexactly(size), self.io_timeout)
                try:
                    tid = validate(body)
                except Rejected as exc:
                    if len(body) < 16 or struct.unpack_from("<HH", body, 2)[1] != 1:
                        raise
                    request_id = struct.unpack_from("<q", body, 8)[0]
                    await self.send(
                        writer,
                        error_reply(request_id, 403, "Rejected by gateway policy"),
                    )
                    LOGGER.info("DROP reason=%s (answered)", exc)
                    continue
                if tid == 1:
                    username, credential = login_fields(body)
                    request_id = struct.unpack_from("<q", body, 8)[0]
                    if not username and short_pin(credential):
                        self.login_guard.record(address, time.monotonic(), False)
                        await self.send(writer, login_reply(request_id))
                        LOGGER.info("PASS tid=1 local_invalid_credential")
                        continue
                    wait = self.login_guard.reserve(address, time.monotonic())
                    if wait is None:
                        LOGGER.info("THROTTLE login over_capacity")
                        await self.send(writer, login_reply(request_id))
                        continue
                    if wait:
                        LOGGER.info("THROTTLE login wait=%.1f", wait)
                        await asyncio.sleep(wait)
                if upstream_writer is None:
                    upstream_reader, upstream_writer = await self.open_upstream()
                if tid in (4, 20):
                    try:
                        await self.authorize_locker(
                            body, upstream_reader, upstream_writer
                        )
                    except Rejected as exc:
                        request_id = struct.unpack_from("<q", body, 8)[0]
                        await self.send(
                            writer,
                            error_reply(
                                request_id,
                                403,
                                "Locker is not assigned to this session",
                            ),
                        )
                        LOGGER.info("DROP reason=%s (answered)", exc)
                        continue
                await self.send(upstream_writer, body)
                reply = await read_frame(upstream_reader, MAX_RESPONSE, self.io_timeout)
                if (
                    len(reply) < 17
                    or struct.unpack_from("<q", reply, 8)[0]
                    != struct.unpack_from("<q", body, 8)[0]
                ):
                    raise Rejected("reply_request_id")
                if tid == 1:
                    self.login_guard.record(address, time.monotonic(), reply[16] == 0)
                await self.send(writer, reply)
                LOGGER.info("PASS tid=%d length=%d", tid, len(body))
        except Rejected as exc:
            LOGGER.info("DROP reason=%s", exc)
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            LOGGER.info("CLOSE transport_or_timeout")
        finally:
            self.active -= 1
            await close(upstream_writer)
            await close(writer)


async def serve(args):
    gateway = Gateway(
        (args.upstream_host, args.upstream_port),
        args.timeout,
        args.idle_timeout,
        args.max_connections,
    )
    server = await asyncio.start_server(gateway.handle, args.bind, args.port)
    LOGGER.info("START port=%d", args.port)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=16004)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=5004)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--idle-timeout", type=float, default=300)
    parser.add_argument("--max-connections", type=int, default=256)
    args = parser.parse_args()
    if args.timeout <= 0 or args.idle_timeout <= 0 or args.max_connections < 1:
        parser.error("timeouts and max-connections must be positive")
    if not 1 <= args.port <= 65535 or not 1 <= args.upstream_port <= 65535:
        parser.error("ports must be in 1..65535")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
