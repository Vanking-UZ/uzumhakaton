import asyncio
import struct
import unittest

import offlocker_gw as gw

TOKEN = b"a1" * 16


def request(tid, fixed_extra=b"", values=(), request_id=42, token=TOKEN):
    block, kinds = gw.SCHEMA[tid]
    fixed = struct.pack("<q", request_id)
    if tid not in (1, 19):
        fixed += token
    fixed += fixed_extra
    if len(fixed) != block:
        raise ValueError("incorrect test fixture block")
    body = struct.pack("<HHHH", block, tid, 1, 1) + fixed
    for value in values:
        if isinstance(value, str):
            value = value.encode("utf-8")
        body += struct.pack("<I", len(value)) + value
    return body


def parcels(lockers, request_id=42, status=0):
    body = struct.pack("<HHHHqBHH", 9, 115, 1, 1, request_id, status, 22, len(lockers))
    for index, locker in enumerate(lockers):
        body += struct.pack("<qiqBB", index + 1, 1, locker, 4, 2)
        for value in ("TRK-1001", "Aziza Karimova", "Parcel"):
            raw = value.encode()
            body += struct.pack("<I", len(raw)) + raw
    return body


class ValidationTests(unittest.TestCase):
    def test_legitimate_protocol_profile(self):
        cases = [
            request(1, b"\x01", ("", "246810")),
            request(1, b"\x02", ("courier", "password")),
            request(2, struct.pack("<i", 0), ("TRK-1001",)),
            request(3, struct.pack("<q", 1)),
            request(4, struct.pack("<qB", 7, 1)),
            request(5, struct.pack("<q", 1), ("246810",)),
            request(5, struct.pack("<q", 1), ("",)),
            request(6, values=("label-TRK-1001.txt",)),
            request(
                7,
                values=(
                    b'<?xml version="1.0" encoding="UTF-8"?><manifest><parcel tracking="IMP-001" station="1" size="M"/></manifest>',
                ),
            ),
            request(8, values=("http://CHILONZOR-01/manifest.xml",)),
            request(9, struct.pack("<i", 1), ("UZ",)),
            request(10, b"\x01"),
            request(11, struct.pack("<q", 1), ("Aziza Karimova",)),
            request(11, struct.pack("<q", 1), ("O\u2019tkir Aliyev",)),
            request(12, struct.pack("<q", 1), (b"status=ok\n", "")),
            request(12, struct.pack("<q", 1), (b"x" * 10, "echo UNDER")),
            request(12, struct.pack("<q", 1), (b"x" * 1272, "")),
            request(13),
            request(14, struct.pack("<i", 1)),
            request(15),
            request(16, struct.pack("<i", 1)),
            request(17, struct.pack("<i", 0)),
            request(18),
            request(19),
            request(20, struct.pack("<q", 7)),
        ]
        for body in cases:
            with self.subTest(tid=struct.unpack_from("<H", body, 2)[0]):
                gw.validate(body)

    def test_url_allowlist_blocks_redirect_and_parser_ambiguities(self):
        values = [
            "http://CHILONZOR-01/redirect",
            "http://127.0.0.1:8080/hr",
            "http://2130706433/hr",
            "http://[::1]/hr",
            "http://CHILONZOR-01.evil/manifest.xml",
            "http://CHILONZOR-01@localhost/manifest.xml",
            "http://CHILONZOR-01:8080/manifest.xml",
            "http://CHILONZOR-01/manifest.xml?next=/redirect",
            "http://CHILONZOR-01/manifest.xml?",
            "http://CHILONZOR-01/manifest.xml#redirect",
            "http://CHILONZOR-01/%2e%2e/redirect",
            "http://CHI\nLONZOR-01/manifest.xml",
            "file:///etc/hosts",
            "https://CHILONZOR-01/manifest.xml",
        ]
        for url in values:
            with self.subTest(url=url), self.assertRaises(gw.Rejected):
                gw.validate(request(8, values=(url,)))

    def test_injection_surface(self):
        cases = [
            request(2, struct.pack("<i", 0), ("x' OR '1'='1",)),
            request(6, values=("../private.txt",)),
            request(6, values=("label.txt\n",)),
            request(
                7,
                values=(
                    b'<!DOCTYPE manifest [<!ENTITY x SYSTEM "file:///etc/hosts">]><manifest>&x;</manifest>',
                ),
            ),
            request(7, values=("<!DOCTYPE manifest><manifest/>".encode("utf-16"),)),
            request(
                7, values=(b'<?xml version="1.0" encoding="ISO-8859-1"?><manifest/>',)
            ),
            request(
                7,
                values=(
                    b'<manifest xmlns:x="http://www.w3.org/2001/XInclude"><x:include href="file:///etc/hosts"/></manifest>',
                ),
            ),
            request(11, struct.pack("<q", 1), ("Name; echo test",)),
            request(11, struct.pack("<q", 1), ("Name\nsecond",)),
            request(12, struct.pack("<q", 1), (b"status=ok", "echo test")),
            request(12, struct.pack("<q", 1), (b"x" * 1273, "")),
            request(13, token=b"Z" * 32),
        ]
        for body in cases:
            with (
                self.subTest(tid=struct.unpack_from("<H", body, 2)[0]),
                self.assertRaises(gw.Rejected),
            ):
                gw.validate(body)

    def test_truncation_and_schema(self):
        valid = request(8, values=("http://CHILONZOR-01/manifest.xml",))
        for end in range(len(valid)):
            with self.subTest(end=end), self.assertRaises(gw.Rejected):
                gw.validate(valid[:end])
        for offset in (0, 2, 4, 6):
            broken = bytearray(valid)
            struct.pack_into("<H", broken, offset, 999)
            with self.assertRaises(gw.Rejected):
                gw.validate(bytes(broken))
        with self.assertRaises(gw.Rejected):
            gw.validate(valid + b"x")

    def test_ownership_response(self):
        self.assertEqual(gw.owned_lockers(parcels([7, 8, 0]), 42), {7, 8})
        self.assertEqual(gw.owned_lockers(parcels([]), 42), set())
        for body in (
            parcels([7], status=3),
            parcels([7], request_id=43),
            parcels([7])[:-1],
            parcels([7]) + b"x",
        ):
            with self.assertRaises(gw.Rejected):
                gw.owned_lockers(body, 42)

    def test_invalid_login_reply_matches_recorded_server_bytes(self):
        recorded = bytes.fromhex(
            "3200650001000100010000000000000003010000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000001300"
            "0000496e76616c69642063726564656e7469616c73"
        )
        self.assertEqual(gw.login_reply(1), recorded)

    def test_short_numeric_pin_is_the_only_locally_refused_shape(self):
        for credential, local in (
            ("1234", True),
            ("1234567", True),
            ("246810", False),
            ("24681a", False),
            ("", False),
        ):
            with self.subTest(credential=credential):
                self.assertEqual(gw.short_pin(credential), local)


class LoginGuardTests(unittest.TestCase):
    def test_customer_mistyping_a_few_times_is_not_delayed(self):
        guard = gw.LoginGuard()
        now = 1000.0
        for _ in range(gw.LOGIN_FAILURE_LIMIT):
            guard.record("10.0.0.9", now, False)
        self.assertEqual(guard.reserve("10.0.0.9", now), 0.0)

    def test_wrong_six_digit_pins_are_paced_not_dropped(self):
        guard = gw.LoginGuard()
        now = 2000.0
        waits = []
        for index in range(25):
            waits.append(guard.reserve("10.0.0.7", now))
            guard.record("10.0.0.7", now, False)
            now += 0.05
        self.assertTrue(all(wait == 0.0 for wait in waits[: gw.LOGIN_FAILURE_LIMIT]))
        queued = [wait for wait in waits[gw.LOGIN_FAILURE_LIMIT :] if wait is not None]
        self.assertTrue(any(wait > 0.0 for wait in queued))
        self.assertLessEqual(max(queued), gw.LOGIN_DELAY_MAX)
        self.assertIn(None, waits[gw.LOGIN_FAILURE_LIMIT :])

    def test_parallel_attempts_cannot_pass_together(self):
        guard = gw.LoginGuard(limit=0, step=0.1, maximum=1.0)
        now = 2500.0
        for _ in range(5):
            guard.record("10.0.0.8", now, False)
        waits = [guard.reserve("10.0.0.8", now) for _ in range(8)]
        self.assertEqual(waits[:2], [0.5, 1.0])
        self.assertTrue(all(wait is None for wait in waits[2:]), waits)
        self.assertEqual(
            len({w for w in waits if w is not None}),
            2,
            "every queued attempt gets its own slot",
        )

    def test_parallel_attempts_share_one_schedule(self):
        guard = gw.LoginGuard(limit=0, step=1.0, maximum=10.0)
        now = 3000.0
        first = guard.reserve("10.0.0.5", now)
        guard.record("10.0.0.5", now, False)
        second = guard.reserve("10.0.0.5", now)
        self.assertEqual(first, 0.0)
        self.assertEqual(second, 1.0)

    def test_success_clears_the_address_budget(self):
        guard = gw.LoginGuard(limit=0, step=1.0, maximum=10.0)
        now = 4000.0
        guard.reserve("10.0.0.4", now)
        guard.record("10.0.0.4", now, False)
        self.assertGreater(guard.reserve("10.0.0.4", now), 0.0)
        self.assertGreater(guard.interval("10.0.0.4", now), 0.0)
        guard.record("10.0.0.4", now, True)
        self.assertEqual(guard.reserve("10.0.0.4", now), 0.0)

    def test_other_addresses_are_unaffected(self):
        guard = gw.LoginGuard()
        now = 5000.0
        for _ in range(50):
            guard.record("10.0.0.3", now, False)
        self.assertGreater(guard.interval("10.0.0.3", now), 0.0)
        self.assertEqual(guard.interval("10.0.0.4", now), 0.0)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.forwarded = []
        self.logins = []
        self.opened = 0
        self.writers = set()
        self.tasks = set()
        self.backend = await asyncio.start_server(self.stub, "127.0.0.1", 0)
        self.gateway = gw.Gateway(
            ("127.0.0.1", self.backend.sockets[0].getsockname()[1]),
            io_timeout=0.3,
            idle_timeout=1,
        )
        self.proxy = await asyncio.start_server(self.track, "127.0.0.1", 0)
        self.port = self.proxy.sockets[0].getsockname()[1]

    async def track(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            await self.gateway.handle(reader, writer)
        finally:
            self.tasks.discard(task)

    async def stub(self, reader, writer):
        self.opened += 1
        self.writers.add(writer)
        try:
            while True:
                body = await gw.read_frame(reader, gw.MAX_RESPONSE, 1)
                tid = struct.unpack_from("<H", body, 2)[0]
                rid = struct.unpack_from("<q", body, 8)[0]
                self.forwarded.append(tid)
                if tid == 15:
                    reply = parcels([7], rid)
                elif tid == 1:
                    self.logins.append(gw.login_fields(body)[1])
                    status = 0 if gw.login_fields(body)[1] == "246810" else 3
                    reply = (
                        struct.pack("<HHHHqBBq", 50, 101, 1, 1, rid, status, 1, 0)
                        + b"\x00" * 32
                        + struct.pack("<I", 0)
                        + struct.pack("<I", 0)
                    )
                else:
                    reply = struct.pack(
                        "<HHHHqB", 9, 119 if tid == 19 else 104, 1, 1, rid, 0
                    )
                writer.write(gw.framed(reply))
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            await gw.close(writer)
        finally:
            self.writers.discard(writer)

    async def asyncTearDown(self):
        self.proxy.close()
        self.backend.close()
        await self.proxy.wait_closed()
        await self.backend.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in list(self.writers):
            await gw.close(writer)

    async def test_fragmented_and_coalesced_frames(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        data = gw.framed(request(19))
        writer.write(data[:2])
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(data[2:] + data)
        await writer.drain()
        self.assertEqual((await gw.read_frame(reader, 1024, 1))[16], 0)
        self.assertEqual((await gw.read_frame(reader, 1024, 1))[16], 0)
        await gw.close(writer)
        self.assertEqual(self.forwarded, [19, 19])

    async def test_owned_locker_forwarded_and_foreign_denied(self):
        for locker, allowed in ((7, True), (8, False)):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            writer.write(gw.framed(request(4, struct.pack("<qB", locker, 1))))
            await writer.drain()
            reply = await gw.read_frame(reader, 1024, 1)
            if allowed:
                self.assertEqual(
                    (struct.unpack_from("<H", reply, 2)[0], reply[16]), (104, 0)
                )
            else:
                self.assertEqual(
                    (struct.unpack_from("<H", reply, 2)[0], reply[16]), (120, 3)
                )
                self.assertEqual(struct.unpack_from("<q", reply, 8)[0], 42)
                writer.write(gw.framed(request(19, request_id=43)))
                await writer.drain()
                self.assertEqual(
                    struct.unpack_from("<q", await gw.read_frame(reader, 1024, 1), 8)[
                        0
                    ],
                    43,
                )
            await gw.close(writer)
        self.assertEqual(self.forwarded.count(15), 2)
        self.assertEqual(self.forwarded.count(4), 1)
        self.assertEqual(
            self.opened,
            2,
            "one upstream session per client, none for the ownership lookup",
        )

    async def test_partial_body_times_out_without_upstream(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(struct.pack("<I", 20) + b"x")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
        self.assertEqual(self.forwarded, [])
        await gw.close(writer)

    async def test_rejected_url_never_reaches_backend(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(gw.framed(request(8, values=("http://CHILONZOR-01/redirect",))))
        await writer.drain()
        reply = await gw.read_frame(reader, 1024, 1)
        self.assertEqual(struct.unpack_from("<H", reply, 2)[0], 120)
        self.assertEqual(self.forwarded, [])
        writer.write(gw.framed(request(19, request_id=7)))
        await writer.drain()
        self.assertEqual(
            struct.unpack_from("<q", await gw.read_frame(reader, 1024, 1), 8)[0], 7
        )
        self.assertEqual(self.forwarded, [19])
        await gw.close(writer)

    async def test_short_pin_answered_locally_valid_pin_still_forwarded(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(gw.framed(request(1, b"\x01", ("", "1234"))))
        await writer.drain()
        reply = await gw.read_frame(reader, 1024, 1)
        self.assertEqual(reply, gw.login_reply(42))
        self.assertEqual(self.logins, [])
        writer.write(gw.framed(request(1, b"\x01", ("", "246810"), request_id=43)))
        await writer.drain()
        reply = await gw.read_frame(reader, 1024, 1)
        self.assertEqual((struct.unpack_from("<q", reply, 8)[0], reply[16]), (43, 0))
        self.assertEqual(self.logins, ["246810"])
        await gw.close(writer)

    async def test_staff_login_with_wrong_short_password_is_forwarded(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(gw.framed(request(1, b"\x03", ("operator", "0p3r"))))
        await writer.drain()
        self.assertEqual((await gw.read_frame(reader, 1024, 1))[16], 3)
        self.assertEqual(self.logins, ["0p3r"])
        await gw.close(writer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
