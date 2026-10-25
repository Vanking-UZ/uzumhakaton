import asyncio
import struct
import unittest
from unittest.mock import patch

import modbus_gw as gw


def adu(fc, payload, unit=1, tid=42):
    return struct.pack("!HHHBB", tid, 0, 2 + len(payload), unit, fc) + payload


class PolicyTests(unittest.TestCase):
    def test_documented_maintenance_and_normal_commands(self):
        examples = [
            adu(4, struct.pack("!HH", 0, 14)),
            adu(5, struct.pack("!HH", 42, 0xFF00)),
            adu(6, struct.pack("!HH", 3, 35)),
            adu(16, struct.pack("!HHBHH", 98, 2, 4, 5, 9)),
            adu(16, struct.pack("!HHBH", 100, 1, 2, 950)),
            adu(22, struct.pack("!HHH", 10, 0xFFFE, 1)),
            adu(23, struct.pack("!HHHHBH", 101, 1, 101, 1, 2, 20)),
        ]
        for packet in examples:
            gw.validate(packet)
        for unit in (1, 2, 3):
            gw.validate(adu(6, struct.pack("!HH", 0, 650), unit))

    def test_undocumented_coils_and_service_spill(self):
        bad = [
            adu(5, struct.pack("!HH", 77, 0xFF00)),
            adu(5, struct.pack("!HH", 78, 0xFF00)),
            adu(15, struct.pack("!HHBB", 7, 4, 1, 15)),
            adu(16, struct.pack("!HHBHHH", 98, 3, 6, 1, 2, 0)),
            adu(23, struct.pack("!HHHHBHHH", 98, 1, 98, 3, 6, 1, 2, 0)),
            adu(6, struct.pack("!HH", 9, 10)),
            adu(6, struct.pack("!HH", 10, 0x8000)),
            adu(22, struct.pack("!HHH", 10, 0, 0x8000)),
            adu(6, struct.pack("!HH", 0, 650), 0),
        ]
        for packet in bad:
            with self.subTest(fc=packet[7]), self.assertRaises(gw.Rejected):
                gw.validate(packet)

    def test_truncated_and_inconsistent_lengths(self):
        packet = adu(16, struct.pack("!HHBHH", 0, 2, 4, 650, 120))
        for end in range(len(packet)):
            with self.assertRaises(gw.Rejected):
                gw.validate(packet[:end])
        with self.assertRaises(gw.Rejected):
            gw.validate(packet + b"x")

    def test_motor_protection_range_for_all_direct_register_writes(self):
        for value in (0, 49, 50, 100, 200, 201, 65535):
            packets = [
                adu(6, struct.pack("!HH", 102, value)),
                adu(16, struct.pack("!HHBH", 102, 1, 2, value)),
                adu(23, struct.pack("!HHHHBH", 0, 1, 102, 1, 2, value)),
            ]
            for packet in packets:
                with self.subTest(value=value, fc=packet[7]):
                    if 50 <= value <= 200:
                        gw.validate(packet)
                    else:
                        with self.assertRaises(gw.Rejected):
                            gw.validate(packet)

    def test_multiple_coils_are_decoded_in_modbus_bit_order(self):
        with patch.object(gw, "writes", wraps=gw.writes) as writes:
            gw.validate(adu(15, struct.pack("!HHBB", 0, 9, 2, 0xA5) + b"\x01"))
            writes.assert_called_once_with(
                0, [1, 0, 1, 0, 0, 1, 0, 1, 1], coil=True, bounds=True
            )


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_reject_then_legitimate_on_same_connection(self):
        forwarded = []

        async def backend(reader, writer):
            try:
                packet = await gw.read_adu(reader, 1)
                forwarded.append(packet)
                writer.write(packet)
                await writer.drain()
            finally:
                await gw.close(writer)

        backend_server = await asyncio.start_server(backend, "127.0.0.1", 0)
        gateway = gw.Gateway(
            ("127.0.0.1", backend_server.sockets[0].getsockname()[1]), timeout=0.3
        )
        server = await asyncio.start_server(gateway.handle, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", server.sockets[0].getsockname()[1]
        )
        bad = adu(5, struct.pack("!HH", 77, 0xFF00))
        good = adu(6, struct.pack("!HH", 3, 35))
        writer.write(bad[:3])
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(bad[3:] + good)
        await writer.drain()
        reject = await gw.read_adu(reader, 1)
        self.assertEqual(reject[7:], b"\x85\x03")
        self.assertEqual(await gw.read_adu(reader, 1), good)
        self.assertEqual(forwarded, [good])
        await gw.close(writer)
        server.close()
        backend_server.close()
        await server.wait_closed()
        await backend_server.wait_closed()
        await asyncio.sleep(0.02)


class StatefulTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.registers = {9: 0, 10: 0, 102: 100}
        self.coils = [0, 0, 0]
        self.forwarded: list[bytes] = []
        self.read_started = asyncio.Event()
        self.release_read = asyncio.Event()
        self.release_read.set()
        self.read_fault = None
        self.write_fault = None
        self.clients = []
        self.backend_writers: list[asyncio.StreamWriter] = []

        async def backend(reader, writer):
            self.backend_writers.append(writer)
            try:
                while True:
                    packet = await gw.read_adu(reader, 1)
                    self.forwarded.append(packet)
                    fc = packet[7]
                    if fc == 4:
                        reply = (
                            packet[:4] + b"\x00\x05" + packet[6:7] + b"\x04\x02\x00\x00"
                        )
                    elif fc in (1, 3):
                        self.read_started.set()
                        await self.release_read.wait()
                        if self.read_fault == "exception":
                            payload = bytes([fc | 0x80, 2])
                        elif self.read_fault == "malformed":
                            payload = bytes([fc, 1, 0])
                        elif fc == 3:
                            address = struct.unpack_from("!H", packet, 8)[0]
                            payload = bytes([3, 2]) + struct.pack(
                                "!H", self.registers[address]
                            )
                        else:
                            payload = bytes(
                                [
                                    1,
                                    1,
                                    sum(
                                        value << index
                                        for index, value in enumerate(self.coils)
                                    ),
                                ]
                            )
                        reply = (
                            packet[:4]
                            + struct.pack("!H", len(payload) + 1)
                            + packet[6:7]
                            + payload
                        )
                    elif self.write_fault == "exception":
                        reply = (
                            packet[:4]
                            + b"\x00\x03"
                            + packet[6:7]
                            + bytes([fc | 0x80, 2])
                        )
                    elif self.write_fault == "bad_ack":
                        reply = packet[:-1] + bytes([packet[-1] ^ 1])
                    elif fc == 22:
                        address, and_mask, or_mask = struct.unpack("!HHH", packet[8:])
                        self.registers[address] = (
                            self.registers[address] & and_mask
                        ) | (or_mask & (~and_mask & 0xFFFF))
                        reply = packet
                    elif fc == 6:
                        address, value = struct.unpack("!HH", packet[8:])
                        self.registers[address] = value
                        reply = packet
                    elif fc == 5:
                        address, value = struct.unpack("!HH", packet[8:])
                        self.coils[address] = int(value != 0)
                        reply = packet
                    elif fc == 15:
                        start, count = struct.unpack_from("!HH", packet, 8)
                        for index in range(count):
                            self.coils[start + index] = (
                                packet[13 + index // 8] >> (index % 8)
                            ) & 1
                        reply = packet[:4] + b"\x00\x06" + packet[6:12]
                    else:
                        raise AssertionError(fc)
                    writer.write(reply)
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                await gw.close(writer)

        self.backend_server = await asyncio.start_server(backend, "127.0.0.1", 0)
        self.gateway = gw.Gateway(
            ("127.0.0.1", self.backend_server.sockets[0].getsockname()[1]), timeout=0.5
        )
        self.server = await asyncio.start_server(self.gateway.handle, "127.0.0.1", 0)

    async def asyncTearDown(self):
        self.release_read.set()
        for writer in self.clients + self.backend_writers:
            await gw.close(writer)
        self.server.close()
        self.backend_server.close()
        await self.server.wait_closed()
        await self.backend_server.wait_closed()
        await asyncio.sleep(0.01)

    async def client(self):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.sockets[0].getsockname()[1]
        )
        self.clients.append(writer)
        return reader, writer

    async def request(self, packet, connection=None):
        reader, writer = connection or await self.client()
        writer.write(packet)
        await writer.drain()
        return await gw.read_adu(reader, 1)

    async def test_mask_effective_values_and_original_wire_semantics(self):
        for address, current, and_mask, or_mask, expected in [
            (9, 3, 0xFFFE, 0, 2),
            (10, 0, 0xFFFE, 1, 1),
            (102, 100, 0xFFFE, 1, 101),
        ]:
            with self.subTest(address=address):
                self.registers[address] = current
                packet = adu(22, struct.pack("!HHH", address, and_mask, or_mask))
                self.assertEqual(await self.request(packet), packet)
                self.assertEqual(self.forwarded[-1], packet)
                self.assertEqual(self.forwarded[-2][7], 3)
                self.assertEqual(self.registers[address], expected)

    async def test_mask_invalid_effective_values_never_reach_backend(self):
        connection = await self.client()
        for address, current, and_mask, or_mask in [
            (9, 0, 0, 65535),
            (10, 0x8000, 0xFFFF, 0),
            (102, 100, 0, 0),
            (102, 100, 0, 201),
        ]:
            with self.subTest(address=address):
                self.registers[address] = current
                self.forwarded.clear()
                packet = adu(22, struct.pack("!HHH", address, and_mask, or_mask))
                self.assertEqual(
                    (await self.request(packet, connection))[7:], b"\x96\x03"
                )
                self.assertEqual([packet[7] for packet in self.forwarded], [3])
                self.assertEqual(self.registers[address], current)
        good = adu(6, struct.pack("!HH", 102, 100))
        self.assertEqual(await self.request(good, connection), good)

    async def test_mask_read_failure_and_write_ack_are_not_success(self):
        packet = adu(22, struct.pack("!HHH", 102, 0xFFFF, 0))
        self.read_fault = "exception"
        self.assertEqual((await self.request(packet))[7:], b"\x96\x02")
        self.assertEqual([packet[7] for packet in self.forwarded], [3])
        self.read_fault = "malformed"
        reader, writer = await self.client()
        writer.write(packet)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertEqual([packet[7] for packet in self.forwarded], [3, 3])
        self.read_fault = None
        self.write_fault = "exception"
        self.assertEqual((await self.request(packet))[7:], b"\x96\x02")
        self.write_fault = "bad_ack"
        reader, writer = await self.client()
        writer.write(packet)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")

    async def test_station_lock_covers_fresh_read_and_write_across_clients_units(self):
        self.release_read.clear()
        first_reader, first_writer = await self.client()
        second_reader, second_writer = await self.client()
        mask = adu(22, struct.pack("!HHH", 9, 0, 2), unit=1)
        direct = adu(6, struct.pack("!HH", 9, 3), unit=3)
        first_writer.write(mask[:5])
        await first_writer.drain()
        first_writer.write(mask[5:])
        await first_writer.drain()
        await asyncio.wait_for(self.read_started.wait(), 1)
        second_writer.write(direct)
        await second_writer.drain()
        await asyncio.sleep(0.02)
        self.assertEqual([packet[7] for packet in self.forwarded], [3])
        self.release_read.set()
        self.assertEqual(await gw.read_adu(first_reader, 1), mask)
        self.assertEqual(await gw.read_adu(second_reader, 1), direct)
        self.assertEqual([packet[7] for packet in self.forwarded], [3, 22, 6])
        self.assertEqual(self.registers[9], 3)

    async def start_held_mask(self):
        self.release_read.clear()
        reader, writer = await self.client()
        mask = adu(22, struct.pack("!HHH", 9, 0, 2))
        writer.write(mask)
        await writer.drain()
        await asyncio.wait_for(self.read_started.wait(), 1)
        return reader, mask

    async def test_telemetry_reads_do_not_wait_for_station_lock(self):
        mask_reader, mask = await self.start_held_mask()
        telemetry = adu(4, struct.pack("!HH", 0, 1))
        for _ in range(5):
            reply = await asyncio.wait_for(self.request(telemetry), 0.2)
            self.assertEqual(reply[7:], b"\x04\x02\x00\x00")
        self.release_read.set()
        self.assertEqual(await gw.read_adu(mask_reader, 1), mask)

    async def test_write_lock_wait_is_bounded_with_busy_exception(self):
        self.gateway.lock_timeout = 0.05
        mask_reader, mask = await self.start_held_mask()
        direct = adu(6, struct.pack("!HH", 9, 3), unit=2)
        reply = await asyncio.wait_for(self.request(direct), 0.5)
        self.assertEqual(reply[7:], b"\x86\x06")
        self.assertNotIn(6, [packet[7] for packet in self.forwarded])
        self.release_read.set()
        self.assertEqual(await gw.read_adu(mask_reader, 1), mask)
        self.assertEqual(await self.request(direct), direct)

    async def test_water_path_interlock_and_atomic_multi_coil_start(self):
        pump_on = adu(5, struct.pack("!HH", 0, 0xFF00))
        self.assertEqual((await self.request(pump_on))[7:], b"\x85\x03")
        self.assertEqual([packet[7] for packet in self.forwarded], [1])
        atomic_on = adu(15, struct.pack("!HHBB", 0, 3, 1, 7))
        reply = await self.request(atomic_on)
        self.assertEqual(reply[7:], b"\x0f\x00\x00\x00\x03")
        self.assertEqual(self.coils, [1, 1, 1])
        atomic_unsafe = adu(15, struct.pack("!HHBB", 0, 3, 1, 5))
        self.assertEqual((await self.request(atomic_unsafe))[7:], b"\x8f\x03")
        self.assertEqual(self.coils, [1, 1, 1])
        self.forwarded.clear()
        close_suction = adu(5, struct.pack("!HH", 1, 0), unit=3)
        self.assertEqual((await self.request(close_suction))[7:], b"\x85\x03")
        self.assertEqual([packet[7] for packet in self.forwarded], [1])
        pump_off = adu(5, struct.pack("!HH", 0, 0), unit=2)
        self.assertEqual(await self.request(pump_off), pump_off)
        self.assertEqual(await self.request(close_suction), close_suction)
        self.assertEqual(self.coils, [0, 0, 1])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class RegressionBackend:
    def __init__(self):
        self.regs = {i: 0 for i in range(13)} | {
            98: 5,
            99: 9,
            100: 1000,
            101: 0,
            102: 100,
            6: 200,
            4: 300,
        }
        self.coils = [0] * 64
        self.fail_coil_writes = 0
        self.seen: list[bytes] = []

    async def handle(self, reader, writer):
        try:
            while True:
                p = await gw.read_adu(reader, 30)
                self.seen.append(p)
                fc = p[7]
                if fc in (1, 2):
                    a, n = struct.unpack("!HH", p[8:])
                    bits = bytearray((n + 7) // 8)
                    for i in range(n):
                        bits[i // 8] |= (self.coils[a + i] if fc == 1 else 0) << (i % 8)
                    pl = bytes([fc, len(bits)]) + bytes(bits)
                elif fc in (3, 4):
                    a, n = struct.unpack("!HH", p[8:])
                    vals = [
                        self.regs.get(a + i, 0)
                        if fc == 3
                        else (2 if a + i == 10 else 0)
                        for i in range(n)
                    ]
                    pl = bytes([fc, 2 * n]) + struct.pack("!" + "H" * n, *vals)
                elif fc == 5 and self.fail_coil_writes:
                    self.fail_coil_writes -= 1
                    pl = bytes([fc | 0x80, 4])
                elif fc == 5:
                    a, v = struct.unpack("!HH", p[8:])
                    self.coils[a] = int(v == 0xFF00)
                    pl = p[7:]
                elif fc == 6:
                    a, v = struct.unpack("!HH", p[8:])
                    self.regs[a] = v
                    pl = p[7:]
                elif fc == 15:
                    a, n = struct.unpack_from("!HH", p, 8)
                    for i in range(n):
                        self.coils[a + i] = (p[13 + i // 8] >> (i % 8)) & 1
                    pl = p[7:12]
                elif fc == 16:
                    a, n = struct.unpack_from("!HH", p, 8)
                    for i in range(n):
                        self.regs[a + i] = struct.unpack_from("!H", p, 13 + 2 * i)[0]
                    pl = p[7:12]
                else:
                    pl = p[7:]
                writer.write(p[:4] + struct.pack("!H", len(pl) + 1) + p[6:7] + pl)
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def monotonic(self):
        return self.now


class RegressionTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, **kwargs):
        self.backend = RegressionBackend()
        self.bs = await asyncio.start_server(self.backend.handle, "127.0.0.1", 0)
        self.gateway = gw.Gateway(
            ("127.0.0.1", self.bs.sockets[0].getsockname()[1]), **kwargs
        )
        self.gs = await asyncio.start_server(self.gateway.handle, "127.0.0.1", 0)
        self.port = self.gs.sockets[0].getsockname()[1]
        self.conns = []

    async def asyncTearDown(self):
        for _, w in self.conns:
            w.close()
        self.gs.close()
        self.bs.close()
        await asyncio.sleep(0.02)

    async def client(self):
        c = await asyncio.open_connection("127.0.0.1", self.port)
        self.conns.append(c)
        return c

    async def rq(self, c, packet, timeout=3):
        c[1].write(packet)
        await c[1].drain()
        return (await asyncio.wait_for(gw.read_adu(c[0], timeout), timeout))[7:]

    async def test_idle_client_outlives_backend_timeout(self):
        await self.start(timeout=0.3, idle_timeout=1.0)
        c = await self.client()
        read = adu(4, struct.pack("!HH", 0, 14))
        self.assertEqual((await self.rq(c, read))[:2], b"\x04\x1c")
        await asyncio.sleep(0.6)
        self.assertEqual((await self.rq(c, read))[:2], b"\x04\x1c")
        await asyncio.sleep(1.3)
        c[1].write(read)
        await c[1].drain()
        self.assertEqual(
            await asyncio.wait_for(c[0].read(32), 2),
            b"",
            "closed only after idle_timeout",
        )

    async def test_duplicate_run_restarts_after_window(self):
        await self.start()
        clock = FakeClock()
        with patch.object(gw, "time", clock):
            c = await self.client()
            replies = []
            for step, t in enumerate((0.0, 0.1, 0.2, 10.0, 10.1)):
                clock.now = 1000.0 + t
                replies.append(
                    (await self.rq(c, adu(6, struct.pack("!HH", 3, 35), tid=step)))[:1]
                )
            self.assertEqual(replies, [b"\x06"] * 5)
            clock.now = 1000.0 + 10.2
            self.assertEqual(
                (await self.rq(c, adu(6, struct.pack("!HH", 3, 35), tid=9)))[:1],
                b"\x06",
            )
            clock.now = 1000.0 + 10.3
            self.assertEqual(
                await self.rq(c, adu(6, struct.pack("!HH", 3, 35), tid=10)), b"\x86\x03"
            )

    async def test_rejected_dose_pulse_is_not_counted(self):
        await self.start()
        self.backend.coils[1] = self.backend.coils[2] = 1
        self.backend.fail_coil_writes = 2
        c = await self.client()
        self.assertEqual(
            (await self.rq(c, adu(6, struct.pack("!HH", 6, 1000))))[:1], b"\x06"
        )
        pulse = adu(5, struct.pack("!HH", 4, 0xFF00))
        self.assertEqual(await self.rq(c, pulse), b"\x85\x04")
        self.assertEqual(await self.rq(c, pulse), b"\x85\x04")
        self.assertEqual(self.gateway.policy.cycle_dose, 0)
        self.assertEqual(self.gateway.policy.cycle_pulses, 0)
        self.assertEqual((await self.rq(c, pulse))[:1], b"\x05")
        self.assertEqual(
            (self.gateway.policy.cycle_dose, self.gateway.policy.cycle_pulses),
            (1000, 1),
        )

    async def test_three_pulses_at_maximum_documented_dose_fit_one_cycle(self):
        await self.start()
        self.backend.coils[1] = self.backend.coils[2] = 1
        c = await self.client()
        self.assertEqual(
            (await self.rq(c, adu(6, struct.pack("!HH", 6, 1000))))[:1], b"\x06"
        )
        for _ in range(3):
            self.assertEqual(
                (await self.rq(c, adu(5, struct.pack("!HH", 4, 0xFF00))))[:1], b"\x05"
            )
            self.assertEqual(
                (await self.rq(c, adu(5, struct.pack("!HH", 4, 0))))[:1], b"\x05"
            )
        self.assertEqual(
            await self.rq(c, adu(5, struct.pack("!HH", 4, 0xFF00))), b"\x85\x03"
        )

    async def test_rate_rules_can_be_disabled_without_losing_structural_checks(self):
        await self.start(duplicate_limit=0, change_limit=0)
        c = await self.client()
        for i in range(20):
            self.assertEqual(
                (await self.rq(c, adu(6, struct.pack("!HH", 3, 35), tid=i)))[:1],
                b"\x06",
            )
        self.assertEqual(
            await self.rq(c, adu(6, struct.pack("!HH", 9, 7), tid=99)), b"\x86\x03"
        )
        self.assertEqual(
            await self.rq(c, adu(5, struct.pack("!HH", 77, 0xFF00), tid=98)),
            b"\x85\x03",
        )

    async def test_value_bounds_switch(self):
        await self.start(value_bounds=False)
        c = await self.client()
        self.assertEqual(
            (await self.rq(c, adu(6, struct.pack("!HH", 5, 850))))[:1], b"\x06"
        )
        self.backend.regs[3] = 0
        mask = adu(22, struct.pack("!HHH", 3, 0, 50), tid=3)
        self.assertEqual((await self.rq(c, mask))[:1], b"\x16")
        self.assertEqual(
            await self.rq(c, adu(6, struct.pack("!HH", 9, 7), tid=2)), b"\x86\x03"
        )
