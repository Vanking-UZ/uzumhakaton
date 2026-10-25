import argparse
import asyncio
import collections
import contextlib
import logging
import struct
import time

COILS = set(range(9)) | {20, 21, 22, 42, 43}
HOLDING = set(range(13)) | set(range(98, 103))
BOUNDS = {
    0: (0, 1000),
    1: (0, 3600),
    2: (200, 900),
    3: (20, 45),
    4: (150, 400),
    5: (400, 800),
    6: (0, 1000),
    7: (0, 3600),
    8: (0, 1000),
    9: (0, 3),
    11: (0, 1000),
    100: (500, 1500),
    101: (0, 200),
    102: (50, 200),
}
ZERO_DISABLES = frozenset({2, 4})
READ_FUNCTIONS = (1, 2, 3, 4)
SERVER_DEVICE_BUSY = 6
OPERATION_FLAGS = 10
RESERVED_FLAGS = 0xFFF0
PUMP_MODE = 9
PRESSURE_SIMULATION = 101
MAIN_PUMP, SUCTION_VALVE, DISCHARGE_VALVE = 0, 1, 2
DOSING_PUMP, HEATER = 4, 5
START_CYCLE, END_CYCLE = 42, 43
HEATER_TARGET = 4
DOSE_REGISTER = 6
CYCLE_DOSE_LIMIT = 3000
CYCLE_PULSE_LIMIT = 12
DUPLICATE_LIMIT = 2
DUPLICATE_WINDOW = 2.0
CHANGE_LIMIT = 8
CHANGE_WINDOW = 1.0
SESSION_BURST = 45.0
SESSION_REFILL = 12.0
WRITE_FUNCTIONS = frozenset({5, 6, 15, 16, 22, 23})
LOGGER = logging.getLogger("modbus_gateway")


class Rejected(ValueError):
    pass


class Broken(ValueError):
    pass


def read_range(start, count, maximum):
    if not 1 <= count <= maximum or start + count > 65536:
        raise Rejected("read_range")


def value_allowed(address, value):
    low, high = BOUNDS.get(address, (0, 0xFFFF))
    if low <= value <= high:
        return True
    return value == 0 and address in ZERO_DISABLES


def writes(start, values, coil=False, bounds=True):
    allowed = COILS if coil else HOLDING
    if any(start + index not in allowed for index in range(len(values))):
        raise Rejected("undocumented_address")
    if coil:
        return
    if start <= 99 < start + len(values) - 1:
        raise Rejected("schedule_calibration_boundary")
    for index, value in enumerate(values):
        address = start + index
        if address == PUMP_MODE and value not in (0, 1, 2, 3):
            raise Rejected("pump_mode")
        if address == OPERATION_FLAGS and value & RESERVED_FLAGS:
            raise Rejected("reserved_flags")
        if bounds and not value_allowed(address, value):
            raise Rejected("value_range")


def elements(adu):
    fc = adu[7]
    pdu = adu[8:]
    if fc == 5:
        start, value = struct.unpack_from("!HH", pdu)
        yield True, start, int(value == 0xFF00)
    elif fc == 6:
        start, value = struct.unpack_from("!HH", pdu)
        yield False, start, value
    elif fc in (15, 16):
        start, count, _ = struct.unpack_from("!HHB", pdu)
        data = pdu[5:]
        if fc == 15:
            for index in range(count):
                yield True, start + index, (data[index // 8] >> (index % 8)) & 1
        else:
            for index in range(count):
                yield False, start + index, struct.unpack_from("!H", data, 2 * index)[0]
    elif fc == 22:
        start, and_mask, or_mask = struct.unpack_from("!HHH", pdu)
        yield False, start, (and_mask, or_mask)
    elif fc == 23:
        write_start, write_count = struct.unpack_from("!HH", pdu, 4)
        data = pdu[9:]
        for index in range(write_count):
            yield (
                False,
                write_start + index,
                struct.unpack_from("!H", data, 2 * index)[0],
            )


def validate(adu, bounds=True):
    if not 8 <= len(adu) <= 260:
        raise Rejected("adu_length")
    _, protocol, length, unit, fc = struct.unpack_from("!HHHBB", adu)
    if protocol != 0 or length != len(adu) - 6 or unit not in (1, 2, 3):
        raise Rejected("mbap")
    pdu = adu[8:]
    if fc in (1, 2, 3, 4):
        if len(pdu) != 4:
            raise Rejected("read_length")
        start, count = struct.unpack_from("!HH", pdu)
        read_range(start, count, 2000 if fc < 3 else 125)
    elif fc in (5, 6):
        if len(pdu) != 4:
            raise Rejected("write_length")
        start, value = struct.unpack_from("!HH", pdu)
        if fc == 5 and value not in (0, 0xFF00):
            raise Rejected("coil_value")
        writes(
            start,
            [int(value == 0xFF00) if fc == 5 else value],
            coil=fc == 5,
            bounds=bounds,
        )
    elif fc in (15, 16):
        if len(pdu) < 5:
            raise Rejected("write_length")
        start, count, byte_count = struct.unpack_from("!HHB", pdu)
        expected = (count + 7) // 8 if fc == 15 else 2 * count
        if (
            not 1 <= count <= (1968 if fc == 15 else 123)
            or byte_count != expected
            or len(pdu) != 5 + expected
        ):
            raise Rejected("write_count")
        values = (
            [(pdu[5 + index // 8] >> (index % 8)) & 1 for index in range(count)]
            if fc == 15
            else list(struct.unpack_from("!" + "H" * count, pdu, 5))
        )
        writes(start, values, coil=fc == 15, bounds=bounds)
    elif fc == 22:
        if len(pdu) != 6:
            raise Rejected("mask_length")
        start, and_mask, or_mask = struct.unpack_from("!HHH", pdu)
        if start not in HOLDING:
            raise Rejected("undocumented_address")
        if start == OPERATION_FLAGS and (or_mask & ~and_mask) & RESERVED_FLAGS:
            raise Rejected("reserved_flags")
    elif fc == 23:
        if len(pdu) < 9:
            raise Rejected("readwrite_length")
        read_start, read_count, write_start, write_count, byte_count = (
            struct.unpack_from("!HHHHB", pdu)
        )
        read_range(read_start, read_count, 125)
        if (
            not 1 <= write_count <= 121
            or byte_count != 2 * write_count
            or len(pdu) != 9 + byte_count
        ):
            raise Rejected("readwrite_count")
        writes(
            write_start,
            list(struct.unpack_from("!" + "H" * write_count, pdu, 9)),
            bounds=bounds,
        )
    else:
        raise Rejected("function")
    return fc


class Session:
    def __init__(self):
        self.tokens = SESSION_BURST
        self.stamp = time.monotonic()

    def spend(self):
        now = time.monotonic()
        self.tokens = min(
            SESSION_BURST, self.tokens + (now - self.stamp) * SESSION_REFILL
        )
        self.stamp = now
        if self.tokens < 1.0:
            raise Rejected("write_rate")
        self.tokens -= 1.0


class Policy:
    def __init__(self, duplicate_limit=DUPLICATE_LIMIT, change_limit=CHANGE_LIMIT):
        self.duplicate_limit = duplicate_limit
        self.change_limit = change_limit
        self.last: dict[tuple[bool, int], tuple[object, int, float]] = {}
        self.changes: dict[tuple[bool, int], collections.deque[float]] = {}
        self.registers: dict[int, int] = {}
        self.coils: dict[int, int] = {}
        self.cycle_dose = 0
        self.cycle_pulses = 0
        self.pending_dose = 0
        self.pending_pulse = False

    def check_value(self, key, value, now):
        previous = self.last.get(key)
        if (
            self.duplicate_limit
            and previous
            and previous[0] == value
            and previous[1] >= self.duplicate_limit
            and now - previous[2] <= DUPLICATE_WINDOW
        ):
            raise Rejected("duplicate_write")
        stamps = self.changes.get(key)
        if self.change_limit and stamps:
            while stamps and now - stamps[0] > CHANGE_WINDOW:
                stamps.popleft()
            if len(stamps) >= self.change_limit:
                raise Rejected("change_rate")

    def guard(self, adu, session):
        if adu[7] not in WRITE_FUNCTIONS:
            return
        if adu[7] != 22:
            now = time.monotonic()
            for coil, address, value in elements(adu):
                self.check_value((coil, address), value, now)
        session.spend()

    def record(self, coil, address, value, now):
        key = (coil, address)
        previous = self.last.get(key)
        count = 0
        if (
            previous is not None
            and previous[0] == value
            and now - previous[2] <= DUPLICATE_WINDOW
        ):
            count = previous[1] + 1
        self.last[key] = (value, count, now)
        if count == 0:
            self.changes.setdefault(key, collections.deque()).append(now)
        if coil:
            self.coils[address] = value
        else:
            self.registers[address] = value

    def reset_cycle(self):
        self.cycle_dose = 0
        self.cycle_pulses = 0

    def commit(self, adu, reply):
        if adu[7] == 22 or reply[7] & 0x80:
            return
        now = time.monotonic()
        cycle_reset = False
        for coil, address, value in elements(adu):
            self.record(coil, address, value, now)
            if coil and address in (START_CYCLE, END_CYCLE) and value:
                cycle_reset = True
        if cycle_reset:
            self.reset_cycle()

    def commit_pulse(self, accepted=True):
        if self.pending_pulse and accepted:
            self.cycle_dose += self.pending_dose
            self.cycle_pulses += 1
        self.pending_dose = 0
        self.pending_pulse = False

    def learn(self, adu, reply):
        if len(reply) < 9 or reply[7] & 0x80:
            return
        fc = reply[7]
        start = struct.unpack_from("!H", adu, 8)[0] if fc in (1, 2, 3, 4) else 0
        count = struct.unpack_from("!H", adu, 10)[0] if fc in (1, 2, 3, 4) else 0
        data = reply[9:]
        if fc == 1:
            if len(data) != (count + 7) // 8:
                return
            for index in range(count):
                self.coils[start + index] = (data[index // 8] >> (index % 8)) & 1
        elif fc == 3:
            if len(data) != 2 * count:
                return
            for index in range(count):
                self.registers[start + index] = struct.unpack_from(
                    "!H", data, 2 * index
                )[0]
        elif fc == 4:
            if len(data) != 2 * count or not (start <= 10 and start + count > 11):
                return
            state = struct.unpack_from("!H", data, 2 * (10 - start))[0]
            dose = struct.unpack_from("!H", data, 2 * (11 - start))[0]
            if state in (0, 1) and dose == 0:
                self.reset_cycle()
            else:
                self.cycle_dose = max(self.cycle_dose, dose)

    def dose_pulse(self, dose):
        if self.cycle_pulses >= CYCLE_PULSE_LIMIT:
            raise Rejected("cycle_pulse_rate")
        if self.cycle_dose + dose > CYCLE_DOSE_LIMIT:
            raise Rejected("cycle_dose")
        self.pending_dose = dose
        self.pending_pulse = True


async def read_adu(reader, timeout):
    header = await asyncio.wait_for(reader.readexactly(7), timeout)
    length = struct.unpack_from("!H", header, 4)[0]
    if not 2 <= length <= 254:
        raise Broken("mbap_length")
    return header + await asyncio.wait_for(reader.readexactly(length - 1), timeout)


async def close(writer):
    if writer:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2)


class Gateway:
    def __init__(
        self,
        upstream: tuple[str, int],
        timeout: float = 10,
        max_connections: int = 256,
        lock_timeout: float = 2.0,
        idle_timeout: float = 300.0,
        duplicate_limit: int = DUPLICATE_LIMIT,
        change_limit: int = CHANGE_LIMIT,
        value_bounds: bool = True,
    ):
        self.upstream = upstream
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.lock_timeout = lock_timeout
        self.max_connections = max_connections
        self.value_bounds = value_bounds
        self.active = 0
        self.station_lock = asyncio.Lock()
        self.policy = Policy(duplicate_limit, change_limit)

    async def exchange(self, reader, writer, adu):
        writer.write(adu)
        await asyncio.wait_for(writer.drain(), self.timeout)
        reply = await read_adu(reader, self.timeout)
        if (
            reply[:4] != adu[:4]
            or reply[6] != adu[6]
            or reply[7] not in (adu[7], adu[7] | 0x80)
        ):
            raise Broken("response_identity")
        return reply

    async def read_coils(self, reader, writer, adu, count=6):
        request = (
            adu[:4] + b"\x00\x06" + adu[6:7] + b"\x01" + struct.pack("!HH", 0, count)
        )
        reply = await self.exchange(reader, writer, request)
        expected = (count + 7) // 8
        if reply[7] == 0x81 or len(reply) != 9 + expected or reply[8] != expected:
            if count > 3:
                return await self.read_coils(reader, writer, adu, 3)
            if reply[7] == 0x81:
                raise Rejected("coil_state_exception")
            raise Broken("coil_state_value")
        data = reply[9:]
        return {
            address: (data[address // 8] >> (address % 8)) & 1
            for address in range(count)
        }

    async def read_register(self, reader, writer, adu, address):
        request = (
            adu[:4] + b"\x00\x06" + adu[6:7] + b"\x03" + struct.pack("!HH", address, 1)
        )
        reply = await self.exchange(reader, writer, request)
        if reply[7] == 0x83:
            raise Rejected("register_state_exception")
        if len(reply) != 11 or reply[8] != 2:
            raise Broken("register_state_value")
        return struct.unpack_from("!H", reply, 9)[0]

    async def check_coils(self, reader, writer, adu):
        touched = {address for _, address, _ in elements(adu)}
        if touched.isdisjoint(
            {MAIN_PUMP, SUCTION_VALVE, DISCHARGE_VALVE, DOSING_PUMP, HEATER}
        ):
            return
        state = await self.read_coils(reader, writer, adu)
        self.policy.coils.update(state)
        prospective = dict(state)
        for _, address, value in elements(adu):
            prospective[address] = value
        if not touched.isdisjoint({MAIN_PUMP, SUCTION_VALVE, DISCHARGE_VALVE}):
            pump_on = prospective.get(MAIN_PUMP) == 1
            if pump_on and prospective.get(SUCTION_VALVE) != 1:
                raise Rejected("suction_closed_under_load")
            if pump_on and prospective.get(DISCHARGE_VALVE) != 1:
                raise Rejected("discharge_closed_under_load")
        if HEATER in touched and not state.get(HEATER) and prospective.get(HEATER) == 1:
            target = await self.read_register(reader, writer, adu, HEATER_TARGET)
            if target > BOUNDS[HEATER_TARGET][1]:
                raise Rejected("heater_overheat_target")
        if (
            DOSING_PUMP in touched
            and not state.get(DOSING_PUMP)
            and prospective.get(DOSING_PUMP) == 1
        ):
            dose = await self.read_register(reader, writer, adu, DOSE_REGISTER)
            self.policy.dose_pulse(dose)

    async def check_pressure_simulation(self, reader, writer, adu, start, value):
        if start != PRESSURE_SIMULATION or value == 0:
            return
        state = await self.read_coils(reader, writer, adu)
        if state.get(MAIN_PUMP):
            raise Rejected("pressure_simulation_under_load")

    async def forward(self, reader, writer, adu):
        if adu[7] in READ_FUNCTIONS:
            return await self.exchange(reader, writer, adu)
        try:
            await asyncio.wait_for(self.station_lock.acquire(), self.lock_timeout)
        except TimeoutError:
            LOGGER.info("BUSY fc=%d", adu[7])
            return self.deny(adu, SERVER_DEVICE_BUSY)
        try:
            return await self.forward_write(reader, writer, adu)
        finally:
            self.station_lock.release()

    def deny(self, adu, code=3):
        return adu[:4] + b"\x00\x03" + adu[6:7] + bytes([adu[7] | 0x80, code])

    async def forward_write(self, reader, writer, adu):
        self.policy.pending_dose = 0
        self.policy.pending_pulse = False
        fc = adu[7]
        if fc in (5, 15):
            await self.check_coils(reader, writer, adu)
        elif fc in (6, 16, 23):
            for _, address, value in elements(adu):
                await self.check_pressure_simulation(
                    reader, writer, adu, address, value
                )
        if fc != 22:
            reply = await self.exchange(reader, writer, adu)
            self.policy.commit(adu, reply)
            self.policy.commit_pulse(accepted=not reply[7] & 0x80)
            return reply
        start, and_mask, or_mask = struct.unpack_from("!HHH", adu, 8)
        read_request = (
            adu[:4] + b"\x00\x06" + adu[6:7] + b"\x03" + struct.pack("!HH", start, 1)
        )
        reply = await self.exchange(reader, writer, read_request)
        if reply[7] == 0x83:
            if len(reply) != 9:
                raise Broken("mask_read_exception")
            return self.deny(adu, reply[8])
        if len(reply) != 11 or reply[8] != 2:
            raise Broken("mask_read_value")
        current = struct.unpack_from("!H", reply, 9)[0]
        effective = (current & and_mask) | (or_mask & (~and_mask & 0xFFFF))
        writes(start, [effective], bounds=self.value_bounds)
        self.policy.check_value((False, start), effective, time.monotonic())
        await self.check_pressure_simulation(reader, writer, adu, start, effective)
        reply = await self.exchange(reader, writer, adu)
        if reply[7] == 0x96:
            if len(reply) != 9:
                raise Broken("mask_write_exception")
            return reply
        if reply != adu:
            raise Broken("mask_write_ack")
        self.policy.record(False, start, effective, time.monotonic())
        return reply

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        upstream_writer: asyncio.StreamWriter | None = None
        if self.active >= self.max_connections:
            await close(writer)
            return
        self.active += 1
        session = Session()
        try:
            while True:
                adu = await read_adu(reader, self.idle_timeout)
                try:
                    validate(adu, self.value_bounds)
                    self.policy.guard(adu, session)
                except Rejected as exc:
                    code = SERVER_DEVICE_BUSY if str(exc) == "write_rate" else 3
                    writer.write(self.deny(adu, code))
                    await asyncio.wait_for(writer.drain(), self.timeout)
                    LOGGER.info("DROP reason=%s", exc)
                    continue
                if upstream_writer is None:
                    connection: tuple[
                        asyncio.StreamReader, asyncio.StreamWriter
                    ] = await asyncio.wait_for(
                        asyncio.open_connection(*self.upstream), self.timeout
                    )
                    upstream_reader, upstream_writer = connection
                try:
                    reply = await self.forward(upstream_reader, upstream_writer, adu)
                except Rejected as exc:
                    self.policy.commit_pulse(accepted=False)
                    reply = adu[:4] + b"\x00\x03" + adu[6:7] + bytes([adu[7] | 0x80, 3])
                    LOGGER.info("DROP reason=%s", exc)
                self.policy.learn(adu, reply)
                writer.write(reply)
                await asyncio.wait_for(writer.drain(), self.timeout)
        except (
            TimeoutError,
            Broken,
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
        ):
            LOGGER.info("CLOSE protocol_or_transport")
        finally:
            self.active -= 1
            await close(upstream_writer)
            await close(writer)


async def serve(args):
    gateway = Gateway(
        (args.upstream_host, args.upstream_port),
        timeout=args.timeout,
        lock_timeout=args.lock_timeout,
        idle_timeout=args.idle_timeout,
        duplicate_limit=args.duplicate_limit,
        change_limit=args.change_limit,
        value_bounds=not args.no_value_bounds,
    )
    server = await asyncio.start_server(gateway.handle, args.bind, args.port)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=16005)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=5005)
    parser.add_argument(
        "--timeout", type=float, default=10, help="backend reply timeout, s"
    )
    parser.add_argument(
        "--lock-timeout", type=float, default=2.0, help="max wait for the write lock, s"
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=300.0,
        help="client silence before disconnect, s",
    )
    parser.add_argument(
        "--duplicate-limit",
        type=int,
        default=DUPLICATE_LIMIT,
        help=f"identical writes allowed inside {DUPLICATE_WINDOW:.0f}s before refusal; 0 disables",
    )
    parser.add_argument(
        "--change-limit",
        type=int,
        default=CHANGE_LIMIT,
        help=f"value changes per register per {CHANGE_WINDOW:.0f}s before refusal; 0 disables",
    )
    parser.add_argument(
        "--no-value-bounds",
        action="store_true",
        help="disable documented setpoint ranges (keep structural, water-path and FC22 rules)",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.upstream_port <= 65535:
        parser.error("ports must be in 1..65535")
    if (
        min(args.timeout, args.lock_timeout, args.idle_timeout) <= 0
        or min(args.duplicate_limit, args.change_limit) < 0
    ):
        parser.error("timeouts must be positive, limits non-negative")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
