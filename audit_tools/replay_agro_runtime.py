import argparse
import asyncio
import importlib
import json
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "agro"))
agro_trace = importlib.import_module("agro_trace")
gw = importlib.import_module("modbus_gw")


async def replay(path: Path, unknown_coils: int):
    rows = agro_trace.pairs(path)
    if not rows or any(row["response"] is None for row in rows):
        raise AssertionError(f"Missing requests or responses: {path.name}")
    index = 0
    observed_hr: dict[int, int] = {}
    observed_coils: dict[int, int] = {}
    extra = []
    backend_errors: list[str] = []
    backend_writers: list[asyncio.StreamWriter] = []

    async def backend(reader, writer):
        nonlocal index
        backend_writers.append(writer)
        try:
            while True:
                packet = await gw.read_adu(reader, 1)
                if index < len(rows) and packet == rows[index]["request"]:
                    row = rows[index]
                    reply = row["response"]
                    values = agro_trace.registers(row)
                    if values and values["space"] == "hr":
                        observed_hr.update(
                            {
                                values["start"] + i: value
                                for i, value in enumerate(values["values"])
                            }
                        )
                    if values and values["space"] == "coil":
                        observed_coils.update(
                            {
                                values["start"] + i: value
                                for i, value in enumerate(values["values"])
                            }
                        )
                    index += 1
                elif (
                    packet[7] == 1
                    and packet[8:10] == b"\0\0"
                    and packet[10:]
                    in (
                        b"\0\3",
                        b"\0\6",
                    )
                ):
                    count = struct.unpack_from("!H", packet, 10)[0]
                    bits = sum(
                        observed_coils.get(i, (unknown_coils >> i) & 1) << i
                        for i in range(3)
                    )
                    reply = packet[:4] + b"\0\4" + packet[6:7] + bytes([1, 1, bits])
                    extra.append(
                        {"function": 1, "start": 0, "count": count, "bits": bits}
                    )
                elif packet[7] == 3 and packet[10:] == b"\0\1":
                    address = struct.unpack_from("!H", packet, 8)[0]
                    if address not in observed_hr:
                        raise AssertionError(
                            f"No captured prior HR observation: {address}"
                        )
                    reply = (
                        packet[:4]
                        + b"\0\5"
                        + packet[6:7]
                        + bytes([3, 2])
                        + struct.pack("!H", observed_hr[address])
                    )
                    extra.append(
                        {"function": 3, "start": address, "value": observed_hr[address]}
                    )
                else:
                    raise AssertionError(
                        f"Unexpected gateway request at capture request {index}"
                    )
                writer.write(reply)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except (
            TimeoutError,
            AssertionError,
            gw.Rejected,
            ConnectionError,
            OSError,
        ) as exc:
            backend_errors.append(str(exc))
        finally:
            await gw.close(writer)

    backend_server = await asyncio.start_server(backend, "127.0.0.1", 0)
    gateway = gw.Gateway(
        ("127.0.0.1", backend_server.sockets[0].getsockname()[1]), timeout=0.5
    )
    server = await asyncio.start_server(gateway.handle, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", server.sockets[0].getsockname()[1]
    )
    try:
        for row in rows:
            writer.write(row["request"])
            await writer.drain()
            response = await gw.read_adu(reader, 1)
            if response != row["response"]:
                raise AssertionError(
                    f"Response changed: {path.name}, frame {row['request_frame']}"
                )
        if index != len(rows) or backend_errors:
            raise AssertionError(
                f"Incomplete fixture replay: {path.name}: {backend_errors}"
            )
    finally:
        await gw.close(writer)
        for backend_writer in backend_writers:
            await gw.close(backend_writer)
        server.close()
        backend_server.close()
        await server.wait_closed()
        await backend_server.wait_closed()
        await asyncio.sleep(0)
    return {
        "capture": path.name,
        "initial_unknown_coil_bits": unknown_coils,
        "requests_passed": len(rows),
        "fresh_read_fixture_values": extra,
    }


async def verify(workspace: Path):
    normal = workspace / "documents/normal_operation.pcap"
    maintenance = workspace / "documents/maintenance_operation.pcap"
    for path in (normal, maintenance):
        if not path.is_file():
            raise FileNotFoundError(path)
    trials = [await replay(normal, bits) for bits in range(8)]
    trials.append(await replay(maintenance, 0))
    if (
        any(trial["requests_passed"] != 45 for trial in trials[:8])
        or trials[8]["requests_passed"] != 24
    ):
        raise AssertionError("Documented capture request totals changed")
    return {
        "mode": "loopback fixture only; no traffic sent to the stand",
        "documented_requests": 69,
        "normal_trials": 8,
        "requests_compared": sum(trial["requests_passed"] for trial in trials),
        "all_responses_byte_identical": True,
        "trials": trials,
        "limitations": [
            "Captured replies are fixture responses, not execution of the application or simulator.",
            "Extra fresh reads use the most recent captured read observation; write ACKs do not update fixture state.",
            "The normal capture has no coil reads, so all eight prior coil 0..2 states are tried.",
            "Historical observations do not establish actual values at the time of a newly inserted read.",
            "This does not prove morning SLA, autonomous server behavior, or prevention of all incidents.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=BASE.parent)
    parser.add_argument(
        "--output", type=Path, default=BASE / "agro/runtime_capture_replay.json"
    )
    args = parser.parse_args()
    summary = asyncio.run(verify(args.workspace))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {key: value for key, value in summary.items() if key != "trials"},
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
