import argparse
import bisect
import collections
import json
import struct
from pathlib import Path

from pcap_reader import streams


def messages(path):
    result = []
    for key, data, spans in streams(path, {5005, 6005}):
        positions = [span[0] for span in spans]
        offset = 0
        while offset + 8 <= len(data):
            transaction, protocol, size, unit, fc = struct.unpack_from(
                "!HHHBB", data, offset
            )
            end = offset + 6 + size
            if protocol != 0 or size < 2 or size > 254 or end > len(data):
                break
            _, frame, timestamp = spans[bisect.bisect_right(positions, offset) - 1]
            request = key[3] in (5005, 6005)
            connection = key if request else (key[1], key[0], key[3], key[2], key[4])
            result.append(
                (
                    frame,
                    timestamp,
                    request,
                    connection,
                    transaction,
                    unit,
                    fc,
                    data[offset:end],
                )
            )
            offset = end
    return sorted(result, key=lambda item: (item[1], item[0]))


def pairs(path):
    pending: dict[tuple, collections.deque[dict]] = collections.defaultdict(
        collections.deque
    )
    result = []
    for (
        frame,
        timestamp,
        is_request,
        connection,
        transaction,
        unit,
        fc,
        adu,
    ) in messages(path):
        identity = (connection, transaction, unit, fc & 127)
        if is_request:
            row = {
                "request_frame": frame,
                "request_time": timestamp,
                "unit": unit,
                "fc": fc,
                "connection": connection,
                "request": adu,
                "response": None,
            }
            pending[identity].append(row)
            result.append(row)
        elif pending[identity]:
            row = pending[identity].popleft()
            row.update(response_frame=frame, response_time=timestamp, response=adu)
    return result


def registers(row):
    request, reply = row["request"], row["response"]
    fc = row["fc"]
    if reply is None or reply[7] != fc or fc not in (1, 2, 3, 4, 23):
        return None
    if len(reply) < 9 or reply[8] != len(reply) - 9:
        return None
    start, count = struct.unpack_from("!HH", request, 8)
    payload = reply[9:]
    if fc in (1, 2):
        if len(payload) != (count + 7) // 8:
            return None
        values = [(payload[index // 8] >> (index % 8)) & 1 for index in range(count)]
    else:
        if len(payload) != 2 * count:
            return None
        values = list(struct.unpack("!" + "H" * count, payload))
    return {
        "space": {1: "coil", 2: "di", 3: "hr", 4: "ir", 23: "hr"}[fc],
        "start": start,
        "values": values,
    }


def write_values(row):
    request = row["request"]
    fc = row["fc"]
    if fc in (5, 6):
        start, value = struct.unpack_from("!HH", request, 8)
        return {
            "space": "coil" if fc == 5 else "hr",
            "start": start,
            "values": [int(value == 0xFF00) if fc == 5 else value],
        }
    if fc in (15, 16):
        start, count, size = struct.unpack_from("!HHB", request, 8)
        data = request[13:]
        values = (
            [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]
            if fc == 15
            else list(struct.unpack("!" + "H" * count, data))
        )
        return {"space": "coil" if fc == 15 else "hr", "start": start, "values": values}
    if fc == 22:
        address, and_mask, or_mask = struct.unpack_from("!HHH", request, 8)
        return {
            "space": "hr_mask",
            "start": address,
            "and_mask": and_mask,
            "or_mask": or_mask,
        }
    if fc == 23:
        _, _, start, count, size = struct.unpack_from("!HHHHB", request, 8)
        return {
            "space": "hr",
            "start": start,
            "values": list(struct.unpack("!" + "H" * count, request[17:])),
        }
    return None


def analyze(path):
    matched = pairs(path)
    read_ranges: collections.Counter[tuple] = collections.Counter()
    write_counts: collections.Counter[tuple] = collections.Counter()
    samples: dict[tuple, list[int]] = {}
    incidents = []
    acknowledged: collections.Counter[tuple] = collections.Counter()
    readbacks = []
    for row in matched:
        fc = row["fc"]
        reply = row["response"]
        values = registers(row)
        if values:
            read_ranges[
                (row["unit"], values["space"], values["start"], len(values["values"]))
            ] += 1
            if values["space"] == "ir":
                for index, value in enumerate(values["values"]):
                    address = values["start"] + index
                    if (
                        address in range(60, 64)
                        or address in range(70, 86)
                        or address in (90, 91)
                    ):
                        incidents.append(
                            {
                                "request_frame": row["request_frame"],
                                "response_frame": row["response_frame"],
                                "time": row["response_time"],
                                "unit": row["unit"],
                                "address": address,
                                "value": value,
                            }
                        )
            if values["space"] in ("hr", "coil"):
                readbacks.append(
                    {"frame": row["response_frame"], "unit": row["unit"], **values}
                )
        write = write_values(row)
        if write:
            key = (row["unit"], fc, json.dumps(write, sort_keys=True))
            write_counts[key] += 1
            samples.setdefault(key, []).append(row["request_frame"])
            status = (
                "unpaired"
                if reply is None
                else ("exception_" + str(reply[8]) if reply[7] & 128 else "ack")
            )
            acknowledged[(fc, write["space"], write["start"], status)] += 1
    return {
        "capture": str(path),
        "requests": len(matched),
        "paired": sum(x["response"] is not None for x in matched),
        "read_ranges": [
            {
                "unit": k[0],
                "space": k[1],
                "start": k[2],
                "count": k[3],
                "observations": v,
            }
            for k, v in read_ranges.items()
        ],
        "write_patterns": [
            {
                "unit": k[0],
                "fc": k[1],
                **json.loads(k[2]),
                "observations": v,
                "example_frames": samples[k][:4],
            }
            for k, v in write_counts.items()
        ],
        "write_acknowledgments": [
            {"fc": k[0], "space": k[1], "start": k[2], "status": k[3], "count": v}
            for k, v in acknowledged.items()
        ],
        "incident_register_observations": incidents,
        "readbacks": readbacks,
        "limits": "TCP reassembly and protocol pairing only; read acknowledgment is not proof of write effects. NAT copies may remain. An absent readback/incident register is not proof no incident occurred.",
    }


def phase_timeline(path, server):
    phases = []
    active = None
    started = False
    observed_ir = set(range(14)) | set(range(60, 64)) | {90, 91}
    for row in pairs(path):
        if row["connection"][1] != server:
            continue
        write = write_values(row)
        if (
            write
            and write["space"] == "coil"
            and write["start"] == 78
            and write["values"] == [1]
        ):
            active = {
                "reset_frame": row["request_frame"],
                "reset_time": row["request_time"],
                "writes": [],
                "incidents": {},
                "before": {},
                "after": {},
            }
            phases.append(active)
            started = False
        if active is None:
            continue
        if write:
            if write["space"] != "coil" or write["start"] != 78:
                started = True
            entries = active["writes"]
            if entries and entries[-1]["write"] == write:
                entries[-1]["count"] += 1
            else:
                entries.append(
                    {"frame": row["request_frame"], "write": write, "count": 1}
                )
        read = registers(row)
        if not read or read["space"] != "ir":
            continue
        for index, value in enumerate(read["values"]):
            address = read["start"] + index
            if address in observed_ir:
                active["after"][str(address)] = value
                if not started:
                    active["before"][str(address)] = value
            if 70 <= address <= 75 and value:
                active["incidents"].setdefault(
                    str(address),
                    {
                        "value": value,
                        "request_frame": row["request_frame"],
                        "response_frame": row["response_frame"],
                    },
                )
    return phases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--phase-server", help="Select one observed endpoint to avoid NAT copies"
    )
    parser.add_argument("--phases-output", type=Path)
    args = parser.parse_args()
    if args.phases_output and (not args.phase_server or len(args.captures) != 1):
        parser.error("phase output requires exactly one capture and --phase-server")
    results = []
    for capture in args.captures:
        result = analyze(capture)
        results.append(result)
        print(
            json.dumps(
                {
                    "capture": str(capture),
                    "requests": result["requests"],
                    "paired": result["paired"],
                    "write_patterns": len(result["write_patterns"]),
                    "incident_samples": len(result["incident_register_observations"]),
                }
            ),
            flush=True,
        )
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    if args.phases_output:
        phases = phase_timeline(args.captures[0], args.phase_server)
        args.phases_output.write_text(
            json.dumps(phases, ensure_ascii=False, indent=2) + "\n"
        )


if __name__ == "__main__":
    main()
