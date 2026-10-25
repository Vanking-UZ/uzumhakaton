import argparse
import csv
import importlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE / "offlocker"), str(BASE / "web"), str(BASE / "agro")]
modbus_gw = importlib.import_module("modbus_gw")
offlocker_gw = importlib.import_module("offlocker_gw")
policy = importlib.import_module("policy")
pcap_reader = importlib.import_module("pcap_reader")
http_pairs, packets, sbe = pcap_reader.http_pairs, pcap_reader.packets, pcap_reader.sbe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=BASE.parent)
    parser.add_argument("--output", type=Path, default=BASE / "offline_evidence.csv")
    args = parser.parse_args()
    root = args.workspace
    capture_base = (
        root
        / "hackathon_backup_1024/extracted/backup_1024_1952/backup_1024_1952/home/attack_logs"
    )
    rows = []
    p = capture_base / "offlocker_traffic.pcap"
    golden = {
        59: "deny",
        94: "allow",
        256: "deny",
        283: "allow",
        629: "allow",
        706: "deny",
        737: "allow",
        5747: "deny",
    }
    golden_seen = set()
    for key, frame, tid, block, body in sbe(p):
        if key[3] not in (5004, 6004):
            continue
        try:
            offlocker_gw.validate(body)
            decision = "needs_backend_ownership" if tid in (4, 20) else "allow"
            reason = ""
        except offlocker_gw.Rejected as exc:
            decision, reason = "deny", str(exc)
        if frame in golden:
            if decision != golden[frame]:
                raise AssertionError(
                    "OffLocker golden frame decision changed: " + str(frame)
                )
            golden_seen.add(frame)
        rows.append(
            {
                "capture": str(p.relative_to(root)),
                "frame": frame,
                "asset": "offlocker",
                "port": key[3],
                "request": "tid_" + str(tid),
                "decision": decision,
                "reason": reason,
            }
        )
    if golden_seen != set(golden):
        raise AssertionError("Missing OffLocker golden frames")
    p = capture_base / "attack_traffic.pcap"
    assets = {6001: "vault", 6002: "market", 6003: "nether", 6006: "nether"}
    for key, request, reply in http_pairs(p):
        if key[3] not in assets:
            continue
        frame, line, headers, body = request
        method, target, _ = line.split(" ", 2)
        try:
            policy.check_request(assets[key[3]], method, target, headers, body)
            decision, reason = "allow", ""
        except policy.Denied as exc:
            decision, reason = "deny", str(exc)
        rows.append(
            {
                "capture": str(p.relative_to(root)),
                "frame": frame,
                "asset": assets[key[3]],
                "port": key[3],
                "request": method + " " + target.partition("?")[0],
                "decision": decision,
                "reason": reason,
            }
        )
    normal = {}
    for relative in (
        "documents/normal_operation.pcap",
        "documents/maintenance_operation.pcap",
        str(p.relative_to(root)),
    ):
        seen = set()
        counts = Counter()
        for frame, tm, src, dst, sp, dp, seq, flags, payload in packets(
            root / relative
        ):
            if dp != 5005 or not payload:
                continue
            signature = (src, dst, sp, dp, seq, payload)
            if signature in seen:
                continue
            seen.add(signature)
            offset = 0
            while offset + 7 <= len(payload):
                length = struct.unpack_from("!H", payload, offset + 4)[0]
                end = offset + 6 + length
                if length < 2 or end > len(payload):
                    counts["incomplete_or_nonmodbus_segment"] += 1
                    break
                adu = payload[offset:end]
                try:
                    modbus_gw.validate(adu)
                    decision, reason = "allow", ""
                except modbus_gw.Rejected as exc:
                    decision, reason = "deny", str(exc)
                counts[decision] += 1
                if relative.startswith("documents/") or decision == "deny":
                    rows.append(
                        {
                            "capture": relative,
                            "frame": frame,
                            "asset": "agro",
                            "port": 5005,
                            "request": "fc_" + str(adu[7]),
                            "decision": decision,
                            "reason": reason,
                        }
                    )
                offset = end
        if relative.startswith("documents/") and counts.get("deny", 0):
            raise AssertionError("Documented Modbus operation was denied: " + relative)
        normal[relative] = dict(counts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=(
                "capture",
                "frame",
                "asset",
                "port",
                "request",
                "decision",
                "reason",
            ),
        )
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "offlocker_golden_frames_passed": len(golden_seen),
        "mode": "offline classification only; no payload sent to any server",
        "http_scope": "request policy only; addon header/response/upload handling tested separately",
        "counts": dict(Counter(row["asset"] + ":" + row["decision"] for row in rows)),
        "modbus_packet_classification": normal,
        "limits": "IPv4 TCP classic PCAP only; no sequence-wrap handling. NAT/interface copies may remain. Counts are not unique vulnerabilities.",
    }
    args.output.with_suffix(".json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
