import ast
import hashlib
import importlib
import json
import re
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "offlocker"))
candidate = importlib.import_module("offlocker_gw")
pcap = importlib.import_module("pcap_reader")
root = BASE.parent
backup = root / "hackathon_backup_1024/extracted/backup_1024_1952/backup_1024_1952/home"
source = (backup / "offlocker_gw.py").read_bytes()
if (
    hashlib.sha256(source).hexdigest()
    != "b47b926305b14af836df1ee8b3fb3fdf87952c3b0f23f133692db2a074dd1b72"
):
    raise RuntimeError("Legacy source changed; manual review is required")
allowed = {"T", "TOK", "SAFE_PATH", "BAD_CMD", "BAD_URL"}
nodes = []
for node in ast.parse(source).body:
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id in allowed for t in node.targets
    ):
        nodes.append(node)
    if isinstance(node, ast.FunctionDef) and node.name == "check":
        nodes.append(node)
namespace = {"struct": struct, "re": re}
exec(
    compile(
        ast.Module(body=nodes, type_ignores=[]), "<reviewed-legacy-validator>", "exec"
    ),
    namespace,
)
results = []
frames = {
    59: "search injection",
    256: "signature command injection",
    5747: "partner redirect SSRF",
}
for key, frame, tid, block, body in pcap.sbe(
    backup / "attack_logs/offlocker_traffic.pcap"
):
    if frame not in frames:
        continue
    old = namespace["check"](body)
    try:
        candidate.validate(body)
        new = None
    except candidate.Rejected as exc:
        new = str(exc)
    if old is not None or new is None:
        raise AssertionError(
            "Expected allow-to-deny regression proof at frame " + str(frame)
        )
    results.append(
        {
            "frame": frame,
            "scenario": frames[frame],
            "legacy": "allow",
            "candidate": "deny",
            "reason": new,
        }
    )
if len(results) != len(frames):
    raise AssertionError("Missing capture evidence")
(BASE / "legacy_comparison.json").write_text(json.dumps(results, indent=2) + "\n")
print(json.dumps(results, indent=2))
