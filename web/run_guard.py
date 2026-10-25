import argparse
import os
import shutil
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset", choices=("vault", "market", "nether"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--origin-port", type=int, required=True)
    parser.add_argument("--public-host", required=True)
    parser.add_argument("--allowed-origin", action="append", default=[])
    args = parser.parse_args()
    if args.port not in (16001, 16002, 16003, 16006):
        parser.error("Use an internal candidate port 16001/16002/16003/16006")
    allowed_origins = {"vault": (5001,), "market": (5002,), "nether": (5003, 5006)}
    if args.origin_port not in allowed_origins[args.asset]:
        parser.error("Origin port does not match asset")
    if not args.public_host or any(c in args.public_host for c in "\r\n/\\"):
        parser.error("public-host must be host[:port]")
    binary = Path(sys.executable).with_name("mitmdump")
    if not binary.is_file():
        located = shutil.which("mitmdump")
        if not located:
            parser.error("Install web/requirements.txt with Python >=3.12")
        binary = Path(located)
    env = dict(
        os.environ,
        GUARD_ASSET=args.asset,
        GUARD_PUBLIC_HOST=args.public_host,
        GUARD_ALLOWED_ORIGINS=",".join(args.allowed_origin),
    )
    command = [
        str(binary),
        "--mode",
        "reverse:http://127.0.0.1:" + str(args.origin_port),
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(args.port),
        "--set",
        "connection_strategy=lazy",
        "--set",
        "block_list=:~all:403",
        "--set",
        "flow_detail=0",
        "-s",
        str(Path(__file__).with_name("guard_addon.py")),
    ]
    os.execve(str(binary), command, env)


if __name__ == "__main__":
    main()
