import asyncio
import struct
import re
import time
import os

UP = ("127.0.0.1", 5004)
LOG = open(os.path.expanduser("~/offlocker_gw.log"), "a", buffering=1)
MAXF = 1336
T = {
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
TOK = re.compile(rb"^[\x21-\x7e]{32}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
BAD_CMD = re.compile(r"[;&|`$<>\\\r\n]")
BAD_URL = re.compile(r"://(localhost|127\.|0\.|169\.254\.|\[|[^/]*@)")


def log(*a):
    LOG.write(time.strftime("%H:%M:%S ") + " ".join(map(str, a)) + "\n")


def check(body):
    bl, tid, sch, ver = struct.unpack_from("<HHHH", body, 0)
    if sch != 1 or ver != 1:
        return "schema"
    if tid not in T:
        return "tid"
    ebl, kinds = T[tid]
    if bl != ebl:
        return "block"
    blk = body[8 : 8 + bl]
    if len(blk) < bl:
        return "trunc"
    if tid not in (1, 19) and not TOK.match(blk[8:40]):
        return "token"
    if tid == 4 and blk[48] not in (1, 2, 3):
        return "action"
    if tid == 10 and blk[40] not in (1, 2, 3):
        return "report"
    off = 8 + bl
    vals = []
    for k in kinds:
        if off + 4 > len(body):
            return "varhdr"
        n = struct.unpack_from("<I", body, off)[0]
        off += 4
        if n > len(body) - off:
            return "varlen"
        v = body[off : off + n]
        off += n
        if k == "s":
            try:
                v = v.decode("utf-8")
            except Exception:
                return "utf8"
            if "\x00" in v:
                return "nul"
        vals.append(v)
    if off != len(body):
        return "trailing"
    if tid == 6 and (not SAFE_PATH.match(vals[0]) or ".." in vals[0]):
        return "path"
    if tid == 8 and (
        not re.match(r"^https?://", vals[0].lower()) or BAD_URL.search(vals[0].lower())
    ):
        return "url"
    if tid == 7 and (b"<!DOCTYPE" in vals[0].upper() or b"<!ENTITY" in vals[0].upper()):
        return "xml"
    if tid == 12 and BAD_CMD.search(vals[1]):
        return "cmd"
    return None


async def up(r, w, peer):
    try:
        while True:
            h = await r.readexactly(4)
            n = struct.unpack("<I", h)[0]
            if n < 8 or n > MAXF:
                log("DROP", peer, "len", n)
                break
            body = await r.readexactly(n)
            tid = struct.unpack_from("<H", body, 2)[0]
            why = check(body)
            if why:
                log("DROP", peer, "tid", tid, why)
                break
            log("PASS", peer, "tid", tid, "len", n)
            w.write(h + body)
            await w.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        w.close()


async def down(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except ConnectionError:
        pass
    finally:
        w.close()


async def handle(cr, cw):
    peer = cw.get_extra_info("peername")[0]
    try:
        ur, uw = await asyncio.open_connection(*UP)
    except Exception as e:
        log("UPFAIL", e)
        cw.close()
        return
    await asyncio.gather(up(cr, uw, peer), down(ur, cw))


async def main():
    s = await asyncio.start_server(handle, "0.0.0.0", 6004)
    log("START")
    async with s:
        await s.serve_forever()


asyncio.run(main())
