import collections
import socket
import struct


def packets(path):
    with open(path, "rb") as f:
        h = f.read(24)
        en = "<" if h[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack_from(en + "I", h, 20)[0]
        num = 0
        while h := f.read(16):
            if len(h) != 16:
                break
            sec, usec, n, orig = struct.unpack(en + "IIII", h)
            if n > 16_777_216:
                break
            d = f.read(n)
            num += 1
            if len(d) != n:
                break
            off = {1: 14, 113: 16, 276: 20}.get(link)
            if off is None or len(d) < off + 20 or d[off] >> 4 != 4:
                continue
            ip = d[off:]
            ih = (ip[0] & 15) * 4
            if (
                ip[9] != 6
                or len(ip) < ih + 20
                or struct.unpack_from("!H", ip, 6)[0] & 0x3FFF
            ):
                continue
            total = struct.unpack_from("!H", ip, 2)[0]
            tcp = ip[ih:total]
            sp, dp, seq = struct.unpack_from("!HHI", tcp)
            th = (tcp[12] >> 4) * 4
            yield (
                num,
                sec + usec / 1e6,
                socket.inet_ntoa(ip[12:16]),
                socket.inet_ntoa(ip[16:20]),
                sp,
                dp,
                seq,
                tcp[13],
                tcp[th:],
            )


def streams(path, ports):
    data = {}
    generation = collections.defaultdict(int)
    seen_syn = set()
    for fr, tm, src, dst, sp, dp, seq, flags, pay in packets(path):
        if sp not in ports and dp not in ports:
            continue
        key = (src, dst, sp, dp)
        if flags & 2 and not flags & 16:
            marker = key + (seq,)
            if marker not in seen_syn:
                generation[key] += 1
                generation[(dst, src, dp, sp)] = generation[key]
                seen_syn.add(marker)
        if not pay:
            continue
        stream = data.setdefault(key + (generation[key],), {})
        if seq not in stream:
            stream[seq] = (fr, tm, pay)
    for key, chunks in data.items():
        current = bytearray()
        spans = []
        expected = None
        for seq, (fr, tm, pay) in sorted(chunks.items()):
            if expected is None or seq > expected:
                if current:
                    yield key, bytes(current), spans
                current = bytearray()
                spans = []
                expected = seq
            skip = max(0, expected - seq)
            if skip < len(pay):
                spans.append((len(current), fr, tm))
                current.extend(pay[skip:])
                expected = seq + len(pay)
        if current:
            yield key, bytes(current), spans


def sbe(path):
    result = []
    for key, d, spans in streams(path, {5004, 6004}):
        off = 0
        while off + 12 <= len(d):
            n = struct.unpack_from("<I", d, off)[0]
            if n < 8 or n > 16777216 or off + 4 + n > len(d):
                break
            body = d[off + 4 : off + 4 + n]
            bl, tid, sch, ver = struct.unpack_from("<HHHH", body)
            if sch != 1 or ver != 1:
                break
            fr = next((fr for o, fr, tm in reversed(spans) if o <= off), spans[0][1])
            result.append((key, fr, tid, bl, body))
            off += 4 + n
    return result


def http_messages(data):
    offset = 0
    while offset < len(data):
        end = data.find(b"\r\n\r\n", offset)
        if end < 0:
            break
        lines = data[offset:end].split(b"\r\n")
        start = lines[0].decode("latin1")
        if not (
            start.startswith("HTTP/")
            or start.split(" ", 1)[0]
            in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        ):
            break
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.lower().decode("latin1")] = v.strip().decode("latin1")
        body_start = end + 4
        body_end = body_start
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = bytearray()
            pos = body_start
            while True:
                e = data.find(b"\r\n", pos)
                if e < 0:
                    return
                try:
                    n = int(data[pos:e].split(b";")[0], 16)
                except ValueError:
                    return
                if n == 0:
                    trailer_end = data.find(b"\r\n\r\n", e + 2)
                    body_end = (
                        e + 4 if data[e + 2 : e + 4] == b"\r\n" else trailer_end + 4
                    )
                    if body_end < e + 4:
                        return
                    break
                if e + 2 + n + 2 > len(data):
                    return
                body.extend(data[e + 2 : e + 2 + n])
                pos = e + 2 + n + 2
            body = bytes(body)
        elif "content-length" in headers:
            try:
                body_end = body_start + int(headers["content-length"])
            except ValueError:
                break
            if body_end > len(data):
                break
            body = data[body_start:body_end]
        else:
            body = b""
        yield offset, start, headers, body
        offset = body_end


def http_pairs(path, ports={5001, 5002, 5003, 5006, 6001, 6002, 6003, 6006}):
    streams_map = {}
    for key, data, spans in streams(path, ports):
        msgs = []
        for off, start, h, body in http_messages(data):
            fr = next((fr for o, fr, tm in reversed(spans) if o <= off), spans[0][1])
            msgs.append((fr, start, h, body))
        if msgs:
            streams_map.setdefault(key, []).extend(msgs)
    for key, reqs in streams_map.items():
        if key[3] not in ports:
            continue
        rev = (key[1], key[0], key[3], key[2], key[4])
        replies = streams_map.get(rev, [])
        for i, req in enumerate(reqs):
            yield key, req, replies[i] if i < len(replies) else None
