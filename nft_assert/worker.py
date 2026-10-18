"""The programs that run *inside* a network namespace: listeners that answer, and probes that try to connect.

They are started with ``ip netns exec NAMESPACE python -m nft_assert.worker MODE``. They speak a line-based
protocol on standard input and output, so one process can try many flows at once.

``listen`` binds TCP and UDP ports and answers every connection or datagram with a banner naming the place
that answered, who it thought was calling and which address it was reached on. It prints ``READY`` once every
socket is bound and ends when standard input closes.

``probe`` reads one JSON request per line and prints one JSON answer per line. A flow is called

* ``accept``  when something answered (a TCP handshake finished, a datagram or an echo reply came back),
* ``reject``  when the firewall said no (TCP reset, ICMP unreachable, administratively prohibited), and
* ``drop``    when nothing came back before the timeout.

Listeners exist on every port that is probed, so a refusal can only come from the firewall, never from a
closed port.
"""

from __future__ import annotations

import errno
import json
import os
import selectors
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

BANNER_PREFIX = "NFTA "
PARALLEL = (
    200  # probes in flight at once in one namespace (each holds a socket, and the limit is usually 1024)
)
REJECT_ERRNOS = {
    errno.ECONNREFUSED,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.ENOPROTOOPT,
    errno.ECONNRESET,
    errno.EPROTO,
}


def banner(label: str, peer: str, local: str) -> bytes:
    return f"{BANNER_PREFIX}label={label} peer={peer} local={local}\n".encode()


def parse_banner(text: str) -> dict[str, str]:
    """``NFTA label=dmz peer=10.0.1.2 local=10.0.2.2:80`` as a dict (empty if it is not a banner)."""
    text = text.strip()
    if not text.startswith(BANNER_PREFIX):
        return {}
    fields = dict(part.split("=", 1) for part in text[len(BANNER_PREFIX) :].split() if "=" in part)
    return {k: v for k, v in fields.items() if k in ("label", "peer", "local")}


# ---- listening ----------------------------------------------------------------------------------------------


def listen(label: str, bind: list[str], tcp: list[int], udp: list[int]) -> int:
    sel = selectors.DefaultSelector()
    for port in tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(64)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, ("tcp", port))
    for address in bind:
        for port in udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((address, port))
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ, ("udp", port))
    sel.register(sys.stdin.fileno(), selectors.EVENT_READ, ("stdin", 0))
    print("READY", flush=True)
    while True:
        for key, _ in sel.select():
            kind, port = key.data
            sock = key.fileobj
            if kind == "stdin":
                if not os.read(sys.stdin.fileno(), 4096):
                    return 0
            elif kind == "tcp":
                try:
                    conn, peer = sock.accept()  # type: ignore[union-attr]
                except OSError:
                    continue
                with conn:
                    conn.settimeout(0.5)
                    try:
                        conn.sendall(banner(label, peer[0], f"{conn.getsockname()[0]}:{port}"))
                    except OSError:
                        pass
            else:
                try:
                    _, peer = sock.recvfrom(512)  # type: ignore[union-attr]
                    sock.sendto(banner(label, peer[0], f"{sock.getsockname()[0]}:{port}"), peer)  # type: ignore[union-attr]
                except OSError:
                    continue


# ---- probing ------------------------------------------------------------------------------------------------


def _answer(outcome: str, detail: str, banner_text: str = "") -> dict[str, Any]:
    return {"outcome": outcome, "detail": detail, "banner": parse_banner(banner_text)}


def tcp_probe(dst: str, port: int, timeout: float) -> dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((dst, port))
        except TimeoutError:
            return _answer("drop", f"no answer to the SYN in {timeout:g} s")
        except OSError as exc:
            if exc.errno in REJECT_ERRNOS:
                return _answer("reject", f"{os.strerror(exc.errno)}")
            return _answer("error", f"connect failed: {exc}")
        s.settimeout(min(timeout, 1.0))
        try:
            data = s.recv(300)
        except (TimeoutError, OSError):
            data = b""
        return _answer("accept", "connection established", data.decode("utf-8", "replace"))
    finally:
        s.close()


def udp_probe(dst: str, port: int, timeout: float) -> dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # Without this Linux reports only "hard" ICMP errors to a UDP socket: a port unreachable, but not
        # a host unreachable, so a firewall that rejects with the latter would look like it dropped.
        s.setsockopt(socket.SOL_IP, getattr(socket, "IP_RECVERR", 11), 1)
        s.connect((dst, port))
        s.send(b"nft-assert")
        data = s.recv(300)
        return _answer("accept", "a reply came back", data.decode("utf-8", "replace"))
    except TimeoutError:
        return _answer("drop", f"no reply in {timeout:g} s")
    except OSError as exc:
        if exc.errno in REJECT_ERRNOS:
            return _answer("reject", f"{os.strerror(exc.errno)}")
        return _answer("error", f"udp failed: {exc}")
    finally:
        s.close()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


_ident_lock = threading.Lock()
_ident = [os.getpid() & 0xFFFF]


def _next_ident() -> int:
    with _ident_lock:
        _ident[0] = (_ident[0] + 1) & 0xFFFF or 1
        return _ident[0]


def icmp_probe(dst: str, timeout: float) -> dict[str, Any]:
    ident, seq = _next_ident(), 1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return _answer("error", "a raw ICMP socket needs root (CAP_NET_RAW)")
    try:
        header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        payload = b"nft-assert"
        packet = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), ident, seq) + payload
        s.sendto(packet, (dst, 0))
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return _answer("drop", f"no echo reply or ICMP error in {timeout:g} s")
            s.settimeout(left)
            try:
                data, addr = s.recvfrom(2048)
            except TimeoutError:
                continue
            ihl = (data[0] & 0x0F) * 4
            icmp = data[ihl:]
            if len(icmp) < 8:
                continue
            kind, code = icmp[0], icmp[1]
            if kind == 0 and struct.unpack("!HH", icmp[4:8]) == (ident, seq):
                return _answer("accept", f"echo reply from {addr[0]}")
            if kind == 3 and len(icmp) >= 8 + 20 + 8:  # destination unreachable quoting our request
                inner = icmp[8:]
                inner_ihl = (inner[0] & 0x0F) * 4
                quoted = inner[inner_ihl : inner_ihl + 8]
                if len(quoted) == 8 and quoted[0] == 8 and struct.unpack("!HH", quoted[4:8]) == (ident, seq):
                    return _answer("reject", f"ICMP destination unreachable (code {code}) from {addr[0]}")
    finally:
        s.close()


def probe_one(req: dict[str, Any]) -> dict[str, Any]:
    proto, dst, timeout = req["proto"], req["dst"], float(req["timeout"])
    try:
        if proto == "tcp":
            return tcp_probe(dst, int(req["port"]), timeout)
        if proto == "udp":
            return udp_probe(dst, int(req["port"]), timeout)
        if proto == "icmp":
            return icmp_probe(dst, timeout)
        return _answer("error", f"unknown protocol {proto!r}")
    except Exception as exc:  # a bug here must be reported to the caller, not hang it
        return _answer("error", f"{type(exc).__name__}: {exc}")


def probe_loop(stdin=sys.stdin, stdout=sys.stdout) -> int:
    lock = threading.Lock()

    def work(req: dict[str, Any]) -> None:
        answer = probe_one(req)
        answer["id"] = req["id"]
        with lock:
            stdout.write(json.dumps(answer) + "\n")
            stdout.flush()

    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        for line in stdin:
            if not line.strip():
                continue
            try:
                req = json.loads(line)
                req["id"], req["proto"], req["dst"], req["timeout"]  # noqa: B018 (a missing key is a bad request)
            except (ValueError, KeyError, TypeError):
                continue
            pool.submit(work, req)
    return 0


def _ports(text: str) -> list[int]:
    return [int(p) for p in text.split(",") if p]


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m nft_assert.worker")
    sub = p.add_subparsers(dest="mode", required=True)
    lp = sub.add_parser("listen")
    lp.add_argument("--label", required=True)
    lp.add_argument("--bind", default="")
    lp.add_argument("--tcp", default="")
    lp.add_argument("--udp", default="")
    sub.add_parser("probe")
    args = p.parse_args(argv)
    if args.mode == "listen":
        return listen(args.label, [a for a in args.bind.split(",") if a], _ports(args.tcp), _ports(args.udp))
    return probe_loop()


if __name__ == "__main__":
    raise SystemExit(main())
