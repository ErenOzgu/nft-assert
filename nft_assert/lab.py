"""The lab: one network namespace for the firewall, one per zone, joined by veth pairs.

::

    zone host  eth0 ---- <iface> [ firewall: your ruleset is loaded here ] <iface> ---- eth0  zone host

Everything is created with ``ip`` and ``nft`` and removed again, including when a run fails or is
interrupted. Every name starts with ``nfta<pid>-`` so ``nft-assert cleanup`` can find what a killed run left.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .spec import FW, Spec
from .worker import PARALLEL

PREFIX = "nfta"
MAX_RULESET_BYTES = 4 << 20
# (file under /proc/sys, value, required). Written with sh, so the sysctl program is not needed. ICMP errors
# must not be rate limited, or the second of two rejected flows would look like a drop.
SYSCTLS = (
    ("net/ipv4/icmp_ratelimit", "0", True),
    ("net/ipv4/icmp_msgs_per_sec", "1000000", False),  # a limit on all ICMP errors at once (50 in a burst)
    ("net/ipv4/icmp_msgs_burst", "1000000", False),
    ("net/ipv4/conf/all/rp_filter", "0", False),
    ("net/ipv6/conf/all/disable_ipv6", "1", False),  # ipv6 may be absent from the kernel: that is fine
)


class LabError(Exception):
    """The lab could not be built or run (not root, a tool is missing, the kernel said no)."""


@dataclass(frozen=True)
class ProbeRequest:
    id: int
    src: str  # endpoint the probe is sent from
    proto: str
    dst: str  # an IPv4 address
    port: int | None


def run(
    argv: list[str], *, input: str | None = None, timeout: float = 30, check: bool = True
) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise LabError(
            f"{argv[0]} is not installed (needed: ip from iproute2, and nft from nftables)"
        ) from None
    except subprocess.TimeoutExpired:
        raise LabError(f"{' '.join(argv[:4])} did not finish in {timeout:g} s") from None
    if check and r.returncode != 0:
        raise LabError(f"{' '.join(argv)} failed: {(r.stderr or r.stdout).strip() or 'no message'}")
    return r


def check_environment() -> None:
    if not sys.platform.startswith("linux"):
        raise LabError("nft-assert needs Linux (network namespaces and nftables)")
    if os.geteuid() != 0:
        raise LabError("nft-assert creates network namespaces and needs root: run it with sudo")
    for tool in ("ip", "nft"):
        run([tool, "--version"], check=False)


def list_namespaces() -> list[str]:
    out = run(["ip", "netns", "list"], check=False).stdout
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def delete_namespace(name: str) -> None:
    pids = run(["ip", "netns", "pids", name], check=False).stdout.split()
    for pid in pids:
        try:
            os.kill(int(pid), 9)
        except (ProcessLookupError, ValueError, PermissionError):
            pass
    run(["ip", "netns", "del", name], check=False)


def cleanup_leftovers() -> list[str]:
    """Delete every namespace this tool made and did not remove. Returns their names."""
    gone = [n for n in list_namespaces() if n.startswith(PREFIX)]
    for name in gone:
        delete_namespace(name)
    return gone


def _blame(r: subprocess.CompletedProcess, path: Path) -> str:
    """nft's complaint, with the file it read from standard input named properly."""
    return (r.stderr or r.stdout).strip().replace(
        "/dev/stdin", str(path)
    ) or "nft refused the ruleset without a message"


class ProbeWorker:
    """One ``python -m nft_assert.worker probe`` process inside a namespace."""

    def __init__(self, lab: Lab, endpoint: str) -> None:
        self.proc = lab.popen(endpoint, ["-m", "nft_assert.worker", "probe"], python=True)
        self.answers: dict[int, dict[str, Any]] = {}
        self.cond = threading.Condition()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                answer = json.loads(line)
            except ValueError:
                continue
            with self.cond:
                self.answers[answer["id"]] = answer
                self.cond.notify_all()

    def send(self, ident: int, req: ProbeRequest, timeout: float) -> None:
        assert self.proc.stdin is not None
        msg = {"id": ident, "proto": req.proto, "dst": req.dst, "port": req.port, "timeout": timeout}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            self.proc.kill()


class Lab:
    def __init__(self, spec: Spec, prefix: str | None = None) -> None:
        self.spec = spec
        self.prefix = prefix or f"{PREFIX}{os.getpid()}-"
        self.ns = {FW: f"{self.prefix}fw", **{z: f"{self.prefix}z-{z}" for z in spec.zones}}
        self._procs: list[subprocess.Popen] = []
        self._workers: dict[str, ProbeWorker] = {}
        self._built = False
        self._seq = (
            0  # probe ids are unique for the life of the lab, so a late answer cannot be taken for a new one
        )

    # ---- building and tearing down --------------------------------------------------------------------

    def __enter__(self) -> Lab:
        check_environment()
        try:
            self._build()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _ip(self, *args: str) -> None:
        run(["ip", *args])

    @staticmethod
    def _sysctl(ns: str, path: str, value: str, required: bool) -> None:
        if not (
            re.fullmatch(r"[a-z0-9_/]+", path) and re.fullmatch(r"[0-9]+", value)
        ):  # it goes into `sh -c`
            raise ValueError(f"not a sysctl path and value: {path!r} {value!r}")
        r = run(["ip", "netns", "exec", ns, "sh", "-c", f"echo {value} > /proc/sys/{path}"], check=False)
        if required and r.returncode != 0:
            raise LabError(
                f"cannot set /proc/sys/{path} in a namespace: {(r.stderr or '').strip() or 'refused'}"
            )

    def _build(self) -> None:
        self._built = True
        for name in self.ns.values():
            self._ip("netns", "add", name)
        for name in self.ns.values():
            self._ip("-n", name, "link", "set", "lo", "up")
            for path, value, required in SYSCTLS:
                self._sysctl(name, path, value, required)
        self._sysctl(self.ns[FW], "net/ipv4/ip_forward", "1", True)
        fw = self.ns[FW]
        for zone in self.spec.zones.values():
            host = self.ns[zone.name]
            self._ip(
                "-n", fw, "link", "add", zone.iface, "type", "veth", "peer", "name", "eth0", "netns", host
            )
            self._ip("-n", fw, "link", "set", zone.iface, "up")
            self._ip("-n", host, "link", "set", "eth0", "up")
            self._ip("-n", fw, "addr", "add", f"{zone.fw_ip}/{zone.subnet.prefixlen}", "dev", zone.iface)
            self._ip("-n", host, "addr", "add", f"{zone.host_ip}/{zone.subnet.prefixlen}", "dev", "eth0")
            self._ip("-n", host, "route", "add", "default", "via", str(zone.fw_ip))

    def rate_limited(self) -> int:
        """How many ICMP errors the kernel has held back since the lab was built (0 where it does not say)."""
        total = 0
        for name in self.ns.values():
            text = run(["ip", "netns", "exec", name, "cat", "/proc/net/snmp"], check=False).stdout
            rows = [line.split() for line in text.splitlines() if line.startswith("Icmp:")]
            if len(rows) == 2:
                counters = dict(zip(rows[0][1:], rows[1][1:], strict=False))
                total += sum(
                    int(counters.get(k, "0"))
                    for k in ("OutRateLimitGlobal", "OutRateLimitHost")
                    if counters.get(k, "0").isdigit()
                )
        return total

    def close(self) -> None:
        for w in self._workers.values():
            w.close()
        self._workers.clear()
        for p in self._procs:
            try:
                if p.stdin:
                    p.stdin.close()
            except OSError:
                pass
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._procs.clear()
        if self._built:
            for name in self.ns.values():
                delete_namespace(name)
            self._built = False

    # ---- running things inside ------------------------------------------------------------------------

    def popen(
        self, endpoint: str, argv: list[str], *, python: bool = False, stderr: int | None = subprocess.PIPE
    ) -> subprocess.Popen:
        env = dict(os.environ)
        here = str(Path(__file__).resolve().parent.parent)
        env["PYTHONPATH"] = here + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        cmd = ["ip", "netns", "exec", self.ns[endpoint], *([sys.executable] if python else []), *argv]
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1, env=env
        )
        self._procs.append(p)
        return p

    def nft(self, *args: str, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
        return run(["ip", "netns", "exec", self.ns[FW], "nft", *args], input=input, check=check)

    def start_listeners(self, probes: set[tuple[str, int]]) -> None:
        """Every namespace listens on every probed port, so a refusal can only come from the firewall."""
        tcp = sorted(p for k, p in probes if k == "tcp")
        udp = sorted(p for k, p in probes if k == "udp")
        started = []
        for endpoint in self.ns:
            bind = self._addresses(endpoint)
            proc = self.popen(
                endpoint,
                [
                    "-m",
                    "nft_assert.worker",
                    "listen",
                    "--label",
                    endpoint,
                    "--bind",
                    ",".join(bind),
                    "--tcp",
                    ",".join(map(str, tcp)),
                    "--udp",
                    ",".join(map(str, udp)),
                ],
                python=True,
            )
            started.append((endpoint, proc))
        for endpoint, proc in started:
            assert proc.stdout is not None
            line = proc.stdout.readline().strip()
            if line != "READY":
                err = proc.stderr.read() if proc.stderr else ""
                raise LabError(f"the listener in {endpoint} did not start: {(err or line).strip()[-300:]}")

    def _addresses(self, endpoint: str) -> list[str]:
        if endpoint == FW:
            return [str(z.fw_ip) for z in self.spec.zones.values()]
        return [str(self.spec.zones[endpoint].host_ip)]

    def load_ruleset(self, path: Path) -> str | None:
        """Load a ruleset into the firewall. Returns nft's complaint, or ``None`` when it loaded."""
        if path.stat().st_size > MAX_RULESET_BYTES:
            raise LabError(f"{path} is larger than {MAX_RULESET_BYTES >> 20} MiB")
        text = path.read_text(encoding="utf-8", errors="replace")
        here = str(path.parent)  # so that `include "common.nft"` finds files next to the ruleset
        r = self.nft("-I", here, "-c", "-f", "-", input=text, check=False)
        if r.returncode != 0:
            return _blame(r, path)
        r = self.nft("-I", here, "-f", "-", input=text, check=False)
        return None if r.returncode == 0 else _blame(r, path)

    def flush(self) -> None:
        self.nft("flush", "ruleset")

    def send_probes(self, requests: list[ProbeRequest], timeout: float) -> dict[int, dict[str, Any]]:
        """Send the probes and wait for every answer. Keys of the result are the ``id`` of each request."""
        by_src: dict[str, list[tuple[int, ProbeRequest]]] = {}
        for r in requests:
            by_src.setdefault(r.src, []).append((self._seq, r))
            self._seq += 1
        for src, reqs in by_src.items():
            worker = self._workers.get(src)
            if worker is None or worker.proc.poll() is not None:
                worker = self._workers[src] = ProbeWorker(self, src)
            for unique, r in reqs:
                worker.send(unique, r, timeout)
        rounds = -(
            -max((len(r) for r in by_src.values()), default=1) // PARALLEL
        )  # probes queue behind PARALLEL at a time
        deadline = time.monotonic() + rounds * (timeout + min(timeout, 1.0) + 0.5) + 8
        held_before = self.rate_limited()
        out: dict[int, dict[str, Any]] = {}
        for src, reqs in by_src.items():
            worker = self._workers[src]
            for unique, r in reqs:
                with worker.cond:
                    while unique not in worker.answers:
                        left = deadline - time.monotonic()
                        if left <= 0 or worker.proc.poll() is not None:
                            break
                        worker.cond.wait(min(left, 0.5))
                    out[r.id] = worker.answers.get(
                        unique,
                        {"outcome": "error", "detail": "the probe process gave no answer", "banner": {}},
                    )
        held = self.rate_limited() - held_before
        if held > 0:  # a reject whose ICMP error was held back is indistinguishable from a drop: do not guess
            raise LabError(
                f"the kernel held back {held} ICMP error(s) because of its rate limits, so a rejected flow could be "
                "reported as dropped. Lower the number of flows, or raise net.ipv4.icmp_msgs_per_sec and "
                "icmp_msgs_burst inside the namespaces (this kernel would not let nft-assert do it)"
            )
        return out
