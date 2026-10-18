"""The spec file: zones, the ruleset to load, and what must (and must not) get through.

A spec is TOML. Every table is checked, and a key this program does not know is an error, because a typo in
``[expect.drop]`` that is silently ignored would turn a test into a pass.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FW = "fw"
VERDICTS = ("accept", "drop", "reject")
PROTOS = ("tcp", "udp", "icmp")
ZONE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,14}")
IFACE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
MAX_ZONES = 8
MAX_FLOWS = 2000
MAX_SPEC_BYTES = 1 << 20
MAX_MATRIX = 5000  # flows one `matrix` or `diff` run sends
DEFAULT_TIMEOUT = 1.0


class SpecError(Exception):
    """The spec file is wrong. The message says where and what to change."""


@dataclass(frozen=True)
class Zone:
    name: str
    subnet: ipaddress.IPv4Network
    iface: str  # the firewall's interface towards this zone
    fw_ip: ipaddress.IPv4Address
    host_ip: ipaddress.IPv4Address


@dataclass(frozen=True)
class Flow:
    """One kind of traffic from one place to another. ``dst`` is a zone, ``fw`` or an IPv4 address."""

    src: str
    dst: str
    proto: str
    port: int | None  # None for icmp

    @property
    def probe(self) -> str:
        return self.proto if self.port is None else f"{self.proto}/{self.port}"

    def __str__(self) -> str:
        return f"{self.src} -> {self.dst} {self.probe}"


@dataclass(frozen=True)
class Observe:
    """Extra facts about an accepted flow: which host answered, on which port, and who it thought was calling."""

    flow: Flow
    reached: str | None = None
    reached_port: int | None = None
    source_seen: str | None = None


@dataclass(frozen=True)
class Expectation:
    flow: Flow
    verdict: str
    observe: Observe | None = None

    def __str__(self) -> str:
        return f"{self.flow} {self.verdict}"


@dataclass(frozen=True)
class MatrixSpec:
    tcp: tuple[int, ...] = (22, 80, 443)
    udp: tuple[int, ...] = (53,)
    icmp: bool = True

    @property
    def probes(self) -> list[tuple[str, int | None]]:
        return (
            [("tcp", p) for p in self.tcp]
            + [("udp", p) for p in self.udp]
            + ([("icmp", None)] if self.icmp else [])
        )


@dataclass
class Spec:
    path: Path
    ruleset: Path
    zones: dict[str, Zone]
    expectations: list[Expectation] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    matrix: MatrixSpec = field(default_factory=MatrixSpec)

    @property
    def endpoints(self) -> list[str]:
        return [FW, *self.zones]


def _table(value: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SpecError(f"{where} must be a table")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SpecError(f"{where}: unknown key {unknown[0]!r} (known: {', '.join(sorted(allowed))})")
    return value


def _ip(text: Any, where: str) -> ipaddress.IPv4Address:
    try:
        if not isinstance(text, str):  # IPv4Address(5) would be 0.0.0.5
            raise TypeError
        return ipaddress.IPv4Address(text)
    except (ValueError, TypeError):
        raise SpecError(f"{where}: {text!r} is not an IPv4 address") from None


def _zone(name: str, raw: Any, taken: list[Zone]) -> Zone:
    where = f"[zones.{name}]"
    if not ZONE_NAME.fullmatch(name):
        raise SpecError(
            f"{where}: a zone name is lower-case letters, digits, - and _, starting with a letter, at most 15 characters"
        )
    if name == FW:
        raise SpecError(f"{where}: 'fw' is the firewall itself and cannot be a zone name")
    t = _table(raw, where, {"subnet", "iface", "fw_address", "host_address"})
    if "subnet" not in t:
        raise SpecError(f'{where}: subnet is required, for example subnet = "10.0.1.0/24"')
    try:
        if not isinstance(t["subnet"], str):
            raise TypeError
        net = ipaddress.IPv4Network(t["subnet"], strict=True)
    except (ValueError, TypeError):
        raise SpecError(
            f"{where}: subnet {t['subnet']!r} is not an IPv4 network such as 10.0.1.0/24"
        ) from None
    if net.prefixlen > 29 or net.prefixlen < 8:
        raise SpecError(f"{where}: subnet {net} must be between /8 and /29")
    hosts = list(net.hosts()) if net.prefixlen >= 24 else None
    fw_ip = (
        _ip(t["fw_address"], f"{where} fw_address") if "fw_address" in t else (hosts[0] if hosts else net[1])
    )
    host_ip = (
        _ip(t["host_address"], f"{where} host_address")
        if "host_address" in t
        else (hosts[1] if hosts else net[2])
    )
    for what, ip in (("fw_address", fw_ip), ("host_address", host_ip)):
        if ip not in net or ip in (net.network_address, net.broadcast_address):
            raise SpecError(f"{where}: {what} {ip} is not a usable address of {net}")
    if fw_ip == host_ip:
        raise SpecError(f"{where}: fw_address and host_address are the same address")
    iface = t.get("iface", name)
    if not isinstance(iface, str) or not IFACE_NAME.fullmatch(iface):
        raise SpecError(
            f"{where}: iface {iface!r} is not an interface name (letters, digits, . _ -, at most 15)"
        )
    for other in taken:
        if other.subnet.overlaps(net):
            raise SpecError(f"{where}: subnet {net} overlaps zone {other.name} ({other.subnet})")
        if other.iface == iface:
            raise SpecError(f"{where}: iface {iface!r} is already used by zone {other.name}")
    return Zone(name, net, iface, fw_ip, host_ip)


def parse_probe(text: Any, where: str) -> tuple[str, int | None]:
    if not isinstance(text, str):
        raise SpecError(f'{where}: {text!r} must be a string such as "tcp/22", "udp/53" or "icmp"')
    proto, _, port = text.strip().lower().partition("/")
    if proto not in PROTOS:
        raise SpecError(f"{where}: {text!r}: the protocol must be one of {', '.join(PROTOS)}")
    if proto == "icmp":
        if port:
            raise SpecError(f"{where}: {text!r}: icmp has no port")
        return proto, None
    if not (port.isascii() and port.isdigit()) or not 1 <= int(port) <= 65535:
        raise SpecError(f"{where}: {text!r}: give a port from 1 to 65535, for example {proto}/22")
    return proto, int(port)


def _endpoint(text: str, zones: dict[str, Zone], where: str, *, allow_ip: bool) -> str:
    text = text.strip()
    if text == FW or text in zones:
        return text
    if allow_ip:
        try:
            return str(ipaddress.IPv4Address(text))
        except ValueError:
            pass
    known = ", ".join([FW, *zones])
    raise SpecError(
        f"{where}: {text!r} is not a known place (known: {known}{', or an IPv4 address' if allow_ip else ''})"
    )


def parse_flow_key(key: str, zones: dict[str, Zone], where: str) -> tuple[str, str]:
    left, arrow, right = key.partition("->")
    if not arrow:
        raise SpecError(f'{where}: {key!r} must look like "lan -> dmz"')
    src = _endpoint(left, zones, where, allow_ip=False)
    dst = _endpoint(right, zones, where, allow_ip=True)
    if src == dst:
        raise SpecError(f"{where}: {key!r} goes from a place to itself")
    return src, dst


def parse_flow(text: str, zones: dict[str, Zone], where: str) -> Flow:
    """``"wan -> 192.0.2.1 tcp/8080"``, as used by ``[[observe]]``."""
    m = re.fullmatch(r"\s*(\S+)\s*->\s*(\S+)\s+(\S+)\s*", text)
    if not m:
        raise SpecError(f'{where}: {text!r} must look like "wan -> 192.0.2.1 tcp/8080"')
    src, dst = parse_flow_key(f"{m.group(1)} -> {m.group(2)}", zones, where)
    proto, port = parse_probe(m.group(3), where)
    return Flow(src, dst, proto, port)


def load(path: str | Path) -> Spec:
    path = Path(path)
    try:
        if path.stat().st_size > MAX_SPEC_BYTES:
            raise SpecError(f"{path} is larger than {MAX_SPEC_BYTES // 1024} KiB")
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise SpecError(f"{path} is not UTF-8 text") from None
    except OSError as exc:
        raise SpecError(f"cannot read {path}: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"{path}: not valid TOML: {exc}") from None
    return parse(raw, path)


def parse(raw: dict[str, Any], path: Path) -> Spec:
    top = _table(raw, str(path), {"timeout", "ruleset", "zones", "expect", "observe", "matrix"})
    rs = _table(top.get("ruleset", {}), "[ruleset]", {"file"})
    if "file" not in rs or not isinstance(rs["file"], str):
        raise SpecError('[ruleset]: file is required, for example file = "firewall.nft"')
    ruleset = (path.parent / rs["file"]).resolve()

    zones_raw = _table(
        top.get("zones", {}),
        "[zones]",
        set(top.get("zones", {})) if isinstance(top.get("zones"), dict) else set(),
    )
    if not zones_raw:
        raise SpecError(
            '[zones]: define at least one zone, for example [zones.lan] with subnet = "10.0.1.0/24"'
        )
    if len(zones_raw) > MAX_ZONES:
        raise SpecError(f"[zones]: at most {MAX_ZONES} zones")
    zones: dict[str, Zone] = {}
    for name, z in zones_raw.items():
        zones[name] = _zone(name, z, list(zones.values()))

    timeout = top.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not 0.2 <= timeout <= 30:
        raise SpecError("timeout must be a number of seconds from 0.2 to 30")

    expectations: dict[Flow, Expectation] = {}
    expect = _table(top.get("expect", {}), "[expect]", set(VERDICTS))
    for verdict in VERDICTS:
        for key, probes in _table(
            expect.get(verdict, {}), f"[expect.{verdict}]", set(expect.get(verdict, {}))
        ).items():
            where = f"[expect.{verdict}] {key!r}"
            src, dst = parse_flow_key(key, zones, where)
            if not isinstance(probes, list) or not probes:
                raise SpecError(f'{where}: give a list such as ["tcp/22", "icmp"]')
            for p in probes:
                proto, port = parse_probe(p, where)
                flow = Flow(src, dst, proto, port)
                if flow in expectations:
                    other = expectations[flow].verdict
                    raise SpecError(
                        f"{flow} is listed under {other} and under {verdict}"
                        if other != verdict
                        else f"{flow} is listed twice under {verdict}"
                    )
                expectations[flow] = Expectation(flow, verdict)
    for i, o in enumerate(top.get("observe", []), start=1):
        where = f"[[observe]] #{i}"
        t = _table(o, where, {"flow", "reached", "reached_port", "source_seen"})
        if "flow" not in t or not isinstance(t["flow"], str):
            raise SpecError(f'{where}: flow is required, for example flow = "wan -> 192.0.2.1 tcp/8080"')
        flow = parse_flow(t["flow"], zones, where)
        e = expectations.get(flow)
        if e is None or e.verdict != "accept":
            raise SpecError(f"{where}: {flow} must also be listed under [expect.accept]")
        reached = t.get("reached")
        if reached is not None and (not isinstance(reached, str) or reached not in (FW, *zones)):
            raise SpecError(f"{where}: reached must be {FW} or a zone name")
        rp = t.get("reached_port")
        if rp is not None and (isinstance(rp, bool) or not isinstance(rp, int) or not 1 <= rp <= 65535):
            raise SpecError(f"{where}: reached_port must be a port number")
        if rp is not None and flow.proto == "icmp":
            raise SpecError(f"{where}: an icmp flow has no port")
        seen = t.get("source_seen")
        if seen is not None:
            seen = str(_ip(seen, f"{where} source_seen"))
        if reached is None and rp is None and seen is None:
            raise SpecError(f"{where}: say what to check: reached, reached_port or source_seen")
        if flow.proto == "icmp" and (reached is not None or seen is not None):
            raise SpecError(
                f"{where}: an icmp flow carries no banner, so reached and source_seen cannot be checked"
            )
        expectations[flow] = Expectation(flow, "accept", Observe(flow, reached, rp, seen))
    if len(expectations) > MAX_FLOWS:
        raise SpecError(f"too many expectations (at most {MAX_FLOWS})")

    m = _table(top.get("matrix", {}), "[matrix]", {"tcp", "udp", "icmp"})
    matrix = MatrixSpec(
        tcp=_ports(m.get("tcp", [22, 80, 443]), "[matrix] tcp"),
        udp=_ports(m.get("udp", [53]), "[matrix] udp"),
        icmp=_bool(m.get("icmp", True), "[matrix] icmp"),
    )
    spec = Spec(path, ruleset, zones, list(expectations.values()), float(timeout), matrix)
    n = len(spec.endpoints) * (len(spec.endpoints) - 1) * len(matrix.probes)
    if n > MAX_MATRIX:
        raise SpecError(
            f"[matrix]: {len(spec.endpoints)} places and {len(matrix.probes)} probes make {n} flows, at most {MAX_MATRIX}"
        )
    return spec


def _ports(value: Any, where: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not all(
        isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in value
    ):
        raise SpecError(f"{where} must be a list of ports from 1 to 65535")
    if len(set(value)) != len(value) or len(value) > 50:
        raise SpecError(f"{where}: no duplicates, at most 50 ports")
    return tuple(value)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise SpecError(f"{where} must be true or false")
    return value


def destination_address(spec: Spec, src: str, dst: str) -> str:
    """The address a probe from ``src`` sends to for the place ``dst``."""
    if dst == FW:
        if src == FW:
            raise SpecError("the firewall cannot probe itself")
        return str(spec.zones[src].fw_ip)
    if dst in spec.zones:
        return str(spec.zones[dst].host_ip)
    return dst
