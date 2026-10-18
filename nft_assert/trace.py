"""Finding out *which rule* decided a flow, with nftables' own packet tracing.

For a failed expectation the flow is sent once more with ``meta nftrace set 1`` switched on for exactly that
traffic, and ``nft monitor trace`` is read. Tracing is only used to explain a failure; whether a flow is
accepted, rejected or dropped is always decided by the packets that really arrived or did not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .spec import Flow

TRACE_TABLE = "nfta_trace"
_EVENT = re.compile(
    r"^trace id (?P<id>[0-9a-f]+) (?P<family>\S+) (?P<table>\S+) (?P<chain>\S+) (?P<rest>.*)$"
)
_SRC = re.compile(r"\bip saddr (\S+) ip daddr (\S+)")
_L4 = re.compile(r"\b(tcp|udp) dport (\d+)")
_ICMP = re.compile(r"\bip protocol icmp\b")
_RULE = re.compile(r"^rule (?P<text>.*) \(verdict (?P<verdict>[^)]*)\)\s*$")
_UNKNOWN = re.compile(r"^unknown rule handle (?P<handle>\d+) \(verdict (?P<verdict>[^)]*)\)\s*$")
_POLICY = re.compile(r"^policy (?P<verdict>\S+)\s*$")
_REJECT = re.compile(r"\breject\b")
_HANDLE = re.compile(r"\s*# handle (\d+)\s*$")
_TABLE = re.compile(r"^table (\S+) (\S+) \{")
_CHAIN = re.compile(r"^\s+chain (\S+) \{")


@dataclass(frozen=True)
class Packet:
    """The header of a traced packet, as printed on its first line."""

    trace_id: str
    src: str
    dst: str
    proto: str
    port: int | None


@dataclass(frozen=True)
class Event:
    trace_id: str
    family: str
    table: str
    chain: str
    kind: str  # "rule" or "policy"
    text: str  # the rule as nft prints it; empty for a policy
    verdict: str
    handle: int | None = None

    @property
    def where(self) -> str:
        return f"{self.family} {self.table} {self.chain}"


def trace_ruleset(flows: list[tuple[str | None, str, Flow]]) -> str:
    """A table that switches tracing on for the given flows, before anything else sees the packets.

    Each flow is ``(source address or None when the firewall itself sends it, destination address, flow)``.
    """
    pre, out = [], []
    for src_ip, dst_ip, flow in flows:
        match = f"ip daddr {dst_ip}"
        if flow.proto in ("tcp", "udp"):
            match += f" {flow.proto} dport {flow.port}"
        else:
            match += " icmp type echo-request"
        if src_ip:
            pre.append(f"ip saddr {src_ip} {match} meta nftrace set 1")
        else:
            out.append(f"{match} meta nftrace set 1")
    chains = ""
    for name, hook, rules in (("pre", "prerouting", pre), ("out", "output", out)):
        if rules:
            body = "\n".join(f"    {r}" for r in rules)
            chains += f"  chain {name} {{\n    type filter hook {hook} priority -350; policy accept;\n{body}\n  }}\n"
    return f"table inet {TRACE_TABLE} {{\n{chains}}}\n"


def rule_texts(listing: str) -> dict[tuple[str, str, int], str]:
    """``nft -a list ruleset`` as {(table, chain, handle): rule text}, to name rules the monitor only numbers."""
    out: dict[tuple[str, str, int], str] = {}
    table = chain = ""
    for line in listing.splitlines():
        if m := _TABLE.match(line):
            table, chain = m.group(2), ""
        elif m := _CHAIN.match(line):
            chain = m.group(1)
        elif chain and (h := _HANDLE.search(line)) and not line.strip().startswith(("type ", "policy ")):
            text = _HANDLE.sub("", line).strip()
            if text and text != "}":
                out[(table, chain, int(h.group(1)))] = text
    return out


def parse(
    output: str, texts: dict[tuple[str, str, int], str] | None = None
) -> tuple[list[Event], dict[str, Packet]]:
    """The rule and policy events of ``nft monitor trace`` output, in order, and the first packet line of each trace."""
    texts = texts or {}
    events: list[Event] = []
    packets: dict[str, Packet] = {}
    entered: dict[str, set[tuple[str, str, str]]] = {}  # the chains each trace id has been seen entering
    later: set[str] = set()  # ids that came round again: a second packet of the same connection reused the id
    for line in output.splitlines():
        m = _EVENT.match(line.strip())
        if not m:
            continue
        rest = m.group("rest")
        if m["id"] in later:
            continue
        if rest.startswith("packet:"):
            here = (m["family"], m["table"], m["chain"])
            if here in entered.setdefault(m["id"], set()):
                later.add(m["id"])
                continue
            entered[m["id"]].add(here)
            if m["id"] not in packets and (a := _SRC.search(rest)):
                l4 = _L4.search(rest)
                proto, port = (
                    (l4.group(1), int(l4.group(2)))
                    if l4
                    else ("icmp" if _ICMP.search(rest) else "other", None)
                )
                packets[m["id"]] = Packet(m["id"], a.group(1), a.group(2), proto, port)
        elif (r := _RULE.match(rest)) is not None:
            last = events[-1] if events else None
            if (
                last is not None
                and last.handle is not None
                and (last.trace_id, last.table, last.chain, last.verdict)
                == (m["id"], m["table"], m["chain"], r["verdict"])
            ):
                events.pop()  # the monitor reported this rule once by number and once by text
            events.append(
                Event(m["id"], m["family"], m["table"], m["chain"], "rule", r["text"], r["verdict"])
            )
        elif (u := _UNKNOWN.match(rest)) is not None:
            handle = int(u["handle"])
            text = texts.get((m["table"], m["chain"], handle), f"(rule with handle {handle})")
            events.append(
                Event(m["id"], m["family"], m["table"], m["chain"], "rule", text, u["verdict"], handle)
            )
        elif (p := _POLICY.match(rest)) is not None:
            events.append(Event(m["id"], m["family"], m["table"], m["chain"], "policy", "", p["verdict"]))
    return events, packets


def events_for(
    events: list[Event], packets: dict[str, Packet], *, src: str | None, dst: str, flow: Flow
) -> list[Event]:
    """The events of the first traced packet that belongs to this flow (``src`` is None for the firewall's own traffic)."""
    for trace_id, p in packets.items():
        if p.dst == dst and p.proto == flow.proto and p.port == flow.port and (src is None or p.src == src):
            return [e for e in events if e.trace_id == trace_id]
    return []


def explain(events: list[Event]) -> list[str]:
    """What the firewall did with one traced packet, as short lines for a person."""
    mine = [e for e in events if e.table != TRACE_TABLE]
    if not mine:
        return [
            "the packet never reached the firewall's netfilter hooks (check the zone's iface name and subnet)"
        ]
    lines = []
    for e in mine:
        if e.kind == "policy":
            lines.append(f"{e.where}: no rule matched, the chain policy is {e.verdict}")
        elif e.verdict in ("accept", "drop") or e.verdict.startswith(("jump", "goto", "return")):
            # nft reports the verdict of a reject statement as "drop"; the rule text says what it really is
            verdict = "reject" if e.verdict == "drop" and _REJECT.search(e.text) else e.verdict
            lines.append(f"{e.where}: rule `{e.text}` -> {verdict}")
    return lines or ["the packet matched no rule that decides anything"]
