"""Running a spec: build the lab, load the ruleset, send the flows, compare what happened with what was expected."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import trace
from .lab import Lab, LabError, ProbeRequest
from .spec import FW, Expectation, Flow, Spec, destination_address

MAX_EXPLAINED = 20


class RulesetError(Exception):
    """nft refused the ruleset. The message is nft's own."""


@dataclass
class FlowResult:
    flow: Flow
    outcome: str  # accept, reject, drop or error
    detail: str
    banner: dict[str, str] = field(default_factory=dict)


@dataclass
class CheckResult:
    expectation: Expectation
    result: FlowResult
    problems: list[str]
    explanation: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass
class CheckRun:
    spec: Spec
    ruleset: Path
    checks: list[CheckResult]
    seconds: float
    sanity_checked: int = 0

    @property
    def failed(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.ok]


@dataclass
class Matrix:
    endpoints: list[str]
    probes: list[tuple[str, int | None]]
    cells: dict[tuple[str, str, tuple[str, int | None]], str]

    def outcome(self, src: str, dst: str, probe: tuple[str, int | None]) -> str | None:
        return self.cells.get((src, dst, probe))


@dataclass(frozen=True)
class Change:
    src: str
    dst: str
    probe: tuple[str, int | None]
    before: str
    after: str


def _label(probe: tuple[str, int | None]) -> str:
    return probe[0] if probe[1] is None else f"{probe[0]}/{probe[1]}"


# ---- sending flows ---------------------------------------------------------------------------------------------


def probe_flows(lab: Lab, spec: Spec, flows: list[Flow], timeout: float) -> list[FlowResult]:
    requests = [
        ProbeRequest(i, f.src, f.proto, destination_address(spec, f.src, f.dst), f.port)
        for i, f in enumerate(flows)
    ]
    answers = lab.send_probes(requests, timeout)
    return [
        FlowResult(f, answers[i]["outcome"], answers[i].get("detail", ""), answers[i].get("banner") or {})
        for i, f in enumerate(flows)
    ]


def _ports(flows: list[Flow], extra: set[tuple[str, int]] | None = None) -> set[tuple[str, int]]:
    ports = {(f.proto, f.port) for f in flows if f.port is not None}
    return ports | (extra or set())


def owned_addresses(spec: Spec) -> set[str]:
    out = set()
    for z in spec.zones.values():
        out |= {str(z.fw_ip), str(z.host_ip)}
    return out


def sanity(lab: Lab, spec: Spec, flows: list[Flow], timeout: float) -> int:
    """With no ruleset loaded every flow to an address in the lab must get through, or the lab is broken."""
    owned = owned_addresses(spec)
    seen: set[tuple[str, str, str, int | None]] = set()
    todo = []
    for f in flows:
        addr = destination_address(spec, f.src, f.dst)
        key = (f.src, addr, f.proto, f.port)
        if addr in owned and key not in seen:
            seen.add(key)
            todo.append(f)
    for r in probe_flows(lab, spec, todo, timeout):
        if r.outcome != "accept":
            raise LabError(
                f"the lab is broken, not your ruleset: {r.flow} got {r.outcome} ({r.detail}) with no ruleset loaded"
            )
    return len(todo)


# ---- checking --------------------------------------------------------------------------------------------------


def _problems(e: Expectation, r: FlowResult) -> list[str]:
    if r.outcome == "error":
        return [f"the probe failed: {r.detail}"]
    if r.outcome != e.verdict:
        return [f"expected {e.verdict}, got {r.outcome} ({r.detail})"]
    out = []
    if e.observe:
        o = e.observe
        if o.reached is not None and r.banner.get("label") != o.reached:
            out.append(
                f"expected {o.reached} to answer, got {r.banner.get('label') or 'nobody identifiable'}"
            )
        if o.reached_port is not None:
            got = r.banner.get("local", "").rpartition(":")[2]
            if got != str(o.reached_port):
                out.append(f"expected the answer on port {o.reached_port}, got {got or 'none'}")
        if o.source_seen is not None and r.banner.get("peer") != o.source_seen:
            out.append(
                f"expected the answering host to see source {o.source_seen}, it saw {r.banner.get('peer') or 'none'}"
            )
    return out


def check(
    spec: Spec,
    ruleset: Path | None = None,
    *,
    explain: bool = True,
    do_sanity: bool = True,
    timeout: float | None = None,
) -> CheckRun:
    timeout = timeout or spec.timeout
    path = ruleset or spec.ruleset
    if not path.is_file():
        raise RulesetError(f"cannot read the ruleset {path}")
    flows = [e.flow for e in spec.expectations]
    extra = {
        (e.flow.proto, e.observe.reached_port)
        for e in spec.expectations
        if e.observe and e.observe.reached_port
    }
    started = time.monotonic()
    with Lab(spec) as lab:
        lab.start_listeners(_ports(flows, extra))  # type: ignore[arg-type]
        checked = sanity(lab, spec, flows, timeout) if do_sanity else 0
        err = lab.load_ruleset(path)
        if err is not None:
            raise RulesetError(err)
        results = probe_flows(lab, spec, flows, timeout)
        checks = [CheckResult(e, r, _problems(e, r)) for e, r in zip(spec.expectations, results, strict=True)]
        if explain:
            bad = [c for c in checks if not c.ok and c.result.outcome != "error"][:MAX_EXPLAINED]
            if bad:
                why = explain_flows(lab, spec, [c.expectation.flow for c in bad], timeout)
                for c in bad:
                    c.explanation = why[c.expectation.flow]
    return CheckRun(spec, path, checks, time.monotonic() - started, checked)


def explain_flows(lab: Lab, spec: Spec, flows: list[Flow], timeout: float) -> dict[Flow, list[str]]:
    """Send the flows once more with tracing on and say, for each, which rule or policy decided it."""
    texts = trace.rule_texts(lab.nft("-a", "list", "ruleset").stdout)
    wanted = [
        (None if f.src == FW else str(spec.zones[f.src].host_ip), destination_address(spec, f.src, f.dst), f)
        for f in flows
    ]
    lab.nft("-f", "-", input=trace.trace_ruleset(wanted))
    mon = lab.popen(FW, ["nft", "monitor", "trace"])
    lines: list[str] = []

    def read() -> None:
        assert mon.stdout is not None
        for line in mon.stdout:
            lines.append(line)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        time.sleep(0.4)
        probe_flows(lab, spec, flows, min(timeout, 2.0))
        time.sleep(0.4)
    finally:
        mon.terminate()
        reader.join(2)
        lab.nft("delete", "table", "inet", trace.TRACE_TABLE, check=False)
    events, packets = trace.parse("".join(lines), texts)
    out = {}
    for src, dst, f in wanted:
        mine = trace.events_for(events, packets, src=src, dst=dst, flow=f)
        out[f] = trace.explain(mine)
    return out


# ---- the matrix and the diff -----------------------------------------------------------------------------------


def all_flows(spec: Spec) -> list[Flow]:
    return [
        Flow(s, d, proto, port)
        for s in spec.endpoints
        for d in spec.endpoints
        if s != d
        for proto, port in spec.matrix.probes
    ]


def _matrix_with(lab: Lab, spec: Spec, flows: list[Flow], timeout: float) -> Matrix:
    results = probe_flows(lab, spec, flows, timeout)
    cells = {(r.flow.src, r.flow.dst, (r.flow.proto, r.flow.port)): r.outcome for r in results}
    return Matrix(spec.endpoints, spec.matrix.probes, cells)


def matrix(spec: Spec, ruleset: Path | None = None, *, timeout: float | None = None) -> Matrix:
    timeout = timeout or spec.timeout
    path = ruleset or spec.ruleset
    flows = all_flows(spec)
    with Lab(spec) as lab:
        lab.start_listeners(_ports(flows))
        sanity(lab, spec, flows[:: max(1, len(flows) // 20)], timeout)
        err = lab.load_ruleset(path)
        if err is not None:
            raise RulesetError(err)
        return _matrix_with(lab, spec, flows, timeout)


def diff(
    spec: Spec, old: Path, new: Path, *, timeout: float | None = None
) -> tuple[Matrix, Matrix, list[Change]]:
    timeout = timeout or spec.timeout
    flows = all_flows(spec)
    with Lab(spec) as lab:
        lab.start_listeners(_ports(flows))
        sanity(lab, spec, flows[:: max(1, len(flows) // 20)], timeout)
        matrices = []
        for path in (old, new):
            lab.flush()
            err = lab.load_ruleset(path)
            if err is not None:
                raise RulesetError(f"{path}: {err}")
            matrices.append(_matrix_with(lab, spec, flows, timeout))
    a, b = matrices
    changes = [
        Change(s, d, p, a.cells[(s, d, p)], b.cells[(s, d, p)])
        for (s, d, p) in a.cells
        if a.cells[(s, d, p)] != b.cells[(s, d, p)]
    ]
    return a, b, changes


def matrix_as_dict(m: Matrix) -> dict[str, Any]:
    return {
        "endpoints": m.endpoints,
        "flows": [
            {"from": s, "to": d, "probe": _label(p), "outcome": o}
            for (s, d, p), o in sorted(m.cells.items(), key=lambda kv: (kv[0][0], kv[0][1], _label(kv[0][2])))
        ],
    }
