"""Results built by hand, so the reports can be tested without a lab."""

from __future__ import annotations

from pathlib import Path

from nft_assert import engine
from nft_assert.spec import Expectation, Flow, Observe, Spec, load

EDGE = Path(__file__).resolve().parent.parent / "examples" / "edge" / "spec.toml"


def edge_spec() -> Spec:
    return load(EDGE)


def result(flow: Flow, outcome: str, detail: str = "", banner: dict | None = None) -> engine.FlowResult:
    return engine.FlowResult(flow, outcome, detail, banner or {})


def fake_run(spec: Spec | None = None) -> engine.CheckRun:
    """Three checks: one passes, one fails with a trace, one passes with an observation."""
    spec = spec or edge_spec()
    ok = Flow("lan", "wan", "tcp", 80)
    bad = Flow("wan", "fw", "tcp", 22)
    seen = Flow("wan", "192.0.2.1", "tcp", 8080)
    checks = [
        engine.CheckResult(Expectation(ok, "accept"), result(ok, "accept", "connection established"), []),
        engine.CheckResult(
            Expectation(bad, "drop"),
            result(bad, "accept", "connection established"),
            ["expected drop, got accept (connection established)"],
            ['inet filter input: rule `iifname "eth0" tcp dport 22 accept` -> accept'],
        ),
        engine.CheckResult(
            Expectation(seen, "accept", Observe(seen, "dmz", 80, "192.0.2.2")),
            result(
                seen,
                "accept",
                "connection established",
                {"label": "dmz", "peer": "192.0.2.2", "local": "10.0.2.2:80"},
            ),
            [],
        ),
    ]
    return engine.CheckRun(spec, spec.ruleset, checks, 1.234, 5)


def fake_matrix() -> engine.Matrix:
    probes = [("tcp", 22), ("udp", 53), ("icmp", None)]
    cells = {}
    for s in ("fw", "a"):
        for d in ("fw", "a"):
            if s != d:
                for p in probes:
                    cells[(s, d, p)] = "accept" if p[0] == "tcp" else "drop"
    return engine.Matrix(["fw", "a"], probes, cells)
