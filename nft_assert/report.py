"""Turning results into text, Markdown, JSON and JUnit."""

from __future__ import annotations

import json
import os
import re
from xml.sax.saxutils import escape, quoteattr

from .engine import Change, CheckResult, CheckRun, Matrix, _label, matrix_as_dict

_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def summary_line(run: CheckRun) -> str:
    n, bad = len(run.checks), len(run.failed)
    return f"{_plural(n, 'expectation')}, {n - bad} pass, {bad} fail"


def facts(c: CheckResult) -> str:
    """What the answering host reported, for a flow whose spec asked to look (an ``[[observe]]`` entry)."""
    b = c.result.banner
    if c.expectation.observe is None or not b:
        return ""
    return f"answered by {b.get('label', '?')} on port {b.get('local', '').rpartition(':')[2] or '?'}, which saw the source {b.get('peer', '?')}"


def render_text(run: CheckRun) -> str:
    spec = run.spec
    zones = ", ".join(spec.zones)
    out = [
        f"nft-assert  {spec.path.name}",
        f"ruleset     {run.ruleset.name}",
        f"lab         firewall + {_plural(len(spec.zones), 'zone')} ({zones})"
        + (
            f"; {run.sanity_checked} flows checked first with no ruleset: all got through"
            if run.sanity_checked
            else ""
        ),
        "",
    ]
    width = max((len(str(c.expectation.flow)) for c in run.checks), default=0)
    for c in run.checks:
        head = f"  {'PASS' if c.ok else 'FAIL'}  {str(c.expectation.flow):<{width}}  {c.expectation.verdict}"
        out.append(head)
        if facts(c):
            out.append(f"          {facts(c)}")
        for problem in c.problems:
            out.append(f"          {problem}")
        if c.explanation:
            out.append("          what the firewall did with the first packet:")
            out += [f"            {line}" for line in c.explanation]
    out.append("")
    out.append(summary_line(run))
    return "\n".join(out)


def render_markdown(run: CheckRun) -> str:
    out = [
        f"### nft-assert: {summary_line(run)}",
        "",
        f"`{run.spec.path.name}` against `{run.ruleset.name}`",
        "",
    ]
    out += ["| | Flow | Expected | Got | Observed |", "|---|---|---|---|---|"]
    for c in run.checks:
        out.append(
            f"| {'✅' if c.ok else '❌'} | `{c.expectation.flow}` | {c.expectation.verdict} | {c.result.outcome} | {facts(c)} |"
        )
    bad = run.failed
    if bad:
        out += ["", "#### Failures", ""]
        for c in bad:
            out.append(f"* `{c.expectation.flow}`: {'; '.join(c.problems)}")
            for line in c.explanation:
                out.append(f"  * {line}")
    return "\n".join(out) + "\n"


def render_json(run: CheckRun) -> str:
    return json.dumps(
        {
            "spec": str(run.spec.path),
            "ruleset": str(run.ruleset),
            "ok": not run.failed,
            "seconds": round(run.seconds, 2),
            "checks": [
                {
                    "flow": str(c.expectation.flow),
                    "expected": c.expectation.verdict,
                    "got": c.result.outcome,
                    "ok": c.ok,
                    "detail": c.result.detail,
                    "observed": facts(c) or None,
                    "problems": c.problems,
                    "trace": c.explanation,
                }
                for c in run.checks
            ],
        },
        indent=2,
    )


def _xml(text: str) -> str:
    return escape(_BAD_XML.sub("?", text))


def render_junit(run: CheckRun) -> str:
    n, bad = len(run.checks), len(run.failed)
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="nft-assert" tests="{n}" failures="{bad}" errors="0" time="{run.seconds:.3f}">',
    ]
    for c in run.checks:
        name = quoteattr(_BAD_XML.sub("?", f"{c.expectation.flow} {c.expectation.verdict}"))
        out.append(f"  <testcase classname={quoteattr(run.spec.path.name)} name={name}>")
        if not c.ok:
            msg = "; ".join(c.problems)
            body = "\n".join([*c.problems, *(f"packet path: {x}" for x in c.explanation)])
            out.append(f"    <failure message={quoteattr(_BAD_XML.sub('?', msg))}>{_xml(body)}</failure>")
        out.append("  </testcase>")
    out.append("</testsuite>")
    return "\n".join(out) + "\n"


def _property(text: str) -> str:
    """Escape a value in the property part of a GitHub workflow command (after ``file=`` and ``title=``)."""
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _message(text: str) -> str:
    """Escape the message part of a GitHub workflow command."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_github_annotations(run: CheckRun, spec_arg: str, workspace: str | None = None) -> str:
    """One ``::error`` workflow command per failed expectation, so GitHub shows it on the pull request.

    ``spec_arg`` is the spec path as the user gave it; GitHub wants it relative to the repository, so a path inside
    ``workspace`` (``$GITHUB_WORKSPACE``) is made relative. Nothing is returned when everything passed.
    """
    file = spec_arg
    if workspace and os.path.isabs(spec_arg):
        root = os.path.join(workspace, "")
        if spec_arg.startswith(root):
            file = spec_arg[len(root) :]
    lines = []
    for c in run.failed:
        title = f"nft-assert: {c.expectation.flow} should {c.expectation.verdict}"
        body = "\n".join([*c.problems, *(f"packet path: {x}" for x in c.explanation)])
        lines.append(f"::error file={_property(file)},title={_property(title)}::{_message(body)}")
    return "\n".join(lines)


# ---- matrix and diff ---------------------------------------------------------------------------------------


def render_matrix(m: Matrix) -> str:
    probes = m.probes
    out = [
        "| From | To | " + " | ".join(_label(p) for p in probes) + " |",
        "|---|---|" + "---|" * len(probes),
    ]
    for s in m.endpoints:
        for d in m.endpoints:
            if s != d:
                out.append(f"| {s} | {d} | " + " | ".join(m.cells.get((s, d, p), "?") for p in probes) + " |")
    return "\n".join(out) + "\n"


def render_matrix_json(m: Matrix) -> str:
    return json.dumps(matrix_as_dict(m), indent=2) + "\n"


def render_diff(changes: list[Change], total: int) -> str:
    if not changes:
        return f"no flow changed ({_plural(total, 'flow')} compared)"
    out = []
    for c in sorted(changes, key=lambda c: (c.src, c.dst, _label(c.probe))):
        out.append(f"{c.src} -> {c.dst} {_label(c.probe)}: {c.before} -> {c.after}")
    out.append("")
    out.append(f"{len(changes)} of {_plural(total, 'flow')} changed")
    return "\n".join(out)


def render_diff_markdown(changes: list[Change], total: int) -> str:
    if not changes:
        return f"### nft-assert diff\n\nNo flow changed ({_plural(total, 'flow')} compared).\n"
    out = [
        f"### nft-assert diff: {len(changes)} of {_plural(total, 'flow')} changed",
        "",
        "| Flow | Before | After |",
        "|---|---|---|",
    ]
    for c in sorted(changes, key=lambda c: (c.src, c.dst, _label(c.probe))):
        out.append(f"| `{c.src} -> {c.dst} {_label(c.probe)}` | {c.before} | **{c.after}** |")
    return "\n".join(out) + "\n"


def render_diff_json(changes: list[Change], total: int) -> str:
    return json.dumps(
        {
            "flows": total,
            "changed": [
                {"from": c.src, "to": c.dst, "probe": _label(c.probe), "before": c.before, "after": c.after}
                for c in sorted(changes, key=lambda c: (c.src, c.dst, _label(c.probe)))
            ],
        },
        indent=2,
    )
