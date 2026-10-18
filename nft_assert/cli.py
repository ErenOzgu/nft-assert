"""nft-assert check SPEC | matrix SPEC | diff SPEC OLD NEW | cleanup

Exit codes: 0 everything as expected, 1 an expectation failed (or the matrix or the diff differs),
2 the spec or the ruleset is wrong, 3 the lab could not run (not root, a tool is missing, a broken lab).
"""

from __future__ import annotations

import argparse
import difflib
import os
import signal
import sys
from pathlib import Path

from . import __version__, engine, report
from . import spec as spec_mod
from .lab import LabError, cleanup_leftovers

OK, FAILED, BAD_INPUT, LAB = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nft-assert",
        description="Load an nftables ruleset into a lab of real network namespaces, send real packets, and check what got through.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("spec", help="the spec file (TOML)")
        sp.add_argument(
            "--timeout",
            type=float,
            metavar="SECONDS",
            help="how long a silent flow is waited for before it counts as dropped (default: the spec's, else 1)",
        )

    c = sub.add_parser("check", help="check the expectations in the spec")
    common(c)
    c.add_argument("--ruleset", metavar="FILE", help="load this ruleset instead of the one named in the spec")
    c.add_argument(
        "-f",
        "--format",
        choices=["text", "md", "json"],
        default="text",
        help="how to print the result (default text)",
    )
    c.add_argument("--junit", metavar="FILE", help="also write a JUnit XML report")
    c.add_argument(
        "--github-summary", action="store_true", help="append a Markdown report to $GITHUB_STEP_SUMMARY"
    )
    c.add_argument(
        "--no-explain",
        action="store_true",
        help="do not re-send failed flows with tracing to find the deciding rule",
    )
    c.add_argument(
        "--no-sanity",
        action="store_true",
        help="skip the first pass that sends every flow with no ruleset loaded",
    )

    m = sub.add_parser(
        "matrix", help="send every kind of traffic between every pair of places and print who can reach whom"
    )
    common(m)
    m.add_argument("--ruleset", metavar="FILE", help="load this ruleset instead of the one named in the spec")
    m.add_argument(
        "-f", "--format", choices=["md", "json"], default="md", help="how to print the matrix (default md)"
    )
    m.add_argument(
        "-o", "--output", metavar="FILE", help="write the matrix to this file instead of printing it"
    )
    m.add_argument(
        "--check",
        metavar="FILE",
        help="compare with a committed matrix and exit 1 with the differences if it changed",
    )

    d = sub.add_parser("diff", help="show which flows a change to the ruleset opens or closes")
    common(d)
    d.add_argument("old", help="the ruleset before")
    d.add_argument("new", help="the ruleset after")
    d.add_argument(
        "-f",
        "--format",
        choices=["text", "md", "json"],
        default="text",
        help="how to print the changes (default text)",
    )

    sub.add_parser("cleanup", help="delete namespaces left behind by a run that was killed")
    return p


def _load(path: str, timeout: float | None) -> spec_mod.Spec:
    s = spec_mod.load(path)
    if timeout is not None:
        if not 0.2 <= timeout <= 30:
            raise spec_mod.SpecError("--timeout must be from 0.2 to 30 seconds")
        s.timeout = timeout
    return s


def _term(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt  # so the lab is torn down on the way out


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    signal.signal(signal.SIGTERM, _term)
    try:
        if args.command == "cleanup":
            gone = cleanup_leftovers()
            print(f"removed {len(gone)} leftover namespace(s)" + (": " + ", ".join(gone) if gone else ""))
            return OK
        s = _load(args.spec, args.timeout)
        if args.command == "check":
            return _check(args, s)
        if args.command == "matrix":
            return _matrix(args, s)
        return _diff(args, s)
    except spec_mod.SpecError as exc:
        print(f"nft-assert: {exc}", file=sys.stderr)
        return BAD_INPUT
    except engine.RulesetError as exc:
        print(f"nft-assert: nft refused the ruleset:\n{exc}", file=sys.stderr)
        return BAD_INPUT
    except LabError as exc:
        print(f"nft-assert: {exc}", file=sys.stderr)
        return LAB
    except KeyboardInterrupt:
        print("nft-assert: interrupted, lab removed", file=sys.stderr)
        return 130


def _check(args: argparse.Namespace, s: spec_mod.Spec) -> int:
    run = engine.check(
        s,
        Path(args.ruleset).resolve() if args.ruleset else None,
        explain=not args.no_explain,
        do_sanity=not args.no_sanity,
    )
    shown = {"text": report.render_text, "md": report.render_markdown, "json": report.render_json}[
        args.format
    ](run)
    print(shown.rstrip("\n"))
    if args.junit:
        Path(args.junit).write_text(report.render_junit(run), encoding="utf-8")
    if args.github_summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(report.render_markdown(run) + "\n")
    return FAILED if run.failed else OK


def _matrix(args: argparse.Namespace, s: spec_mod.Spec) -> int:
    m = engine.matrix(s, Path(args.ruleset).resolve() if args.ruleset else None)
    text = report.render_matrix(m) if args.format == "md" else report.render_matrix_json(m)
    if args.check:
        committed = Path(args.check).read_text(encoding="utf-8")
        if committed == text:
            print(f"{args.check} is up to date")
            return OK
        sys.stdout.writelines(
            difflib.unified_diff(
                committed.splitlines(keepends=True), text.splitlines(keepends=True), args.check, "now"
            )
        )
        print(f"\nnft-assert: who can reach whom no longer matches {args.check}", file=sys.stderr)
        return FAILED
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text.rstrip("\n"))
    return OK


def _diff(args: argparse.Namespace, s: spec_mod.Spec) -> int:
    _, _, changes = engine.diff(s, Path(args.old).resolve(), Path(args.new).resolve())
    total = len(engine.all_flows(s))
    render = {"text": report.render_diff, "md": report.render_diff_markdown, "json": report.render_diff_json}[
        args.format
    ]
    print(render(changes, total).rstrip("\n"))
    return FAILED if changes else OK
