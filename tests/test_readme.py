"""The README quotes output and lists options. These keep both equal to what the code and the examples say.

``python tests/test_readme.py --write`` refreshes the generated parts of README.md (the blocks between the
``<!-- include:... -->`` and ``<!-- options:start -->`` markers). The test fails when they are out of date.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nft_assert.cli import build_parser  # noqa: E402

README_PATH = ROOT / "README.md"
INCLUDE = re.compile(r"<!-- include:(?P<path>\S+) -->\n.*?<!-- /include -->", re.DOTALL)
OPTIONS = re.compile(r"<!-- options:start -->\n.*?<!-- options:end -->", re.DOTALL)
FENCES = {".toml": "toml", ".nft": "text", ".txt": "text", ".sh": "sh"}


def include_block(path: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8").rstrip("\n")
    suffix = Path(path).suffix
    body = text if suffix == ".md" else f"```{FENCES.get(suffix, 'text')}\n{text}\n```"
    return f"<!-- include:{path} -->\n{body}\n<!-- /include -->"


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return dict(action.choices)
    return {}


def _usage(action: argparse.Action) -> str:
    if not action.option_strings:
        return f"`{action.dest.upper()}`"
    names = ", ".join(action.option_strings)
    if action.choices:
        return f"`{names} {{{','.join(map(str, action.choices))}}}`"
    if action.nargs == 0:
        return f"`{names}`"
    return f"`{names} {action.metavar or action.dest.upper()}`"


def options_table() -> str:
    rows = ["| Command | Argument or option | What it does |", "|---|---|---|"]
    for name, sub in _subparsers(build_parser()).items():
        for action in sub._actions:  # noqa: SLF001
            if isinstance(action, argparse._HelpAction):  # noqa: SLF001
                continue
            rows.append(f"| `{name}` | {_usage(action)} | {action.help} |")
    return "\n".join(rows)


def options_block() -> str:
    return f"<!-- options:start -->\n{options_table()}\n<!-- options:end -->"


def sync(text: str) -> str:
    text = INCLUDE.sub(lambda m: include_block(m["path"]), text)
    return OPTIONS.sub(lambda _m: options_block(), text)


def test_every_generated_block_in_the_readme_is_current():
    readme = README_PATH.read_text(encoding="utf-8")
    assert INCLUDE.search(readme) and OPTIONS.search(readme), "the markers are missing"
    assert sync(readme) == readme, "run: python tests/test_readme.py --write"


def test_every_included_file_exists_and_is_used_at_least_once():
    readme = README_PATH.read_text(encoding="utf-8")
    paths = INCLUDE.findall(readme) and re.findall(r"<!-- include:(\S+) -->", readme)
    assert paths and all((ROOT / p).is_file() for p in paths)
    assert {"examples/edge/check-broken.txt", "examples/edge/matrix.md", "examples/edge/diff.txt"} <= set(
        paths
    )


def test_every_option_of_every_command_is_in_the_readme():
    readme = README_PATH.read_text(encoding="utf-8")
    subs = _subparsers(build_parser())
    assert set(subs) == {"check", "matrix", "diff", "cleanup"}
    for name, sub in subs.items():
        assert f"nft-assert {name}" in readme, f"the command {name} is never shown"
        for action in sub._actions:  # noqa: SLF001
            for opt in action.option_strings:
                if opt not in ("-h", "--help"):
                    assert f"`{opt}" in readme or f"`{', '.join(action.option_strings)}" in readme, opt


def test_every_option_the_readme_documents_exists():
    readme = README_PATH.read_text(encoding="utf-8")
    real = {o for sub in _subparsers(build_parser()).values() for a in sub._actions for o in a.option_strings}  # noqa: SLF001
    real |= {"--version", "-h", "--help"}
    documented = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", readme))
    assert documented <= real, sorted(documented - real)


def test_the_exit_codes_in_the_readme_are_the_ones_the_code_uses():
    from nft_assert import cli

    readme = README_PATH.read_text(encoding="utf-8")
    for code in (cli.OK, cli.FAILED, cli.BAD_INPUT, cli.LAB, 130):
        assert re.search(rf"^\| {code} \|", readme, re.MULTILINE), code


def test_the_spec_keys_in_the_reference_are_the_ones_the_parser_accepts():
    import inspect

    from nft_assert import spec

    source = inspect.getsource(spec)
    readme = README_PATH.read_text(encoding="utf-8")
    keys = set(
        re.findall(
            r"^\| `([a-z_]+)` \|",
            readme.split("## Spec reference", 1)[1].split("## Commands", 1)[0],
            re.MULTILINE,
        )
    )
    assert {
        "subnet",
        "iface",
        "fw_address",
        "host_address",
        "file",
        "flow",
        "reached",
        "reached_port",
        "source_seen",
        "tcp",
        "udp",
        "icmp",
        "timeout",
    } <= keys
    for k in keys:
        assert f'"{k}"' in source, f"documented but not parsed: {k}"


if __name__ == "__main__":
    if "--write" in sys.argv:
        README_PATH.write_text(sync(README_PATH.read_text(encoding="utf-8")), encoding="utf-8")
        print("README.md refreshed")
    else:
        print(options_table())
