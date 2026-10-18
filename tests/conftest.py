"""Shared helpers. Tests that build a real lab are skipped unless this machine can: root, ip, nft, namespaces."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _can_build_lab() -> str | None:
    """None when a lab can be built here, else why not."""
    if not sys.platform.startswith("linux"):
        return "not Linux"
    if os.geteuid() != 0:
        return "not root"
    if not (shutil.which("ip") and shutil.which("nft")):
        return "ip or nft is not installed"
    name = f"nftatest{os.getpid()}"
    r = subprocess.run(["ip", "netns", "add", name], capture_output=True, text=True)
    if r.returncode != 0:
        return f"cannot create a network namespace: {r.stderr.strip()}"
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", name, "nft", "add", "table", "inet", "t"], capture_output=True, text=True
        )
        if r.returncode != 0:
            return f"nft does not work in a namespace here: {r.stderr.strip()}"
    finally:
        subprocess.run(["ip", "netns", "del", name], capture_output=True)
    return None


WHY_NOT = _can_build_lab()
if WHY_NOT and os.environ.get("NFT_ASSERT_REQUIRE_LAB") == "1":
    raise RuntimeError(f"NFT_ASSERT_REQUIRE_LAB=1, but no lab can be built here: {WHY_NOT}")

live = pytest.mark.live


def pytest_collection_modifyitems(config, items):
    if WHY_NOT is None:
        return
    skip = pytest.mark.skip(reason=f"no lab here: {WHY_NOT}")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)


def leftover_namespaces() -> list[str]:
    out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    return [line.split()[0] for line in out.splitlines() if line.startswith("nfta")]


@pytest.fixture(autouse=True)
def no_namespace_left_behind(request):
    """Every live test must leave the machine as it found it."""
    if WHY_NOT is not None or request.node.get_closest_marker("live") is None:
        yield
        return
    before = set(leftover_namespaces())
    yield
    after = set(leftover_namespaces()) - before
    assert not after, f"the test left network namespaces behind: {sorted(after)}"


TWO_ZONES = """\
[ruleset]
file = "fw.nft"

[zones.a]
subnet = "10.1.0.0/24"
iface = "ea"

[zones.b]
subnet = "10.2.0.0/24"
iface = "eb"
"""


def make_spec(
    tmp_path: Path, ruleset: str, rules: str = "", *, zones: str = TWO_ZONES, name: str = "spec.toml"
) -> Path:
    """Write a spec and its ruleset into tmp_path and return the spec's path."""
    (tmp_path / "fw.nft").write_text(ruleset)
    path = tmp_path / name
    path.write_text(zones + "\n" + rules)
    return path


FORWARD_ONLY = """\
flush ruleset
table inet filter {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
%s
  }
}
"""


def forward_ruleset(*rules: str) -> str:
    return FORWARD_ONLY % "\n".join(f"    {r}" for r in rules)
