"""What the program is allowed to do, checked on its source rather than on its behaviour."""

import ast
import sys
from pathlib import Path

import pytest

from nft_assert import lab

PKG = Path(__file__).resolve().parent.parent / "nft_assert"
FILES = sorted(PKG.glob("*.py"))


def trees():
    for f in FILES:
        yield f, ast.parse(f.read_text())


def calls(tree):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)]


def dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def test_the_package_has_the_files_this_test_expects():
    assert {f.name for f in FILES} >= {
        "cli.py",
        "engine.py",
        "lab.py",
        "report.py",
        "spec.py",
        "trace.py",
        "worker.py",
    }


@pytest.mark.parametrize("name", ["eval", "exec", "compile", "__import__"])
def test_no_dynamic_code(name):
    for f, tree in trees():
        assert not [c for c in calls(tree) if dotted(c.func) == name], f"{f.name} calls {name}"


@pytest.mark.parametrize(
    "name", ["os.system", "os.popen", "os.spawnl", "os.execv", "pickle.loads", "marshal.loads", "yaml.load"]
)
def test_no_shell_or_deserialisation_shortcuts(name):
    for f, tree in trees():
        assert not [c for c in calls(tree) if dotted(c.func) == name], f"{f.name} calls {name}"


def test_no_command_is_run_through_a_shell_string():
    for f, tree in trees():
        for c in calls(tree):
            if dotted(c.func).startswith("subprocess."):
                assert not any(k.arg == "shell" for k in c.keywords), f"{f.name}: shell= argument"
                if c.args and isinstance(c.args[0], ast.Constant):
                    pytest.fail(f"{f.name}: a command given as one string")


def test_only_the_standard_library_is_imported():
    stdlib = sys.stdlib_module_names
    for f, tree in trees():
        for n in ast.walk(tree):
            names = (
                [a.name for a in n.names]
                if isinstance(n, ast.Import)
                else [n.module]
                if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module
                else []
            )
            for name in names:
                assert name.split(".")[0] in stdlib or name.split(".")[0] == "nft_assert", (
                    f"{f.name} imports {name}"
                )


def test_only_the_worker_opens_sockets_and_it_only_ever_runs_inside_a_namespace():
    for f, tree in trees():
        uses = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Import) and any(a.name == "socket" for a in n.names)
        ]
        assert bool(uses) == (f.name == "worker.py"), f.name
    source = (PKG / "lab.py").read_text()
    assert '"-m", "nft_assert.worker"' in source and 'ip", "netns", "exec"' in source.replace("'", '"')


def test_nothing_is_ever_sent_to_the_machines_own_network_stack():
    """Every ``ip`` and ``nft`` command either acts on a namespace by name or on one made by this run."""
    src = (PKG / "lab.py").read_text()
    assert src.count('"netns", "add"') == 1
    assert 'run(["nft"' not in src and 'run(["ip", "link"' not in src
    assert 'self.ns[FW], "nft"' in src


def test_the_namespaces_this_tool_makes_are_all_recognisable_and_only_those_are_deleted():
    spec = type("S", (), {"zones": {"a": 1}})
    names = lab.Lab(spec, prefix="nfta42-").ns
    assert all(n.startswith(lab.PREFIX) for n in names.values())
    assert lab.PREFIX == "nfta"
    src = (PKG / "lab.py").read_text()
    assert "n.startswith(PREFIX)" in src


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("net/ipv4/x; rm -rf /", "0"),
        ("net/ipv4/x", "0; reboot"),
        ("../etc", "1"),
        ("net/ipv4/x", ""),
        ("net/ipv4/x", "$(id)"),
    ],
)
def test_sysctl_arguments_cannot_carry_a_command(path, value):
    with pytest.raises(ValueError):
        lab.Lab._sysctl("ns", path, value, True)


def test_no_secret_shaped_strings(tmp_path):
    import re

    pattern = re.compile(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
    for f in [*FILES, *Path(__file__).parent.glob("*.py")]:
        assert not pattern.search(f.read_text()), f
