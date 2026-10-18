import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from nft_assert import cli, engine, lab
from nft_assert.lab import LabError

from .conftest import ROOT, make_spec
from .fakes import EDGE, fake_matrix, fake_run


def run_cli(*argv: str, **kw):
    return subprocess.run(
        [sys.executable, "-m", "nft_assert", *argv],
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(ROOT)),
        timeout=120,
        **kw,
    )


class TestBadInput:
    def test_a_missing_spec_is_exit_2_with_a_plain_message(self, tmp_path):
        r = run_cli("check", str(tmp_path / "nope.toml"))
        assert r.returncode == 2 and "cannot read" in r.stderr and "Traceback" not in r.stderr

    def test_a_typo_in_the_spec_is_exit_2(self, tmp_path):
        spec = make_spec(tmp_path, "", '[expect.dropp]\n"a -> b" = ["tcp/22"]\n')
        r = run_cli("check", str(spec))
        assert r.returncode == 2 and "unknown key 'dropp'" in r.stderr

    @pytest.mark.parametrize("value", ["0", "0.1", "31", "-3", "nan"])
    def test_timeout_out_of_range(self, tmp_path, value):
        spec = make_spec(tmp_path, "")
        r = run_cli("check", str(spec), "--timeout", value)
        assert r.returncode == 2 and "--timeout" in r.stderr

    def test_no_command_is_a_usage_error(self):
        assert run_cli().returncode == 2

    def test_version(self):
        r = run_cli("--version")
        assert r.returncode == 0 and r.stdout.startswith("nft-assert ")


class TestNoLab:
    """Without root (or without the tools) the answer is exit 3 and a sentence, never a traceback."""

    def test_not_root(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(lab.os, "geteuid", lambda: 1000)
        spec = make_spec(tmp_path, "")
        assert cli.main(["check", str(spec)]) == 3
        assert "needs root" in capsys.readouterr().err

    def test_tools_missing(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
        monkeypatch.setenv("PATH", str(tmp_path))
        spec = make_spec(tmp_path, "")
        assert cli.main(["matrix", str(spec)]) == 3
        assert "is not installed" in capsys.readouterr().err

    def test_not_linux(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(lab.sys, "platform", "darwin")
        assert cli.main(["check", str(make_spec(tmp_path, ""))]) == 3
        assert "needs Linux" in capsys.readouterr().err


class FakeEngine:
    """Replaces the engine so the CLI's own behaviour (formats, files, exit codes) is tested without a lab."""

    def __init__(self, monkeypatch, *, failing=True):
        self.calls = []
        run = fake_run()
        if not failing:
            run.checks = [c for c in run.checks if c.ok]
        monkeypatch.setattr(
            engine, "check", lambda spec, ruleset=None, **kw: (self.calls.append((ruleset, kw)), run)[1]
        )
        monkeypatch.setattr(engine, "matrix", lambda spec, ruleset=None, **kw: fake_matrix())
        monkeypatch.setattr(
            engine, "diff", lambda spec, old, new, **kw: (fake_matrix(), fake_matrix(), self.changes)
        )
        monkeypatch.setattr(engine, "all_flows", lambda spec: [None] * 12)
        self.changes = []


class TestCheck:
    def test_exit_1_when_something_failed_and_0_when_not(self, monkeypatch, capsys):
        FakeEngine(monkeypatch)
        assert cli.main(["check", str(EDGE)]) == 1
        assert "FAIL  wan -> fw tcp/22" in capsys.readouterr().out
        FakeEngine(monkeypatch, failing=False)
        assert cli.main(["check", str(EDGE)]) == 0

    @pytest.mark.parametrize(
        ("fmt", "needle"), [("text", "PASS  lan -> wan"), ("md", "### nft-assert"), ("json", '"checks"')]
    )
    def test_formats(self, monkeypatch, capsys, fmt, needle):
        FakeEngine(monkeypatch)
        cli.main(["check", str(EDGE), "-f", fmt])
        assert needle in capsys.readouterr().out

    def test_options_reach_the_engine(self, monkeypatch, tmp_path):
        fake = FakeEngine(monkeypatch)
        other = tmp_path / "other.nft"
        other.write_text("")
        cli.main(["check", str(EDGE), "--ruleset", str(other), "--no-explain", "--no-sanity"])
        ruleset, kw = fake.calls[0]
        assert ruleset == other.resolve() and kw == {"explain": False, "do_sanity": False}

    def test_junit_file(self, monkeypatch, tmp_path):
        FakeEngine(monkeypatch)
        out = tmp_path / "r.xml"
        cli.main(["check", str(EDGE), "--junit", str(out)])
        assert ET.parse(out).getroot().get("failures") == "1"

    def test_github_summary_is_appended_only_when_asked_and_available(self, monkeypatch, tmp_path):
        FakeEngine(monkeypatch)
        summary = tmp_path / "summary.md"
        summary.write_text("earlier\n")
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        cli.main(["check", str(EDGE)])
        assert summary.read_text() == "earlier\n"
        cli.main(["check", str(EDGE), "--github-summary"])
        assert summary.read_text().startswith("earlier\n### nft-assert")
        monkeypatch.delenv("GITHUB_STEP_SUMMARY")
        cli.main(["check", str(EDGE), "--github-summary"])  # no variable: nothing happens, nothing breaks

    def test_annotations_are_printed_only_when_asked(self, monkeypatch, capsys):
        FakeEngine(monkeypatch)
        cli.main(["check", str(EDGE)])
        assert "::error" not in capsys.readouterr().out
        assert cli.main(["check", str(EDGE), "--github-annotations"]) == 1
        out = capsys.readouterr().out
        assert out.count("::error file=") == 1
        assert out.rstrip("\n").splitlines()[-1].startswith("::error file=")

    def test_annotations_use_the_workspace_to_name_the_file(self, monkeypatch, capsys):
        FakeEngine(monkeypatch)
        monkeypatch.setenv("GITHUB_WORKSPACE", str(EDGE.parent))
        cli.main(["check", str(EDGE), "--github-annotations"])
        assert f"::error file={EDGE.name}," in capsys.readouterr().out


class TestMatrix:
    def test_print_write_and_check(self, monkeypatch, capsys, tmp_path):
        FakeEngine(monkeypatch)
        assert cli.main(["matrix", str(EDGE)]) == 0
        printed = capsys.readouterr().out
        assert printed.startswith("| From | To |")
        out = tmp_path / "m.md"
        assert cli.main(["matrix", str(EDGE), "-o", str(out)]) == 0
        assert out.read_text() == printed
        assert cli.main(["matrix", str(EDGE), "--check", str(out)]) == 0
        assert "is up to date" in capsys.readouterr().out

    def test_a_changed_matrix_fails_the_check_and_shows_the_difference(self, monkeypatch, capsys, tmp_path):
        FakeEngine(monkeypatch)
        committed = tmp_path / "m.md"
        committed.write_text(
            "| From | To | tcp/22 | udp/53 | icmp |\n|---|---|---|---|---|\n| fw | a | drop | drop | drop |\n"
        )
        assert cli.main(["matrix", str(EDGE), "--check", str(committed)]) == 1
        captured = capsys.readouterr()
        assert (
            "-| fw | a | drop | drop | drop |" in captured.out
            and "+| fw | a | accept | drop | drop |" in captured.out
        )
        assert "no longer matches" in captured.err

    def test_json(self, monkeypatch, capsys):
        FakeEngine(monkeypatch)
        cli.main(["matrix", str(EDGE), "-f", "json"])
        assert json.loads(capsys.readouterr().out)["endpoints"] == ["fw", "a"]

    def test_checking_against_a_file_that_is_not_there(self, monkeypatch, tmp_path):
        FakeEngine(monkeypatch)
        with pytest.raises(FileNotFoundError):
            cli.main(["matrix", str(EDGE), "--check", str(tmp_path / "none.md")])


class TestDiff:
    def test_no_change_is_exit_0_and_a_change_is_exit_1(self, monkeypatch, capsys):
        fake = FakeEngine(monkeypatch)
        assert cli.main(["diff", str(EDGE), "a.nft", "b.nft"]) == 0
        assert "no flow changed (12 flows compared)" in capsys.readouterr().out
        fake.changes = [engine.Change("lan", "dmz", ("tcp", 22), "drop", "accept")]
        assert cli.main(["diff", str(EDGE), "a.nft", "b.nft", "-f", "json"]) == 1
        assert json.loads(capsys.readouterr().out)["changed"][0]["after"] == "accept"


class TestErrors:
    def test_a_ruleset_nft_refuses_is_exit_2_with_nfts_words(self, monkeypatch, capsys):
        def refuse(*a, **k):
            raise engine.RulesetError("/x/fw.nft:3:5-9: Error: syntax error, unexpected counter")

        monkeypatch.setattr(engine, "check", refuse)
        assert cli.main(["check", str(EDGE)]) == 2
        assert "nft refused the ruleset" in capsys.readouterr().err

    def test_a_broken_lab_is_exit_3(self, monkeypatch, capsys):
        def broken(*a, **k):
            raise LabError("the lab is broken, not your ruleset: lan -> wan tcp/80 got drop")

        monkeypatch.setattr(engine, "check", broken)
        assert cli.main(["check", str(EDGE)]) == 3
        assert "lab is broken" in capsys.readouterr().err

    def test_ctrl_c_is_exit_130(self, monkeypatch, capsys):
        def stop(*a, **k):
            raise KeyboardInterrupt

        monkeypatch.setattr(engine, "check", stop)
        assert cli.main(["check", str(EDGE)]) == 130
        assert "interrupted" in capsys.readouterr().err


def test_cleanup_reports_what_it_removed(monkeypatch, capsys):
    monkeypatch.setattr(cli, "cleanup_leftovers", lambda: ["nfta1-fw", "nfta1-z-a"])
    assert cli.main(["cleanup"]) == 0
    assert "removed 2 leftover namespace(s): nfta1-fw, nfta1-z-a" in capsys.readouterr().out
    monkeypatch.setattr(cli, "cleanup_leftovers", lambda: [])
    cli.main(["cleanup"])
    assert capsys.readouterr().out.strip() == "removed 0 leftover namespace(s)"
