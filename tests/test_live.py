"""Against real network namespaces and the kernel's nftables. Skipped where no lab can be built (see conftest)."""

from __future__ import annotations

import os
import random
import signal
import subprocess
import sys
import time

import pytest

from nft_assert import engine, lab, report
from nft_assert import spec as S

from .conftest import EXAMPLES, ROOT, forward_ruleset, leftover_namespaces, make_spec

pytestmark = pytest.mark.live


def check(tmp_path, ruleset, rules, **kw):
    spec = S.load(make_spec(tmp_path, ruleset, rules))
    return engine.check(spec, **kw)


def verdicts(run):
    return {str(c.expectation.flow): c.result.outcome for c in run.checks}


def cli(*argv, **kw):
    return subprocess.run(
        [sys.executable, "-m", "nft_assert", *argv],
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(ROOT)),
        timeout=120,
        **kw,
    )


class TestVerdicts:
    def test_accept_drop_and_reject_are_told_apart(self, tmp_path):
        rules = forward_ruleset(
            'iifname "ea" oifname "eb" tcp dport 22 accept',
            'iifname "ea" oifname "eb" tcp dport 25 reject with tcp reset',
            'iifname "ea" oifname "eb" tcp dport 26 drop',
        )
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> b" = ["tcp/22"]\n[expect.reject]\n"a -> b" = ["tcp/25"]\n[expect.drop]\n"a -> b" = ["tcp/26", "tcp/27"]\n',
        )
        assert verdicts(run) == {
            "a -> b tcp/22": "accept",
            "a -> b tcp/25": "reject",
            "a -> b tcp/26": "drop",
            "a -> b tcp/27": "drop",
        }
        assert not run.failed

    def test_every_kind_of_rejection_is_a_reject(self, tmp_path):
        rules = forward_ruleset(
            'iifname "ea" oifname "eb" tcp dport 25 reject with tcp reset',
            'iifname "ea" oifname "eb" tcp dport 26 reject',
            'iifname "ea" oifname "eb" udp dport 53 reject',
            'iifname "ea" oifname "eb" udp dport 54 reject with icmp type host-unreachable',
            'iifname "ea" oifname "eb" udp dport 55 reject with icmp type net-unreachable',
            'iifname "ea" oifname "eb" udp dport 56 reject with icmp type admin-prohibited',
            'iifname "ea" oifname "eb" tcp dport 27 reject with icmp type host-unreachable',
            'iifname "ea" oifname "eb" tcp dport 28 reject with icmp type admin-prohibited',
            'iifname "ea" oifname "eb" icmp type echo-request reject with icmp type admin-prohibited',
        )
        run = check(
            tmp_path,
            rules,
            '[expect.reject]\n"a -> b" = ["tcp/25", "tcp/26", "tcp/27", "tcp/28", "udp/53", "udp/54", "udp/55", "udp/56", "icmp"]\n',
        )
        assert not run.failed, report.render_text(run)

    def test_udp_and_icmp_accepts_and_drops(self, tmp_path):
        rules = forward_ruleset(
            'iifname "ea" oifname "eb" udp dport 53 accept',
            'iifname "ea" oifname "eb" icmp type echo-request accept',
        )
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> b" = ["udp/53", "icmp"]\n[expect.drop]\n"a -> b" = ["udp/54"]\n"b -> a" = ["icmp", "udp/53"]\n',
        )
        assert not run.failed, report.render_text(run)

    def test_the_direction_matters(self, tmp_path):
        rules = forward_ruleset('iifname "ea" oifname "eb" tcp dport 22 accept')
        run = check(
            tmp_path, rules, '[expect.accept]\n"a -> b" = ["tcp/22"]\n[expect.drop]\n"b -> a" = ["tcp/22"]\n'
        )
        assert not run.failed

    def test_traffic_to_the_firewall_goes_through_the_input_chain(self, tmp_path):
        rules = """flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "ea" tcp dport 22 accept
    iifname "eb" tcp dport 22 reject with tcp reset
  }
}
"""
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> fw" = ["tcp/22"]\n[expect.reject]\n"b -> fw" = ["tcp/22"]\n[expect.drop]\n"a -> fw" = ["tcp/23"]\n',
        )
        assert not run.failed, report.render_text(run)

    def test_traffic_from_the_firewall_goes_through_the_output_chain(self, tmp_path):
        rules = """flush ruleset
table inet filter {
  chain output {
    type filter hook output priority 0; policy accept;
    ip daddr 10.2.0.2 tcp dport 25 reject with tcp reset
    ip daddr 10.2.0.2 tcp dport 26 drop
  }
}
"""
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"fw -> a" = ["tcp/25"]\n"fw -> b" = ["tcp/22"]\n[expect.reject]\n"fw -> b" = ["tcp/25"]\n[expect.drop]\n"fw -> b" = ["tcp/26"]\n',
        )
        assert not run.failed, report.render_text(run)

    def test_an_address_can_be_the_destination(self, tmp_path):
        rules = forward_ruleset('iifname "ea" ip daddr 10.2.0.2 tcp dport 22 accept')
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> 10.2.0.2" = ["tcp/22"]\n[expect.drop]\n"a -> 10.2.0.9" = ["tcp/22"]\n',
        )
        assert verdicts(run)["a -> 10.2.0.2 tcp/22"] == "accept"

    def test_a_stateful_rule_only_lets_replies_in(self, tmp_path):
        rules = forward_ruleset(
            'iifname "eb" oifname "ea" ct state new drop', 'iifname "ea" oifname "eb" accept'
        )
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> b" = ["tcp/22", "udp/53", "icmp"]\n[expect.drop]\n"b -> a" = ["tcp/22", "udp/53", "icmp"]\n',
        )
        assert not run.failed, report.render_text(run)

    def test_many_rejects_at_once_are_not_lost_to_icmp_rate_limiting(self, tmp_path):
        ports = list(range(3000, 3060))
        rules = forward_ruleset(
            f'iifname "ea" oifname "eb" udp dport {{ {", ".join(map(str, ports))} }} reject'
        )
        expect = ", ".join(f'"udp/{p}"' for p in ports)
        run = check(tmp_path, rules, f'[expect.reject]\n"a -> b" = [{expect}]\n')
        assert not run.failed, report.render_text(run)

    def test_silence_costs_one_timeout_not_one_per_flow(self, tmp_path):
        ports = ", ".join(f'"tcp/{p}"' for p in range(4000, 4080))
        started = time.monotonic()
        run = check(tmp_path, forward_ruleset(), f'[expect.drop]\n"a -> b" = [{ports}]\n', do_sanity=False)
        assert not run.failed and time.monotonic() - started < 10


class TestNat:
    def test_the_edge_example_passes_including_the_port_forward_and_the_masquerade(self):
        run = engine.check(S.load(EXAMPLES / "edge" / "spec.toml"))
        assert not run.failed, report.render_text(run)
        assert sum(1 for c in run.checks if c.expectation.observe) == 2

    def test_observe_fails_when_the_wrong_host_answers(self, tmp_path):
        rules = forward_ruleset('iifname "ea" oifname "eb" tcp dport 80 accept')
        text = '[expect.accept]\n"a -> b" = ["tcp/80"]\n[[observe]]\nflow = "a -> b tcp/80"\nreached = "a"\nreached_port = 8080\nsource_seen = "10.9.9.9"\n'
        (c,) = check(tmp_path, rules, text).checks
        assert not c.ok and len(c.problems) == 3
        assert "expected a to answer, got b" in c.problems[0]
        assert "port 8080, got 80" in c.problems[1]
        assert "see source 10.9.9.9, it saw 10.1.0.2" in c.problems[2]

    def test_a_source_nat_is_seen_by_the_other_side(self, tmp_path):
        rules = """flush ruleset
table inet filter {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "ea" oifname "eb" accept
  }
}
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eb" snat to 10.2.0.1
  }
}
"""
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> b" = ["tcp/80"]\n[[observe]]\nflow = "a -> b tcp/80"\nsource_seen = "10.2.0.1"\n',
        )
        assert not run.failed, report.render_text(run)


class TestFailuresAreExplained:
    RULES = forward_ruleset(
        'iifname "ea" oifname "eb" tcp dport 22 accept comment "ssh"',
        'iifname "eb" oifname "ea" tcp dport 25 reject with tcp reset',
    )

    def test_a_wrong_expectation_names_the_rule_that_decided(self, tmp_path):
        run = check(
            tmp_path,
            self.RULES,
            '[expect.drop]\n"a -> b" = ["tcp/22"]\n[expect.accept]\n"b -> a" = ["tcp/25"]\n"a -> b" = ["tcp/80"]\n',
        )
        by = {str(c.expectation.flow): c for c in run.checks}
        ssh = by["a -> b tcp/22"]
        assert not ssh.ok and "expected drop, got accept" in ssh.problems[0]
        assert any(
            'tcp dport 22 accept comment "ssh"' in line and line.endswith("-> accept")
            for line in ssh.explanation
        )
        mail = by["b -> a tcp/25"]
        assert any(
            "reject with tcp reset" in line and line.endswith("-> reject") for line in mail.explanation
        )
        web = by["a -> b tcp/80"]
        assert web.explanation[-1] == "inet filter forward: no rule matched, the chain policy is drop"

    def test_explaining_can_be_switched_off(self, tmp_path):
        run = check(tmp_path, self.RULES, '[expect.drop]\n"a -> b" = ["tcp/22"]\n', explain=False)
        assert run.failed and run.checks[0].explanation == []

    def test_only_failures_are_traced(self, tmp_path):
        run = check(
            tmp_path,
            self.RULES,
            '[expect.accept]\n"a -> b" = ["tcp/22"]\n[expect.drop]\n"a -> b" = ["tcp/80", "tcp/22x"]\n'.replace(
                ', "tcp/22x"', ""
            ),
        )
        assert all(c.explanation == [] for c in run.checks)

    def test_the_traced_flow_does_not_change_the_ruleset_afterwards(self, tmp_path):
        spec = S.load(make_spec(tmp_path, self.RULES, '[expect.drop]\n"a -> b" = ["tcp/22"]\n'))
        with lab.Lab(spec) as lb:
            lb.start_listeners({("tcp", 22)})
            assert lb.load_ruleset(spec.ruleset) is None
            before = lb.nft("list", "ruleset").stdout
            engine.explain_flows(lb, spec, [spec.expectations[0].flow], 1.0)
            assert lb.nft("list", "ruleset").stdout == before

    def test_a_ruleset_that_never_sees_the_packets_says_so(self, tmp_path):
        rules = forward_ruleset('iifname "ea" oifname "eb" tcp dport 22 accept')
        spec = S.load(make_spec(tmp_path, rules, '[expect.accept]\n"a -> b" = ["tcp/22"]\n'))
        with lab.Lab(spec) as lb:
            lb.start_listeners({("tcp", 22)})
            lb.nft(
                "-f",
                "-",
                input="table inet t {\n chain c {\n  type filter hook prerouting priority -500;\n  ip daddr 10.2.0.2 drop\n }\n}\n",
            )
            out = engine.explain_flows(lb, spec, [spec.expectations[0].flow], 1.0)
            assert "never reached" in out[spec.expectations[0].flow][0]


class TestRulesetErrors:
    def test_a_syntax_error_is_nfts_message_and_leaves_nothing_behind(self, tmp_path):
        spec = make_spec(
            tmp_path,
            "table inet f { chain c { type filter hook input priority 0; counter counter bogus } }\n",
            '[expect.accept]\n"a -> b" = ["tcp/22"]\n',
        )
        r = cli("check", str(spec))
        assert r.returncode == 2 and "nft refused the ruleset" in r.stderr and "fw.nft" in r.stderr
        assert leftover_namespaces() == []

    def test_a_missing_ruleset_file(self, tmp_path):
        spec = make_spec(tmp_path, "", '[expect.accept]\n"a -> b" = ["tcp/22"]\n')
        (tmp_path / "fw.nft").unlink()
        r = cli("check", str(spec))
        assert r.returncode == 2 and "cannot read the ruleset" in r.stderr

    def test_the_ruleset_can_be_replaced_on_the_command_line(self, tmp_path):
        spec = make_spec(tmp_path, forward_ruleset(), '[expect.accept]\n"a -> b" = ["tcp/22"]\n')
        other = tmp_path / "open.nft"
        other.write_text(forward_ruleset('iifname "ea" oifname "eb" accept'))
        assert cli("check", str(spec)).returncode == 1
        assert cli("check", str(spec), "--ruleset", str(other)).returncode == 0


class TestRulesetFeatures:
    def test_include_finds_files_next_to_the_ruleset(self, tmp_path):
        (tmp_path / "common.nft").write_text("define ssh = 22\n")
        rules = 'include "common.nft"\n' + forward_ruleset('iifname "ea" oifname "eb" tcp dport $ssh accept')
        run = check(
            tmp_path, rules, '[expect.accept]\n"a -> b" = ["tcp/22"]\n[expect.drop]\n"a -> b" = ["tcp/23"]\n'
        )
        assert not run.failed, report.render_text(run)

    def test_sets_maps_and_counters_work(self, tmp_path):
        rules = """flush ruleset
table inet filter {
  set web { type inet_service; elements = { 80, 443 } }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "ea" oifname "eb" tcp dport @web counter accept
  }
}
"""
        run = check(
            tmp_path,
            rules,
            '[expect.accept]\n"a -> b" = ["tcp/80", "tcp/443"]\n[expect.drop]\n"a -> b" = ["tcp/8080"]\n',
        )
        assert not run.failed

    def test_a_ruleset_in_a_chain_with_jumps_is_traced_through_them(self, tmp_path):
        rules = """flush ruleset
table inet filter {
  chain allowed {
    tcp dport 22 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "ea" jump allowed
  }
}
"""
        run = check(tmp_path, rules, '[expect.drop]\n"a -> b" = ["tcp/22"]\n')
        (c,) = run.checks
        assert [line.split(": ")[0] for line in c.explanation] == [
            "inet filter forward",
            "inet filter allowed",
        ]
        assert c.explanation[-1].endswith("tcp dport 22 accept` -> accept")


class TestTheLabItself:
    def test_the_sanity_pass_refuses_to_blame_the_ruleset_for_a_broken_lab(self, tmp_path):
        spec = S.load(make_spec(tmp_path, "", '[expect.accept]\n"a -> b" = ["tcp/22"]\n'))
        with lab.Lab(spec) as lb:
            lb.start_listeners({("tcp", 22)})
            lb.nft(
                "-f",
                "-",
                input="table inet t {\n chain c {\n  type filter hook forward priority 0; policy drop;\n }\n}\n",
            )
            with pytest.raises(lab.LabError, match="the lab is broken, not your ruleset"):
                engine.sanity(lb, spec, [spec.expectations[0].flow], 0.5)

    def test_sanity_can_be_skipped(self, tmp_path):
        run = check(tmp_path, forward_ruleset(), '[expect.drop]\n"a -> b" = ["tcp/22"]\n', do_sanity=False)
        assert run.sanity_checked == 0 and not run.failed

    def test_with_no_ruleset_everything_between_zones_flows(self, tmp_path):
        spec = S.load(
            make_spec(
                tmp_path,
                "",
                '[expect.accept]\n"a -> b" = ["tcp/22", "udp/53", "icmp"]\n"b -> a" = ["tcp/22"]\n"a -> fw" = ["tcp/22", "icmp"]\n"fw -> b" = ["udp/53"]\n',
            )
        )
        with lab.Lab(spec) as lb:
            lb.start_listeners({("tcp", 22), ("udp", 53)})
            got = engine.probe_flows(lb, spec, [e.flow for e in spec.expectations], 1.0)
        assert {r.outcome for r in got} == {"accept"}

    def test_a_namespace_is_isolated_from_the_machine(self, tmp_path):
        spec = S.load(make_spec(tmp_path, "", '[expect.accept]\n"a -> b" = ["tcp/22"]\n'))
        before = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True).stdout
        with lab.Lab(spec) as lb:
            inside = subprocess.run(
                ["ip", "netns", "exec", lb.ns["fw"], "ip", "-o", "link"], capture_output=True, text=True
            ).stdout
            assert "ea@" in inside and "eb@" in inside and "docker" not in inside
        assert subprocess.run(["ip", "-o", "link"], capture_output=True, text=True).stdout == before

    def test_the_machines_own_ruleset_is_untouched(self, tmp_path):
        before = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout
        check(tmp_path, forward_ruleset('iifname "ea" accept'), '[expect.accept]\n"a -> b" = ["tcp/22"]\n')
        assert subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True).stdout == before

    def test_two_runs_at_the_same_time_do_not_collide(self, tmp_path):
        spec = make_spec(
            tmp_path,
            forward_ruleset('iifname "ea" oifname "eb" tcp dport 22 accept'),
            '[expect.accept]\n"a -> b" = ["tcp/22"]\n[expect.drop]\n"a -> b" = ["tcp/80"]\n',
        )
        procs = [
            subprocess.Popen(
                [sys.executable, "-m", "nft_assert", "check", str(spec)],
                stdout=subprocess.PIPE,
                text=True,
                env=dict(os.environ, PYTHONPATH=str(ROOT)),
            )
            for _ in range(3)
        ]
        assert [p.wait(timeout=120) for p in procs] == [0, 0, 0]


class TestCleanup:
    def test_a_normal_run_leaves_nothing(self, tmp_path):
        spec = make_spec(tmp_path, forward_ruleset(), '[expect.accept]\n"a -> b" = ["tcp/22"]\n')
        assert cli("check", str(spec)).returncode == 1
        assert leftover_namespaces() == []

    def test_sigterm_tears_the_lab_down(self, tmp_path):
        ports = ", ".join(f'"tcp/{p}"' for p in range(5000, 5010))
        spec = make_spec(
            tmp_path,
            forward_ruleset(),
            f'timeout = 20\n[expect.drop]\n"a -> b" = [{ports}]\n'.replace("timeout = 20\n", ""),
        )
        text = (tmp_path / "spec.toml").read_text()
        (tmp_path / "spec.toml").write_text("timeout = 20\n" + text)
        p = subprocess.Popen(
            [sys.executable, "-m", "nft_assert", "check", str(spec), "--no-sanity"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, PYTHONPATH=str(ROOT)),
        )
        try:
            deadline = time.monotonic() + 30
            while not any(n.startswith(f"nfta{p.pid}-") for n in leftover_namespaces()):
                assert time.monotonic() < deadline and p.poll() is None, "the lab never appeared"
                time.sleep(0.05)
            time.sleep(1.0)  # let it get as far as sending the probes
            p.send_signal(signal.SIGTERM)
            out, err = p.communicate(timeout=60)
        finally:
            if p.poll() is None:
                p.kill()
        assert p.returncode == 130 and "interrupted, lab removed" in err
        assert [n for n in leftover_namespaces() if n.startswith(f"nfta{p.pid}-")] == []

    def test_cleanup_removes_what_a_killed_run_left(self):
        for n in ("nfta999999-fw", "nfta999999-z-a"):
            subprocess.run(["ip", "netns", "add", n], check=True)
        keeper = "someoneelses"
        subprocess.run(["ip", "netns", "add", keeper], check=True)
        try:
            r = cli("cleanup")
            assert r.returncode == 0 and "removed 2 leftover namespace(s)" in r.stdout
            assert "nfta999999-fw" not in leftover_namespaces()
            assert keeper in lab.list_namespaces()
        finally:
            subprocess.run(["ip", "netns", "del", keeper], capture_output=True)
            lab.cleanup_leftovers()

    def test_cleanup_kills_what_still_runs_inside(self):
        subprocess.run(["ip", "netns", "add", "nfta999998-fw"], check=True)
        sleeper = subprocess.Popen(["ip", "netns", "exec", "nfta999998-fw", "sleep", "300"])
        time.sleep(0.3)
        try:
            lab.cleanup_leftovers()
            assert sleeper.wait(timeout=10) != 0
            assert "nfta999998-fw" not in leftover_namespaces()
        finally:
            sleeper.kill()
            lab.cleanup_leftovers()


class TestMatrixAndDiff:
    def test_the_matrix_says_who_can_reach_whom(self, tmp_path):
        rules = forward_ruleset(
            'iifname "ea" oifname "eb" tcp dport 22 accept',
            'iifname "eb" oifname "ea" tcp dport 25 reject with tcp reset',
        )
        spec = S.load(make_spec(tmp_path, rules, "[matrix]\ntcp = [22, 25]\nudp = []\nicmp = false\n"))
        m = engine.matrix(spec)
        assert m.outcome("a", "b", ("tcp", 22)) == "accept"
        assert m.outcome("a", "b", ("tcp", 25)) == "drop"
        assert m.outcome("b", "a", ("tcp", 25)) == "reject"
        assert m.outcome("b", "a", ("tcp", 22)) == "drop"
        assert m.outcome("fw", "a", ("tcp", 22)) == "accept"
        assert m.outcome("a", "fw", ("tcp", 22)) == "accept"  # the ruleset has no input chain at all

    def test_diff_shows_exactly_the_flow_that_changed(self, tmp_path):
        spec = S.load(make_spec(tmp_path, "", "[matrix]\ntcp = [22, 80, 443]\nudp = [53]\nicmp = true\n"))
        old = tmp_path / "old.nft"
        new = tmp_path / "new.nft"
        old.write_text(forward_ruleset('iifname "ea" oifname "eb" tcp dport { 22, 443 } accept'))
        new.write_text(forward_ruleset('iifname "ea" oifname "eb" tcp dport { 22, 443, 80 } accept'))
        _, _, changes = engine.diff(spec, old, new)
        assert [(c.src, c.dst, c.probe, c.before, c.after) for c in changes] == [
            ("a", "b", ("tcp", 80), "drop", "accept")
        ]

    def test_diff_of_two_identical_files_is_empty(self, tmp_path):
        spec = S.load(make_spec(tmp_path, "", ""))
        f = tmp_path / "x.nft"
        f.write_text(forward_ruleset('iifname "ea" oifname "eb" accept'))
        assert engine.diff(spec, f, f)[2] == []

    def test_diff_isolates_the_two_rulesets_from_each_other(self, tmp_path):
        spec = S.load(make_spec(tmp_path, "", "[matrix]\ntcp = [22]\nudp = []\nicmp = false\n"))
        a, b = tmp_path / "a.nft", tmp_path / "b.nft"
        a.write_text(forward_ruleset('iifname "ea" oifname "eb" tcp dport 22 accept'))
        b.write_text(
            "table inet other {\n}\n"
        )  # no flush of its own: it must not inherit the first ruleset's policy
        _, new, changes = engine.diff(spec, a, b)
        assert set(new.cells.values()) == {"accept"}  # an empty ruleset lets everything through
        assert [(c.src, c.dst, c.before) for c in changes] == [
            ("b", "a", "drop")
        ]  # the one flow the first dropped

    def test_diff_cli_exit_codes(self, tmp_path):
        spec = make_spec(tmp_path, "", "[matrix]\ntcp = [22]\nudp = []\nicmp = false\n")
        a, b = tmp_path / "a.nft", tmp_path / "b.nft"
        a.write_text(forward_ruleset())
        b.write_text(forward_ruleset('iifname "ea" oifname "eb" tcp dport 22 accept'))
        same = cli("diff", str(spec), str(a), str(a))
        assert same.returncode == 0 and "no flow changed" in same.stdout
        diff = cli("diff", str(spec), str(a), str(b))
        assert diff.returncode == 1 and "a -> b tcp/22: drop -> accept" in diff.stdout


class TestPropertyTruthTable:
    """A random truth table is turned into a ruleset; what the lab measures must be exactly the table."""

    @pytest.mark.parametrize("seed", range(6))
    def test_the_matrix_is_what_the_ruleset_was_built_from(self, tmp_path, seed):
        rng = random.Random(seed)
        probes = (
            [("tcp", p) for p in (21, 22, 23, 80, 443, 8080)]
            + [("udp", p) for p in (53, 123)]
            + [("icmp", None)]
        )
        table = {
            (s, d, p): rng.choice(["accept", "drop", "reject"])
            for s, d in (("a", "b"), ("b", "a"))
            for p in probes
        }
        rules = []
        for (s, d, (proto, port)), verdict in table.items():
            match = f'iifname "e{s}" oifname "e{d}" ' + (
                "icmp type echo-request" if proto == "icmp" else f"{proto} dport {port}"
            )
            if verdict == "accept":
                rules.append(f"{match} accept")
            elif verdict == "reject":
                tail = (
                    "reject with tcp reset"
                    if proto == "tcp"
                    else "reject with icmp type admin-prohibited"
                    if proto == "icmp"
                    else "reject"
                )
                rules.append(f"{match} {tail}")
            elif rng.random() < 0.5:
                rules.append(f"{match} drop")  # sometimes explicit, sometimes just the policy
        spec = S.load(
            make_spec(
                tmp_path,
                forward_ruleset(*rules),
                "[matrix]\ntcp = [21, 22, 23, 80, 443, 8080]\nudp = [53, 123]\nicmp = true\n",
            )
        )
        m = engine.matrix(spec)
        for (s, d, p), verdict in table.items():
            assert m.outcome(s, d, p) == verdict, (
                f"{s} -> {d} {p}: built as {verdict}, measured {m.outcome(s, d, p)}"
            )


class TestKernelRateLimits:
    def flood(self, tmp_path, lower_limits: bool):
        ports = list(range(3000, 3100))
        rules = forward_ruleset(
            f'iifname "ea" oifname "eb" udp dport {{ {", ".join(map(str, ports))} }} reject'
        )
        spec = S.load(make_spec(tmp_path, rules, ""))
        flows = [S.Flow("a", "b", "udp", p) for p in ports]
        with lab.Lab(spec) as lb:
            if (
                "OutRateLimitGlobal"
                not in lab.run(["ip", "netns", "exec", lb.ns["fw"], "cat", "/proc/net/snmp"]).stdout
            ):
                pytest.skip("this kernel does not count rate-limited ICMP errors")
            lb.start_listeners({("udp", p) for p in ports})
            if (
                lower_limits
            ):  # put the kernel's defaults back, as on a kernel that would not let us raise them
                for ns in lb.ns.values():
                    lab.run(
                        [
                            "ip",
                            "netns",
                            "exec",
                            ns,
                            "sh",
                            "-c",
                            "echo 50 > /proc/sys/net/ipv4/icmp_msgs_burst; echo 1000 > /proc/sys/net/ipv4/icmp_msgs_per_sec",
                        ]
                    )
            assert lb.load_ruleset(spec.ruleset) is None
            return engine.probe_flows(lb, spec, flows, 1.0)

    def test_a_hundred_simultaneous_rejects_are_all_seen(self, tmp_path):
        assert {r.outcome for r in self.flood(tmp_path, lower_limits=False)} == {"reject"}

    def test_if_the_kernel_does_hold_errors_back_the_run_stops_instead_of_guessing(self, tmp_path):
        with pytest.raises(lab.LabError, match="held back .* ICMP error"):
            self.flood(tmp_path, lower_limits=True)
