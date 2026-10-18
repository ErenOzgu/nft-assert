import random
from pathlib import Path

import pytest

from nft_assert import trace
from nft_assert.spec import Flow

FIXTURE = (Path(__file__).parent / "fixtures" / "nft-monitor-trace.out").read_text()
TEXTS = {
    ("filter", "forward", 3): "ct state invalid drop",
    ("filter", "forward", 4): 'iifname "vl" oifname "vd" tcp dport 8080 reject with tcp reset',
}
A, B = "10.0.1.2", "10.0.2.2"


def explain_for(output: str, port: int, texts=None, src=A, dst=B, proto="tcp"):
    events, packets = trace.parse(output, texts or {})
    return trace.explain(
        trace.events_for(events, packets, src=src, dst=dst, flow=Flow("lan", "dmz", proto, port))
    )


class TestRecordedOutput:
    """FIXTURE is output recorded from ``nft monitor trace`` on the machine this was written on. Some of its
    lines are cut short or run into each other, as happens when the monitor is killed mid-line."""

    def test_the_accepting_rule_is_named_from_the_first_packet(self):
        assert explain_for(FIXTURE, 22) == [
            'inet filter forward: rule `iifname "vl" oifname "vd" tcp dport 22 accept` -> accept'
        ]

    def test_a_policy_drop(self):
        assert explain_for(FIXTURE, 80) == ["inet filter forward: no rule matched, the chain policy is drop"]

    def test_a_rule_the_monitor_only_numbered_is_looked_up(self):
        out = "\n".join(
            [
                "trace id 9 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 8080",
                "trace id 9 inet filter forward unknown rule handle 4 (verdict drop)",
            ]
        )
        assert explain_for(out, 8080, TEXTS) == [
            'inet filter forward: rule `iifname "vl" oifname "vd" tcp dport 8080 reject with tcp reset` -> reject'
        ]

    def test_an_unknown_handle_is_still_reported(self):
        out = "\n".join(
            [
                "trace id 9 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 8080",
                "trace id 9 inet filter forward unknown rule handle 77 (verdict drop)",
            ]
        )
        assert explain_for(out, 8080, TEXTS) == ["inet filter forward: rule `(rule with handle 77)` -> drop"]

    def test_a_reject_is_called_a_reject_even_though_nft_says_drop(self):
        assert explain_for(FIXTURE, 8080, TEXTS) == [
            'inet filter forward: rule `iifname "vl" oifname "vd" tcp dport 8080 reject with tcp reset` -> reject'
        ]

    def test_the_helper_table_is_never_reported(self):
        events, _ = trace.parse(FIXTURE)
        assert any(e.table == trace.TRACE_TABLE for e in events)
        assert not any("nfta_trace" in line for port in (22, 80, 8080) for line in explain_for(FIXTURE, port))

    def test_a_flow_that_was_never_seen_has_no_events(self):
        events, packets = trace.parse(FIXTURE)
        assert trace.events_for(events, packets, src=A, dst=B, flow=Flow("lan", "dmz", "tcp", 9999)) == []
        assert trace.events_for(events, packets, src="1.2.3.4", dst=B, flow=Flow("x", "dmz", "tcp", 22)) == []

    @pytest.mark.parametrize("seed", range(5))
    def test_damaged_output_never_raises(self, seed):
        rng = random.Random(seed)
        for _ in range(100):
            lines = FIXTURE.splitlines()
            rng.shuffle(lines)
            text = "\n".join(
                line[: rng.randint(0, len(line))] for line in lines[: rng.randint(0, len(lines))]
            )
            events, packets = trace.parse(text, TEXTS)
            trace.explain(trace.events_for(events, packets, src=A, dst=B, flow=Flow("lan", "dmz", "tcp", 22)))


class TestParse:
    def test_nothing_in_nothing_out(self):
        assert trace.parse("") == ([], {})
        assert trace.parse("hello\n\ntrace id\nnot a trace line") == ([], {})

    def test_an_icmp_packet(self):
        line = 'trace id 1 inet filter forward packet: iif "a" oif "b" ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol icmp icmp type echo-request'
        _, packets = trace.parse(line)
        p = packets["1"]
        assert (p.src, p.dst, p.proto, p.port) == (A, B, "icmp", None)

    def test_a_udp_packet(self):
        line = "trace id 1 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol udp udp sport 5 udp dport 53 udp length 8"
        assert trace.parse(line)[1]["1"].proto == "udp"
        assert trace.parse(line)[1]["1"].port == 53

    def test_a_second_packet_that_reuses_an_id_is_not_mixed_into_the_first(self):
        out = "\n".join(
            [
                "trace id 7 inet filter input packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22 tcp flags == syn",
                'trace id 7 inet filter input rule iifname "x" tcp dport 22 accept (verdict accept)',
                "trace id 7 inet filter input packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22 tcp flags == ack",
                "trace id 7 inet filter input rule ct state established,related accept (verdict accept)",
            ]
        )
        assert explain_for(out, 22) == ['inet filter input: rule `iifname "x" tcp dport 22 accept` -> accept']

    def test_the_same_id_in_different_chains_is_one_packet(self):
        out = "\n".join(
            [
                "trace id 7 ip nat prerouting packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22",
                "trace id 7 ip nat prerouting policy accept",
                "trace id 7 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22",
                "trace id 7 inet filter forward policy drop",
            ]
        )
        assert explain_for(out, 22) == [
            "ip nat prerouting: no rule matched, the chain policy is accept",
            "inet filter forward: no rule matched, the chain policy is drop",
        ]

    def test_jumps_are_reported_but_continues_are_not(self):
        out = "\n".join(
            [
                "trace id 7 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22",
                "trace id 7 inet filter forward rule ct state new counter (verdict continue)",
                "trace id 7 inet filter forward rule tcp dport 22 jump allowed (verdict jump allowed)",
                "trace id 7 inet filter allowed rule tcp dport 22 accept (verdict accept)",
            ]
        )
        assert explain_for(out, 22) == [
            "inet filter forward: rule `tcp dport 22 jump allowed` -> jump allowed",
            "inet filter allowed: rule `tcp dport 22 accept` -> accept",
        ]

    def test_a_trace_with_only_our_own_rules_says_the_packet_never_arrived(self):
        out = "\n".join(
            [
                "trace id 7 inet nfta_trace pre packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22",
                "trace id 7 inet nfta_trace pre policy accept",
            ]
        )
        (line,) = explain_for(out, 22)
        assert "never reached the firewall's netfilter hooks" in line and "iface" in line

    def test_no_events_at_all_gives_the_same_hint(self):
        assert "never reached" in trace.explain([])[0]

    def test_a_trace_that_decides_nothing(self):
        out = "\n".join(
            [
                "trace id 7 inet filter forward packet: ip saddr 10.0.1.2 ip daddr 10.0.2.2 ip protocol tcp tcp dport 22",
                "trace id 7 inet filter forward rule counter (verdict continue)",
            ]
        )
        assert explain_for(out, 22) == ["the packet matched no rule that decides anything"]


LISTING = """\
table inet filter { # handle 1
\tchain input { # handle 1
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept # handle 2
\t\tiifname "ea" tcp dport 22 accept # handle 3
\t}

\tchain forward { # handle 2
\t\ttype filter hook forward priority filter; policy drop;
\t\tiifname "ea" oifname "eb" tcp dport { 22, 80 } accept comment "web" # handle 4
\t}
}
table ip nat { # handle 2
\tchain prerouting { # handle 1
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\ttcp dport 8080 dnat to 10.0.2.2:80 # handle 2
\t}
}
"""


class TestRuleTexts:
    def test_rules_are_mapped_by_table_chain_and_handle(self):
        t = trace.rule_texts(LISTING)
        assert t[("filter", "input", 3)] == 'iifname "ea" tcp dport 22 accept'
        assert (
            t[("filter", "forward", 4)]
            == 'iifname "ea" oifname "eb" tcp dport { 22, 80 } accept comment "web"'
        )
        assert t[("nat", "prerouting", 2)] == "tcp dport 8080 dnat to 10.0.2.2:80"

    def test_chain_and_table_lines_are_not_rules(self):
        t = trace.rule_texts(LISTING)
        assert len(t) == 4
        assert not any("hook" in v or "chain" in v for v in t.values())

    def test_empty_and_odd_listings(self):
        assert trace.rule_texts("") == {}
        assert trace.rule_texts("# handle 3\n}\n") == {}


class TestTraceRuleset:
    def test_forwarded_flows_are_marked_in_prerouting_before_anything_else(self):
        text = trace.trace_ruleset(
            [
                (A, B, Flow("lan", "dmz", "tcp", 22)),
                (A, B, Flow("lan", "dmz", "udp", 53)),
                (A, B, Flow("lan", "dmz", "icmp", None)),
            ]
        )
        assert "table inet nfta_trace" in text and "hook prerouting priority -350" in text
        assert f"ip saddr {A} ip daddr {B} tcp dport 22 meta nftrace set 1" in text
        assert f"ip saddr {A} ip daddr {B} udp dport 53 meta nftrace set 1" in text
        assert f"ip saddr {A} ip daddr {B} icmp type echo-request meta nftrace set 1" in text
        assert "hook output" not in text

    def test_traffic_the_firewall_sends_itself_is_marked_in_output(self):
        text = trace.trace_ruleset([(None, B, Flow("fw", "dmz", "tcp", 25))])
        assert "hook output" in text and "hook prerouting" not in text
        assert f"ip daddr {B} tcp dport 25 meta nftrace set 1" in text
