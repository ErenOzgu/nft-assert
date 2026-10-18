import json
import xml.etree.ElementTree as ET

from nft_assert import engine, report
from nft_assert.spec import Expectation, Flow

from .fakes import fake_matrix, fake_run, result


class TestText:
    def test_a_run(self):
        text = report.render_text(fake_run())
        lines = text.splitlines()
        assert lines[0] == "nft-assert  spec.toml"
        assert lines[1] == "ruleset     firewall.nft"
        assert (
            "firewall + 3 zones (wan, lan, dmz); 5 flows checked first with no ruleset: all got through"
            in lines[2]
        )
        assert "  PASS  lan -> wan tcp/80          accept" in lines
        assert "  FAIL  wan -> fw tcp/22           drop" in lines
        assert lines[-1] == "3 expectations, 2 pass, 1 fail"

    def test_the_failure_comes_with_the_problem_and_the_trace(self):
        text = report.render_text(fake_run())
        assert "          expected drop, got accept (connection established)" in text
        assert "          what the firewall did with the first packet:" in text
        assert '            inet filter input: rule `iifname "eth0" tcp dport 22 accept` -> accept' in text

    def test_what_the_answering_host_saw_is_shown_only_when_the_spec_asked(self):
        text = report.render_text(fake_run())
        assert text.count("answered by") == 1
        assert "answered by dmz on port 80, which saw the source 192.0.2.2" in text

    def test_there_is_no_clock_in_the_text_so_outputs_can_be_committed(self):
        a, b = fake_run(), fake_run()
        b.seconds = 99.9
        assert report.render_text(a) == report.render_text(b)

    def test_a_single_expectation_is_singular(self):
        run = fake_run()
        run.checks = run.checks[:1]
        assert report.render_text(run).endswith("1 expectation, 1 pass, 0 fail")


class TestMarkdown:
    def test_table_and_failures(self):
        md = report.render_markdown(fake_run())
        assert md.startswith("### nft-assert: 3 expectations, 2 pass, 1 fail")
        assert "| ✅ | `lan -> wan tcp/80` | accept | accept |  |" in md
        assert "| ❌ | `wan -> fw tcp/22` | drop | accept |  |" in md
        assert "which saw the source 192.0.2.2 |" in md
        assert "#### Failures" in md and "* `wan -> fw tcp/22`: expected drop, got accept" in md

    def test_no_failures_section_when_all_pass(self):
        run = fake_run()
        run.checks = [c for c in run.checks if c.ok]
        assert "Failures" not in report.render_markdown(run)


class TestJson:
    def test_shape(self):
        data = json.loads(report.render_json(fake_run()))
        assert data["ok"] is False and data["seconds"] == 1.23
        assert [c["flow"] for c in data["checks"]] == [
            "lan -> wan tcp/80",
            "wan -> fw tcp/22",
            "wan -> 192.0.2.1 tcp/8080",
        ]
        bad = data["checks"][1]
        assert (bad["expected"], bad["got"], bad["ok"]) == ("drop", "accept", False)
        assert bad["trace"] and bad["problems"]
        assert data["checks"][2]["observed"].startswith("answered by dmz")
        assert data["checks"][0]["observed"] is None


class TestJunit:
    def test_valid_xml_with_one_failure(self):
        root = ET.fromstring(report.render_junit(fake_run()))
        assert root.tag == "testsuite" and root.get("tests") == "3" and root.get("failures") == "1"
        cases = root.findall("testcase")
        assert [c.get("name") for c in cases][1] == "wan -> fw tcp/22 drop"
        (failure,) = root.findall("testcase/failure")
        assert "expected drop, got accept" in failure.get("message")
        assert "packet path:" in failure.text

    def test_hostile_text_cannot_break_the_xml(self):
        run = fake_run()
        run.checks[1].problems = ['bad "quote" <tag> & \x00\x07 control']
        run.checks[1].explanation = ["]]> <x/>"]
        root = ET.fromstring(report.render_junit(run))
        assert root.find("testcase/failure") is not None


class TestMatrixAndDiff:
    def test_matrix_table(self):
        md = report.render_matrix(fake_matrix())
        assert md.splitlines()[0] == "| From | To | tcp/22 | udp/53 | icmp |"
        assert md.splitlines()[1] == "|---|---|---|---|---|"
        assert "| fw | a | accept | drop | drop |" in md and "| a | fw | accept | drop | drop |" in md
        assert md.count("\n") == 4 and md.endswith("\n")

    def test_matrix_json(self):
        data = json.loads(report.render_matrix_json(fake_matrix()))
        assert data["endpoints"] == ["fw", "a"]
        assert {"from": "a", "to": "fw", "probe": "udp/53", "outcome": "drop"} in data["flows"]

    def changes(self):
        return [
            engine.Change("lan", "dmz", ("tcp", 3306), "drop", "accept"),
            engine.Change("fw", "lan", ("icmp", None), "accept", "drop"),
        ]

    def test_diff_text_is_sorted_and_counts(self):
        out = report.render_diff(self.changes(), 84)
        assert out.splitlines() == [
            "fw -> lan icmp: accept -> drop",
            "lan -> dmz tcp/3306: drop -> accept",
            "",
            "2 of 84 flows changed",
        ]

    def test_diff_with_nothing_changed(self):
        assert report.render_diff([], 12) == "no flow changed (12 flows compared)"
        assert "No flow changed" in report.render_diff_markdown([], 1)

    def test_diff_markdown_and_json(self):
        md = report.render_diff_markdown(self.changes(), 84)
        assert (
            "### nft-assert diff: 2 of 84 flows changed" in md
            and "| `lan -> dmz tcp/3306` | drop | **accept** |" in md
        )
        data = json.loads(report.render_diff_json(self.changes(), 84))
        assert data["flows"] == 84 and len(data["changed"]) == 2
        assert data["changed"][0] == {
            "from": "fw",
            "to": "lan",
            "probe": "icmp",
            "before": "accept",
            "after": "drop",
        }


def test_facts_are_empty_without_an_observation():
    run = fake_run()
    assert report.facts(run.checks[0]) == ""
    f = Flow("a", "b", "tcp", 1)
    c = engine.CheckResult(Expectation(f, "accept"), result(f, "accept", "", {"label": "b"}), [])
    assert report.facts(c) == ""


class TestGithubAnnotations:
    def test_one_error_line_per_failed_expectation(self):
        out = report.render_github_annotations(fake_run(), "firewall/spec.toml")
        lines = out.splitlines()
        assert len(lines) == 1
        assert lines[0].startswith(
            "::error file=firewall/spec.toml,title=nft-assert%3A wan -> fw tcp/22 should drop::"
        )

    def test_the_message_carries_the_problem_and_the_packet_path_on_one_line(self):
        (line,) = report.render_github_annotations(fake_run(), "spec.toml").splitlines()
        message = line.split("::", 2)[2]
        assert "expected drop, got accept (connection established)" in message
        assert (
            '%0Apacket path: inet filter input: rule `iifname "eth0" tcp dport 22 accept` -> accept'
            in message
        )
        assert "\n" not in line

    def test_nothing_is_printed_when_everything_passed(self):
        run = fake_run()
        run.checks = [c for c in run.checks if c.ok]
        assert report.render_github_annotations(run, "spec.toml") == ""

    def test_special_characters_are_escaped_the_way_github_wants(self):
        run = fake_run()
        run.checks[1].problems = ["100% wrong\r\nsecond line"]
        run.checks[1].explanation = []
        line = report.render_github_annotations(run, "dir,odd:name.toml")
        assert "file=dir%2Codd%3Aname.toml," in line
        assert line.endswith("::100%25 wrong%0D%0Asecond line")

    def test_an_absolute_path_inside_the_workspace_is_made_relative(self):
        spec = "/home/runner/work/repo/repo/firewall/spec.toml"
        out = report.render_github_annotations(fake_run(), spec, "/home/runner/work/repo/repo")
        assert out.startswith("::error file=firewall/spec.toml,")

    def test_a_path_outside_the_workspace_or_a_relative_one_is_left_alone(self):
        outside = report.render_github_annotations(
            fake_run(), "/etc/spec.toml", "/home/runner/work/repo/repo"
        )
        assert outside.startswith("::error file=/etc/spec.toml,")
        sibling = report.render_github_annotations(fake_run(), "/work/repo2/spec.toml", "/work/repo")
        assert sibling.startswith("::error file=/work/repo2/spec.toml,")
        rel = report.render_github_annotations(fake_run(), "spec.toml", "/work/repo")
        assert rel.startswith("::error file=spec.toml,")
