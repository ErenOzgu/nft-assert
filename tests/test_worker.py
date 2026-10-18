import errno
import io
import json
import os
import socket
import subprocess
import sys
import time

import pytest

from nft_assert import worker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def listener():
    """A real ``worker listen`` process on loopback; yields (tcp port, udp port)."""
    tcp, udp = free_port(), free_port()
    env = dict(os.environ, PYTHONPATH=ROOT)
    p = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "nft_assert.worker",
            "listen",
            "--label",
            "box",
            "--bind",
            "127.0.0.1",
            "--tcp",
            str(tcp),
            "--udp",
            str(udp),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert p.stdout.readline().strip() == "READY"
    yield tcp, udp
    p.stdin.close()
    assert p.wait(timeout=10) == 0


class TestBanner:
    def test_roundtrip(self):
        assert worker.parse_banner(worker.banner("dmz", "10.0.1.2", "10.0.2.2:80").decode()) == {
            "label": "dmz",
            "peer": "10.0.1.2",
            "local": "10.0.2.2:80",
        }

    @pytest.mark.parametrize("text", ["", "hello", "NFTA", "NFTA \n", "nfta label=x", "SSH-2.0-OpenSSH_9.6"])
    def test_anything_else_is_not_a_banner(self, text):
        assert worker.parse_banner(text) == {}

    def test_only_known_fields_are_taken(self):
        assert worker.parse_banner("NFTA label=a evil=b peer=1.2.3.4 junk") == {
            "label": "a",
            "peer": "1.2.3.4",
        }


def test_the_checksum_of_the_textbook_ip_header():
    header = bytes.fromhex("45000073000040004011" + "0000" + "c0a80001c0a800c7")
    assert worker._checksum(header) == 0xB861
    assert worker._checksum(b"\x01") == worker._checksum(b"\x01\x00")  # odd lengths are padded


class TestAgainstARealListener:
    def test_tcp_accept_carries_the_banner(self, listener):
        tcp, _ = listener
        r = worker.tcp_probe("127.0.0.1", tcp, 2)
        assert r["outcome"] == "accept"
        assert r["banner"] == {"label": "box", "peer": "127.0.0.1", "local": f"127.0.0.1:{tcp}"}

    def test_tcp_to_a_closed_port_is_a_reject(self, listener):
        r = worker.tcp_probe("127.0.0.1", free_port(), 2)
        assert r["outcome"] == "reject" and "refused" in r["detail"].lower()

    def test_udp_accept_carries_the_banner(self, listener):
        _, udp = listener
        r = worker.udp_probe("127.0.0.1", udp, 2)
        assert r["outcome"] == "accept"
        assert r["banner"]["label"] == "box" and r["banner"]["local"] == f"127.0.0.1:{udp}"

    def test_udp_to_a_closed_port_is_a_reject(self, listener):
        assert worker.udp_probe("127.0.0.1", free_port(), 2)["outcome"] == "reject"

    @pytest.mark.skipif(os.geteuid() != 0, reason="a raw ICMP socket needs root")
    def test_icmp_echo_to_loopback_is_an_accept(self, listener):
        r = worker.icmp_probe("127.0.0.1", 2)
        assert r["outcome"] == "accept" and "echo reply" in r["detail"]

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can open the socket")
    def test_icmp_without_root_says_why(self):
        r = worker.icmp_probe("127.0.0.1", 1)
        assert r["outcome"] == "error" and "needs root" in r["detail"]

    def test_the_listener_ends_when_its_input_closes(self, listener):
        pass  # the fixture closes stdin and requires exit code 0

    def test_hundreds_of_probes_at_once_are_all_answered(self, listener):
        port = free_port()
        lines = "".join(
            json.dumps({"id": i, "proto": "tcp", "dst": "127.0.0.1", "port": port, "timeout": 2}) + "\n"
            for i in range(600)
        )
        out = io.StringIO()
        worker.probe_loop(io.StringIO(lines), out)
        answers = [json.loads(line) for line in out.getvalue().splitlines()]
        assert sorted(a["id"] for a in answers) == list(range(600))
        assert {a["outcome"] for a in answers} == {"reject"}


class TestOutcomes:
    class Sock:
        def __init__(self, exc):
            self.exc = exc

        options: list = []

        def settimeout(self, _):
            pass

        def setsockopt(self, *args):
            self.options.append(args)

        def connect(self, _):
            raise self.exc

        send = recv = lambda *a: (_ for _ in ()).throw(AssertionError)

        def close(self):
            pass

    def patched(self, monkeypatch, exc):
        monkeypatch.setattr(worker.socket, "socket", lambda *a, **k: self.Sock(exc))

    def test_silence_is_a_drop(self, monkeypatch):
        self.patched(monkeypatch, TimeoutError())
        r = worker.tcp_probe("10.0.0.1", 22, 0.5)
        assert r["outcome"] == "drop" and "0.5" in r["detail"]

    @pytest.mark.parametrize("code", sorted(worker.REJECT_ERRNOS))
    def test_these_errors_are_the_firewall_saying_no(self, monkeypatch, code):
        self.patched(monkeypatch, OSError(code, os.strerror(code)))
        assert worker.tcp_probe("10.0.0.1", 22, 1)["outcome"] == "reject"
        assert worker.udp_probe("10.0.0.1", 22, 1)["outcome"] == "reject"

    def test_udp_asks_the_kernel_to_report_every_icmp_error(self, monkeypatch):
        self.Sock.options = []
        self.patched(monkeypatch, OSError(errno.EHOSTUNREACH, "no route"))
        worker.udp_probe("10.0.0.1", 53, 1)
        assert (
            socket.SOL_IP,
            11,
            1,
        ) in self.Sock.options  # IP_RECVERR: without it a host-unreachable is ignored

    @pytest.mark.parametrize("code", [errno.EACCES, errno.EMFILE, errno.EADDRNOTAVAIL, errno.ENETDOWN])
    def test_other_errors_are_errors_not_verdicts(self, monkeypatch, code):
        self.patched(monkeypatch, OSError(code, os.strerror(code)))
        assert worker.tcp_probe("10.0.0.1", 22, 1)["outcome"] == "error"
        assert worker.udp_probe("10.0.0.1", 22, 1)["outcome"] == "error"


class TestProbeLoop:
    def run(self, lines):
        out = io.StringIO()
        worker.probe_loop(io.StringIO("\n".join(lines) + "\n"), out)
        return [json.loads(x) for x in out.getvalue().splitlines()]

    def test_one_answer_per_valid_request_carrying_its_id(self):
        r = self.run([json.dumps({"id": 41, "proto": "sctp", "dst": "10.0.0.1", "port": 1, "timeout": 1})])
        assert (
            len(r) == 1
            and r[0]["id"] == 41
            and r[0]["outcome"] == "error"
            and "unknown protocol" in r[0]["detail"]
        )

    def test_broken_lines_are_skipped_and_do_not_end_the_worker(self):
        good = json.dumps({"id": 1, "proto": "sctp", "dst": "x", "port": 1, "timeout": 1})
        r = self.run(["", "not json", "[]", "{}", '{"id": 5}', '"text"', "null", good])
        assert [a["id"] for a in r] == [1]

    def test_a_bug_in_one_probe_is_reported_not_raised(self):
        r = self.run([json.dumps({"id": 2, "proto": "tcp", "dst": "10.0.0.1", "port": "x", "timeout": 1})])
        assert r[0]["outcome"] == "error" and "ValueError" in r[0]["detail"]


def test_main_needs_a_mode():
    with pytest.raises(SystemExit):
        worker.main([])


def test_a_listener_that_cannot_bind_says_so():
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    s.listen()
    port = s.getsockname()[1]
    try:
        p = subprocess.run(
            [sys.executable, "-m", "nft_assert.worker", "listen", "--label", "x", "--tcp", str(port)],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=ROOT),
            timeout=20,
            input="",
        )
    finally:
        s.close()
    assert p.returncode != 0 and "READY" not in p.stdout
    assert "Address already in use" in p.stderr


def test_probe_timing_is_bounded_by_the_timeout(monkeypatch):
    class Slow:
        def settimeout(self, _):
            pass

        def connect(self, _):
            raise TimeoutError()

        def close(self):
            pass

    monkeypatch.setattr(worker.socket, "socket", lambda *a, **k: Slow())
    t = time.monotonic()
    worker.tcp_probe("10.0.0.1", 1, 0.3)
    assert time.monotonic() - t < 1


class TestIcmpMatching:
    """The raw socket sees every ICMP message in the namespace, so only the ones about our own echo count."""

    @staticmethod
    def ip(payload: bytes) -> bytes:
        return bytes([0x45]) + bytes(19) + payload  # a 20-byte IPv4 header the code skips by its length field

    @staticmethod
    def icmp(kind: int, code: int, ident: int, seq: int, tail: bytes = b"") -> bytes:
        import struct

        return struct.pack("!BBHHH", kind, code, 0, ident, seq) + tail

    def run(self, monkeypatch, responder):
        import struct

        sent = {}

        class Raw:
            def __init__(self, *a):
                self.queue = []

            def settimeout(self, _):
                pass

            def sendto(self, packet, addr):
                sent["ident"], sent["seq"] = struct.unpack("!HH", packet[4:8])
                self.queue = [
                    (self_outer.ip(p), ("10.0.0.1", 0)) for p in responder(*struct.unpack("!HH", packet[4:8]))
                ]

            def recvfrom(self, _):
                if self.queue:
                    return self.queue.pop(0)
                raise TimeoutError

            def close(self):
                pass

        self_outer = self
        monkeypatch.setattr(worker.socket, "socket", Raw)
        return worker.icmp_probe("10.0.0.1", 0.3)

    def quoted_request(self, ident, seq, kind=8):
        inner_ip = bytes([0x45]) + bytes(19)
        return self.icmp(3, 13, 0, 0, inner_ip + self.icmp(kind, 0, ident, seq))

    def test_an_echo_reply_to_us_is_an_accept(self, monkeypatch):
        r = self.run(monkeypatch, lambda i, s: [self.icmp(0, 0, i, s)])
        assert r["outcome"] == "accept"

    def test_an_unreachable_that_quotes_our_request_is_a_reject(self, monkeypatch):
        r = self.run(monkeypatch, lambda i, s: [self.quoted_request(i, s)])
        assert r["outcome"] == "reject" and "code 13" in r["detail"]

    def test_replies_to_somebody_elses_ping_are_ignored(self, monkeypatch):
        r = self.run(monkeypatch, lambda i, s: [self.icmp(0, 0, i ^ 1, s), self.icmp(0, 0, i, s + 1)])
        assert r["outcome"] == "drop"

    def test_a_message_that_is_not_an_echo_reply_but_has_our_numbers_is_ignored(self, monkeypatch):
        r = self.run(monkeypatch, lambda i, s: [self.icmp(8, 0, i, s), self.icmp(13, 0, i, s)])
        assert r["outcome"] == "drop"

    def test_an_unreachable_about_another_packet_is_ignored(self, monkeypatch):
        udp_like = (
            self.quoted_request(0, 0)[:28] + bytes([17, 0, 0, 0]) + b"\0" * 4
        )  # does not start with an echo request
        r = self.run(
            monkeypatch,
            lambda i, s: [udp_like, self.quoted_request(i, s, kind=0), self.quoted_request(i ^ 7, s)],
        )
        assert r["outcome"] == "drop"

    def test_a_truncated_message_is_ignored(self, monkeypatch):
        r = self.run(monkeypatch, lambda i, s: [b"\x00\x00", self.icmp(3, 1, 0, 0)])
        assert r["outcome"] == "drop"
