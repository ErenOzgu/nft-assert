import random
import tomllib
from pathlib import Path

import pytest

from nft_assert import spec as S
from nft_assert.spec import Flow, SpecError

ZONES = """
[ruleset]
file = "fw.nft"
[zones.lan]
subnet = "10.0.1.0/24"
[zones.wan]
subnet = "192.0.2.0/24"
iface = "eth0"
"""


def parse(text: str, name: str = "spec.toml") -> S.Spec:
    return S.parse(tomllib.loads(text), Path("/specs") / name)


def bad(text: str) -> str:
    with pytest.raises(SpecError) as exc:
        parse(text)
    return str(exc.value)


class TestZones:
    def test_defaults(self):
        s = parse(ZONES)
        lan = s.zones["lan"]
        assert (str(lan.subnet), lan.iface, str(lan.fw_ip), str(lan.host_ip)) == (
            "10.0.1.0/24",
            "lan",
            "10.0.1.1",
            "10.0.1.2",
        )
        assert s.zones["wan"].iface == "eth0"
        assert s.endpoints == ["fw", "lan", "wan"]
        assert s.ruleset == Path("/specs/fw.nft")
        assert s.timeout == 1.0

    def test_explicit_addresses(self):
        s = parse(
            ZONES
            + '[zones.dmz]\nsubnet = "10.0.2.0/24"\nfw_address = "10.0.2.254"\nhost_address = "10.0.2.10"\n'
        )
        assert (str(s.zones["dmz"].fw_ip), str(s.zones["dmz"].host_ip)) == ("10.0.2.254", "10.0.2.10")

    def test_a_small_subnet_has_room_for_both(self):
        s = parse(ZONES.replace("10.0.1.0/24", "10.0.1.0/29"))
        assert (str(s.zones["lan"].fw_ip), str(s.zones["lan"].host_ip)) == ("10.0.1.1", "10.0.1.2")

    def test_a_big_subnet_works_too(self):
        s = parse(ZONES.replace("10.0.1.0/24", "10.0.0.0/8"))
        assert str(s.zones["lan"].host_ip) == "10.0.0.2"

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ('subnet = "10.0.1.0/24"\n[zones.x]\nsubnet = "10.0.1.128/25"', "overlaps zone lan"),
            (
                'subnet = "10.0.1.0/24"\n[zones.x]\nsubnet = "10.9.0.0/24"\niface = "lan"',
                "already used by zone lan",
            ),
            ('subnet = "10.0.1.1/24"', "not an IPv4 network"),
            ('subnet = "10.0.1.0/30"', "between /8 and /29"),
            ('subnet = "10.0.0.0/7"', "between /8 and /29"),
            ('subnet = "fd00::/64"', "not an IPv4 network"),
            ("subnet = 5", "not an IPv4 network"),
            ('subnet = "10.0.1.0/24"\nfw_address = "10.0.2.1"', "not a usable address"),
            ('subnet = "10.0.1.0/24"\nfw_address = "10.0.1.0"', "not a usable address"),
            ('subnet = "10.0.1.0/24"\nhost_address = "10.0.1.255"', "not a usable address"),
            (
                'subnet = "10.0.1.0/24"\nfw_address = "10.0.1.7"\nhost_address = "10.0.1.7"',
                "the same address",
            ),
            ('subnet = "10.0.1.0/24"\nfw_address = "nope"', "not an IPv4 address"),
            ('subnet = "10.0.1.0/24"\niface = "has space"', "not an interface name"),
            ('subnet = "10.0.1.0/24"\niface = "waytoolonginterfacename"', "not an interface name"),
            ('subnet = "10.0.1.0/24"\niface = 5', "not an interface name"),
            ('subnet = "10.0.1.0/24"\nsubnett = 1', "unknown key 'subnett'"),
            ('iface = "x"', "subnet is required"),
        ],
    )
    def test_bad_zones(self, change, message):
        text = ZONES.replace('[zones.lan]\nsubnet = "10.0.1.0/24"', "[zones.lan]\n" + change)
        assert message in bad(text)

    @pytest.mark.parametrize("name", ["fw", "Lan", "1lan", "a b", "a;b", "x" * 16, "ünï", "a.b"])
    def test_bad_zone_names(self, name):
        text = ZONES + f'[zones."{name}"]\nsubnet = "10.0.9.0/24"\n'
        assert "zone" in bad(text)

    def test_at_least_one_zone_and_at_most_eight(self):
        assert "at least one zone" in bad('[ruleset]\nfile = "x"\n')
        many = '[ruleset]\nfile = "x"\n' + "".join(
            f'[zones.z{i}]\nsubnet = "10.{i}.0.0/24"\n' for i in range(9)
        )
        assert "at most 8 zones" in bad(many)

    def test_the_ruleset_file_is_required(self):
        assert "file is required" in bad('[zones.a]\nsubnet = "10.0.1.0/24"\n')
        assert "unknown key 'path'" in bad('[ruleset]\npath = "x"\n[zones.a]\nsubnet = "10.0.1.0/24"\n')


class TestExpectations:
    def test_compact_form_expands_to_one_expectation_per_probe(self):
        s = parse(
            ZONES
            + '[expect.accept]\n"lan -> wan" = ["tcp/80", "udp/53", "icmp"]\n[expect.drop]\n"wan -> fw" = ["tcp/22"]\n'
        )
        assert [str(e) for e in s.expectations] == [
            "lan -> wan tcp/80 accept",
            "lan -> wan udp/53 accept",
            "lan -> wan icmp accept",
            "wan -> fw tcp/22 drop",
        ]

    def test_an_address_can_be_the_destination(self):
        s = parse(ZONES + '[expect.accept]\n"wan -> 192.0.2.1" = ["tcp/8080"]\n')
        assert s.expectations[0].flow == Flow("wan", "192.0.2.1", "tcp", 8080)

    def test_the_firewall_can_be_the_source(self):
        s = parse(ZONES + '[expect.drop]\n"fw -> lan" = ["tcp/25"]\n')
        assert s.expectations[0].flow.src == "fw"

    def test_whitespace_and_case_are_forgiven(self):
        s = parse(ZONES + '[expect.accept]\n" lan->wan " = [" TCP/80 "]\n')
        assert str(s.expectations[0].flow) == "lan -> wan tcp/80"

    @pytest.mark.parametrize(
        ("rule", "message"),
        [
            ('"lan -> nowhere" = ["tcp/22"]', "not a known place"),
            ('"lan => wan" = ["tcp/22"]', "must look like"),
            ('"lan -> lan" = ["tcp/22"]', "from a place to itself"),
            ('"10.0.0.1 -> wan" = ["tcp/22"]', "not a known place"),
            ('"lan -> wan" = "tcp/22"', "give a list"),
            ('"lan -> wan" = []', "give a list"),
            ('"lan -> wan" = ["tcp"]', "give a port"),
            ('"lan -> wan" = ["tcp/0"]', "1 to 65535"),
            ('"lan -> wan" = ["tcp/65536"]', "1 to 65535"),
            ('"lan -> wan" = ["tcp/-1"]', "1 to 65535"),
            ('"lan -> wan" = ["tcp/²"]', "1 to 65535"),
            ('"lan -> wan" = ["tcp/ 22"]', "1 to 65535"),
            ('"lan -> wan" = ["sctp/22"]', "must be one of tcp, udp, icmp"),
            ('"lan -> wan" = ["icmp/8"]', "icmp has no port"),
            ('"lan -> wan" = [22]', "must be a string"),
        ],
    )
    def test_bad_expectations(self, rule, message):
        assert message in bad(ZONES + "[expect.accept]\n" + rule + "\n")

    def test_a_flow_cannot_be_both_accepted_and_dropped(self):
        text = (
            ZONES + '[expect.accept]\n"lan -> wan" = ["tcp/22"]\n[expect.drop]\n"lan -> wan" = ["tcp/22"]\n'
        )
        assert "listed under accept and under drop" in bad(text)

    def test_a_flow_cannot_be_listed_twice(self):
        assert "listed twice under accept" in bad(
            ZONES + '[expect.accept]\n"lan -> wan" = ["tcp/22", "tcp/22"]\n'
        )

    def test_a_typo_in_the_verdict_table_is_an_error_not_a_silent_pass(self):
        message = bad(ZONES + '[expect.dropp]\n"lan -> wan" = ["tcp/22"]\n')
        assert "unknown key 'dropp'" in message and "accept, drop, reject" in message

    def test_a_typo_at_the_top_level_is_an_error(self):
        assert "unknown key 'expects'" in bad(ZONES + '[expects.drop]\n"lan -> wan" = ["tcp/22"]\n')

    def test_too_many_expectations(self):
        ports = ", ".join(f'"tcp/{p}"' for p in range(1, 1001))
        text = (
            ZONES
            + f'[expect.accept]\n"lan -> wan" = [{ports}]\n"wan -> lan" = [{ports}]\n[expect.drop]\n"lan -> fw" = [{ports}]\n'
        )
        assert "too many expectations" in bad(text)


class TestObserve:
    BASE = ZONES + '[expect.accept]\n"wan -> 192.0.2.1" = ["tcp/8080", "icmp"]\n'

    def test_observe_attaches_to_an_accept_expectation(self):
        s = parse(
            self.BASE
            + '[[observe]]\nflow = "wan -> 192.0.2.1 tcp/8080"\nreached = "lan"\nreached_port = 80\nsource_seen = "192.0.2.2"\n'
        )
        o = s.expectations[0].observe
        assert (o.reached, o.reached_port, o.source_seen) == ("lan", 80, "192.0.2.2")
        assert s.expectations[1].observe is None

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ('flow = "wan -> 192.0.2.1 tcp/9"\nreached = "lan"', "must also be listed under [expect.accept]"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"', "say what to check"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"\nreached = "mars"', "reached must be"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"\nreached_port = 0', "reached_port must be a port"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"\nreached_port = true', "reached_port must be a port"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"\nsource_seen = "x"', "not an IPv4 address"),
            ('flow = "wan -> 192.0.2.1 icmp"\nreached = "lan"', "carries no banner"),
            ('flow = "wan -> 192.0.2.1 icmp"\nreached_port = 3', "has no port"),
            ('reached = "lan"', "flow is required"),
            ('flow = "nonsense"\nreached = "lan"', "must look like"),
            ('flow = "wan -> 192.0.2.1 tcp/8080"\nreached = "lan"\nextra = 1', "unknown key 'extra'"),
        ],
    )
    def test_bad_observe(self, body, message):
        assert message in bad(self.BASE + "[[observe]]\n" + body + "\n")

    def test_observe_on_a_flow_expected_to_drop_is_refused(self):
        text = (
            ZONES
            + '[expect.drop]\n"wan -> lan" = ["tcp/22"]\n[[observe]]\nflow = "wan -> lan tcp/22"\nreached = "lan"\n'
        )
        assert "must also be listed under [expect.accept]" in bad(text)


class TestMatrixAndTimeout:
    def test_defaults(self):
        s = parse(ZONES)
        assert s.matrix.probes == [("tcp", 22), ("tcp", 80), ("tcp", 443), ("udp", 53), ("icmp", None)]

    def test_custom(self):
        s = parse(ZONES + "[matrix]\ntcp = [25]\nudp = []\nicmp = false\n")
        assert s.matrix.probes == [("tcp", 25)]

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ("tcp = 22", "list of ports"),
            ("tcp = [0]", "list of ports"),
            ("tcp = [true]", "list of ports"),
            ("tcp = [22, 22]", "no duplicates"),
            ("icmp = 1", "true or false"),
            ("colour = 1", "unknown key"),
        ],
    )
    def test_bad_matrix(self, body, message):
        assert message in bad(ZONES + "[matrix]\n" + body + "\n")

    def test_a_matrix_that_would_send_too_many_flows(self):
        zones = "".join(f'[zones.z{i}]\nsubnet = "10.{i}.0.0/24"\n' for i in range(8))
        ports = ", ".join(map(str, range(1, 51)))
        text = f'[ruleset]\nfile = "x"\n{zones}[matrix]\ntcp = [{ports}]\nudp = [{ports}]\n'
        assert "at most 5000" in bad(text)

    @pytest.mark.parametrize("value", ["0.1", "31", "true", '"1"', "-1"])
    def test_bad_timeout(self, value):
        assert "timeout must be" in bad(f"timeout = {value}\n" + ZONES)

    def test_timeout(self):
        assert parse("timeout = 2\n" + ZONES).timeout == 2.0


class TestLoad:
    def test_loads_a_file_and_resolves_the_ruleset_next_to_it(self, tmp_path):
        (tmp_path / "s.toml").write_text(ZONES)
        s = S.load(tmp_path / "s.toml")
        assert s.ruleset == (tmp_path / "fw.nft").resolve()

    def test_missing_file(self, tmp_path):
        with pytest.raises(SpecError, match="cannot read"):
            S.load(tmp_path / "nope.toml")

    def test_not_toml(self, tmp_path):
        (tmp_path / "s.toml").write_text("this is [not toml")
        with pytest.raises(SpecError, match="not valid TOML"):
            S.load(tmp_path / "s.toml")

    def test_not_utf8(self, tmp_path):
        (tmp_path / "s.toml").write_bytes(b"\xff\xfe\x00")
        with pytest.raises(SpecError, match="UTF-8"):
            S.load(tmp_path / "s.toml")

    def test_a_directory(self, tmp_path):
        with pytest.raises(SpecError, match="cannot read"):
            S.load(tmp_path)

    def test_a_huge_file_is_refused_unread(self, tmp_path):
        (tmp_path / "s.toml").write_text("#" * (S.MAX_SPEC_BYTES + 1))
        with pytest.raises(SpecError, match="larger than"):
            S.load(tmp_path / "s.toml")


def test_the_destination_address(tmp_path):
    s = parse(ZONES)
    assert S.destination_address(s, "lan", "fw") == "10.0.1.1"
    assert S.destination_address(s, "lan", "wan") == "192.0.2.2"
    assert S.destination_address(s, "lan", "8.8.8.8") == "8.8.8.8"
    with pytest.raises(SpecError):
        S.destination_address(s, "fw", "fw")


def test_every_committed_example_spec_parses():
    for path in sorted((Path(__file__).resolve().parent.parent / "examples").glob("*/spec.toml")):
        assert S.load(path).expectations, path


@pytest.mark.parametrize("seed", range(8))
def test_mutated_specs_either_parse_or_say_why(seed):
    """Random damage to a valid spec must give a SpecError or a Spec, never another exception."""
    original = (Path(__file__).resolve().parent.parent / "examples" / "edge" / "spec.toml").read_text()
    rng = random.Random(seed)
    for _ in range(150):
        chars = list(original)
        for _ in range(rng.randint(1, 6)):
            i = rng.randrange(len(chars))
            op = rng.choice(["drop", "dup", "swap", "digit", "quote"])
            if op == "drop":
                del chars[i]
            elif op == "dup":
                chars.insert(i, chars[i])
            elif op == "swap" and i + 1 < len(chars):
                chars[i], chars[i + 1] = chars[i + 1], chars[i]
            elif op == "digit":
                chars[i] = rng.choice("0123456789²٣-/.")
            else:
                chars[i] = rng.choice("\"'[]=,\n")
            if not chars:
                break
        try:
            raw = tomllib.loads("".join(chars))
        except tomllib.TOMLDecodeError:
            continue
        try:
            S.parse(raw, Path("/specs/spec.toml"))
        except SpecError:
            pass
