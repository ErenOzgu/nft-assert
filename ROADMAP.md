# Roadmap

Small steps, in order. A step is done when it has tests, the README says what changed, CI is green and the CHANGELOG
has a line for it. Each step is meant to be a few hours of work, not a rewrite.

- [x] `check --github-annotations`: failures on the pull request
- [ ] `check --only PATTERN` and `--skip PATTERN`: run the expectations whose `from -> to probe` text matches a glob
      (useful while fixing one rule in a large spec)
- [ ] IPv6, step 1: accept `subnet6` in a zone and validate it; no change in behaviour yet (an unknown key stays an error)
- [ ] IPv6, step 2: dual-stack addressing in the lab; the sanity pass sends every flow over both families
- [ ] IPv6, step 3: probes over AF_INET6 and ICMPv6 echo; reject codes for IPv6 (`icmpv6 type` unreachable codes)
- [ ] IPv6, step 4: README, examples and the matrix with an `inet` ruleset that treats both families
- [ ] Other ICMP types as probes (`icmp/time-exceeded` style names), starting with the ones a firewall usually filters
- [ ] A `suggest` command that reads `nft list ruleset` and proposes a starting spec (zones from interfaces, flows from
      the rules); output to be reviewed, never trusted
