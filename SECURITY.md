# Security Policy

## Reporting issues with the detection content

This repository publishes detection rules for AI/ML attacks. If you believe a rule is **incorrect, dangerous, or could be weaponized**, please do not open a public issue. Instead, email the maintainer directly (see GitHub profile for contact).

Examples of what belongs in a private report:
- A rule whose logic could reveal exploitable information about an organization's defenses
- A test artifact that works as a functional exploit rather than a safe test case
- Any content you believe crosses the line between detection and attack enablement

## Reporting bugs, false positives, or improvements

For normal false-positive reports, rule bugs, tuning issues, or coverage gaps, **please use public issues** — open discussion benefits the community. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Scope

This repository contains:
- Detection rule files (Sigma, YARA, Suricata)
- Synthetic test artifacts clearly marked as test data
- Documentation

This repository does NOT contain:
- Real malware samples
- Working exploits
- Sensitive organizational data
- Credentials

If you find anything in this repo that violates the above, please report it privately.

## A note on research ethics

All rules in this pack target publicly disclosed attack techniques (CVEs, published research, vendor advisories). No rule is based on private threat intelligence or ongoing incidents. If you contribute new rules, please follow the same standard — contribute coverage for public techniques only.
