# Contributing

Thanks for considering a contribution. This project exists to give DFIR and detection teams open, deployable coverage for AI/ML attacks — every rule submission, test case, or investigator war story makes the pack more useful for the community.

## Types of contributions welcome

- **New detection rules** (Sigma, YARA, Suricata)
- **Rule tuning** — false positive reports, environment-specific exclusions
- **Test artifacts** — sample logs, benign/malicious files, PCAPs
- **Documentation improvements** — fixes, clarifications, new examples
- **ATLAS / OWASP mapping corrections**
- **New category coverage** — if there's an attack surface not represented

## Rule submission requirements

Every new rule must:

1. **Reference an attack technique** — ATLAS ID, CVE, or published research (paper, advisory, or well-documented blog post from a trusted source)
2. **Include test data** in `tests/` — sample log line, file, or PCAP demonstrating the detection
3. **Document false positives** in the rule's `falsepositives:` section
4. **Use lowercase, snake_case** filenames matching the threat (e.g., `ray_jobs_api_rce.rules`)
5. **Tag with ATLAS techniques** in Sigma rules using the `attack.atlas.txxxx` namespace
6. **Include author and date** fields

## Sigma format

Follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification). Rules should convert cleanly with pySigma using the Elastic backend — run this before submitting:

```bash
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene --without-pipeline your-new-rule.yml
```

Write keyword/content matches in lowercase and rely on case-insensitive
`contains` (the Sigma convention) — do not use the `re|i` modifier to force
case folding, as Lucene's regex engine rejects the `(?i)` flag. See the case
sensitivity note in the README for the Elastic `text`-vs-`keyword` mapping
requirement.

## YARA format

- Test with YARA 4.x (not deprecated 3.x syntax)
- Include metadata: `author`, `date`, `description`, `reference`, `atlas`, `severity`
- Use `filesize` limits where appropriate to avoid scanning huge files
- Avoid regex backreferences (YARA doesn't support them)

## Suricata format

- Assign SID in the local range (1000000–1999999) by default; the maintainer will renumber on merge
- Include `msg:`, `classtype:`, `reference:`, `metadata:` (with ATLAS/CVE), and `sid:`/`rev:`
- Test with `suricata -T -c /etc/suricata/suricata.yaml` to validate

## Testing before submission

Run the existing smoke test suite:

```bash
cd tests/
./validate.sh
```

Your new rule should pass the suite, and ideally add a new test case for the behavior you're detecting.

## Pull request process

1. Fork the repo and create a feature branch (`feat/new-detection-foo` or `fix/rule-bar-fp`)
2. Keep PRs focused — one logical change per PR
3. Update `MAPPINGS.md` if adding a new rule
4. Update the category `README.md` with the new rule name and purpose
5. Describe the attack scenario and test data in the PR description
6. Link to the research/CVE/advisory that motivated the rule

## Questions or ideas?

Open an issue for discussion before writing a large rule — saves effort if the approach needs adjustment or if there's existing coverage.

## Licensing

By submitting a pull request, you agree to license your contribution under the [Apache License 2.0](./LICENSE), the same license as the rest of the project.
