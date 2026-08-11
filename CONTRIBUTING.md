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

## Artifact catalog contributions

The [`artifacts/`](./artifacts/) catalog has its own submission rules, because it
is reference data rather than detection logic.

### Adding a tool

1. Check it does not already exist: `grep -ril "<tool>" artifacts/catalog/`
2. Scaffold: `python skills/agent-artifact-catalog/scripts/new_entry.py "Tool Name"`
3. Research it — see `skills/agent-artifact-catalog/references/research-checklist.md`
4. Validate: `cd artifacts && python scripts/validate.py`
5. Regenerate feeds: `python scripts/export.py && python scripts/export_forensicartifacts.py`
6. Commit the entry **and** the regenerated `artifacts/docs/api/` in the same commit
7. Open a PR describing how you verified the paths

### Catalog rules

**IDs are permanent.** Never renumber an existing entry — downstream detections
reference them. New entries take the next free ID.

**Confidence must reflect provenance, not conviction.** If you did not verify a
path on a real host or in vendor documentation, it is not `high`. Mark
single-source artifacts with `unverified: true`. CI enforces this.

**Omit rather than guess.** A missing field is honest. A guessed one becomes
somebody's broken detection.

**Cite your sources** in the `references` block with an access date — several of
these tools change paths between releases.

**Defensive content only.** Document where artifacts live and what they prove.
No exploit code, no working attack tooling, no step-by-step abuse instructions.

### Catalog detections

Sigma only — no SPL, no KQL, no proprietary query language. Put the rule in
`artifacts/detections/sigma/`, give it a fresh UUID, and confirm it converts:

```bash
sigma convert -t splunk artifacts/detections/sigma/your_rule.yml
cd artifacts && python scripts/validate.py
```

Rate `level` honestly and fill in `falsepositives`. A rule that fires constantly
in its target environment is worse than no rule, because it teaches people to
ignore the whole feed.

### Case studies

Only for documented, dated, publicly reported incidents. Include concrete IOCs
(paths, package names and versions, commit hashes, network destinations),
response actions, and the transferable lesson. No IOCs, no case study.

### Reporting a catalog error

Open an issue with the entry ID, the field, what it says, what it should say, and
how you verified. Corrections are logged in `artifacts/docs/VERIFICATION.md`.

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
