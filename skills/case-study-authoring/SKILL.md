---
name: case-study-authoring
description: >-
  Research, author, audit and validate AI DFIR case studies and threat actor
  profiles - the incident layer of the artifact catalog under
  artifacts/case-studies/ and artifacts/intel/actors/. Use this skill whenever
  the user asks to add or update a case study, turn a vendor report or an
  intel-candidate issue into a case, add indicators or detections to an
  existing case, link a case to an actor, create or revise an AIRT-TA actor
  profile, or audit how well a case is sourced. Also use it when the user names
  an incident or a campaign and asks whether it belongs in the catalog, asks how
  confident an attribution is, or says a case "only has one source" - even if
  they do not use the words case study.
---

# Case Study and Actor Profile Authoring

A case study asserts things about somebody else's incident. The reader is a
responder who will act on it during their own, so the entry has to say what
happened, what to look for, and how far each claim can be trusted. Most of the
work is the last part.

Run every command from `artifacts/` unless a line says otherwise.

## The one rule that decides confidence

**Count the parties who wrote from their own data.** Nothing else counts.

Sort every source into one of four kinds before writing a word:

| Kind | What it is | Counts as a party |
|---|---|---|
| Observer | Saw the activity in its own telemetry, samples or systems | Yes |
| Affected party | The vendor, platform or victim confirming it happened to them | Yes, for what they confirm and no further |
| Relay | Repeats an observer: trade press, a MITRE ATLAS or ATT&CK entry whose only reference is the vendor post, a government advisory that credits the vendor for its indicators | No |
| Agreement | A second party saying the first party's conclusion is consistent with what it saw | No, for the conclusion. Yes, for what it saw |

Then:

- `high` - two or more parties from their own data agree, or the affected
  party's own documentation states it.
- `medium` - one party, however authoritative. Vendor disclosure of an incident
  nobody else has corroborated is `medium`, whatever the vendor's reputation.
- `low` - inferred, or a single source that is itself second-hand.

"Widely corroborated in trade press" is not corroboration. Three cases carried
`high` on that phrase until the November 2026 audit, and one was lowered.

A case usually has **layers with different support**. Rate the layer that is the
reason the case is in this catalog, and say so in `basis`. AIRT-CS-0024 is the
worked example: four parties confirm the intrusion, one asserts that an AI agent
drove it, and the responders say in terms that they cannot confirm that. It is
`medium`, because the AI is why it is here.

## Workflow

### 1. Decide whether it is a case at all

- **No indicators, no case study.** Reported AI use with nothing a responder can
  search for is a `sighting` on an actor profile, not a case.
- Check for an existing case first: `grep -ril "<name or CVE>" case-studies/`.
  Update in place. `AIRT-CS-NNNN` ids are permanent, like entry ids.
- A new case takes the next free id: `ls case-studies/ | tail -1`.

### 2. Find every party, not only the first report

The first report is rarely the only one and often not the best one for
indicators. Look for, in this order:

1. The affected vendor's own advisory or trust page. It usually has the
   complete indicator list and the timeline.
2. Responders who saw it in customer environments: managed security providers,
   incident response firms. They report what was actually taken and which
   indicator did what.
3. Other research teams who examined the same samples or infrastructure.
4. The platform that hosted or relayed it, confirming a takedown.

Follow the citations in each report. A report that credits another one is
telling you who the observer is.

### 3. Read the page, not a summary of it

`accessed` on a reference means somebody read that page on that date. A search
result's snippet is a third party's rendering and does not earn the stamp. From
a restricted runner, a live Firecrawl fetch (`maxAge: 0`, check the status code
and source URL) is a read of the page. Ask it for direct quotes when a field is
verbatim.

If an agent did the reading, verify anything you will quote, every hash and
every attribution statement yourself before it is committed. Note which facts
you verified and which you took from the agent.

Before naming an organisation the repository has never named, run
`git grep -il "<name>"`. Then check it against the employer rule in `CLAUDE.md`:
the terms are in a CI secret, not in the repository, so the check that can see
them runs only once a pull request exists. If there is any doubt, ask the owner
before the commit, because a pull request preserves every commit it was opened
with.

### 4. Write `basis` and `contested`

`basis` answers three questions in plain sentences: who observed what, what
rests on one party alone, and what nobody states. Name the layer the confidence
applies to.

`contested` is for disagreement, and it is required reading for a responder.
Record it; do not resolve it. Typical entries:

- Parties counting different things (tenants attempted, tenants authenticated,
  tenants with follow-on activity). Say they are different numbers and must not
  be added.
- Parties describing one indicator differently.
- A source that disagrees with itself. Record both forms and tell the reader to
  search for both.
- How autonomous the AI was. This is contested in nearly every agentic case and
  is the thing a responder most needs to be able to adjudicate.
- A later re-attribution, with who made it and how sure they said they were.

### 5. Write the indicators

- Types are a closed enum in `schema/case-study.schema.json`. Defang addresses
  as `1.2.3[.]4` and malicious domains and URLs the same way. Leave a legitimate
  service the campaign abused (a public mining pool, a provider API) plain, and
  say in the description that it is not an indicator alone.
- Each description says **who reported it and what it did**, when sources differ
  on that. "Listed by one party for X; another saw it only in Y" is more useful
  than a bare address.
- Say what a hash is a hash of. A package hash finds a download; a file hash
  finds an install. They are not interchangeable.
- An identifier that every tenant or host sees daily (a first-party client id, a
  common user agent) is a `behavior` or `pattern` with the condition that makes
  it suspicious, never an atomic indicator. The feeds drop the description, and
  somebody will block on the bare value.
- Baselines are indicators too. What the legitimate activity looks like is often
  the fastest test.
- Artefacts reported for the tool in *other* intrusions may be listed, labelled
  as not observed for this actor.
- Leave out actor handles, personal names, contact details and wallet
  addresses. Private individuals are not profiled.
- Publish what the source published. If a source lists forty hashes, take the
  ones its own text discusses and point at the file for the rest.

### 6. Link actors and victims only as stated

- An actor link carries two confidences. `link_confidence` is ours and follows
  the counting rule above: one attributing party is `medium`.
  `stated_confidence` is the attributor's own words, verbatim, in quotes.
- Overlap is not an alias. "Overlaps with activity tracked as X" goes in the
  profile's `basis`, not in `aliases`.
- When an attribution covers only part of a case, or the attributor hedges, use
  `role: suspected` and say which part in `contested`. A profile derives its
  techniques and indicators from every linked case, so a loose link contaminates
  the profile.
- Victims are only what a source states. A sector with no term in
  `schema/intel-vocab.json` is left out and named in `victims.basis`.
- Techniques, victims, indicators, detections and dates on an actor profile are
  derived by `scripts/intel_graph.py`. Author only the identity.

### 7. Link detections honestly

`detections` lists rule file names that exist in the repository. If no rule
fits, leave the list empty and say so in `lesson`; do not link a rule that only
shares a keyword. If you write a rule for the case:

- Sigma only. Prove it parses: `sigma convert -t lucene --without-pipeline <rule>`.
- Say in the rule's description whether it has been fired against real events.
  Most have not.
- Give it a row in `MAPPINGS.md` and run `python scripts/sync_mappings.py`.
- Remember where the AI ran. When it ran on the actor's side, the rule reads
  what the victim records and says nothing about whether a model was involved.
  Say that in the rule.

### 8. Write in our own words

Summaries are ours. Quote only attribution statements and confidence wording.
Never paste a source's prose, and take only facts - ids, dates, names, URLs -
from CC BY-SA sources. Notes follow the caption style: sentence case, no shouted
words, a terminal period only when the note is more than one sentence.

### 9. Regenerate and gate

```bash
python scripts/intel_graph.py --export        # intel.json, STIX, Maltego
python scripts/export.py                      # detections index, if a rule changed
python scripts/readme_counts.py
python scripts/intel_graph.py --check
python scripts/validate_techniques.py
python scripts/cve_status.py                  # a cited CVE must be in the pin
python scripts/build_site.py --check
(cd .. && python artifacts/scripts/validate_mappings.py)
```

`cve_status.py` fails on a CVE that is cited and not pinned. Re-pinning needs
`www.cisa.gov`; from a runner that cannot reach it, describe the vulnerability
without its id and leave a note.

Update the root `CHANGELOG.md`, and the figures in `CLAUDE.md` if indicator or
rule totals moved. Commit the case and the regenerated `docs/api/` together.

## Auditing an existing case

Ask of each case, in this order, and stop at the first failure:

1. Does every reference resolve, and is it the page the title says it is?
2. Sort the references by the table above. How many parties are left?
3. Does `confidence` match that count for the layer that matters?
4. Does the source publish indicators the case does not carry?
5. Has anybody re-attributed, corrected or withdrawn anything since the case
   was written? Vendors update advisories for weeks.
6. Does a rule exist now that did not when the case was written?

Record what the audit did **not** change as well as what it did. A case that
stays single-source after a search for a second one should say that a search
was made.

## Checklist before commit

- [ ] Every reference was read from the page and carries `accessed`
- [ ] `basis` names who observed what and which layer the confidence rates
- [ ] `contested` records every disagreement found, unresolved
- [ ] No indicator is a bare value that legitimate activity also produces
- [ ] No private individual, handle, wallet or contact detail
- [ ] Attribution wording in `stated_confidence` is verbatim
- [ ] New organisation names checked with `git grep` and against the employer rule
- [ ] Feeds regenerated, every gate at zero problems
