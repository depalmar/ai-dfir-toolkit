# -*- coding: utf-8 -*-
"""Normalise the `description` notes on artifact, credential and MCP rows.

The notes accumulated four styles across 363 rows: sentence case, ALL-CAPS
emphasis, a leading SHOUTED token, and bare lowercase fragments - with a
terminal period on roughly half. They render side by side in one table column
and in one CSV field, so the inconsistency is visible to every reader.

The shouting is also redundant. `PLAINTEXT` duplicates `storage: plaintext`,
`HIGH-VALUE FORENSIC ARTIFACT` duplicates `forensic_value: high`, and a reader
filtering the CSV cannot use either of them. Emphasis belongs in the structured
fields the schema already defines; the note is a caption.

Three rules, all mechanically checkable so `validate.py` can gate them:

1. No shouted prose. An ALL-CAPS token is left alone only when it is an
   identifier - an env var, a constant, a filename, an acronym - never when it
   is a word being emphasised.
2. Sentence-case start, unless the note opens with an identifier or a name that
   is genuinely lowercase (npm, npx, macOS).
3. Terminal period only when the note is more than one sentence. A caption is
   not a sentence, and half-and-half is what made the column look ragged.

Usage:
    python scripts/normalize_notes.py            # rewrite
    python scripts/normalize_notes.py --check    # report only, non-zero on drift
"""
import argparse
import glob
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

# Acronyms and initialisms that are correctly uppercase in running prose. Kept
# deliberately short: anything not here that is ALL-CAPS is either an identifier
# (caught structurally below) or emphasis (which is what we are removing).
# Derived by enumerating every ALL-CAPS token in the corpus and classifying it,
# rather than guessed - the first pass guessed, and turned CWD into "cwd" and
# PKCE into "pkce". Anything not here that is ALL-CAPS is either an identifier
# (caught structurally below) or emphasis, which is what we are removing.
ACRONYMS = {
    "AES", "AI", "AIDR", "API", "APIS", "ARM", "AWS", "BYOK", "CI", "CISA",
    "CLI", "CORS", "CVSS",
    "CPU", "CRUD", "CSV", "CWD", "DB", "DLL", "DNS", "DPAPI", "EAX", "EOL",
    "GCP", "GGUF", "GPU", "GUI", "HTTP", "HTTPS", "IAM", "ID", "IDE", "IOC",
    "IP", "IR", "JS", "KEV",
    "ITW", "JSON", "JWT", "LLM", "LM", "LOCALAPPDATA", "LOLBIN", "MCP", "MFA",
    "MITRE", "ATLAS", "ATT&CK", "NIST", "OWASP", "CVE", "NVD", "KEV", "SIEM",
    "EDR", "DFIR", "TTP", "TTPS", "XDR", "SOC",
    "ML", "MSIX",
    "NPM", "OS", "OSS", "OTLP", "PATH", "PEM", "PID", "PII", "PKCE", "POSIX",
    "PAT", "POST", "PR", "RAG", "REPL", "RCE", "README", "REST", "RPC", "RSA", "SDK", "SQL",
    "WSL", "ACP", "GPUI", "XDG",
    "SSE", "SSH", "SSO", "STS", "TCP", "TLS", "TOML", "TTY", "UI", "URI",
    # WSL and ACP arrived with AIRT-0050/0051. The allowlist is derived from the
    # corpus it was built against, so it is complete only for that corpus - the
    # same way MITRE had to be added when AIRT-0047 first used it. Adding a tool
    # that speaks a new acronym means adding the acronym, or the normalizer
    # quietly writes "wsl".
    "URL", "UUID", "VM", "VPN", "VS", "WAL", "XML", "YAML", "YOLO", "ZIP",
}

# Shouted proper nouns take title case, not lowercase.
PROPER = {"PYTHON": "Python", "TYPESCRIPT": "TypeScript", "JAVASCRIPT": "JavaScript"}

# A token is an identifier - and therefore keeps its case - if it carries any
# structural marker a prose word never would. A hyphen is deliberately NOT such
# a marker: HIGH-VALUE and CLIENT-SIDE are hyphenated prose, and treating the
# hyphen as structural let both of them keep shouting. A leading dash still is,
# because that is a command-line flag.
IDENTIFIER = re.compile(r"[_/\\.:@%$\d>]|^-")

# Names that are lowercase by convention and must not be sentence-cased.
LOWERCASE_NAMES = {
    "npm", "npx", "pnpm", "yarn", "pip", "pipx", "uv", "uvx", "git", "curl",
    "jq", "macOS", "iOS", "iPadOS", "watchOS", "tvOS", "systemd", "launchd",
    "journalctl", "sudo", "bash", "zsh", "sh", "cmd", "powershell", "node",
    "python", "python3", "docker", "kubectl", "ssh", "scp", "rsync",
}

WORD = re.compile(r"[A-Za-z][A-Za-z'-]*")


def _deshout_token(tok: str) -> str:
    """Lowercase a shouted prose word; leave identifiers and acronyms alone."""
    # Strip punctuation BEFORE the identifier test. Testing the raw token meant a
    # sentence-final period made every word look like a filename, so any shouted
    # word that ended a sentence escaped - "NO DEFAULT AUTHENTICATION." lost the
    # first two words and kept the third.
    core = tok.strip("'\"()[],;:.!?")
    if IDENTIFIER.search(core):
        return tok
    # A single capital is an initial or a product name - "Amazon Q", not shouting.
    if len(core) < 2 or not core.isupper():
        return tok
    if core in PROPER:
        return tok.replace(core, PROPER[core])
    # Hyphenated compounds shout as a unit: HIGH-VALUE, CLIENT-SIDE.
    parts = core.split("-")
    if all(p in ACRONYMS for p in parts if p):
        return tok
    lowered = "-".join(p if p in ACRONYMS else PROPER.get(p, p.lower()) for p in parts)
    return tok.replace(core, lowered)


def _sentence_start(text: str) -> str:
    m = WORD.search(text[:1])
    if not m:
        return text          # opens with a path, a quote, a brace - leave it
    first = WORD.match(text)
    if first and first.group(0) in LOWERCASE_NAMES:
        return text
    head = text.split(None, 1)[0] if text.split() else ""
    if IDENTIFIER.search(head):
        return text          # opens with an identifier such as settings.json
    return text[0].upper() + text[1:]


SENTENCE = re.compile(r"([.!?]\s+)([a-z][a-z'-]*)")


def _capitalise_sentences(text: str, after_break: bool = False) -> str:
    """Capitalise the word that opens each sentence.

    De-shouting a word that happened to start a sentence leaves it lowercase -
    "...above. derived, not..." - which reads worse than the shouting did. The
    LOWERCASE_NAMES set is honoured, so "...above. npm installs..." stays put.
    """
    def fix(m):
        lead, word = m.group(1), m.group(2)
        if word in LOWERCASE_NAMES or IDENTIFIER.search(word):
            return m.group(0)
        return lead + word[0].upper() + word[1:]
    out = SENTENCE.sub(fix, text)
    return _sentence_start(out) if after_break else out


def _terminal(text: str) -> str:
    """A caption takes no full stop; prose of two or more sentences takes one."""
    body = text.rstrip()
    stripped = body.rstrip(".")
    # Count sentence breaks in the body, ignoring abbreviations like "incl."
    breaks = len(re.findall(r"[.!?]\s+[A-Z(]", stripped))
    if breaks:
        return stripped + "." if not body.endswith((".", "!", "?")) else body
    return stripped if body.endswith(".") and not body.endswith("..") else body


def clean(text: str) -> str:
    if not text:
        return text
    out = " ".join(_deshout_token(t) for t in text.split())
    out = _sentence_start(_capitalise_sentences(out))
    return _terminal(out)


def clean_prose(text: str) -> str:
    """De-shout a prose field without touching its punctuation.

    `abuse_potential` is a paragraph, not a caption, so the caption rules do not
    apply to it - but "NO AUTHENTICATION BY DESIGN" shouts in the drawer exactly
    the way the row notes did.
    """
    if not text:
        return text
    out = " ".join(_deshout_token(t) for t in text.split())
    return _sentence_start(_capitalise_sentences(out))


def each_note(entry):
    """Yield (container, key) for every note field on an entry."""
    for arts in (entry.get("artifacts") or {}).values():
        for a in arts or []:
            yield a, "description"
            # retention renders in the same column as a description and drifts
            # the same way. "Purged after 14 days" and "PURGED AFTER 14 DAYS."
            # would both be accepted if this were left out.
            yield a, "retention"
    for c in entry.get("credentials") or []:
        yield c, "description"
    for m in entry.get("mcp") or []:
        yield m, "description"
        yield m, "notes"


# Indented only. The entry-level `description:` sits at column 0 and is prose
# about the tool, not a caption on a row - it keeps its full stop and is out of
# scope here.
DESC = re.compile(r"^(\s+)(description|notes|retention):(\s*)(.*)$")
PROSE_KEY = re.compile(r"^(abuse_potential):(\s*)(.*)$")
BLOCK = re.compile(r"^[|>][+-]?\d*$")


def rewrite(raw: str) -> str:
    """Rewrite every description scalar in place, line by line.

    Not a YAML round-trip: re-dumping would lose the comments, the key order and
    the block scalars this repo is written in. Not a whole-string replace either
    - the first version of this did that and silently missed 107 of 289 notes,
    because a folded scalar is not one line and never matched. Working per line
    means a folded scalar keeps its exact wrapping: the transform is word-level,
    so each line can be de-shouted where it sits, and only the first and last
    lines of the block need the sentence-start and terminal-period rules.
    """
    lines = raw.split("\n")
    out, i = [], 0
    while i < len(lines):
        pm = PROSE_KEY.match(lines[i])
        if pm:
            key, gap, value = pm.groups()
            if not BLOCK.match(value.strip()):
                out.append(f"{key}:{gap}{_scalar(value, clean_prose)}"); i += 1; continue
            out.append(lines[i]); i += 1
            while i < len(lines) and (not lines[i].strip()
                                      or lines[i][:1] in (" ", "\t")):
                line = lines[i]
                if line.strip():
                    pad = line[:len(line) - len(line.lstrip())]
                    line = pad + " ".join(_deshout_token(t) for t in line.split())
                out.append(line); i += 1
            continue
        m = DESC.match(lines[i])
        if not m:
            out.append(lines[i]); i += 1; continue
        indent, key, gap, value = m.groups()
        if not BLOCK.match(value.strip()):
            out.append(f"{indent}{key}:{gap}{_scalar(value)}"); i += 1; continue

        # Folded or literal block: collect the more-indented body.
        out.append(lines[i]); i += 1
        body_start, carry = len(out), False
        while i < len(lines) and (not lines[i].strip()
                                  or len(lines[i]) - len(lines[i].lstrip()) > len(indent)):
            line, prev_break = lines[i], carry
            if line.strip():
                pad = line[:len(line) - len(line.lstrip())]
                body_txt = " ".join(_deshout_token(t) for t in line.split())
                line = pad + _capitalise_sentences(body_txt, after_break=prev_break)
                # Mirror SENTENCE exactly: the punctuation must be the last
                # character and must not be an ellipsis. Allowing a trailing
                # quote made `api_key: ..."` look like a sentence end and
                # capitalised the next line's first word.
                carry = bool(re.search(r"(?<!\.)[.!?]$", line.rstrip()))
            out.append(line)
            i += 1
        body = [j for j in range(body_start, len(out)) if out[j].strip()]
        if body:
            first = out[body[0]]
            pad = first[:len(first) - len(first.lstrip())]
            out[body[0]] = pad + _sentence_start(first.lstrip())
            # Terminal punctuation is a property of the whole note, not of its
            # last line, so decide from the joined text and apply to the tail.
            joined = " ".join(out[j].strip() for j in body)
            last = out[body[-1]]
            fixed = _terminal(joined)
            if fixed.endswith(".") and not joined.endswith("."):
                out[body[-1]] = last + "."
            elif joined.endswith(".") and not fixed.endswith("."):
                out[body[-1]] = last.rstrip().rstrip(".")
    return "\n".join(out)


def _scalar(value: str, fn=None) -> str:
    """Transform a single-line value, preserving its quoting."""
    fn = fn or clean
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        q, inner = v[0], v[1:-1]
        return f"{q}{fn(inner)}{q}"
    return fn(v)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only, writes nothing")
    args = ap.parse_args()

    changes, files = [], 0
    for path in sorted(glob.glob(str(ROOT / "catalog" / "*.yml"))):
        raw = Path(path).read_text(encoding="utf-8")
        entry = yaml.safe_load(raw)
        for holder, key in each_note(entry):
            before = holder.get(key) or ""
            after = clean(before)
            if after != before:
                changes.append((entry["id"], before, after))
        new = rewrite(raw)
        if new != raw:
            files += 1
            if not args.check:
                Path(path).write_text(new, encoding="utf-8", newline="\n")

    for eid, before, after in changes[:12]:
        print(f"  {eid}\n    - {before[:100]}\n    + {after[:100]}")
    if len(changes) > 12:
        print(f"  ... and {len(changes) - 12} more")
    print(f"\n{len(changes)} note(s) across {files} file(s) "
          f"{'differ from' if args.check else 'normalised to'} the note style.")
    return 1 if (args.check and changes) else 0


if __name__ == "__main__":
    sys.exit(main())
