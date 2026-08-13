# Verifying catalogued paths on a real host

This is the work that cannot be done from CI, and it is the highest-value work
available on the catalog. 17 entries are `medium` and 4 are `low` purely because
their paths came from documentation rather than from a machine. Turning one of
those into a verified path is worth a pull request on its own.

**Partial progress is welcome.** One entry, one OS, one tool version.

## The rule that is not negotiable

**Check existence, permissions and structure. Never read credential file
contents.**

`~/.claude/.credentials.json`, `~/.codex/auth.json` and `~/.gemini/oauth_creds.json`
hold live tokens. The forensic question is *"does this exist and what mode is
it"*. The secret itself must never reach a transcript, a commit, a screenshot or
an issue comment.

```bash
ls -la ~/.codex/                      # fine
stat -c "%a %n" ~/.codex/auth.json    # fine  (macOS: stat -f "%Sp %N")
jq 'keys' ~/.claude/settings.json     # fine - key names, not values
cat ~/.codex/auth.json                # NEVER
```

If you are unsure whether a file holds a secret, treat it as though it does.

## The fast path

`scripts/verify_host.py` does the whole sweep for the OS you are on. It stats
paths and never opens them, so it cannot leak a token.

```bash
cd artifacts
python scripts/verify_host.py                  # every path applicable to this OS
python scripts/verify_host.py --entry AIRT-0001
python scripts/verify_host.py --only-found     # just the hits
python scripts/verify_host.py --markdown       # a table to paste into a PR
```

It ends with the list that matters:

```
3 path(s) present on this host that the catalog rates medium or low.
These are the findings worth recording - note the tool version, then raise the
confidence and log it in docs/VERIFICATION.md
```

### What a HIT and a MISS each mean

A **HIT** on a `medium` or `low` path is the finding. The path is real; record
the OS, the OS version and the **tool version**, raise the entry's confidence,
and log it.

A **MISS** means only that the path is not on *this* host. The script cannot
distinguish "the catalogued path is wrong" from "the tool is not installed", and
it never claims the former. That judgement needs the tool actually installed and
used at least once — many of these paths are created lazily on first run, not at
install time.

So: **install the tool, run it once, then re-check.** A MISS on a machine where
the tool has never run tells you nothing.

## Doing it by hand

Per OS, for a path such as `~/.claude/`:

```bash
# macOS / Linux
ls -la ~/.claude/
stat -c "%a %U:%G %n" ~/.claude/.credentials.json     # Linux
stat -f "%Sp %Su:%Sg %N" ~/.claude/.credentials.json  # macOS
find ~/.claude -maxdepth 2 -type f -printf "%M %p\n"  # structure, no contents
```

```powershell
# Windows
Get-ChildItem "$env:APPDATA\npm" -Force | Select-Object Mode,Length,Name
(Get-Acl "$env:USERPROFILE\.claude.json").Access |
  Select-Object IdentityReference,FileSystemRights
Get-AppxPackage -Name *Claude* | Select-Object PackageFamilyName
```

Getting the tool version matters as much as the path, because a path is only
true for a version range:

```bash
claude --version ; codex --version ; ollama --version
pip show open-interpreter | head -3
npm ls -g --depth=0
```

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Select-Object DisplayName,DisplayVersion | Where-Object DisplayName -match 'Cursor|Warp|Docker'
```

## Listeners and processes

Several entries turn on whether something is bound beyond loopback. That is a
finding, not inventory:

```bash
ss -ltnp 2>/dev/null | grep -E '11434|1234|8000|8283|12434|7860|5678'   # Linux
lsof -nP -iTCP -sTCP:LISTEN | grep -E '11434|1234|8000|8283|12434'      # macOS
```

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -in 11434,1234,8000,8283,12434,7860,5678 |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

A `0.0.0.0` bind with no authentication is worth its own line in
`docs/VERIFICATION.md` regardless of what the path check found.

## Recording what you found

Add a row to `docs/VERIFICATION.md` for **every entry you checked**, including
the ones that were already right:

| Scope | Field | Was | Now | Basis |
|---|---|---|---|---|
| `AIRT-00NN` | artifact_path | `~/.tool/config.json` | **`~/.config/tool/config.json`** | CORRECTED. Verified on macOS 15.4, tool v2.1.0, 2026-08-13. |
| `AIRT-00NN` | confidence | medium | **high** | Verified on Ubuntu 24.04, tool v1.9.2, 2026-08-13. Path and mode as documented. |

"Re-confirmed, no change" is a result. Without it the next pass cannot tell what
has already been looked at, and the same handful of entries get checked
repeatedly while others are never touched.

Then set `last_verified` on the entry to the date you checked it. `validate.py`
reports anything past 90 days, and anything never checked at all.

## Before you open the pull request

```bash
cd artifacts
python scripts/validate.py
python scripts/export.py && python scripts/export_forensicartifacts.py
python scripts/export_kape.py && python scripts/export_velociraptor.py
python ../collectors/gen_credential_targets.py
python scripts/build_site.py --check
```

All five regenerate scripts, not the ones your change looks like it touched — a
new credential location makes `collectors/targets.yaml` stale, and that lives
outside `artifacts/` where it is easy to miss.
