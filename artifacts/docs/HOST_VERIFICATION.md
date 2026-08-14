# Verifying catalogued paths on a real host

This is the work that cannot be done from CI, and it is the highest-value work
available on the catalog. Most `medium` and `low` rows are rated that way purely
because their paths came from documentation rather than from a machine. Turning
one of those into a verified path is worth a pull request on its own.

For the current list, run `python scripts/verification_worklist.py --summary`
rather than trusting a count written down here - this file used to carry one and
it had already drifted by two entries before anyone noticed.

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
paths and never opens them, and on Windows it also checks catalogued **registry
keys** for existence without ever reading a value - so it cannot leak a token by
either route.

Registry coverage was added on 2026-08-14. Before that `rows_for()` walked disk,
credentials and MCP rows only, while the module docstring claimed it covered
"every locator on an entry that is checkable on this OS". 24 entries carry
registry claims that the sweep silently skipped for as long as that was true. If
you are reading an older transcript that reports registry rows as unchecked, that
is why.

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

### What each result means

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

The inverse trap is just as easy to fall into. A HIT on a path a tool merely
*shares* with other software proves nothing either: `~/.aws` hit for AIRT-0033
Claude Computer Use on a host where the demo had never been installed, and the
entry correctly stayed unverified. Ask whether the path is specific to the tool
before treating a HIT as evidence of it.

**`KEY?`** appears on registry rows only. It means the key exists but the
catalogued row names a specific *value*, and this script will not read one. Keys
like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Environment`
exist on every Windows host, so counting key existence as a HIT would manufacture
evidence for a tool that registered nothing. `KEY?` rows are deliberately
excluded from the upgrade list at the end of the run. To confirm one, read the
value by hand — and only if it is not itself a secret.

**Not resolvable here** covers rows the script declines to guess at: a
repo-relative path, a Windows variable on POSIX, and any registry key whose
wildcard component reduces to a bare `*`. That last one matters:
`...\Uninstall\<Cursor GUID>` matches every sibling product code, so reporting
the first match would name a stranger's software as Cursor's. Telling those
apart needs `DisplayName`, which is a value, so the script stops instead.

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

### Registry rows

The sweep covers these now, but two shapes still need a human, and both have
already produced corrections.

**An uninstall key named by a GUID.** The catalog writes these as
`...\Uninstall\<Tool GUID>` because the key name carries no tool name at all —
it is a bare product code. Enumerate and match on `DisplayName`, which also
hands you the version for free:

```powershell
foreach ($h in 'HKCU:','HKLM:','HKLM:\Software\WOW6432Node') {
  Get-ChildItem "$h\Software\Microsoft\Windows\CurrentVersion\Uninstall" -EA SilentlyContinue |
    ForEach-Object { $i = Get-ItemProperty $_.PSPath -EA SilentlyContinue
      if ($i.DisplayName -match 'Cursor|LM Studio|Open WebUI') {
        "{0,-22} {1,-10} {2}" -f $i.DisplayName, $i.DisplayVersion, $_.PSChildName } } }
```

Absence proves less than it looks. A packaged MSIX install creates **no**
uninstall key, so a miss there means "query `Get-AppxPackage` instead", not "the
app is absent" — which is exactly how AIRT-0011's uninstall row came to be
downgraded.

**A row that names a specific value.** Confirm the value exists without printing
anything that could be a secret:

```powershell
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
(Get-Item $k).GetValueNames() -contains 'Cursor'   # true/false, no value data
```

A protocol handler is the useful exception: its default value is a launch
command, not a secret, and on a packaged app it names the `WindowsApps` path —
which yields the package full name and version without the package manager.

```powershell
(Get-ItemProperty 'HKCU:\Software\Classes\claude\shell\open\command').'(default)'
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
