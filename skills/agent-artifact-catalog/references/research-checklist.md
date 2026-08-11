# Per-Platform Research Checklist

Work through this for each tool. An entry that answers all of these is complete.

## Windows
- [ ] Install directory (`%LOCALAPPDATA%\Programs\`, `%PROGRAMFILES%`, npm global)
- [ ] MSIX/Store variant? If so the virtualized `%LOCALAPPDATA%\Packages\...\LocalCache\Roaming\` path
- [ ] Config under `%APPDATA%` / `%LOCALAPPDATA%`
- [ ] Registry: Uninstall key, `HKCU\...\Run`, protocol handler, `HKCU\Environment`
- [ ] Process name, typical parent, typical children
- [ ] Listening ports (`Get-NetTCPConnection -State Listen`)
- [ ] Scheduled tasks or services

## macOS
- [ ] `/Applications`, `~/Library/Application Support/`, `~/Library/Caches/`
- [ ] `~/Library/Logs/`
- [ ] LaunchAgents / LaunchDaemons
- [ ] Keychain entries (service and account names)
- [ ] Dot-directory in `$HOME`

## Linux
- [ ] Binary path (`/usr/local/bin`, `~/.local/bin`)
- [ ] `~/.config/<tool>/`, `~/.cache/<tool>/`
- [ ] systemd unit + drop-in `.d/` overrides
- [ ] Service-account home (e.g. `/usr/share/ollama/.ollama`)
- [ ] System-wide config in `/etc/`

## Cross-platform
- [ ] Credential storage mechanism and exact location
- [ ] Environment variables, including `*_BASE_URL` redirection vectors
- [ ] MCP config paths, all scopes (user, project, system)
- [ ] Session/history/transcript files and their retention window
- [ ] Model files and caches
- [ ] Egress domains
- [ ] Project-scoped files that travel with a git clone
