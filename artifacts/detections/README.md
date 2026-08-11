# Detections

Detection content here is **vendor-neutral by design**. Nothing in this directory
is written in a proprietary query language.

## Why Sigma

Sigma is the generic signature format for log events. One rule converts to
Splunk, Elastic, Sentinel, QRadar, Chronicle, CrowdStrike, Panther, and others
via `sigma-cli`, so the catalog does not have to pick a SIEM on your behalf - and
you are not re-implementing rules that a converter can generate:

```bash
pip install sigma-cli
sigma convert -t splunk detections/sigma/            # Splunk SPL
sigma convert -t microsoft365defender detections/sigma/
sigma convert -t esql detections/sigma/              # Elasticsearch
```

## Why osquery for inventory

Inventory is a fleet-state question, not an event-stream question. "Which hosts
have an unauthenticated inference API listening on a routable address" is a
`SELECT`, not a detection rule. The pack in `osquery/artifact-catalog.conf` answers
that class of question and is equally consumable by any platform that can run
osquery.

## Rules

| Rule | Level | What it catches |
|---|---|---|
| `ai_agent_mcp_config_modification` | low | MCP config created or changed - inventory and change tracking |
| `ai_agent_spawning_shell` | low | Agent launching a command interpreter - baseline-dependent |
| `ai_agent_spawning_lolbin` | high | Agent launching a LOLBAS binary - rarely legitimate |
| `local_llm_listener_non_loopback` | high | Unauthenticated inference API exposed off-host |
| `ai_agent_credential_file_access` | high | Plaintext AI token read by a non-owning process |
| `ai_inference_endpoint_redirection` | high | Prompts and code silently rerouted to another endpoint |
| `mcp_server_remote_code_fetch` | medium | MCP server pulling `@latest` at every launch |
| `browser_agent_session_state_capture` | high | Cookie and localStorage serialization by a browser agent |
| `ai_agent_autostart_persistence` | low | Agent registered to start at login |
| `langflow_rce_exploitation_attempt` | high | CVE-2025-3248 (CISA KEV) and CVE-2026-5027 exploitation |
| `ai_agent_docker_socket_mount` | high | Agent container given host-root-equivalent daemon access |
| `ai_model_file_written_to_endpoint` | low | Model weights landing on an endpoint - shadow AI signal |

## On tuning, honestly

Several rules are deliberately `level: low`. On a developer estate, an agent
spawning a shell is the product working correctly, and shipping that as `high`
would train people to ignore the feed. The `low` rules are worth collecting and
baselining rather than alerting on; the `high` rules describe behaviour that is
hard to explain as normal use.

Validate any rule against your own telemetry before enabling it. Field names
vary by shipper - `TargetFilename`, `Image`, and `ParentImage` assume
Sysmon-style process and file events, and your pipeline may name them
differently.
