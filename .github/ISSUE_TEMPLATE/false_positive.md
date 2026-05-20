---
name: False positive / bug report
about: A rule is firing on benign activity, or a rule has a bug
title: "[FP] "
labels: bug
---

## Rule affected

<!-- Path to the rule file, e.g. 04-ai-infrastructure/ray_jobs_api_rce.rules -->

## Detection platform

<!-- e.g. Elastic / Wazuh / Suricata / etc. + version -->

## What fired

<!-- Paste the event/alert/log line that triggered (redact any real hostnames, IPs, usernames) -->

```
<paste here>
```

## Why it's a false positive (or bug)

<!-- Explain why this activity is benign, or what the rule is doing incorrectly -->

## Suggested fix

<!-- If you have a proposed selector / filter / exclusion, describe it here -->

## Environment context

<!-- Anything about your environment that helps reproduce (e.g. "internal Ray cluster used by data team on schedule X") -->
