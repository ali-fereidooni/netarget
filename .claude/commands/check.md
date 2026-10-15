---
description: Run netarget's CLI against a domain and explain the diagnosis
argument-hint: <domain>
---

Run `go run ./cmd/domaindoctor check $ARGUMENTS --json` from the repo root (it uses a local
in-process agent). Then summarize: overall root cause, each layer's status, and the prioritized
fixes. If a finding looks wrong, check it against `.claude/skills/dns-diagnostics/SKILL.md`.
