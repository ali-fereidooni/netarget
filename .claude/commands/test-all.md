---
description: Vet, build and test the whole project, then summarize failures
---

Run `go vet ./...`, `go build ./...` and `go test ./...` from the repo root. If anything fails,
show the failing test names with the relevant output and propose (do not apply) a fix.
