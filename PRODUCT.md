# Product: netarget

**What it is.** A troubleshooting tool: enter a domain, it checks registration → name servers →
DNS zone → reachability → web server, stops at the layer that fails, names the root cause, and
lists fixes in priority order.

**Who uses it.** Hosting customers, web developers and support engineers, often in the middle of an
outage ("my site is down"), frequently on networks in Iran. Persian and English speakers.

**The job.** Get from "it's broken" to "this is why, do this" in under a minute, and hand a
shareable link to whoever must fix it (registrar, DNS provider, hosting support).

**Surface mode.** Operate (an app panel, not a marketing page). Scanability, trust and state clarity
beat expression.

**Reference.** Visual language of the ParsPack client panel (my.parspack.com): dark navy panel,
blue primary, rounded widgets, sidebar navigation, Persian-first typography.

**Constraints.** Strict CSP (`'self'` only: no CDNs, no inline script/style). Vanilla JS, embedded in
the Go binary. Diagnosis text from the backend is English; the UI chrome is English or Persian (RTL).
