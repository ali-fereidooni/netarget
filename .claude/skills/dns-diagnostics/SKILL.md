---
name: dns-diagnostics
description: Failure-to-fix knowledge for domain troubleshooting (registration, delegation, DNS zone, email auth, DNSSEC, reachability, HTTP/TLS). Use when adding or changing a netarget finding code, writing diagnosis rules or fix text, or explaining a check result.
---

# DNS diagnostics knowledge base

Each finding in netarget has a stable code. When you add one: add the detection in
`internal/checks`, a rule in `internal/diagnose/rules.go` (cause or symptom, priority, fix text),
and a row here. Causes explain later failures; symptoms are explained by an earlier cause.

## Layer order and what a failure explains
registration → nameservers → zone → reachability → web. A FAIL in a layer explains FAILs in every
later layer that depends on it (expired domain ⇒ NXDOMAIN ⇒ no A record ⇒ no ping ⇒ no web).

## Registration (`reg.*`)
| Code | Meaning | Fix |
|---|---|---|
| reg.not_registered | RDAP 404 / WHOIS "No match" | Register the domain (or check spelling). Cause. |
| reg.expired | expiry date in the past | Renew at the registrar now; DNS returns once registry reactivates (minutes–hours). Cause. |
| reg.expiring_soon | < 30 days left | Renew, enable auto-renew. WARN. |
| reg.redemption | `redemption period` EPP status | Domain deleted after expiry; restore via registrar (fee). Cause. |
| reg.pending_delete | `pending delete` | Cannot be restored; wait for drop and re-register. Cause. |
| reg.client_hold / reg.server_hold | `client hold` / `server hold` | Registry removes NS from the zone. Client: registrar hold (unpaid, unverified WHOIS email, abuse) — contact registrar, verify contact email. Server: registry/legal hold — contact registrar. Cause. |
| reg.lookup_failed | RDAP and WHOIS both failed | Informational WARN; continue checks. |
| reg.not_published | `.ir` apex and the RDAP/WHOIS lookup failed (IRNIC has no RDAP; registrars hide data) | INFO instead of reg.lookup_failed, layer OK; expiry is checked in the IRNIC account. |

## Name servers (`ns.*`)
| Code | Meaning | Fix |
|---|---|---|
| ns.checker_dns_blocked | root servers silent too: the *checker's* network blocks outbound port 53 | Not the domain's fault; run from a network allowing UDP/TCP 53. Cause (stops DNS layers). |
| ns.limited_mode | DoH resolver mode: port 53 blocked at the checker, data via public resolvers | Info only; per-server checks skipped. |
| ns.too_many | > 13 NS names delegated; only the first 13 checked | Trim the NS list. |
| ns.parent_unreachable | root answers but the TLD servers do not | Retry; TLD outage if persistent. |
| ns.no_delegation | TLD returns no NS for the domain | Set name servers at the registrar. Cause. |
| ns.lame | NS answers without AA or REFUSED/SERVFAIL for the zone | Add the zone on that server or remove it from the delegation. Cause if all lame. |
| ns.unreachable | NS IP does not answer (timeout) | Fix firewall (UDP+TCP 53) or replace the server. |
| ns.no_address | NS hostname has no A/AAAA | Create the A/AAAA record for the NS host, or fix the NS name. |
| ns.missing_glue | in-bailiwick NS without glue at parent | Add glue (host records) at the registrar. |
| ns.glue_mismatch | glue IP ≠ authoritative A of NS | Update glue at registrar. |
| ns.parent_child_mismatch | parent NS set ≠ zone apex NS set | Make the zone NS records match the registrar delegation. WARN. |
| ns.too_few | < 2 NS | Add a second NS on a different network (RFC 1034 / registry policy). WARN. |
| ns.single_network | all NS in one /24 (v4) or one ASN | Add a NS in another network/provider. WARN. |
| ns.serial_mismatch | SOA serials differ | Secondary not transferring: check AXFR/IXFR ACL, NOTIFY, primary reachability. WARN. |
| ns.private_ip | NS resolves to private IP | Publish public addresses for the NS. |

## Zone (`dns.*`, `mail.*`, `dnssec.*`)
| Code | Meaning | Fix |
|---|---|---|
| dns.nxdomain | authoritative NXDOMAIN for the name | Create the records in the zone. |
| dns.no_address | no A/AAAA at apex (and www) | Add A/AAAA (or ALIAS/flattened CNAME at apex). Cause for web layer. |
| dns.cname_at_apex | CNAME at zone apex | Illegal with SOA/NS; use ALIAS/ANAME/CNAME flattening or A records. |
| dns.dangling_cname | CNAME target NXDOMAIN | Fix/remove CNAME (also a subdomain-takeover risk). |
| dns.mx_cname | MX points to a CNAME | RFC 2181 §10.3: point MX at a hostname with A/AAAA. |
| dns.mx_unresolvable | MX host has no address | Fix MX target. |
| dns.no_mx | no MX | Only matters if the domain receives mail; consider null MX `0 .`. INFO. |
| dns.propagation | public resolvers disagree with authoritative | Wait TTL (shown) or flush caches; if a resolver shows old NS, check registrar change timing. |
| mail.spf_missing / spf_multiple / spf_syntax / spf_too_many_lookups / spf_plus_all | SPF problems | Single `v=spf1` TXT, ≤10 DNS-lookup mechanisms (include, a, mx, ptr, exists, redirect), end with `~all`/`-all`. |
| mail.dmarc_missing / dmarc_invalid / dmarc_none | DMARC problems | Publish `_dmarc` TXT `v=DMARC1; p=quarantine; rua=mailto:...`. |
| mail.dkim_none_found | no common selector found | Informational: selectors are unguessable; check the provider's selector. |
| dnssec.broken | DS at parent but chain fails (no matching DNSKEY, bad/expired RRSIG) | Most common: DS left at registrar after changing DNS provider. Remove the DS or publish matching DNSKEY. Validating resolvers return SERVFAIL ⇒ cause. |
| dnssec.unsigned | no DS | INFO; recommend enabling. |
| dnssec.sig_expiring | RRSIG has < 72 h and < 20% of its validity window left (online signers like Cloudflare use few-day windows and are not flagged) | Check signer automation. |

## Reachability (`reach.*`)
| Code | Meaning | Fix |
|---|---|---|
| reach.down_all | no node gets ICMP or TCP 80/443 | Host down, firewall, or wrong A record. Cause for web. |
| reach.icmp_blocked | ICMP fails but TCP works | OK with note: ICMP filtered. |
| reach.partial | some nodes reach, others not | Regional/routing/geo-blocking problem; compare traceroutes. |
| reach.v6_broken | AAAA published but IPv6 unreachable | Fix IPv6 or remove AAAA (dual-stack clients suffer delays). |

## Web (`web.*`, `tls.*`)
| Code | Meaning | Fix |
|---|---|---|
| web.timeout / refused / reset | connection-level errors | Server not listening / firewall / crashed. refused = port closed; timeout = filtered. |
| web.5xx (502/503/504) | upstream errors | 502 bad gateway: app behind proxy is down; 503: overloaded/maintenance; 504: upstream timeout. |
| web.4xx | client error at root | 403 often WAF/geo-block; 404 at root means vhost/docroot misconfigured. |
| web.cdn_error | Cloudflare 52x / CloudFront error page | 521 origin down, 522 origin timeout, 525/526 origin TLS problems. |
| web.redirect_loop | redirect chain loops / > 10 | Usually HTTPS redirect at both CDN and origin ("Flexible SSL" loop). |
| web.no_https_redirect | http:// does not redirect to https:// | Add 301 to https. |
| web.apex_www_inconsistent | apex and www end at different places | Pick a canonical host and redirect the other. |
| web.missing_security_headers | no HSTS/CSP/etc. | Add headers. WARN/INFO. |
| tls.expired / not_yet_valid / expiring_soon | cert dates | Renew; check ACME automation. |
| tls.hostname_mismatch | SAN does not cover host | Reissue cert with the hostname, or fix vhost/SNI routing. |
| tls.incomplete_chain | server does not send intermediates | Serve full chain (fullchain.pem). |
| tls.handshake_failed | handshake error | Old protocol/cipher, SNI missing, or wrong cert. |
| tls.old_protocol | TLS < 1.2 negotiated | Disable TLS 1.0/1.1. |
