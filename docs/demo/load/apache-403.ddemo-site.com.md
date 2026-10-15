# Domain Doctor report: apache-403.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `eaa9763db5cd63b17de4a3fa8411856ada52bbdc`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**403 Forbidden from Apache**

- Root cause (web): Apache refuses to serve the page (403 Forbidden): an access rule, a missing index file or file permissions
- Evidence: `HTTP 403 on GET https://apache-403.ddemo-site.com/ (browser UA); web server detected: Apache httpd; response body contains "You don't have permission to access" (Apache's standard 403 page)`

### Fixes (in priority order)

1. **403 Forbidden from Apache** — Read the Apache error log for this request; the log line names the reason. (see the Website load section for all steps and server-specific snippets)

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ❌ FAIL | https://apache-403.ddemo-site.com/ → 403 in 29 ms — Apache refuses to serve the page (403 Forbidden): an access rule, a missing index file or file permissions |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-03 (199 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.ddemo-site.com. | 3.0.0.1 | ok | true | 1 | 0.5 |
| ns2.ddemo-dns.net. | 3.0.1.1 | ok | true | 1 | 0.5 |

### ✅ DNS zone — OK

- **INFO** `dns.no_www` www has no address record; visitors typing www. will get an error.
- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dns.no_mx` No MX record: the domain cannot receive email (fine if intended).
- **INFO** `dnssec.unsigned` DNSSEC is not enabled for this domain. (`no DS at parent`)

| Name | Type | TTL | Value |
|---|---|---|---|
| ddemo-site.com | NS | 3600 | ns1.ddemo-site.com. |
| ddemo-site.com | NS | 3600 | ns2.ddemo-dns.net. |
| ddemo-site.com | SOA | 3600 | ns1.ddemo-site.com. hostmaster.ddemo-site.com. 1 7200 3600 1209600 300 |
| ddemo-site.com | TXT | 3600 | "v=spf1 -all" |
| apache-403.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.http.403.apache` Apache refuses to serve the page (403 Forbidden): an access rule, a missing index file or file permissions (`HTTP 403 on GET https://apache-403.ddemo-site.com/ (browser UA); web server detected: Apache httpd; response body contains "You don't have permission to access" (Apache's standard 403 page)`)

**Verdict:** Apache refuses to serve the page (403 Forbidden): an access rule, a missing index file or file permissions

- Layer at fault: **server** (confidence medium, 75%)

Evidence:

- `HTTP 403 on GET https://apache-403.ddemo-site.com/ (browser UA)`
- `web server detected: Apache httpd`
- `response body contains "You don't have permission to access" (Apache's standard 403 page)`

Likely causes:

- (high) An .htaccess or vhost rule denies access (Require all denied, Deny from all, an IP/geo rule, or a RewriteRule with the [F] flag).
- (high) No index file (index.php / index.html) in the document root and directory listing is disabled.
- (medium) Apache's user cannot read the files or enter a parent directory (permissions or ownership).
- (medium) ModSecurity or a hosting security tool (Imunify360, CSF) blocked the request.
- (low) Hotlink protection or a Referer/User-Agent rule matched.

Fix steps:

1. Read the Apache error log for this request; the log line names the reason.
   - Why: 'client denied by server configuration' = an access rule; 'Cannot serve directory: No matching DirectoryIndex' = missing index; 'Permission denied' = permissions; 'ModSecurity: Access denied' = WAF.

   apache:

   ```
   sudo tail -n 50 /var/log/apache2/error.log     # Debian/Ubuntu
   sudo tail -n 50 /var/log/httpd/error_log       # RHEL/CentOS
   # cPanel: /usr/local/apache/logs/error_log or ~/logs/
   ```

   - Verify: You can name which of the causes applies.
2. If it is an access rule: check every .htaccess from the document root down and the vhost for deny rules; the public directory should allow access.

   apache:

   ```
   # .htaccess in the document root
   <IfModule mod_authz_core.c>
       Require all granted
   </IfModule>
   DirectoryIndex index.php index.html
   ```

   - Verify: curl -sI https://apache-403.ddemo-site.com/ returns 200 after the change.
3. If the index file is missing: upload index.php/index.html or set DirectoryIndex to the real start file.

   apache:

   ```
   DirectoryIndex index.php index.html
   ```

   - Verify: The home page loads instead of 403.
4. If it is permissions: give directories 755 and files 644, owned by the site user, so Apache can traverse and read them.

   apache:

   ```
   DOCROOT=/var/www/apache-403.ddemo-site.com   # set to your document root
   sudo find "$DOCROOT" -type d -exec chmod 755 {} +
   sudo find "$DOCROOT" -type f -exec chmod 644 {} +
   sudo chmod 640 "$DOCROOT"/wp-config.php "$DOCROOT"/.env 2>/dev/null   # keep secrets private
   sudo chown -R siteuser:www-data "$DOCROOT"   # adjust user/group to your setup
   ```

   - Verify: namei -l /var/www/apache-403.ddemo-site.com/index.php shows read access for Apache's user on every component.
5. If ModSecurity blocked it: note the id of the rule that matched in the audit log and add a narrow exception for that rule and path instead of switching the engine off.

   apache:

   ```
   <LocationMatch "^/path/that/is/blocked">
       # the id of the rule that matched (from the audit log), e.g. 942100.
       # Never 949110/959100: they only add up anomaly scores; removing them disables all blocking here.
       SecRuleRemoveById 942100
   </LocationMatch>
   ```

   - Verify: The request passes and the audit log shows no new block for that rule.

> Warning: Do not make files or directories world-writable (mode 777) to 'fix' a 403: it does not help Apache read files and lets any local process modify your site.

Could not determine from outside:

- The Apache error log line (the definitive reason).
- File permissions and ownership on the server.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | Apache httpd | high | header server: Apache (GET https://apache-403.ddemo-site.com/); page content "<address>Apache" (GET https://apache-403.ddemo-site.com/); page content "Server at apache-403.ddemo-site.com Port 80" (GET https://apache-403.ddemo-site.com/); page content "You don't have permission to access" (GET https://apache-403.ddemo-site.com/) |
| server | nginx | medium | header server: nginx/1.27.5 (GET http://apache-403.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 29 | 29 |  |
| Frankfurt | GET http://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 19 | 19 |  |
| Frankfurt | HEAD https://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 20 | 20 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ curl UA | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 26 | 26 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ googlebot UA | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 26 | 26 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ HTTP/1.1 | https://apache-403.ddemo-site.com/ | 403 | HTTP/1.1 | 30 | 30 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ HTTP/2 | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 22 | 22 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ gzip | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 21 | 21 |  |
| Frankfurt | GET https://apache-403.ddemo-site.com/ no compression | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 25 | 25 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 21 | 21 |  |
| Tehran | GET http://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 30 | 30 |  |
| Tehran | HEAD https://apache-403.ddemo-site.com/ | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 18 | 19 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ curl UA | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 26 | 26 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ googlebot UA | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 23 | 23 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ HTTP/1.1 | https://apache-403.ddemo-site.com/ | 403 | HTTP/1.1 | 32 | 32 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ HTTP/2 | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 28 | 28 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ gzip | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 26 | 26 |  |
| Tehran | GET https://apache-403.ddemo-site.com/ no compression | https://apache-403.ddemo-site.com/ | 403 | HTTP/2.0 | 26 | 26 |  |
