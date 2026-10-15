# netarget report: apache-500.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `953719a6ee09dd72a3e01e44758e5c0777228436`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**500 from Apache/LiteSpeed — likely an .htaccess error**

- Root cause (web): Apache httpd returns 500 Internal Server Error with its generic 'misconfiguration' page — most often a broken .htaccess rule
- Evidence: `HTTP 500 on GET https://apache-500.ddemo-site.com/ (browser UA); Apache's generic 500 page ("internal error or misconfiguration"); web server detected: Apache httpd (Apache-compatible server (reads .htaccess))`

### Fixes (in priority order)

1. **500 from Apache/LiteSpeed — likely an .htaccess error** — Read the error log; an .htaccess problem is reported with the file and line ('Invalid command', 'RewriteRule: bad flag'). (see the Website load section for all steps and server-specific snippets)

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ❌ FAIL | https://apache-500.ddemo-site.com/ → 500 in 33 ms — Apache httpd returns 500 Internal Server Error with its generic 'misconfiguration' page — most often a broken .htaccess rule |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-03 (199 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.ddemo-site.com. | 3.0.0.1 | ok | true | 1 | 0.0 |
| ns2.ddemo-dns.net. | 3.0.1.1 | ok | true | 1 | 0.0 |

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
| apache-500.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.http.500.htaccess` Apache httpd returns 500 Internal Server Error with its generic 'misconfiguration' page — most often a broken .htaccess rule (`HTTP 500 on GET https://apache-500.ddemo-site.com/ (browser UA); Apache's generic 500 page ("internal error or misconfiguration"); web server detected: Apache httpd (Apache-compatible server (reads .htaccess))`)

**Verdict:** Apache httpd returns 500 Internal Server Error with its generic 'misconfiguration' page — most often a broken .htaccess rule

- Layer at fault: **server** (confidence medium, 75%)

Evidence:

- `HTTP 500 on GET https://apache-500.ddemo-site.com/ (browser UA)`
- `Apache's generic 500 page ("internal error or misconfiguration")`
- `web server detected: Apache httpd (Apache-compatible server (reads .htaccess))`

Likely causes:

- (high) Invalid directive or syntax in .htaccess (a module that is not loaded, a typo, a bad RewriteRule).
- (medium) A PHP handler/version directive in .htaccess that the server does not support.
- (medium) Files or folders with unsafe permissions that suPHP/LiteSpeed refuse to execute.

Fix steps:

1. Read the error log; an .htaccess problem is reported with the file and line ('Invalid command', 'RewriteRule: bad flag').

   apache:

   ```
   sudo tail -n 50 /var/log/apache2/error.log    # Debian/Ubuntu
   sudo tail -n 50 /var/log/httpd/error_log      # RHEL/CentOS
   # cPanel: ~/logs/ or cPanel → Metrics → Errors
   ```

   - Verify: The log points to the exact .htaccess line.
2. Test by renaming .htaccess temporarily; if the site comes back, fix the offending line and restore the file.

   apache:

   ```
   cd /var/www/apache-500.ddemo-site.com || exit   # the site's document root
   mv .htaccess .htaccess.bak     # test only
   # reload the page, then restore and fix:
   mv .htaccess.bak .htaccess
   ```

   - Verify: With the fixed .htaccess in place, curl -sI https://apache-500.ddemo-site.com/ returns 200.
   - Warning: While .htaccess is renamed, its access restrictions and redirects are off too; restore it within minutes.
3. Make sure files are 644 and directories 755 (some PHP handlers refuse group/world-writable files).

   apache:

   ```
   DOCROOT=/var/www/apache-500.ddemo-site.com   # set to your document root
   find "$DOCROOT" -type d -exec chmod 755 {} +
   find "$DOCROOT" -type f -exec chmod 644 {} +
   chmod 640 "$DOCROOT"/wp-config.php "$DOCROOT"/.env 2>/dev/null   # keep secrets private
   ```

   - Verify: No 'is writable by group/others' messages in the log.

Could not determine from outside:

- The error log line; renaming .htaccess is a test you must do on the server.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | Apache httpd | high | header server: Apache (GET https://apache-500.ddemo-site.com/); page content "<address>Apache" (GET https://apache-500.ddemo-site.com/); page content "Server at apache-500.ddemo-site.com Port 80" (GET https://apache-500.ddemo-site.com/) |
| server | nginx | medium | header server: nginx/1.27.5 (GET http://apache-500.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 33 | 33 |  |
| Frankfurt | GET http://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 13 | 13 |  |
| Frankfurt | HEAD https://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 16 | 16 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ curl UA | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 34 | 34 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ googlebot UA | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 21 | 21 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ HTTP/1.1 | https://apache-500.ddemo-site.com/ | 500 | HTTP/1.1 | 32 | 32 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ HTTP/2 | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 35 | 35 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ gzip | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 34 | 34 |  |
| Frankfurt | GET https://apache-500.ddemo-site.com/ no compression | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 35 | 35 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 22 | 22 |  |
| Tehran | GET http://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 19 | 19 |  |
| Tehran | HEAD https://apache-500.ddemo-site.com/ | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 15 | 16 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ curl UA | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 43 | 43 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ googlebot UA | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 23 | 23 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ HTTP/1.1 | https://apache-500.ddemo-site.com/ | 500 | HTTP/1.1 | 29 | 29 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ HTTP/2 | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 43 | 43 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ gzip | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 20 | 20 |  |
| Tehran | GET https://apache-500.ddemo-site.com/ no compression | https://apache-500.ddemo-site.com/ | 500 | HTTP/2.0 | 39 | 39 |  |
