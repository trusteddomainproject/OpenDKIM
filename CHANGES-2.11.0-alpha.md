# OpenDKIM develop branch - change summary (pre-2.11.0)

This document summarizes the changes merged into the `develop` branch
during the triage and stabilization effort in May 2026. Over 100 open
pull requests were reviewed; roughly 80 were merged, closed as
superseded, or closed with explanation. The open issue count dropped
from ~125 to ~35.  At the time of this writing, there are 3 open pull
requests awaiting further testing or discussion.

---

## Security

- **CVE-2020-35766**: Insecure use of predictable path `/tmp/testkeys`
  in key generation tools. (#260, #288)
- **CVE-2022-48521**: `Authentication-Results` headers were deleted in
  forward order, leaving a window where a crafted message could
  preserve a forged header. Fixed to delete in reverse. (#287)
- **SubDomains overlapping buffer**: `strlcpy()` was called with
  overlapping source and destination when updating `mctx_domain` during
  the subdomain walk. Undefined behavior; manifests as corrupted `d=`
  tags (invalid signatures) on FreeBSD. Replaced with `memmove()`. (#356)
- **Header character validity check**: Always-false NULL check on
  `mctx_domain` (a fixed-size array) meant downstream code used a
  potentially empty domain string. (#343, issue #88)

---

## Correctness fixes

- **DKIM result for ignored signatures**: Ignored signatures were
  reported as `dkim=fail` in Authentication-Results. RFC-correct result
  is `dkim=policy`. (#302, #234, issue #233)
- **A-R header in sign-only mode**: An `Authentication-Results` header
  was incorrectly added in sign-only mode when the sender domain was
  unresolvable. (#345, issue #130)
- **A-R / DKIM-Signature header insertion order**: Headers were
  appended rather than prepended, violating the expectation that the
  most-recent results appear first. Now inserted at index 0. (#346,
  issue #24)
- **AuthservIDWithJobID quoting**: The authserv-id was not quoted when
  `AuthservIDWithJobID` produced a value containing a job ID, producing
  an invalid header. (#308, issue #103)
- **`On-DNSError` not honoured on key retrieval failure**: DNS errors
  during key lookup were not dispatched to the configured action. (#309,
  issue #176)
- **libunbound nameserver default**: libunbound ignored
  `/etc/resolv.conf` and used its own root hints, causing DNSSEC
  validation failures in environments with a local validating resolver.
  Now defaults to the system resolver. (#305, issue #181)
- **NXDOMAIN vs. DNS error**: The stub resolver did not distinguish
  "name does not exist" from "DNS failure", leading to misleading log
  messages and potentially wrong actions. (#312, issue #49)
- **Multiple DKIM key TXT records**: When multiple TXT records were
  present for a selector, the library used the last one rather than the
  first. (#295)
- **`l=` body length tag and missing CRLF**: Verification incorrectly
  failed on messages where the body length tag was present but the body
  lacked a trailing CRLF. (#339, issue #45)
- **`MUSTBESIGNED`/`REQUIREDHDRS` option labels**: Incorrectly labelled
  as "ordered" in documentation and option parsing. (#304, issue #179)
- **AR header `no-result` parsing**: `Authentication-Results: host; none`
  is valid per RFC 8601 but was rejected by the parser. (#205)
- **AR header comment delimiter**: Semicolons inside parenthesized
  comments in AR headers confused OpenDMARC's tokenizer. Changed to
  comma. (#136)
- **DNAME records in DNS responses**: DNS answer packets containing
  DNAME records (whole-zone redirections) caused verification failures.
  DNAME records are now skipped alongside RRSIG records in all DNS
  response parsers. (#353, issue #156)
- **`RequiredHeaders` error messages**: "not exactly one From/Date
  field" now distinguishes "no From field" from "multiple From fields"
  for easier diagnosis. (#144)
- **`UserID` supplemental groups**: When an explicit group was given in
  `UserID`, the user's primary group was dropped from the supplemental
  group list. (#301, issue #40)
- **`KeyFile` silently ignored with `KeyTable`**: If both were
  configured, `KeyFile` was silently ignored with no warning. Now logs a
  warning. (#310, issue #240)
- **SigningTable consistency check**: DB handle was not correctly
  maintained during the startup SigningTable/KeyTable consistency walk,
  causing spurious failures. (#325, #230, issue #229)
- **`ldapi://` URI reconstruction**: The socket path was dropped when
  reconstructing an `ldapi://` URI, breaking LDAP over Unix socket. (#314)
- **`dkim_canon_selecthdrs` assert**: An assertion fired when all
  candidate headers were skipped (e.g. all omitted), causing a crash
  instead of a clean error. (#313, issue #174)
- **Unsupported signing algorithm handling**: When an unsupported
  algorithm was encountered and skipped, `sig_signalg` was left set to
  `rsa-sha1` for the next signature, causing incorrect algorithm
  assignment. (#334)
- **`dkim_diffheaders` strlcpy size**: The destination buffer size
  argument to `strlcpy` was wrong, risking truncation. (#291)
- **`smfi_insheader` stub removed**: A stub for `smfi_insheader()` that
  was required for sendmail 8.12 (released 2001) was still present.
  Removed; libmilter >= sendmail 8.13.0 (2004) is now required. (#333,
  issue #89)
- **`mctx_domain` NULL check**: Comparing a fixed-size array address to
  NULL always evaluates false; corrected to check for empty string. (#343)
- **`res_setservers` struct type**: `struct state` should be `struct
  __res_state`; caused compile failure on some platforms. (#283)
- **`res_nslist` syntax errors**: Syntax errors in
  `dkim_res_nslist()`/`rbl_res_nslist()` that prevented compilation when
  `HAVE_RES_SETSERVERS` was defined. (#298)
- **`vbr.c` snprintf buffer size**: Two `snprintf()` calls used
  `sizeof(pointer)` (8 bytes) instead of the buffer size, truncating
  error messages. (#244)
- **`opendkim.c` NULL pointer comparison**: Fixed companion issue in
  `dkimf_add_signrequest`. (#244)
- **SignHeaders/SkipHeaders regex buffer**: Fixed-size `BUFRSZ` limit on
  the regex buffer caused truncation with long header lists. Now
  dynamically sized. (#341, issue #120)
- **Minimum signing percentage with empty body**: `Minimum` percentage
  checks incorrectly handled messages with an empty body. (#223,
  issue #222)
- **Lua `del_header` index**: `odkim.del_header()` used an incorrect
  header index (off-by-one), deleting the wrong header. (#191)
- **`KeepAuthResults` deleting wrong headers**: Could delete the wrong
  `Authentication-Results` header when multiple were present. (issue #148)
- **`AuthservID` with job ID producing invalid header**: Quoting fix for
  job-ID-appended authserv-ids. (#308, issue #103)
- **SHA1 on restricted platforms**: On systems where the OS crypto policy
  disables SHA1 (e.g. RHEL 9 / AlmaLinux 9 DEFAULT policy), `dkim_init()`
  now probes SHA1 availability at startup and stores the result. Signing
  returns `DKIM_STAT_SIGGEN` with a clear message; verification sets
  `DKIM_SIGERROR_UNSUPPORTED_A` and returns `DKIM_STAT_OK` rather than
  `DKIM_STAT_INTERNAL`. Works correctly for OS-packaged binaries built on
  permissive systems and deployed to restricted ones, and for operators
  who re-enable SHA1 after install (update-crypto-policies + reboot).
  (#365, issue #364)

---

## Crashes and stability

- **miltertest body replacement stack overflow**: Replacing a message
  body larger than `BUFRSZ` bytes caused a stack overflow in miltertest.
  (#340, issue #66)
- **memcache `SigningTable` assert**: Using memcache as the `SigningTable`
  backend caused an `assert(0)` crash. (#286)
- **Use-after-free in `mlfi_close`**: Under `QUERY_CACHE`, a connection
  context could be accessed after being freed. (#280, issue #272)
- **`dkim_canon_selecthdrs` assert on empty header list**: (#313)
- **Segfault with empty `RequiredHeaders`**: assert in selecthdrs when
  option was set but produced no headers. (#313, issue #174)
- **`MultipleSignatures` orphaned signreq entries**: Sign request list
  tail pointer was not maintained, causing use-after-free or missed
  entries with multiple signatures. (#274)
- **`DKIMF_STATUS_KEYFAIL` undefined**: Missing define caused incorrect
  handling of key failure status. (#329)

---

## Memory leaks and resource management

A systematic audit of memory and resource leaks (issue #272) produced
fixes across multiple code paths:

- Lua global `lg_name` leak in global cleanup (#273)
- Orphaned signreq list entries with MultipleSignatures (#274)
- `conf_remardb` not closed in `dkimf_config_free()` (#275)
- Leak in `dkimf_db_mkarray_base` (#276)
- GnuTLS hash context leak on aborted messages (#277)
- Config struct leak on deprecated-setting abort in `dkimf_config_reload` (#278)
- Leaks on OOM error paths (#279)
- FD leak from missing `endpwent()` in key safety checks (#284)
- `dkim_free()` memory leak in ed25519 path (#321)

---

## New features

- **`StdoutLog` / `-O` flag**: Log to stdout/stderr instead of syslog,
  for container/Docker deployments. (#323, issue #153)
- **`CheckSigningTable` option**: Skip the startup SigningTable/KeyTable
  consistency walk, which could be slow with large tables. (#281, #228)
- **Per-key signing algorithm in KeyTable**: A fourth field in KeyTable
  entries specifies the signing algorithm for that key, enabling
  dual-algorithm signing (RSA + ed25519) from a single config. (#269,
  issue #6)
- **`opendkim-testkey` ed25519 support**: The key testing tool now
  supports ed25519 keys in addition to RSA. (#299, issue #183)
- **`opendkim-genkey` ed25519 on OpenSSL 3**: Replaced hardcoded version
  check with a functional test; ed25519 key generation now works on
  OpenSSL 3.x. (#135)
- **`sd_notify()` systemd readiness**: When built with libsystemd
  (auto-detected), opendkim sends `READY=1` once the milter socket is
  bound. Enables `Type=notify` in the service unit, eliminating the
  race condition where units ordered after opendkim could start before
  it could accept connections. (#352)
- **`miltertest` `MT_SMTPREPLY` after any callback**: Previously only
  worked after EOM. (#342, issue #95)
- **Configure arguments in `opendkim -V` output**: `$ac_configure_args`
  is now captured at configure time and printed by `opendkim -V`,
  making it straightforward to reproduce a packaged build from source
  or diagnose support requests involving non-standard builds. (#358,
  issue #357)
- **Git hash in version string for development builds**: `configure.ac`
  now embeds `git describe --tags --dirty` in `DKIMF_VERSION` when building
  from an untagged commit (e.g. `2.11.0-alpha-5-gabcdef7`). Tagged release
  builds and environments without git show the plain version number.
  Appears in the `DKIM-Filter` software header, `--version` output, and
  startup/shutdown log messages. (#366, issue #350)
- **`SoftwareHeader` includes milter hostname when different from MTA**:
  When the milter runs on a different host than the MTA (e.g. a milter
  pool behind a load balancer), the `DKIM-Filter` header now appends
  `via <milterhostname>` between the MTA hostname and the job ID,
  making it possible to identify which backend instance processed a
  message. Single-host deployments are unchanged. (#367, issue #349)
- **Inline IPv6 CIDR entries in dataset lists**: Bracketed IPv6 addresses
  (e.g. `[fd00:368::]/40`) can now be used directly in inline dataset
  values for `PeerList`, `InternalHosts`, and similar options, without
  requiring a file reference. The colons in an IPv6 address were
  previously misidentified as a `type:` prefix. (#368, issue #319)
- **MySQL DSN special characters in passwords**: `=XY` escape sequences
  in DSN credential fields were never decoded. A typo also caused
  lowercase hex digits `a`-`e` to decode incorrectly. Both are fixed;
  passwords containing `=`, `%`, and other special characters now round-trip
  correctly through the DSN parser. (#369, issue #248)
- **Auto-detect `SignatureAlgorithm` from key type**: When `SignatureAlgorithm`
  is not explicitly set in the config, opendkim now inspects the loaded
  `KeyFile` and automatically selects `ed25519-sha256` for ed25519 keys.
  RSA keys continue to default to `rsa-sha256`. This eliminates the
  previously undocumented requirement to add `SignatureAlgorithm ed25519-sha256`
  alongside an ed25519 `KeyFile`. (#370, issue #107)

---

## Build system and portability

- **`__P()` macro removed**: The K&R C compatibility shim was present in
  400+ function prototypes across 36 files. musl libc (Alpine Linux and
  other minimal distros) does not define `__P()`, causing build failures
  there. Removed all uses; purely mechanical transformation to standard
  C prototypes. (#337, issue #140)
- **`res_ninit()` configure detection**: On non-glibc platforms (FreeBSD,
  etc.), `resolv.h` requires prerequisite headers; the configure check
  was including only `resolv.h`, causing `res_ninit` to go undetected.
  Fixed by moving `AC_HEADER_RESOLV` before the check and adding the
  prerequisite headers to the test program. (#362, #297, issue #203)
- **Lua detection rewrite**: Overhauled `configure.ac` Lua detection to
  use pkg-config where available, with manual fallback. Supports Lua
  5.1-5.5, respects `LUA_CFLAGS`/`LUA_LIBS` environment variables,
  drops the stale `lua5.1` pkg-config name. (#264, #266, #327,
  issues #111)
- **Lua 5.5 compatibility**: C API changes in Lua 5.5 (`lua_newstate`
  seed, `lua_pop` placement, writer function signature). (#267, #268,
  #328, issue #265)
- **OpenSSL 3 EVP API**: Replaced deprecated `SHA1_Init/Update/Final`
  and `SHA256_Init/Update/Final` with the unified `EVP_MD_CTX` API.
  Drops `#ifdef HAVE_SHA256` guards. Compatible with OpenSSL 1.1.1 and
  3.x. (#351, closes #162)
- **OpenSSL version check**: Version comparison now ignores patch letter
  and status suffix, fixing false negatives on patch releases like
  `1.1.1n`. (#307, issue #178)
- **`libssl` detection**: Fixed configure test for OpenSSL 1.1.0+. (#317)
- **Autoconf minimum version**: Relaxed from 2.71 to 2.69, restoring
  support for Ubuntu 20.04, Debian 11, and RHEL 9 development
  environments. (#306, issue #177)
- **`--with-milter` explicit path**: When an explicit path was given,
  configure still ran a link test that could override it. (#336,
  issue #85)
- **`--with-libxml2` removed from INSTALL**: The flag was never
  implemented. (#335, issue #91)
- **`--with-ldns` removed**: The ldns backend was removed years ago;
  the configure flag was stale. (#311, issue #169)
- **`smfi_insheader` minimum libmilter version**: Removed backwards
  compat stub for sendmail 8.12. (#333)
- **K&R function prototype**: `dkimf_base64_encode_file` was using
  pre-ANSI K&R declaration style, removed in C23. (#261)
- **SASL/LDAP pkg-config**: Improved detection. (#192)
- **Incompatible pointer type warnings**: Fixed in several places. (#214)

---

## ed25519 support

- **GnuTLS ed25519 verification**: libopendkim now verifies
  ed25519-sha256 signatures when built with GnuTLS. (#282)
- **ed25519 key comparison fix**: `dkim_test_key()` used `i2d_PUBKEY_bio`
  output (which includes a 12-byte ASN.1 prefix) to compare against the
  raw ed25519 key from DNS. Fixed to use
  `EVP_PKEY_get_raw_public_key()`. (#299, closes #245)
- **ed25519 test coverage**: Added unit tests for ed25519 signing and
  verification, multi-signing, and key bit count. (#321, #326)
- **`dkim_sig_keybits()` for ed25519**: Returned 0; now returns 256. (#321)

---

## systemd / deployment

- **`network-online.target`**: Service unit now waits for
  `network-online.target` instead of `network.target`, ensuring
  interfaces have addresses before opendkim starts. (#315, issue #141)
- **`Type=notify`**: With the new `sd_notify()` support, the service
  unit switches from `Type=simple` to `Type=notify`, eliminating the
  startup race condition. (#316, #352)
- **Hardening directives**: Added `CapabilityBoundingSet`,
  `ProtectSystem=strict`, `PrivateUsers`, `RestrictAddressFamilies`,
  `SystemCallFilter`, `NoExecPaths`/`ExecPaths`, and others. (#316)
- **`Restart=on-abnormal`**: Service now restarts on unexpected exit. (#316)

---

## Documentation

- **`opendkim.conf(5)` case-insensitivity**: Documented that config
  parameter names are case-insensitive. (#289)
- **`SignHeaders` documentation**: Clarified semantics, added examples. (#292)
- **IPv6 `PeerList` inline limitation**: Documented workaround using a
  file for IPv6 CIDR entries. (#318, issue #155)
- **`SignatureAlgorithm` for ed25519**: Documented that `SignatureAlgorithm`
  must be explicitly set when using ed25519 keys. (#300, issue #107) --
  superseded by #370; the setting is now auto-detected from the key type.
- **Dual-algorithm signing example**: Added KeyTable example and caveats
  for signing with both RSA and ed25519. (#270)
- **`HowToRelease` modernized**: Updated for GitHub workflow, consistent
  release asset naming. (#338)
- **Spelling fixes**: Various typos in docs and code comments. (#347)

---

## Code quality and cleanup

- **`SingleAuthResult` removed**: Deprecated config option removed. (#258)
- **`conf_refcnt` assert removed**: Defensive assert that fired
  spuriously during normal operation. (#294)
- **Duplicate block comment marker**: Removed stale `/*` in
  libopendkim. (#293)
- **`stdio.h` includes**: Added missing includes in libopendkim/util.c
  and libvbr/vbr.c. (#320)
- **Python 3 Twisted**: Replaced deprecated `defer.returnValue()` with
  plain `return` in contrib/repute. (#237)
- **Compiler warning cleanup** (`-Wincompatible-pointer-types`,
  `-Wformat-truncation`): `entry_name` in the `-V` output path declared
  `const char *` to match `dkim_nametable_first`/`next` signatures;
  `snprintf` call sites in `dkim-util.c`, `opendkim.c`, and
  `opendkim-genzone.c` given explicit `%.*s` width bounds or larger
  buffers. (#360, issue #359)

---

## CI and testing

- **GitHub Actions**: Added Linux CI workflow (Ubuntu, OpenSSL 3, Lua
  5.4) running on push and PR to `develop`. (#332)
- **`workflow_dispatch`**: Added manual trigger button in Actions UI. (#355)
- **Parallel test ordering**: Fixed `make -j check` failures due to
  test ordering dependencies. (#296)
- **Test socket path**: Tests now use `./testkeys` instead of
  `/tmp/testkeys` (CVE-2020-35766 hardening). (#288)
- **Multi-signing tests**: Added `t-test204` and `t-test205` covering
  multiple simultaneous signatures. (#326)

---

## Still open / needs-testing

- **#151**: Transparent `strlcpy`/`strlcat` via libbsd-overlay - proposed
  by guijan, who build-tested on Alpine Linux and OpenBSD. On hold: making
  libbsd (or a compatible library) a mandatory dependency on non-BSD
  platforms needs broader team discussion before we can accept it.

- **#149**: libunbound UDP socket accumulation under sustained load -
  reported by multiple RHEL 9 / AlmaLinux 9 users (conathan, KIC-8462852,
  sfsumn, juresaht2); pattern is sockets growing unboundedly, requiring
  twice-daily restarts. Reproducer running on AWS EC2 AlmaLinux 9 with
  real friends-and-family mail traffic; no accumulation seen after 3+ hours. May be volume- or configuration-dependent.

- **#354**: Remove or modernize REPUTE/reprrd PHP contrib code - the PHP
  files in `contrib/repute/` and `reprrd/` use the `mysql_*` extension
  removed in PHP 7.0 (2015) and are not functional on any modern PHP
  version. Pending release announcement to surface any remaining users
  before removal.

- **#110**: `make -j check` failures under parallel test execution - a
  fix for test ordering dependencies landed in #296, but intermittent
  parallel failures have not been independently confirmed resolved.
  Needs a run of `make -j check` over several iterations.

- **#265**: Lua 5.5 compatibility - C API changes (`lua_newstate` seed
  parameter, `lua_pop` placement, writer function signature) were fixed
  in #267/#268/#328. Needs a build and smoke test against Lua 5.5.

- **#167**: `ldapi://` URI not working - the socket path was dropped
  when reconstructing the URI; fixed in #314. Needs confirmation from
  someone with an ldapi LDAP setup.

- **#248**: MySQL DSN special characters in passwords - fix merged in #369.
  Needs production testing from someone with special characters (`=`, `%`,
  etc.) in their SQL credentials to confirm round-trip correctness.

- **#107**: Auto-detect `SignatureAlgorithm` from key type - implemented in
  #370. Needs a test with an ed25519 `KeyFile` and no explicit
  `SignatureAlgorithm` config option to confirm the algorithm is
  automatically selected and signing succeeds.

---

## Community Requests (No Issue ID)

* It's become apparent that there are a number of widely used cases where OpenDKIM is in use, and because of some of the options available (LDAP, Lua, SQL, etc), as well as the uniqueness of some operating systems (OpenBSD, Linuxes that use the MUSL libraries, Different OpenSSL versions, GNUTLS, etc).  This doubles the challenge of debugging issues, because not only do we need to troubleshoot the issue, we need to duplicate the setup involved.  Suggestions on testing platforms/reproducers to keep consistent on AWS or in private infrastructure would be useful -- we want to know how YOU are using this.  If you'd like to volunteer to help as a reproducer, reach out.

* As of the time of this writing, our mailing lists are still being restored and should be up shortly (you may need to resubscribe), but in the mean time, github issues are a good way to communicate.