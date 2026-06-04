# Internationalized Domain Names and EAI Mail in OpenDKIM

## Background

DKIM (RFC 6376) was designed for traditional ASCII email.  The Email Address
Internationalization (EAI) suite of RFCs extends email to support Unicode
throughout: UTF-8 header field bodies (RFC 6532), internationalized addresses
in SMTP (RFC 6531), and internationalized domain names (IDN) in DNS.  RFC 8616
updates DKIM to describe how signing and verification should work in this
environment.

This document covers what OpenDKIM currently supports, what it does not, and
how to configure it correctly if your domain name contains non-ASCII characters.


## What OpenDKIM supports

As of the fix for issue #47 (partial RFC 8616 support):

- **Signing and verifying messages with UTF-8 header field bodies.**  A message
  whose `Subject:`, `From:`, or other headers contain UTF-8 bytes can be signed
  and verified correctly.  The canonicalization algorithms (simple and relaxed)
  operate on raw octets and have always been byte-correct; the fix removed a
  gate in `dkim_header()` that was rejecting high bytes before they reached
  canonicalization.

- **Parsing `DKIM-Signature` headers that contain UTF-8 in the `i=` local-part.**
  RFC 8616 section 4 permits the local-part of the `i=` Agent or User
  Identifier tag to be UTF-8 in EAI messages.  `dkim_process_set()` previously
  rejected any non-ASCII byte unconditionally; it now allows high bytes through
  in tag-value context while still requiring tag names to be ASCII.


## What OpenDKIM does NOT support

- **Automatic U-label to A-label conversion.**  OpenDKIM does not include
  libidn2 or any equivalent, so it cannot automatically translate a Unicode
  domain name (U-label, e.g. `münchen.de`) to its Punycode/ACE form (A-label,
  e.g. `xn--mnchen-3ya.de`).

- **U-labels in configuration.**  If you put a U-label directly in
  `opendkim.conf` (as the value of `Domain`, `SubDomains`, or a signing table
  entry), OpenDKIM will pass it as-is to the DNS resolver.  DNS only understands
  A-labels; the lookup will fail and signing will not occur.

  There is no warning or error for this misconfiguration - the DNS query simply
  returns no results.


## If you MUST use an internationalized domain name

### Step 1: Find the A-label for your domain

The A-label is the ASCII-compatible encoding (ACE) of your domain.  Your DNS
registrar will show it, but you can also derive it yourself:

**Using Python (no extra packages required):**

```
python3 -c "print('münchen.de'.encode('idna').decode('ascii'))"
xn--mnchen-3ya.de
```

**Using the `idn` tool (from the libidn package):**

```
idn --quiet -a münchen.de
xn--mnchen-3ya.de
```

**Using `dig` to confirm the A-label resolves:**

```
dig TXT mail._domainkey.xn--mnchen-3ya.de
```

Multi-label domains (e.g. `mail.münchen.de`) encode each label independently;
only the non-ASCII labels are encoded:

```
python3 -c "print('mail.münchen.de'.encode('idna').decode('ascii'))"
mail.xn--mnchen-3ya.de
```


### Step 2: Configure OpenDKIM with the A-label

In `opendkim.conf`, always use the A-label:

```
Domain      xn--mnchen-3ya.de
Selector    mail
KeyFile     /etc/opendkim/keys/xn--mnchen-3ya.de/mail.private
```

The same applies to signing table and key table entries:

```
# SigningTable
*@münchen.de     münchen           # WRONG - DNS lookup will fail
*@xn--mnchen-3ya.de  xn--mnchen-3ya.de  # correct
```

Or if your MTA delivers mail using the Unicode form of the address, use a
wildcard or regex approach that maps to an A-label key table entry:

```
# /etc/opendkim/signing.table
*@münchen.de     default

# /etc/opendkim/key.table  
default   xn--mnchen-3ya.de:mail:/etc/opendkim/keys/mail.private
```


### Step 3: Publish DNS records under the A-label

Your DKIM TXT record must be published under the A-label selector._domainkey
name.  The record itself is standard ASCII:

```
mail._domainkey.xn--mnchen-3ya.de.  IN  TXT  "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

Verify it is reachable:

```
opendkim-testkey -d xn--mnchen-3ya.de -s mail -vvv
```


## The `i=` tag and EAI mail

The optional `i=` tag in a `DKIM-Signature` header identifies the Agent or
User Identifier (AUID).  For a signing domain of `xn--mnchen-3ya.de`, a
signer might include:

```
i=søren@xn--mnchen-3ya.de
```

where the local-part `søren` contains UTF-8.  RFC 8616 section 4 explicitly
allows this in messages that transit an EAI-capable path.  OpenDKIM will now
parse and verify such signatures without treating the UTF-8 bytes as a syntax
error.

Note that the domain portion of `i=` must still be an A-label; only the
local-part may be UTF-8.

If you do not configure an explicit `i=` value (most deployments do not),
OpenDKIM omits the tag entirely, which is valid per RFC 6376 and requires no
special handling.


## Limitations and future work

- **No libidn2 integration.**  Adding automatic U-label to A-label translation
  in `opendkim.conf` parsing would require linking against libidn2 (or
  equivalent).  This is a possible future enhancement but is out of scope for
  the current change.

- **No EAI SMTP negotiation.**  OpenDKIM operates as a milter and does not
  inspect SMTP-level EAI capability negotiation (RFC 6531 `SMTPUTF8`).
  Whether the underlying message uses EAI headers is transparent to OpenDKIM:
  it processes whatever header bytes the MTA delivers.

- **RFC 8616 section 3.2 (address rewriting).**  This section discusses how
  a relay that downgrades an EAI message to ASCII must handle DKIM signatures.
  OpenDKIM does not perform any such downgrade; that is the MTA's
  responsibility.

- **Milter-level address parsing for SMTPUTF8 mail is unaudited.**  When an
  MTA uses the SMTPUTF8 extension (RFC 6531) and delivers a message whose
  `From:` header contains a U-label domain (e.g. `user@münchen.de`), OpenDKIM
  must extract that domain to perform signing table and key table lookups.  The
  address-parsing code in the milter has not been audited for UTF-8 correctness.
  If it expects ASCII, the lookup will silently fail to match and the message
  will not be signed, even if the key table entry is correct.  Until this is
  audited and tested, operators running SMTPUTF8-capable MTAs should verify
  that signing actually occurs for EAI mail (check for a `DKIM-Signature:`
  header on outbound messages) rather than assuming it does.


## Summary

| Scenario | Supported? |
|---|---|
| Signing messages with UTF-8 headers (RFC 6532) | Yes |
| Verifying messages with UTF-8 headers | Yes |
| `i=` tag with UTF-8 local-part | Yes (parse and verify) |
| `d=` A-label domain in config | Yes |
| `d=` U-label domain in config (auto-convert) | No - use A-label explicitly |
| DKIM signing of EAI mail end-to-end | Yes, with A-label config |
