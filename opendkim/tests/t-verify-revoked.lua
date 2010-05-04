-- $Id: t-verify-revoked.lua,v 1.1.2.2 2010/05/04 03:24:20 cm-msk Exp $

-- Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.

-- revoked key verify test
-- 
-- Confirms that a signature matching a revoked key is reported as such

mt.echo("*** simple/simple verify revoked key")

-- try to start the filter
mt.startfilter("../opendkim", "-x", "t-verify-revoked.conf")
mt.sleep(2)

-- try to connect to it
conn = mt.connect("inet:12345@localhost")
if conn == nil then
	error "mt.connect() failed"
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost", "127.0.0.1") ~= nil then
	error "mt.conninfo() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.conninfo() unexpected reply"
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "j", "t-verify-revoked")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.mailfrom() unexpected reply"
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "DKIM-Signature", "v=1; a=rsa-sha256; c=relaxed/relaxed;\n\td=example.com; s=revoked;\n\th=domainkey-signature:mime-version:received:received:in-reply-to:\n\t references:date:message-id:subject:from:to:cc:content-type;\n\tbh=34lkc8Kvp/4C7BZOHlFJr8XlPeQt1pLHo4V8JljV13c=;\n\tb=sF59xX14kHxUUF2NQs1sF7Jla+dfLKwqCkYRFfLAo1n48oRvlcc3W1nwWU/BEk6mp9\n\t 0ZoylqVfErDrxDTeAEDLwaaPSL+4ZMjvp3WZyuFp2gCoQb5U8INu+vdnNvAgr4hi1Ku4\n\t mEQhR5ncoCxOUWq4e7r1CCIH4DM2fLbZa4ywQ=") ~= nil then
	error "mt.header(DKIM-Signature) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.header(From) unexpected reply"
end
if mt.header(conn, "From", "user@example.com") ~= nil then
	error "mt.header(From) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.header(From) unexpected reply"
end
if mt.header(conn, "Date", "Tue, 22 Dec 2009 13:04:12 -0800") ~= nil then
	error "mt.header(Date) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.header(Date) unexpected reply"
end
if mt.header(conn, "Subject", "Signing test") ~= nil then
	error "mt.header(Subject) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.header(Subject) unexpected reply"
end

-- send EOH
if mt.eoh(conn) ~= nil then
	error "mt.eoh() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.eoh() unexpected reply"
end

-- send body
if mt.bodystring(conn, "This is a test!\r\n") ~= nil then
	error "mt.bodystring() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.bodystring() unexpected reply"
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error "mt.eom() failed"
end
if mt.getreply(conn) ~= SMFIR_TEMPFAIL then
	error "mt.eom() unexpected reply"
end

-- verify that an Authentication-Results header field got added
if not mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") then
	error "no Authentication-Results added"
end
ar = mt.getheader(conn, "Authentication-Results", 0)
if string.find(ar, "dkim=fail", 1, true) == nil then
	error "incorrect DKIM result"
end
if string.find(ar, "revoked", 1, true) == nil then
	error "incorrect DKIM result"
end
