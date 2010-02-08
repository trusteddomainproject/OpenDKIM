-- $Id: t-sign-rs-multiple.lua,v 1.1 2010/02/08 05:47:23 cm-msk Exp $

-- Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.

-- relaxed/simple multiple signing test
-- 
-- Confirms that a signature is added with the correct contents.

mt_echo("*** relaxed/simple multiple signing test")

-- try to start the filter
mt_startfilter("../opendkim", "-x", "t-sign-rs-multiple.conf")
mt_sleep(2)

-- try to connect to it
conn = mt_connect("inet:12345@localhost")
if conn == nil then
	error "mt_connect() failed"
end

-- send connection information
-- mt_negotiate() is called implicitly
if mt_conninfo(conn, "localhost", "127.0.0.1") ~= nil then
	error "mt_conninfo() failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_conninfo() unexpected reply"
end

-- send envelope macros and sender data
-- mt_helo() is called implicitly
mt_macro(conn, SMFIC_MAIL, "j", "t-sign-ss")
if mt_mailfrom(conn, "user@example.com") ~= nil then
	error "mt_mailfrom() failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_mailfrom() unexpected reply"
end

-- send headers
-- mt_rcptto() is called implicitly
if mt_header(conn, "From", "user@example.com") ~= nil then
	error "mt_header(From) failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_header(From) unexpected reply"
end
if mt_header(conn, "Date", "Tue, 22 Dec 2009 13:04:12 -0800") ~= nil then
	error "mt_header(Date) failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_header(Date) unexpected reply"
end
if mt_header(conn, "Subject", "Signing test") ~= nil then
	error "mt_header(Subject) failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_header() unexpected reply"
end

-- send EOH
if mt_eoh(conn) ~= nil then
	error "mt_eoh() failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_eoh() unexpected reply"
end

-- send body
if mt_bodystring(conn, "This is a test!\r\n") ~= nil then
	error "mt_bodystring() failed"
end
if mt_getreply(conn) ~= SMFIR_CONTINUE then
	error "mt_bodystring() unexpected reply"
end

-- end of message; let the filter react
if mt_eom(conn) ~= nil then
	error "mt_eom() failed"
end
if mt_getreply(conn) ~= SMFIR_ACCEPT then
	error "mt_bodystring() unexpected reply"
end

-- verify that a signature got added
if not mt_eom_check(conn, MT_HDRINSERT, "DKIM-Signature") then
	error "no signature added"
end

-- confirm properties
sig = mt_getheader(conn, "DKIM-Signature", 0)
if sig == nil then
	error "first signature not added"
end
if string.find(sig, "c=relaxed/simple", 1, true) == nil then
	error "signature has wrong c= value"
end
if string.find(sig, "v=1", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "d=example.net", 1, true) == nil then
	error "signature has wrong d= value (expecting example.net)"
end
if string.find(sig, "s=test2", 1, true) == nil then
	error "signature has wrong s= value (expecting test2)"
end
if string.find(sig, "bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=", 1, true) == nil then
	error "signature has wrong bh= value"
end
if string.find(sig, "h=From:Date:Subject", 1, true) == nil then
	error "signature has wrong h= value"
end

sig = mt_getheader(conn, "DKIM-Signature", 1)
if sig == nil then
	error "second signature not added"
end
if string.find(sig, "c=relaxed/simple", 1, true) == nil then
	error "signature has wrong c= value"
end
if string.find(sig, "v=1", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error "signature has wrong d= value (expecting example.com)"
end
if string.find(sig, "s=test", 1, true) == nil then
	error "signature has wrong s= value (expecting test)"
end
if string.find(sig, "bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=", 1, true) == nil then
	error "signature has wrong bh= value"
end
if string.find(sig, "h=From:Date:Subject", 1, true) == nil then
	error "signature has wrong h= value"
end
