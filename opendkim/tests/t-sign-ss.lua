-- $Id: t-sign-ss.lua,v 1.1.2.3 2009/12/23 08:30:44 cm-msk Exp $

-- simple/simple signing test
-- 
-- Confirms that a signature is added with the correct contents.

mt_echo("*** simple/simple signing test")

-- try to start the filter
mt_startfilter("../opendkim", "-x", "t-sign-ss.conf")
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
if string.find(sig, "c=simple/simple", 1, true) == nil then
	error "signature has wrong c= value"
end
if string.find(sig, "v=1", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "s=test", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "s=test", 1, true) == nil then
	error "signature has wrong v= value"
end
if string.find(sig, "bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=", 1, true) == nil then
	error "signature has wrong bh= value"
end
if string.find(sig, "h=From:Date:Subject", 1, true) == nil then
	error "signature has wrong h= value"
end
