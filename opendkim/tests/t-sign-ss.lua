-- $Id: t-sign-ss.lua,v 1.1.2.1 2009/12/23 00:18:16 cm-msk Exp $

-- simple/simple signing test
-- 
-- Confirms that a signature is added.  Does NOT currently verify that it
-- is correct; for now we rely on the unit tests of libopendkim for that.
-- Also, the current incarnation of "miltertest" doesn't allow for pattern
-- matches on added header fields; that will have to change.

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
