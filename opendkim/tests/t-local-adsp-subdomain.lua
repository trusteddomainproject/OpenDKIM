
-- Copyright (c) 2009-2012, The OpenDKIM Project.  All rights reserved.

-- 
-- verify config option LocalADSP works

mt.echo("*** test config option LocalADSP with subdomain checking")

-- setup
sock = "unix:" .. mt.getcwd() .. "/t-local-adsp-subdomain.sock"
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-local-adsp-subdomain.conf",
               "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.05)
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
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-revoked")
if mt.mailfrom(conn, "user@subdomaincheck.example.com") ~= nil then
	error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error "mt.mailfrom() unexpected reply"
end

if mt.header(conn, "From", "user@example2.com") ~= nil then
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
if mt.header(conn, "Subject", "adsp test") ~= nil then
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
if mt.getreply(conn) ~= SMFIR_SKIP and
   mt.getreply(conn) ~= SMFIR_CONTINUE then
	print(mt.getreply(conn))
	error "mt.bodystring() unexpected reply"
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error "mt.eom() failed"
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error "mt.eom() unexpected reply"
end

-- verify that an Authentication-Results header field got added
if not mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") and
   not mt.eom_check(conn, MT_HDRADD, "Authentication-Results") then
	error "no Authentication-Results added"
end
ar = mt.getheader(conn, "Authentication-Results", 0)
if string.find(ar, "dkim-adsp=discard", 1, true) == nil then
	print(ar)
	error "incorrect ADSP result"
end

mt.disconnect(conn)
