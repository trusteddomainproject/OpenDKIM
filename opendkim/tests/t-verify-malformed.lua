-- Copyright (c) 2009-2013, The Trusted Domain Project.  All rights reserved.

-- malformed From: field message test
-- 
-- Confirms that an unsigned message produces the correct result

mt.echo("*** malformed From: field message")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-verify-malformed.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-verify-malformed.conf",
               "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn == nil then
	error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost", "127.0.0.1") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-malformed")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user") ~= nil then
	error("mt.header(From) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(From) unexpected reply")
end
if mt.header(conn, "Date", "Tue, 22 Dec 2009 13:04:12 -0800") ~= nil then
	error("mt.header(Date) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Date) unexpected reply")
end
if mt.header(conn, "Subject", "Signing test") ~= nil then
	error("mt.header(Subject) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Subject) unexpected reply")
end

-- send EOH
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eoh() unexpected reply")
end

-- send body
if mt.bodystring(conn, "This is a test!\r\n") ~= nil then
	error("mt.bodystring() failed")
end
if mt.getreply(conn) ~= SMFIR_SKIP and
   mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.bodystring() unexpected reply")
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

-- verify that the right Authentication-Results header field got added
if mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") or
   mt.eom_check(conn, MT_HDRADD, "Authentication-Results") then
	ar = mt.getheader(conn, "Authentication-Results", 0)
	if string.find(ar, "format", 1, true) == nil then
		error("incorrect Authentication-Results field")
	end
else
	error("missing Authentication-Results field")
end

mt.disconnect(conn)
