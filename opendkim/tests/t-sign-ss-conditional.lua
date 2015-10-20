-- Copyright (c) 2009, 2010, 2013, 2015, The Trusted Domain Project.
--   All rights reserved.

-- simple/simple signing test
-- 
-- Confirms that a signature is added with the correct contents.

mt.echo("*** simple/simple signing test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-sign-ss-conditional.sock"
end

binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-sign-ss-conditional.conf", "-p", sock)

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
mt.macro(conn, SMFIC_MAIL, "i", "t-sign-ss-conditional")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end
if mt.rcptto(conn, "user@example.net") ~= nil then
	error("mt.rcptto() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.rcptto() unexpected reply")
end

-- send headers
if mt.header(conn, "From", "user@example.com") ~= nil then
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
if mt.header(conn, "To", "user@example.net") ~= nil then
	error("mt.header(To) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(To) unexpected reply")
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
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.bodystring() unexpected reply")
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

-- verify that a signature got added
if not mt.eom_check(conn, MT_HDRINSERT, "DKIM-Signature") and
   not mt.eom_check(conn, MT_HDRADD, "DKIM-Signature") then
	error("no signature added")
end

-- confirm properties
-- first the conditional signature
sig = mt.getheader(conn, "DKIM-Signature", 0)
mt.echo(sig)
if string.find(sig, "c=simple/simple", 1, true) == nil then
	error("conditional signature has wrong c= value")
end
if string.find(sig, "v=2", 1, true) == nil then
	error("conditional signature has wrong v= value")
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error("conditional signature has wrong d= value")
end
if string.find(sig, "!cd=example.net", 1, true) == nil then
	error("conditional signature has wrong !cd= value")
end
if string.find(sig, "s=test", 1, true) == nil then
	error("conditional signature has wrong s= value")
end
if string.find(sig, "bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", 1, true) == nil then
	error("conditional signature has wrong bh= value")
end
if string.find(sig, "h=From:Date:Subject:To", 1, true) == nil then
	error("conditional signature has wrong h= value")
end

-- then the regular one
sig = mt.getheader(conn, "DKIM-Signature", 1)
if sig == nil then
	error("only one signature found")
end
mt.echo(sig)
if string.find(sig, "c=simple/simple", 1, true) == nil then
	error("primary signature has wrong c= value")
end
if string.find(sig, "v=1", 1, true) == nil then
	error("primary signature has wrong v= value")
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error("primary signature has wrong d= value")
end
if string.find(sig, "!cd=", 1, true) ~= nil then
	error("primary signature has a !cd= value")
end
if string.find(sig, "s=test", 1, true) == nil then
	error("primary signature has wrong s= value")
end
if string.find(sig, "bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=", 1, true) == nil then
	error("primary signature has wrong bh= value")
end
if string.find(sig, "h=From:Date:Subject:To", 1, true) == nil then
	error("primary signature has wrong h= value")
end

mt.disconnect(conn)
