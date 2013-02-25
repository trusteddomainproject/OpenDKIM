-- Copyright (c) 2010-2013, The Trusted Domain Project.  All rights reserved.

-- Syntax error proccessing test
-- 
-- Confirms that an message with a syntax error TEMPFAILs

mt.echo("*** syntax error in DKIM signature")

-- try to start the filter
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-verify-syntax.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end
mt.startfilter(binpath .. "/opendkim", "-x", "t-verify-syntax.conf", "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn == nil then
	error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost", "unspec") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-syntax")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
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
-- syntax error in signature
-- doesn't get processed until eoh though this could change later
if mt.header(conn, "DKIM-Signature", "v=1 a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1283905216; bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=;\r\n\th=From:Date:Subject;\r\n\tb=AiGrvHu2mODRK2BlLXJy/YjCiBg3qr/QZ7laVq7ccMeA2QDmrksc9Hoj7lsFQc+bs\r\n\t lgIJh+8gzyQeGZz8TYX/LJaBg8kH8jn0w70hvI63sgN4wytwhvpvkPInUhLXgpkknj\r\n\t DT70LzX2ABd24nHDshfS22v+nwUl9xuMAq77UtbE=") ~= nil then
	error("mt.header(DKIM-Signature) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(DKIM-Signature) unexpected reply")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Subject) unexpected reply")
end

-- send EOH
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_REPLYCODE then
	error("mt.eoh() unexpected reply - expected REPLYCODE (reject)")
end

mt.disconnect(conn)
