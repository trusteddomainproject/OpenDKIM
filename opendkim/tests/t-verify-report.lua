-- Copyright (c) 2009-2013, The Trusted Domain Project.  All rights reserved.

-- reporting key verify test
-- 
-- Confirms that a report is sent when the verification fails

mt.echo("*** test reporting of failed signatures occurs")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-verify-report.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-verify-report.conf",
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

-- send HELO unles it was negotiated out
if not mt.test_option(conn, SMFIP_NOHELO) then
	if mt.helo(conn, "localhost") ~= nil then
		error("mt.helo() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.helo() unexpected reply")
	end
end
	
-- send envelope macros and sender data
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-report")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "DKIM-Signature", "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\n\tt=1329113412; r=y; bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=;\n\th=From:Date:Subject;\n\tb=J4DYccKlZx8+EFXvnUEZyiQn2JNpQ0JSvTT1PeyGfrYPAux//SHXb/K/Z6jYzqH5z\n\t ZkiQ5UutfDjkkW2WsRCilkvodnp0PGrLK5fDFHBK7vGTLzXyhI/zubkeYVZufd+9U7\n\t kuVE9jz2Vb4YDL8DC9EZJ5SyAY8uNnsrky8gQ948=") ~= nil then
	error("mt.header(DKIM-Signature) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(DKIM-Signature) unexpected reply")
end
if mt.header(conn, "From", "user@ex4mple.com") ~= nil then
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
if mt.header(conn, "Message-ID", "<184510.abcdefg@example.com>") ~= nil then
	error("mt.header(Message-ID) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Message-ID) unexpected reply")
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

-- verify that an Authentication-Results header field got added
if not mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") and
   not mt.eom_check(conn, MT_HDRADD, "Authentication-Results") then
	error("no Authentication-Results added")
end
ar = mt.getheader(conn, "Authentication-Results", 0)
if string.find(ar, "dkim=fail", 1, true) == nil then
	print(ar)
	error("incorrect DKIM result")
end
if string.find(ar, "verification failed", 1, true) == nil then
	print(ar)
	error("incorrect DKIM result")
end

mt.disconnect(conn)
