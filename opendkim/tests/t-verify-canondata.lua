-- Copyright (c) 2026, The Trusted Domain Project.  All rights reserved.

-- simple/simple verify test with AddCanonicalizedData (should pass)
--
-- Confirms that a valid, verified signature gets X-DKIM-Canonicalized-Header
-- and X-DKIM-Canonicalized-Body fields added, tagged with the signature's
-- domain and selector, containing base64 of the exact bytes used to verify
-- the signature.

mt.echo("*** simple/simple verifying test with AddCanonicalizedData (good)")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-verify-canondata.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-verify-canondata.conf",
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
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-canondata")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "DKIM-Signature", "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1296710324; bh=3VWGQGY+cSNYd1MGM+X6hRXU0stl8JCaQtl4mbX/j2I=;\r\n\th=From:Date:Subject;\r\n\tb=RNAhx6cV5AeZWJDEJG1hROdvCukhJnokhI9oABHwAyUAzC6MDntoH4PrS2jS7HGw2\r\n\t D7pU4yLGrlNsGlK8JvqizYNHl+v9+B6OnWAgzkgTimWTqBCYwo8X01N6hqoXDAm8hC\r\n\t RUpmeJvC84K5/nHHLASCb4W1PC2R4VkxUoyVnlYE=") ~=nil then
	error("mt.header(DKIM-Signature) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(DKIM-Signature) unexpected reply")
end
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

-- verify that an Authentication-Results header field got added, and it
-- reports a pass, confirming this signature verified successfully (i.e.
-- the canonicalized-data headers below are being added for a *passing*
-- signature, not merely on failure)
if not mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") and
   not mt.eom_check(conn, MT_HDRADD, "Authentication-Results") then
	error("no Authentication-Results added")
end

n = 0
found = 0
while true do
	ar = mt.getheader(conn, "Authentication-Results", n)
	if ar == nil then
		break
	end
	if string.find(ar, "dkim=pass", 1, true) ~= nil then
		found = 1
		break
	end
	n = n + 1
end
if found == 0 then
	error("incorrect DKIM result")
end

-- verify that X-DKIM-Canonicalized-Header and X-DKIM-Canonicalized-Body
-- got added, tagged with the signature's domain/selector, and containing
-- the expected base64 of the exact canonicalized bytes used to verify it
if not mt.eom_check(conn, MT_HDRINSERT, "X-DKIM-Canonicalized-Header") and
   not mt.eom_check(conn, MT_HDRADD, "X-DKIM-Canonicalized-Header") then
	error("no X-DKIM-Canonicalized-Header added")
end
if not mt.eom_check(conn, MT_HDRINSERT, "X-DKIM-Canonicalized-Body") and
   not mt.eom_check(conn, MT_HDRADD, "X-DKIM-Canonicalized-Body") then
	error("no X-DKIM-Canonicalized-Body added")
end

chdr = mt.getheader(conn, "X-DKIM-Canonicalized-Header", 0)
cbody = mt.getheader(conn, "X-DKIM-Canonicalized-Body", 0)

expect_chdr = "d=example.com; s=test; b=RnJvbTogdXNlckBleGFtcGxlLmNvbQ0KRGF0ZTogVHVlLCAy\n        MiBEZWMgMjAwOSAxMzowNDoxMiAtMDgwMA0KU3ViamVjdDogU2lnbmluZyB0ZXN0\n        DQpES0lNLVNpZ25hdHVyZTogdj0xOyBhPXJzYS1zaGEyNTY7IGM9c2ltcGxlL3Np\n        bXBsZTsgZD1leGFtcGxlLmNvbTsgcz10ZXN0Ow0KCXQ9MTI5NjcxMDMyNDsgYmg9\n        M1ZXR1FHWStjU05ZZDFNR00rWDZoUlhVMHN0bDhKQ2FRdGw0bWJYL2oyST07DQoJ\n        aD1Gcm9tOkRhdGU6U3ViamVjdDsNCgliPQ=="
expect_cbody = "d=example.com; s=test; b=VGhpcyBpcyBhIHRlc3QhDQo="

if chdr ~= expect_chdr then
	print("got: " .. tostring(chdr))
	print("want: " .. expect_chdr)
	error("incorrect X-DKIM-Canonicalized-Header value")
end
if cbody ~= expect_cbody then
	print("got: " .. tostring(cbody))
	print("want: " .. expect_cbody)
	error("incorrect X-DKIM-Canonicalized-Body value")
end

mt.disconnect(conn)
