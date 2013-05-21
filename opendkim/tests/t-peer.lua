-- Copyright (c) 2010-2013, The Trusted Domain Project.  All rights reserved.

-- PeerList calculation test

mt.echo("*** PeerList calculation test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-peer.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-peer.conf", "-p", sock)

-- Those in the peer list should have SMFIR_ACCEPT as the result
-- to prevent any verification or signing practices

test = {
-- hostname test
	{ "peer.example.com", "127.0.0.1", SMFIR_ACCEPT },
	{ "bob.example.com", "127.0.0.1", SMFIR_ACCEPT },
	{ "bob.example.net", "127.0.0.1", SMFIR_CONTINUE },
	{ "nonpeer.example.com", "127.0.0.1", SMFIR_CONTINUE },
	{ "xyz.nonpeer.example.com", "127.0.0.1", SMFIR_CONTINUE },
	{ "allowed.nonpeer.example.com", "127.0.0.1", SMFIR_ACCEPT },
	{ "smtp.example.net", "127.0.0.1", SMFIR_ACCEPT },
-- ipv4 tests
	{ "localhost", "127.0.0.1", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.1", SMFIR_ACCEPT },
	{ "localhost", "192.168.1.64", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.128", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.129", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.130", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.131", SMFIR_CONTINUE },
	{ "localhost", "192.168.1.132", SMFIR_ACCEPT },
-- ipv6 tests
	{ "localhost", "9001:db8::8:800:200c:417a", SMFIR_CONTINUE },
	{ "localhost", "2001:db8::91", SMFIR_ACCEPT },
	{ "localhost", "2001:db8::fff0", SMFIR_CONTINUE },
	{ "localhost", "2001:db8::fff1", SMFIR_CONTINUE },
	{ "localhost", "2001:db8::fff2", SMFIR_CONTINUE },
	{ "localhost", "2001:db8::fff3", SMFIR_CONTINUE },
	{ "localhost", "2001:db8::fff4", SMFIR_ACCEPT }
	}

for index = 1, #test
do
	-- try to connect to it
	conn = mt.connect(sock, 40, 0.25)
	if conn == nil then
		error("mt.connect() failed")
	end

	if mt.conninfo(conn, test[index][1], test[index][2]) ~= nil then
		stre = "mt.conninfo() failed for " .. test[index][1] .. 
		       " (" .. test[index][2] .. ")"
		error(stre)
	end
	if mt.getreply(conn) ~= test[index][3] then
		stre = "mt.conninfo() unexpected reply " .. test[index][1] ..
		       "(" .. test[index][2] .. ") should be " 
		if test[index][3] == SMFIR_CONTINUE then
			stre = stre .. "SMFIR_CONTINUE"
		else 	
			stre = stre .. "SMFIR_ACCEPT"
		end
		error(stre)
	end

	-- disconnect
	mt.disconnect(conn)
end
