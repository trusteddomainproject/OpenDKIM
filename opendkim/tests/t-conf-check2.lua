-- Copyright (c) 2009, 2010, 2012, 2013, The Trusted Domain Project.
--   All rights reserved.

-- Configuration validity check2
-- 
-- Confirms that the configuration file is acceptable (fail test)

mt.echo("*** invalid signing configuration test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-conf-check2.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-conf-check2.conf", "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn ~= nil then
	error("mt.connect() succeeded (shouldn't have)")
end
