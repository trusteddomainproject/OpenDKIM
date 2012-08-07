-- Copyright (c) 2010 Jozsef Kovacs and Alex Beregszaszi
--
-- Development kindly sponsored by Datira (www.datira.com),
-- a professional hosting company.
--
-- License: MIT
--

local logging_enabled = 1

local function logger (logwhat)
    if logging_enabled == 1 then
        odkim.log(ctx, "LUA-SETUP "..logwhat)
    end
end

local function signer (domain)
	if odkim.sign(ctx, domain) == 1 then
		logger("Signing requested")
	else
		logger("Signing failed")
	end
end

-- Get SASL username
local author = odkim.get_mtasymbol(ctx, "{auth_authen}")

-- Incoming mail (without sasl username), verify only
if author == nil then
    odkim.verify(ctx)
    return nil
end

logger("SASL username: "..author)

-- Sign mail using the key associated to the envelope sender domain
local mailfromdomain = odkim.get_fromdomain(ctx)
local mailfrom = odkim.get_mtasymbol(ctx, "{mail_addr}")
local headerfromaddr = odkim.get_header(ctx, "From", 0)

logger("Mail from domain: "..mailfromdomain)
logger("Mail from address: "..mailfrom)
logger("Header from address: "..headerfromaddr)

-- TODO: regexp email matching for headerfromaddr
if string.find(headerfromaddr, mailfrom) ~= nil then
    -- If we have a direct match, sign the mail
    if author == mailfrom then
        signer(mailfromdomain)
        return nil
    end

    -- Check for additional possible sender aliases
    -- requires luasql-mysql
    require "luasql.mysql"
    local sql = luasql.mysql()
    if sql ~= nil then
        local conn = sql:connect("dbname", "dbuser", "dbpass", "db.example.com")
        if conn ~= nil then
            local cur = conn:execute(string.format("select * from alias where address=\"%s\" and goto like \"%%%s%%\"", mailfrom, author))
            if cur ~= nil then
                if cur:numrows() > 0 then
                    cur:close()
                    conn:close()
                    sql:close()
                    logger("Alias found in SQL")
                    signer(mailfromdomain)
                    return nil
                end
                logger("No alias in SQL")
                cur:close()
            end
            conn:close()
			odkim.set_result(ctx, SMFIS_REJECT)
			return nil
        end
        sql:close()
		-- temporary failure: hope to process it again and SQL is available the second time
		odkim.set_result(ctx, SMFIS_TEMPFAIL)
		return nil
    end
end

-- If we got this far we have a forged sender associated to the sasl username
odkim.set_result(ctx, SMFIS_REJECT)

return nil
