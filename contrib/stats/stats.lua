-- stats.lua -- conventional stats extensions
--
-- Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
--
-- Referencing this as StatisticsScript from an opendkim that has both "stats"
-- and "lua" enabled will produce some extended stats lines for each message
-- that indicate whether the message passed SPF and/or SenderID, and
-- whether or not SpamAssassin thought the message was spam.  This might
-- be useful for data correlation at the data aggregation point.

--
-- SpamAssassin
--
spam = odkim.get_header(ctx, "X-Spam-Status", 0)
if spam == nil then
	odkim.stats(ctx, "spam", "-1")
elseif string.sub(spam, 1, 3) == "No," or string.sub(spam, 2, 4) == "No," then
	odkim.stats(ctx, "spam", "0")
elseif string.sub(spam, 1, 4) == "Yes," or string.sub(spam, 2, 5) == "Yes," then
	odkim.stats(ctx, "spam", "1")
else
	odkim.stats(ctx, "spam", "-1")
end

--
-- SPF/Sender-ID
--
n = 0
done = 0
found = 0
while (done == 0) do
	ares = odkim.get_header(ctx, "Authentication-Results", n)
	if ares == nil then
		done = 1
	else
		spf = string.find(ares, "spf=", 1, true)
		if spf ~= nil then
			done = 1
			found = 1
			if string.find(ares, "spf=pass", 1, true) ~= nil then
				odkim.stats(ctx, "spf", "1")
			elseif string.find(ares, "spf=fail", 1, true) ~= nil then
				odkim.stats(ctx, "spf", "0")
			else
				odkim.stats(ctx, "spf", "-1")
			end
			if string.find(ares, "sender-id=pass", 1, true) ~= nil then
				odkim.stats(ctx, "senderid", "1")
			elseif string.find(ares, "sender-id=fail", 1, true) ~= nil then
				odkim.stats(ctx, "senderid", "0")
			else
				odkim.stats(ctx, "senderid", "-1")
			end
		end
	end
	n = n + 1
end
if found == 0 then
	odkim.stats(ctx, "spf", "-1")
	odkim.stats(ctx, "senderid", "-1")
end

odkim.stats(ctx, "rcpts", tostring(odkim.rcpt_count(ctx)))
