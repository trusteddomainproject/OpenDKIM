lib_LIBRARIES = libopendkim.a
libopendkim_a_SOURCES = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-policy.c dkim-rep.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c rfc2822.c util.c vbr.c
libopendkim_a_CFLAGS = 

if BODYLENGTH_DB
libopendkim_a_CFLAGS += -D_FFR_BODYLENGTH_DB
endif

if DIFFHEADERS
libopendkim_a_CFLAGS += -D_FFR_DIFFHEADERS
endif

if DKIM_REPUTATION
libopendkim_a_CFLAGS += -D_FFR_DKIM_REPUTATION
endif

if DNS_UPGRADE
libopendkim_a_CFLAGS += -D_FFR_DNS_UPGRADE
endif

if PARSE_TIME
libopendkim_a_CFLAGS += -D_FFR_PARSE_TIME
endif

if STATS
libopendkim_a_CFLAGS += -D_FFR_STATS
endif

if VBR
libopendkim_a_CFLAGS += -D_FFR_VBR
endif
