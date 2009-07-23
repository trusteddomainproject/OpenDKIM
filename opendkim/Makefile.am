# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -pthread --pedantic -Wall -O2
AM_LDFLAGS = -pthread

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
sbin_PROGRAMS = opendkim opendkim-testkey opendkim-testadsp
sbin_SCRIPTS = opendkim-genkey.sh

exampledir = $(datarootdir)/doc/@PACKAGE@
example_DATA = opendkim.conf.sample

opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h config.c config.h stats.c stats.h test.c test.h util.c util.h
opendkim_CFLAGS = 
opendkim_CPPFLAGS = -I../libopendkim -I../libar -I$(LIBMILTER_INCLUDES)
opendkim_LDFLAGS = -L../libopendkim -L../libar -L$(LIBMILTER_LIBS) $(LIBUNBOUND_LIBDIRS)
opendkim_LDADD = -lopendkim -lar -lmilter $(LIBUNBOUND_LIBS)
if BODYLENGTH_DB
opendkim_CFLAGS += -DUSE_DB -D_FFR_BODYLENGTH_DB
endif
if CAPTURE_UNKNOWN_ERRORS
opendkim_CFLAGS += -D_FFR_CAPTURE_UNKNOWN_ERRORS
endif
if COMMAIZE
opendkim_CFLAGS += -D_FFR_COMMAIZE
endif
if DIFFHEADERS
opendkim_CFLAGS += -D_FFR_DIFFHEADERS
endif
if DKIM_REPUTATION
opendkim_CFLAGS += -D_FFR_DKIM_REPUTATION
endif
if MULTIPLE_SIGNATURES
opendkim_CFLAGS += -D_FFR_MULTIPLE_SIGNATURES
endif
if PARSE_TIME
opendkim_CFLAGS += -D_FFR_PARSE_TIME
endif
if QUERY_CACHE
opendkim_CFLAGS += -DUSE_DB -DQUERY_CACHE
endif
if REPLACE_RULES
opendkim_CFLAGS += -D_FFR_REPLACE_RULES
endif
if REPORT_INTERVALS
opendkim_CFLAGS += -D_FFR_REPORT_INTERVALS
endif
if SELECTOR_HEADER
opendkim_CFLAGS += -D_FFR_SELECTOR_HEADER
endif
if SENDER_HEADERS
opendkim_CFLAGS += -D_FFR_SENDER_HEADERS
endif
if STATS
opendkim_CFLAGS += -DUSE_DB -D_FFR_STATS
endif
if USE_ARLIB
opendkim_CFLAGS += -DUSE_ARLIB
endif
if USE_UNBOUND
opendkim_CFLAGS += -DUSE_UNBOUND
endif
if VBR
opendkim_CFLAGS += -D_FFR_VBR
endif
if ZTAGS
opendkim_CFLAGS += -D_FFR_ZTAGS
endif

if STATS
sbin_PROGRAMS += opendkim-stats
opendkim_stats_SOURCES = opendkim-db.c opendkim-stats.c
opendkim_stats_CPPFLAGS = -I../libopendkim -I../libar
opendkim_stats_LDFLAGS = -L../libopendkim -L../libar $(LIBUNBOUND_LIBDIRS)
opendkim_stats_LDADD = -lopendkim -lar $(LIBUNBOUND_LIBS)
endif

opendkim_testkey_SOURCES = opendkim-testkey.c
opendkim_testkey_CPPFLAGS = -I../libopendkim -I../libar
opendkim_testkey_LDFLAGS = -L../libopendkim -L../libar $(LIBUNBOUND_LIBDIRS)
opendkim_testkey_LDADD = -lopendkim -lar $(LIBUNBOUND_LIBS)

opendkim_testadsp_SOURCES = opendkim-testadsp.c
opendkim_testadsp_CPPFLAGS = -I../libopendkim -I../libar
opendkim_testadsp_LDFLAGS = -L../libopendkim -L../libar $(LIBUNBOUND_LIBDIRS)
opendkim_testadsp_LDADD = -lopendkim -lar $(LIBUNBOUND_LIBS)

man_MANS = opendkim.conf.5 opendkim-genkey.8 opendkim-testadsp.8 opendkim-testkey.8 opendkim.8
if STATS
man_MANS += opendkim-stats.8
endif

EXTRA_DIST = $(example_DATA) $(man_MANS) opendkim-stats.8 $(sbin_SCRIPTS)
