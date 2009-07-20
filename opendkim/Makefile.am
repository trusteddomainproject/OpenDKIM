# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -pthread --pedantic -Wall -std=c99 -O2 -I../libopendkim -I../libar
AM_LDFLAGS = -pthread -L../libopendkim -L../libar

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
sbin_PROGRAMS = opendkim opendkim-stats opendkim-testkey opendkim-testadsp
sbin_SCRIPTS = opendkim-genkey.sh

exampledir = $(datarootdir)/doc/@PACKAGE@
example_DATA = opendkim.conf.sample

opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h config.c config.h stats.c stats.h test.c test.h util.c util.h
opendkim_LDADD = -lopendkim -lar

opendkim_stats_SOURCES = opendkim-stats.c

opendkim_testkey_SOURCES = opendkim-testkey.c

opendkim_testadsp_SOURCES = opendkim-testadsp.c

man_MANS = opendkim.conf.5 opendkim-genkey.8 opendkim-stats.8 opendkim-testadsp.8 opendkim-testkey.8 opendkim.8
