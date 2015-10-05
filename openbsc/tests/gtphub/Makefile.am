AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)

EXTRA_DIST = \
	gtphub_test.ok

noinst_PROGRAMS = gtphub_test

gtphub_test_SOURCES = gtphub_test.c

gtphub_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	-lgtp -lrt

