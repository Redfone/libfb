AUTOMAKE_OPTIONS = foreign # Ignore need for README/AUTHORS... etc

AM_CFLAGS=-Wall

# Include buildinc target
include $(top_srcdir)/buildinc.mk

lib_LTLIBRARIES = libfb.la
libfb_la_SOURCES = libfb/ethernet.c libfb/fb_lib.c libfb/flash.c libfb/poll.c libfb/utility.c libfb/get_local_mac.c libfb/fblib_ver.h libfb/sha1.c

libfb_la_LIBADD = @LTLIBOBJS@ @LIBNET@ @LIBPCAP@
libfb_la_LDFLAGS = -version-info 0:0:0

nobase_include_HEADERS = libfb/fb_lib.h libfb/fb_context.h libfb/fb_config.h libfb/sha1.h



