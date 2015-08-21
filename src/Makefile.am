SUBDIRS = lib

AM_CPPFLAGS = -I$(top_srcdir)/include

if HAVE_LIBAO
  bin_PROGRAMS = shairplay
  shairplay_SOURCES = shairplay.c
  shairplay_LDADD = lib/libshairplay.la
  shairplay_CFLAGS =
  shairplay_LDFLAGS = -static-libtool-libs

  shairplay_CFLAGS += $(libao_CFLAGS)
  shairplay_LDADD += $(libao_LIBS)

if HAVE_JSONC
  shairplay_CFLAGS += $(json_CLFAGS)
  shairplay_LDADD += $(json_LIBS)
endif

if HAVE_LIBCURL
  shairplay_CFLAGS += $(libcurl_CFLAGS)
  shairplay_LDADD += $(libcurl_LIBS)
endif
endif
