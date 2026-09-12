noinst_LTLIBRARIES = libslog.la

libslog_la_SOURCES = slog.cpp slog.hpp
libslog_la_LIBADD = ../libdrakvuf/libdrakvuf.la $(PTHREAD_LIBS)

AM_CPPFLAGS = $(CPPFLAGS) -I$(top_srcdir) -I$(top_srcdir)/src
AM_CPPFLAGS += $(VMI_CFLAGS) $(GLIB_CFLAGS) $(JSONC_CFLAGS) $(PTHREAD_CFLAGS)
AM_CXXFLAGS = $(CXXFLAGS)

AM_LDFLAGS = $(LDFLAGS)
AM_LDFLAGS += $(VMI_LIBS) $(GLIB_LIBS) $(JSONC_LIBS) $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

if HARDENING
AM_CXXFLAGS += $(HARDEN_CFLAGS) -DHARDENING
AM_LDFLAGS += $(HARDEN_LDFLAGS)
endif

if SANITIZE
AM_CXXFLAGS += $(SANITIZE_CXXFLAGS)
AM_LDFLAGS += $(SANITIZE_LDFLAGS)
endif

if DEBUG
AM_CXXFLAGS += -DDRAKVUF_DEBUG -Werror -Wall -Wextra -g -ggdb3
AM_CXXFLAGS += -Wcast-qual -Wcast-align -Wstrict-aliasing \
               -Wpointer-arith -Winit-self -Wshadow \
               -Wredundant-decls -Wfloat-equal -Wundef \
               -Wvla -Wformat -Wformat-security
endif
