knot_modules_dnstap_la_SOURCES = knot/modules/dnstap/dnstap.c \
                                 knot/modules/dnstap/dnstapcounter.c \
                                 knot/modules/dnstap/dnstapcounter.h

EXTRA_DIST +=                    knot/modules/dnstap/dnstap.rst

if STATIC_MODULE_dnstap
libknotd_la_SOURCES += $(knot_modules_dnstap_la_SOURCES)
libknotd_la_CPPFLAGS += $(DNSTAP_CFLAGS)
libknotd_la_LIBADD += $(libdnstap_LIBS)
endif

if SHARED_MODULE_dnstap
knot_modules_dnstap_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_dnstap_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS) $(DNSTAP_CFLAGS)
knot_modules_dnstap_la_LIBADD = $(libdnstap_LIBS)
pkglib_LTLIBRARIES += knot/modules/dnstap.la
endif
