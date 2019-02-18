PACKAGE = dhcpd-pd
VERSION = 0.0.1

srcdir ?= $(dir $(firstword ${MAKEFILE_LIST}))
builddir ?= .

VPATH = ${srcdir}

DEBUG_LEVEL =	0x7c
#DEBUG_LEVEL =	0xffff

OPTFLAGS =	-O2 -g3
CFLAGS_flto =	-flto
LDFLAGS_flto =	-fuse-linker-plugin
AM_CFLAGS =	-std=gnu11 -Wall -W -Wno-unused-parameter -Wmissing-prototypes
AM_CPPFLAGS =	-I${srcdir} -D_GNU_SOURCE -DDEBUG_LEVEL=${DEBUG_LEVEL}
CFLAGS =	${OPTFLAGS} -Werror -D_FORTIFY_SOURCE=2 -fstack-protector ${CFLAGS_flto}
LDFLAGS =	${LDFLAGS_flto} -Wl,-as-needed
LDLIBS  =	-lcrypto

ifdef HAVE_NO_GETRANDOM
AM_CPPFLAGS +=	-DHAVE_NO_GETRANDOM
endif

ifdef IN_COVSCAN
AM_CPPFLAGS +=	-include ${srcdir}/contrib/coverity-compat.h
endif

SUBDIRS = tests

### set the default target

all:

### include make rules

include ${srcdir}/mk/generic.mk
include ${srcdir}/mk/gcov.mk
include ${srcdir}/mk/compile.mk
include ${srcdir}/mk/install.mk
include ${srcdir}/mk/tests.mk

### local rules

sbin_PROGRAMS = \
	dhcpd-pd \
	dhcpd-pd-net6-combine \

noinst_PROGRAMS =

dhcpd-pd_SOURCES = \
	ensc-lib/logging.c \
	ensc-lib/logging.h \
	ensc-lib/sd-notify.h \
	ensc-lib/sd-notify.c \
	src/buffer.c \
	src/buffer.h \
	src/dhcpv6-util.c \
	src/dhcpv6-util.h \
	src/dhcpv6.h \
	src/duid.c \
	src/duid.h \
	src/iapd.c \
	src/logging-dhcp.c \
	src/logging.h \
	src/time.c \
	src/time.h \
	src/script.c \
	src/util.h \
	src/dhcpd-pd.c \

dhcpd-pd-net6-combine_SOURCES = \
	src/net6-combine.c

### include subdir rules

include $(patsubst %,${srcdir}/%/Modules.mk,${SUBDIRS})

###

all:	${sbin_PROGRAMS}

world:	all ${noinst_PROGRAMS}

run-tests:	$(addprefix .run-test-,$(TESTS))

### register build objects

$(call register_tests,${TESTS})
$(call register_programs,${sbin_PROGRAMS} ${noinst_PROGRAMS})

$(call register_install,sbin,PROGRAMS)
