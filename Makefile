srcdir ?= $(dir $(firstword ${MAKEFILE_LIST}))
VPATH = ${srcdir}

INSTALL = install
INSTALL_BIN = ${INSTALL} -p -m 0755

AM_CFLAGS =	-std=gnu11 -Wall -W -Wno-unused-parameter
CFLAGS =	-O2 -g3 -Werror -D_FORTIFY_SOURCE=2 -fstack-protector
LDLIBS  =	-lcrypto

compile_link = ${CC} -o $@ \
	${AM_CPPFLAGS} ${CPPFLAGS} \
	${AM_CFLAGS} ${CFLAGS} \
	${AM_LDFLAGS} ${LDFLAGS} \
	$1 \
	${LDLIBS}

prefix ?=			/usr/local
sbindir ?=			${prefix}/sbin

all:	dhcpd-pd

dhcpd-pd:	src/dhcpd-pd.c
	$(call compile_link,$(filter %.c,$^))

clean:
	rm -f dhcpd-pd
