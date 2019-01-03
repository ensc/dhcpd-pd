builddir ?= .
srcdir ?= $(dir $(firstword ${MAKEFILE_LIST}))
VPATH = ${srcdir}

INSTALL =	install
INSTALL_BIN =	${INSTALL} -p -m 0755
MKDIR_P =	${INSTALL} -d -m 0755

DEBUG_LEVEL =	0xfffc
#DEBUG_LEVEL =	0xffff

OPTFLAGS =	-O2 -g3
CFLAGS_flto =	-flto
LDFLAGS_flto =	-fuse-linker-plugin
AM_CFLAGS =	-std=gnu11 -Wall -W -Wno-unused-parameter -Wmissing-prototypes
AM_CPPFLAGS =	-I${srcdir} -D_GNU_SOURCE
CFLAGS =	${OPTFLAGS} -Werror -D_FORTIFY_SOURCE=2 -fstack-protector -DDEBUG_LEVEL=${DEBUG_LEVEL} ${CFLAGS_flto}
LDFLAGS =	${LDFLAGS_flto} -Wl,-as-needed
LDLIBS  =	-lcrypto
PROFILE_FLAGS =	--coverage -fprofile-dir=${builddir}/.gcov/${@F} -fprofile-abs-path -fno-inline

GENHTML =		genhtml
GENHTML_OUTDIR =	.lcov-html
LCOV =			lcov
LCOV_FLAGS =		-b ${srcdir} --no-external
LCOV_INFO =		dhcpd-pd.lcov.info

compile_link = ${CC} -o $@ \
	${AM_CPPFLAGS} ${CPPFLAGS} \
	${AM_CFLAGS} ${CFLAGS} \
	${AM_LDFLAGS} ${LDFLAGS} \
	$1 \
	${LDLIBS}

register_program = $1: $${$1_SOURCES}

prefix ?=			/usr/local
sbindir ?=			${prefix}/sbin

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

include ${srcdir}/tests/Modules.mk

all:	${sbin_PROGRAMS}

world:	all ${noinst_PROGRAMS}

clean:
	rm -f ${sbin_PROGRAMS} ${noinst_PROGRAMS}
	rm -f *.gcno *.gcda ${LCOV_INFO}
	rm -rf ${GENHTML_OUTDIR} .gcov

install:	.install-sbin

.install-sbin:	${sbin_PROGRAMS}
	${MKDIR_P} ${DESTDIR}${sbindir}/dhcpd-pd
	${INSTALL_BIN} -D $^ ${DESTDIR}${sbindir}/

${sbin_PROGRAMS} ${noinst_PROGRAMS}:
	rm -f *.gcno
	$(call compile_link,$(filter %.c,$^))
	mkdir -p '${builddir}/.gcov/${@F}'
	for i in *.gcno; do ! test -e "$$i" || mv $$i ${builddir}/.gcov/${@F}/; done

run-lcov:
	${LCOV} --zerocounters -d ${builddir}
	@echo "================== running tests ==================="
	${MAKE} --no-print-directory run-tests TEST_MODE=lcov
	@echo "================== combining lcov data ==================="
	for i in .gcov/*/test.info; do echo "-a $$i"; done | xargs \
		${LCOV} ${LCOV_FLAGS} --output ${LCOV_INFO}
	@echo "================== generating html output ==================="
	${GENHTML} -o ${GENHTML_OUTDIR} ${LCOV_INFO}

run-tests:	${noinst_PROGRAMS}
	${MAKE} $(addprefix .run-test-,$^)

$(addprefix .run-test-,${noinst_PROGRAMS}):.run-test-%:	%
	$<
	$(if ${TEST_MODE},${MAKE} --no-print-directory .run-${TEST_MODE}-$*)

$(addprefix .run-lcov-,${noinst_PROGRAMS}):.run-lcov-%:	%
	${LCOV} ${LCOV_FLAGS} -c -d .gcov/${<F} -o .gcov/${<F}/test.info

$(foreach p,${sbin_PROGRAMS} ${noinst_PROGRAMS},$(eval $(call register_program,$p)))
