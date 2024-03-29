TESTS += \
	${TEST_BINARIES} \
	${TEST_SCRIPTS} \

TEST_BINARIES += \
	tests/00-utils_network \
	tests/00-utils_reliability \
	tests/00-utils_xmit \
	tests/00-time \
	tests/00-buffer \
	tests/00-script \
	tests/01-logging \
	tests/99-coverage \

TEST_SCRIPTS += \
	tests/80-net6-combine.sh \

tests/00-utils_network_SOURCES = \
	tests/00-utils_network.c \
	tests/test-base.c \
	src/dhcpv6-util.c \
	src/dhcpv6-util.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \

tests/00-utils_reliability_SOURCES = \
	tests/00-utils_reliability.c \
	tests/test-base.c \
	src/dhcpv6-util.c \
	src/dhcpv6-util.h \
	src/time.c \
	src/time.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \

tests/00-utils_xmit_SOURCES = \
	tests/00-utils_xmit.c \
	tests/test-base.c \
	src/dhcpv6-util.c \
	src/dhcpv6-util.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \

tests/00-time_SOURCES = \
	tests/00-time.c \
	tests/test-base.c \
	src/time.c \
	src/time.h \
	ensc-lib/logging.c \
	ensc-lib/logging.h \

tests/00-buffer_SOURCES = \
	tests/00-buffer.c \
	tests/test-base.c \
	src/buffer.c \
	src/buffer.h \

tests/00-script_SOURCES = \
	tests/00-script.c \
	tests/test-base.c \
	ensc-lib/logging.c \
	ensc-lib/logging.h \
	src/logging.h \

tests/01-logging_SOURCES = \
	tests/01-logging.c \
	tests/test-base.c \
	ensc-lib/logging.c \
	ensc-lib/logging.h \
	src/logging-dhcp.c \
	src/logging.h \

tests/99-coverage_SOURCES = \
	tests/99-coverage.c \
	tests/test-base.c \
	${dhcpd-pd_SOURCES} \

tests/80-net6-combine.sh_ARGS = \
	${builddir}/dhcpd-pd-net6-combine

tests/80-net6-combine.sh_DEPS = \
	dhcpd-pd-net6-combine

define declare_test
noinst_PROGRAMS += $1

$1:	| $(dir $1)/.dirstamp
$1:     override CFLAGS:=${TEST_CFLAGS}
$1:	override OPTFLAGS=
$1:	override CFLAGS_flto=
$1:	override LDFLAGS_flto=
endef

TEST_CFLAGS = ${CFLAGS} -O1 -g3 -DTESTSUITE -Dmain=orig_main -fno-inline \
	-fstrict-overflow -ftrapv \
	-fsanitize=undefined -fsanitize-address-use-after-scope

$(foreach t,${TEST_BINARIES},$(eval $(call declare_test,$t)))


define shell_test
$1_TESTMODES = plain valgrind_wrapped
endef

$(foreach t,${TEST_SCRIPTS},$(eval $(call shell_test,$t)))
