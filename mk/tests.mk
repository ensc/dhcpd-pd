# Copyright (C) 2019 Enrico Scholz <enrico.scholz@ensc.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

VALGRIND_BIN = valgrind
VALGRIND = ${VALGRIND_BIN} --error-exitcode=42 --quiet
VALGRIND_MEMCHECK = ${VALGRIND} --tool=memcheck --leak-check=full

have_valgrind := $(shell type -p ${VALGRIND_BIN} >/dev/null 2>/dev/null && echo 1)

TESTMODES = \
	plain \
	$(if ${have_valgrind},valgrind) \

define _register_test
_testmodes :=	$$(if $$($1_TESTMODES),$$($1_TESTMODES),$${TESTMODES})

$${_testrules}:	$1
$${_testrules}:
.run-test-$1:	override ARGS=$${$1_ARGS}
.run-test-$1:	override _TESTMODES:=$${_testmodes}
.run-test-$1:	$1 $${$1_DEPS}
	+@$${ORIG_MAKE} --no-print-directory $$(addprefix ..run-test-,$${_TESTMODES}) PROG=$$< ARGS='$${ARGS}'

_testrules :=
endef

register_tests = \
	$(foreach t, $(sort $1),$(eval $(call _register_test,$t)))

#####

run_testprog = \
	$1 ${<D}/${<F} $2 ${ARGS} && \
	{ res=$$?; msg=ok; } || { res=$$?; msg=FAIL; }; \
	o=`printf "TEST: '%s' (%s)" '${PROG}' '$(patsubst ..run-test-%,%,$@)'`; \
	printf "%-50s\t%s\n" "$$o" "$$msg"; \
	exit $$res

..run-test-plain:	${PROG} FORCE
	@$(call run_testprog)

..run-test-valgrind:	${PROG} FORCE
	@$(call run_testprog,${VALGRIND_MEMCHECK})
