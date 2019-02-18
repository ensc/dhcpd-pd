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

GCOV = gcov
## lcov creates '#...#...#' temporary files in local directory; prevent
## parallel execution
LCOV = flock ${builddir} lcov
LCOV_FLAGS = -b ${srcdir} --no-external
LCOV_INFO = ${PACKAGE}.lcov.info

GCOV_OUTDIR = ${builddir}/.gcov

GENHTML = genhtml
GENHTML_OUTDIR = ${builddir}/.lcov-html

PROFILE_FLAGS = --coverage -fprofile-dir='${GCOV_OUTDIR}/${@F}' -fprofile-abs-path -fno-inline

############

ifeq (${RUN_GCOV},)

gcov_prepare =
gcov_commit =

else				# RUN_GCOV

AM_CFLAGS += ${PROFILE_FLAGS}

.NOTPARALLEL:

define gcov_prepare
	rm -f *.gcno
endef

define gcov_commit
	rm -rf '${GCOV_OUTDIR}/${@F}'
	mkdir -p '${GCOV_OUTDIR}/${@F}'
	for i in *.gcno; do ! test -e "$$i" || mv $$i '${GCOV_OUTDIR}/${@F}/'; done
endef

endif				# RUN_GCOV

############

clean:	.clean-gcov
.clean-gcov:
	rm -f ${LCOV_INFO}
	rm -rf '${GENHTML_OUTDIR}' '${GCOV_OUTDIR}'

##

run-gcov:
	@rm -rf '${GCOV_OUTDIR}'/*/*.gcda
	${ORIG_MAKE} RUN_GCOV=1 TESTMODES=plain run-tests
	${ORIG_MAKE} '.$@'

lcov_remove = ${LCOV} --remove $1 --output-file $1 $(abspath $2)

## NOTE: this expands only in a submake!  E.g. 'run-tests' and
## '.run-gcov' can not be in the same make level
_gcov_pattern = ${GCOV_OUTDIR}/*/*.gcda ${GCOV_OUTDIR}/*/*.gcno
_gcov_subdirs = $(sort $(dir $(wildcard ${_gcov_pattern})))

%/lcov.info:    %
	@rm -f $@
	${LCOV} ${LCOV_FLAGS} -q --output $@ -c -d "${@D}"
	@touch $@

${LCOV_INFO}:   $(addsuffix /lcov.info,${_gcov_subdirs})
	for i in $^; do \
	        test -s "$$i" && echo "-a $$i"; \
	done | xargs ${LCOV} ${LCOV_FLAGS} --output $@
	$(call lcov_remove,$@,${BUILTSOURCES})

.run-gcov:      ${LCOV_INFO}
	${LCOV} --list $<
	${GENHTML} -o ${GENHTML_OUTDIR} $<
