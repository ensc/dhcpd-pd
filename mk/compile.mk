# Copyright (C) 2016 Enrico Scholz <enrico.scholz@ensc.de>
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

ANALYZE = \
	clang --analyze  --analyzer-output ${ANALYZE_OUTPUT} \
	$(foreach a,${ANALYZE_CHECKERS}, -Xclang -analyzer-checker=$a) \
	$(foreach a,${ANALYZE_BAD_CHECKERS}, -Xclang -analyzer-disable-checker=$a) \

ANALYZE_OUTPUT = text

ANALYZE_CHECKERS = \
	alpha core deadcode nullability security unix valist

ANALYZE_BAD_CHECKERS = \
	security.insecureAPI.DeprecatedOrUnsafeBufferHandling \
	alpha.clone.CloneChecker \

compile_link = ${CC} -o $@ \
	${AM_CPPFLAGS} ${CPPFLAGS} \
	${AM_CFLAGS} ${CFLAGS} \
	${AM_LDFLAGS} ${LDFLAGS} \
	$(filter %.c,$^) \
	${LDLIBS} \

analyze = ${ANALYZE} \
	${AM_CPPFLAGS} ${CPPFLAGS} \
	${AM_CFLAGS} ${CFLAGS} \
	$(filter %.c,$^) \

## register_program <prog>
define _register_program
$1: | $(dir $1)/.dirstamp
$1: $${$1_SOURCES} $${$1_BUILTSOURCES}
	$$(call gcov_prepare)
	$$(call compile_link)
	$$(call gcov_commit)

.analyze-$1:	$${$1_SOURCES} $${$1_BUILTSOURCES}
analyze:	.analyze-$1

EXTRA_CLEAN += $${$1_BUILTSOURCES}
BUILTSOURCES += $$($1_BUILTSOURCES)
endef				# register_program

register_programs = \
	$(foreach p,$(sort $1),$(eval $(call _register_program,$p)))

##

.analyze-%:
	$(call analyze,$^)


clean:	.clean-exec
.clean-exec:
	rm -f ${bin_PROGRAMS} ${sbin_PROGRAMS} ${noinst_PROGRAMS}
	rm -f *.stamp *.gcda *.gcno
	rm -rf *.plist
