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

abs_srcdir = $(abspath ${srcdir})
abs_builddir = $(abspath ${builddir})

INSTALL = install
MKDIR_P = mkdir -p

ORIG_MAKE = ${MAKE} -f $(abspath $(firstword $(MAKEFILE_LIST)))

## generic rules
%/.dirstamp:
	${MKDIR_P} ${@D}
	@touch $@

FORCE:
.PHONY: FORCE

clean:	.clean-generic

.clean-generic:
	rm -f ${EXTRA_CLEAN}
