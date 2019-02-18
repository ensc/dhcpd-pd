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

INSTALL_PROG = ${INSTALL} -p -m 0755
INSTALL_DATA = ${INSTALL} -p -m 0644

prefix ?= /usr/local
sbindir ?= ${prefix}/sbin
includedir ?= ${prefix}/include

__install_PROGRAMS = ${INSTALL_PROG}
__install_HEADERS  = ${INSTALL_DATA}

define _register_install
install:	.install-$1
.install-$1:	$${$1_$2}
	$${MKDIR_P} -d -m 0755 $${DESTDIR}$${${1}dir}
	$${__install_$2} $$^ $${DESTDIR}$${${1}dir}
endef

register_install = $(eval $(call _register_install,$1,$2))
