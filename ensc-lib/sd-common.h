/*	--*- c -*--
 * Copyright (C) 2016 Enrico Scholz <enrico.scholz@ensc.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_ENSC_SD_COMMON_H
#define H_ENSC_SD_COMMON_H

#ifndef _sd_printf_attr_
#  if __GNUC__ >= 4
#    define _sd_printf_attr_(a,b) __attribute__ ((format (printf, a, b)))
#  else
#    define _sd_printf_attr_(a,b)
#  endif
#endif

#ifndef DISABLE_SYSTEMD
#  define ENSC_SYSTEMD_FN(_proto, _attr, _ret_stmt)	\
	_proto _attr
#else
#  define ENSC_SYSTEMD_FN(_proto, _attr, _ret_stmt)	\
	inline static _proto _attr;			\
	inline static _proto { _ret_stmt; } \
	asm("")
#endif

#endif	/* H_ENSC_SD_COMMON_H */
