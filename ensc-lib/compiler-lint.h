/*	--*- c -*--
 * Copyright (C) 2013 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_UTUN_INCLUDE_COMPILER_LINT_H
#define H_UTUN_INCLUDE_COMPILER_LINT_H

#define likely(_cond)				(_cond)
#define unlikely(_cond)				(_cond)
#define barrier() do { } while (0==1)

/*lint -sem(sign_cast,pure) -emacro(732,sign_cast) -emacro(960,sign_cast)*/
#define sign_cast(_totype, _fromtype, _v)	\
	((_totype)(_v))


#define __section_classb
#define __section_classb_inv

#define __global
#define __noreturn
#define __packed
#define __aligned(_a)
#define __force_inline
#define __must_be_checked
#define __unused

/*lint -emacro(632,__builtin_constant_p)*/
#define __builtin_constant_p(_v)		(0==1)
#define __builtin_types_compatible_p(_a,_b)	(1==1)

#define __must_be_builtin_constant(_cond)	(0)
#define __must_be_array(_a)			(0)
/*lint -emacro(923,__builtin_offsetof)*/
/*lint -emacro(545,__builtin_offsetof)*/
#define __builtin_offsetof(_type,_attr) \
	((size_t)&(((_type *)1u)->_attr) - 1u)

/* Still violates 11.3 "A cast should not be performed between a pointer type
 * and an integral type but that's an advisory only. */
/*lint -emacro(923,container_of)*/
/*lint -emacro(586,container_of)*/
#define container_of(_ptr, _type, _attr) (	\
		(_type *)((uintptr_t)(_ptr) - offsetof(_type,_attr)))


/*lint -sem(__builtin_popcountl,pure)*/
extern int __builtin_popcountl(unsigned long x);
/*lint -sem(__builtin_clz,pure)*/
extern int __builtin_ctz(unsigned int x);
/*lint -sem(__builtin_ctz,pure)*/
extern int __builtin_clz(unsigned int x);
/*lint -sem(__builtin_ffs,pure)*/
extern int __builtin_ffs(unsigned int x);
extern void __builtin_va_start(void const *a, void const *b);
/*lint -function(exit,__do_die)*/
extern void __do_die(int code);

#endif	/* H_UTUN_INCLUDE_COMPILER_LINT_H */
