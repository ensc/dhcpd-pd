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

#ifndef H_ENSC_TYPE_UTILS_H
#define H_ENSC_TYPE_UTILS_H

#include "compiler.h"

#if COMPILER_HAS_C11_GENERIC
#  define variable_is_signed(_var) \
	_Generic(_var,				\
		 signed char: true,		\
		 unsigned char: false,		\
		 int: true,			\
		 short: true,			\
		 long: true,			\
		 long long: true,		\
		 unsigned short: false,		\
		 unsigned int: false,		\
		 unsigned long: false,		\
		 unsigned long long: false)
#else
#  define variable_is_signed(_var) __extension__			\
	({								\
		int _is_signed_res;					\
		if (__is_type(&(_var), int *) ||			\
		    __is_type(&(_var), short *) ||			\
		    __is_type(&(_var), long *) ||			\
		    __is_type(&(_var), long long *))			\
			_is_signed_res = 0;				\
		else if (__is_type(&(_var), unsigned short *) ||	\
			 __is_type(&(_var), unsigned int *) ||		\
			 __is_type(&(_var), unsigned long *) ||		\
			 __is_type(&(_var), unsigned long long *))	\
			_is_signed_res = 1;				\
		else {							\
			/* keep _is_signed_res undefined to cause	\
			 * uninitialized warnings! */			\
		}							\
		_is_signed_res;						\
	})
#endif

#if COMPILER_HAS_C11_GENERIC
#  define variable_max_value(_var)			\
	_Generic(_var,					\
		 char: CHAR_MAX,			\
		 unsigned char: UCHAR_MAX,		\
		 signed char: SCHAR_MAX,		\
		 signed short: SHRT_MAX,		\
		 unsigned short: USHRT_MAX,		\
		 signed int: INT_MAX,			\
		 unsigned int: UINT_MAX,		\
		 signed long: LONG_MAX,			\
		 unsigned long: ULONG_MAX,		\
		 signed long long: LLONG_MAX,		\
		 unsigned long long: ULLONG_MAX)

#  define variable_min_value(_var)			\
	_Generic(_var,					\
		 char: CHAR_MIN,			\
		 unsigned char: (unsigned char)0,	\
		 signed char: SCHAR_MIN,		\
		 signed short: SHRT_MIN,		\
		 unsigned short: (unsigned short)0,	\
		 signed int: INT_MIN,			\
		 unsigned int: 0u,			\
		 signed long: LONG_MIN,			\
		 unsigned long: 0ul,			\
		 signed long long: LLONG_MIN,		\
		 unsigned long long: 0ull)
#else
#  define variable_max_value(_var) __extension__			\
	({								\
		uintmax_t _variable_max_value_res;			\
		__typeof__(_var) *	_tmp;				\
		if (__is_type(_tmp, char *))				\
			_variable_max_value_res = CHAR_MAX;		\
		else if (__is_type(_tmp, signed char *))		\
			_variable_max_value_res = SCHAR_MAX;		\
		else if (__is_type(_tmp, unsigned char *))		\
			_variable_max_value_res = UCHAR_MAX;		\
		else if (__is_type(_tmp, signed short *))		\
			_variable_max_value_res = SHRT_MAX;		\
		else if (__is_type(_tmp, unsigned short *))		\
			_variable_max_value_res = USHRT_MAX;		\
		else if (__is_type(_tmp, int *))			\
			_variable_max_value_res = INT_MAX;		\
		else if (__is_type(_tmp, signed int *))			\
			_variable_max_value_res = INT_MAX;		\
		else if (__is_type(_tmp, unsigned int *))		\
			_variable_max_value_res = UINT_MAX;		\
		else if (__is_type(_tmp, long *))			\
			_variable_max_value_res = LONG_MAX;		\
		else if (__is_type(_tmp, signed long *))		\
			_variable_max_value_res = LONG_MAX;		\
		else if (__is_type(_tmp, unsigned long *))		\
			_variable_max_value_res = ULONG_MAX;		\
		else if (__is_type(_tmp, long long *))			\
			_variable_max_value_res = LLONG_MAX;		\
		else if (__is_type(_tmp, signed long long *))		\
			_variable_max_value_res = LLONG_MAX;		\
		else if (__is_type(_tmp, unsigned long long *))		\
			_variable_max_value_res = ULLONG_MAX;		\
		else {							\
			/* keep _is_signed_res undefined to cause	\
			 * uninitialized warnings! */			\
		}							\
		(__typeof__(_var))(_variable_max_value_res);		\
	})

#  define variable_min_value(_var) __extension__			\
	({								\
		intmax_t _variable_min_value_res;			\
		__typeof__(_var) *	_tmp;				\
		if (__is_type(_tmp, char *))				\
			_variable_min_value_res = CHAR_MIN;		\
		else if (__is_type(_tmp, signed char *))		\
			_variable_min_value_res = SCHAR_MIN;		\
		else if (__is_type(_tmp, unsigned char *))		\
			_variable_min_value_res = 0;			\
		else if (__is_type(_tmp, signed short *))		\
			_variable_min_value_res = SHRT_MIN;		\
		else if (__is_type(_tmp, unsigned short *))		\
			_variable_min_value_res = 0;			\
		else if (__is_type(_tmp, signed int *))			\
			_variable_min_value_res = INT_MIN;		\
		else if (__is_type(_tmp, unsigned int *))		\
			_variable_min_value_res = 0;			\
		else if (__is_type(_tmp, signed long *))		\
			_variable_min_value_res = LONG_MIN;		\
		else if (__is_type(_tmp, unsigned long *))		\
			_variable_min_value_res = 0;			\
		else if (__is_type(_tmp, signed long long *))		\
			_variable_min_value_res = LLONG_MIN;		\
		else if (__is_type(_tmp, unsigned long long *))		\
			_variable_min_value_res = 0;			\
		else {							\
			/* keep _is_signed_res undefined to cause	\
			 * uninitialized warnings! */			\
		}							\
		(__typeof__(_var))(_variable_min_value_res);		\
	})
#endif

#define integer_safe_assign(_dst, _src) __extension__			\
	({								\
		int _safe_assign_res = 1;				\
		if ((__typeof__(_src))((__typeof__(_dst))(_src)) != (_src)) \
			_safe_assign_res = 0;				\
		else							\
			(_dst) = (__typeof__(_dst))(_src);		\
		_safe_assign_res;					\
	})

#if HAVE_BUILTIN_MUL_OVERFLOW
#  define _mul_overflow(_a, _b, _res) \
	__builtin_mul_overflow(_a, _b, _res)
#else
#  define _mul_overflow(_a, _b, _res) __extension__			\
	({								\
		int	_mul_overflow_res;				\
		__typeof__(_a) *		tmp_a;			\
		__typeof__(_b) *		tmp_b;			\
		__typeof__(_res)		tmp_res;		\
		_Static_assert(__builtin_types_compatible_p(__typeof__(tmp_a), \
							    __typeof__(tmp_b)), \
			       "incompatible operand types");		\
		_Static_assert(__builtin_types_compatible_p(__typeof__(tmp_a), \
							    __typeof__(tmp_res)), \
			       "incompatible result type");		\
		if (variable_min_value(_a) != 0) { \
			/* keep result undefined to cause		\
			 * uninitialized warnings! */			\
		} else if ((_a) != 0 && variable_max_value(*(_res)) / (_a) < (_b)) { \
			_mul_overflow_res = 1;				\
		} else if (!integer_safe_assign(*(_res), (_a) * (_b))) { \
			_mul_overflow_res = 1;				\
		} else {						\
			_mul_overflow_res = 0;				\
		}							\
		_mul_overflow_res;					\
	})
#endif

#if HAVE_BUILTIN_SUB_OVERFLOW
#  define _add_overflow(_a, _b, _res)		\
	__builtin_add_overflow(_a, _b, _res)
#else
#  define _add_overflow(_a, _b, _res) __extension__			\
	({								\
		int	_add_overflow_res;				\
		__typeof__(_a) *		tmp_a;			\
		__typeof__(_b) *		tmp_b;			\
		__typeof__(_res)		tmp_res;		\
		_Static_assert(__builtin_types_compatible_p(__typeof__(tmp_a), \
							    __typeof__(tmp_b)), \
			       "incompatible operand types");		\
		_Static_assert(__builtin_types_compatible_p(__typeof__(tmp_a), \
							    __typeof__(tmp_res)), \
			       "incompatible result type");		\
		if (variable_max_value(_a) - (_a) < (_b)) {		\
			_add_overflow_res = 1;				\
		} else if (!integer_safe_assign(*(_res), (_a) + (_b))) { \
			_add_overflow_res = 1;				\
		} else {						\
			_add_overflow_res = 0;				\
		}							\
		_add_overflow_res;					\
	})
#endif

#endif	/* H_ENSC_TYPE_UTILS_H */
