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

#ifndef H_ENSC_LIB_LOGGING_H
#define H_ENSC_LIB_LOGGING_H

#include <stdbool.h>
#include "compiler.h"

enum {
	L_DEBUG1 = (1u <<  0),
	L_DEBUG  = (1u <<  1),
	L_INFO1  = (1u <<  2),
	L_INFO   = (1u <<  3),
	L_WARN   = (1u <<  4),
	L_ERR    = (1u <<  5),
	L_PANIC  = (1u <<  6),
	L_TRACE  = (1u <<  7),
	L_ALLOC  = (1u <<  8),

	L_MASK_LEVELS = (1u << 28) - 1u,

	L_NONL	 = (1u << 28),
	L_NOTM   = (1u << 29),
	L_PUSH   = (1u << 30),
	L_POP    = (int)(1u << 31),

	L_START_FLAGS = 28,
	L_MASK_FLAGS  = ~L_MASK_LEVELS,
};

extern int	_log_fd;

void		_log_pop(void);
void		_log_push(void);
void		_log_reset(void);
unsigned int	_log_get_debug_level(unsigned int domain) _pure_;

void		_log_msg(unsigned int lvl, unsigned int domain,
			 char const *fn, unsigned int line,
			 char const *fmt, ...)
	__attribute__((__format__(printf, 5, 6)));

inline static bool _pure_ log_enabled(unsigned int lvl, unsigned int domain)
{
	bool	rc;

	lvl &= L_MASK_LEVELS;

#ifdef CONFIG_DYNAMIC_DEBUG_LEVEL
	rc = (lvl & _log_get_debug_level(domain)) != 0;
#elif defined(DEBUG_LEVEL)
	rc = (lvl & DEBUG_LEVEL) != 0;
#else
	rc = lvl != 0;
#endif

	if (!rc)
		return rc;

	return rc;
}

inline static void	_trace_destructor(bool *flag)
{
	if (*flag)
		_log_pop();
}

#define LOG_DECLARE_BLOCK_FLAG(_lvl, _dom)	\
	bool _ensc_log_block_flag				\
	__attribute__((__cleanup__(_trace_destructor))) =	\
		log_enabled(_lvl, _dom); \
	(void)_ensc_log_block_flag;

#define LOG_SET_BLOCK_FLAG(_lvl, _dom, _v)				\
	if ((_v) && !log_enabled(_lvl, _dom)) {				\
		; /* noop */						\
	} else {							\
		_ensc_log_block_flag = (_v);				\
	}

#define LOG_WRAP(_lvl, _dom, _fn, ...)				\
	do {							\
		if (log_enabled(_lvl, _dom))			\
			_fn(__VA_ARGS__);	\
	} while (0)

#define log_pop(_lvl, _dom)		       \
	LOG_SET_BLOCK_FLAG(_lvl, _dom, false); \
	LOG_WRAP(_lvl, _dom, _log_pop)

#define log_push(_lvl, _dom)		 \
	LOG_WRAP(_lvl, _dom, _log_push);	\
	LOG_DECLARE_BLOCK_FLAG(_lvl, _dom)

#define log_msg(_lvl, _dom, ...)		\
	LOG_WRAP(_lvl, _dom, _log_msg, _lvl, _dom, __func__, __LINE__, \
		 ## __VA_ARGS__)

#define log_entry(_dom) \
	log_msg(L_TRACE, _dom, ">>>");		\
	log_push(L_TRACE, _dom)


#endif	/* H_ENSC_LIB_LOGGING_H */
