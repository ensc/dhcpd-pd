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

#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "compiler.h"

#ifdef __dietlibc__
#  define dprintf(fd, ...)	fdprintf(fd, ## __VA_ARGS__)
#  define vdprintf(fd, ...)	vfdprintf(fd, ## __VA_ARGS__)
#endif

enum {
	L_COLOR_NONE	= 0,
	L_COLOR_DATE	= (1 << L_START_FLAGS),
	L_COLOR_FN	= (2 << L_START_FLAGS),
	L_COLOR_PID	= (3 << L_START_FLAGS),
	L_COLOR_DOMAIN	= (4 << L_START_FLAGS),
};

static unsigned int		intent_level = 0;

void _hidden_ _log_pop(void)
{
	if (intent_level > 0)
		--intent_level;
}

void _hidden_ _log_push(void)
{
	++intent_level;
}

void _hidden_ _log_reset(void)
{
	intent_level = 0;
}

static char const	*get_color(unsigned int lvl)
{
	static int	is_tty = -1;
	static char const * const	DOM_COLORS[] = {
		"\e[37;40m", "\e[37;41m", "\e[37;42m", "\e[37;43m",
		"\e[37;44m", "\e[37;45m", "\e[37;46m", "\e[37'47m",
	};

	if (is_tty == -1)
		is_tty = isatty(_log_fd);

	if (!is_tty)
		return "";

	if ((lvl & L_MASK_FLAGS) == L_COLOR_DATE)
		return "\e[0m";
	if ((lvl & L_MASK_FLAGS) == L_COLOR_FN)
		return "\e[0;32m";
	if ((lvl & L_MASK_FLAGS) == L_COLOR_PID)
		return "\e[0;7m";
	if ((lvl & L_MASK_FLAGS) == L_COLOR_DOMAIN)
		return DOM_COLORS[(lvl & L_MASK_LEVELS) %
				  ARRAY_SIZE(DOM_COLORS)];
	if ((lvl & L_ERR))
		return "\e[1;33;41m";
	if ((lvl & L_WARN))
		return "\e[1;31m";
	if ((lvl & (L_INFO|L_INFO1)))
		return "\e[0;34m";
	if ((lvl & L_DEBUG1))
		return "\e[0;38;2;150;150;150m";
	if (lvl == 0)
		return "\e[m";

	return "";
}

char const *  __attribute__((__weak__)) log_transform_fmt(char const *fmt)
{
	return strdup(fmt);
}

static bool log_fd_is_open(void)
{
	static int	last_log_fd = -1;
	bool		is_open = false;
	struct stat	st;

	if (_log_fd == -1)
		return false;

	if (_log_fd != last_log_fd)
		is_open = fstat(_log_fd, &st) >= 0;

	return is_open;
}

void _log_msg(unsigned int lvl, unsigned int domain,
	      char const *fn, unsigned int line,
	      char const *fmt, ...)
{
	va_list ap;
	struct timeval          tv;
	struct tm               tm;
	int const		orig_errno = errno;
	bool			is_locked = false;

	if ((lvl & L_POP))
		_log_pop();

	if (!log_fd_is_open())
		goto finish;

	if (lockf(_log_fd, F_LOCK, 0) >= 0)
		is_locked = true;

	if (!fmt)
		/* when called with NULL fmt; skip output and honor L_POP and
		 * L_PUSH only */
		goto finish;

	if (!(lvl & L_NOTM)) {
		char	fn_buf[128];

		snprintf(fn_buf, sizeof fn_buf, "%s:%u", fn, line);

		gettimeofday(&tv, NULL);
		localtime_r(&tv.tv_sec, &tm);
		dprintf(_log_fd,
			"%s%5u%s %s%02d:%02d:%02d.%03ld%s %s|%3u|%s%s%40s|%s %*s",

			get_color(L_COLOR_PID),
			getpid(),
			get_color(L_COLOR_NONE),

			get_color(L_COLOR_DATE),
			tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec/1000,
			get_color(L_COLOR_NONE),

			get_color(L_COLOR_DOMAIN | domain),
			domain,
			get_color(L_COLOR_NONE),

			get_color(L_COLOR_FN),
			fn_buf,
			get_color(L_COLOR_NONE),

			intent_level*2, "");
	}

	fmt = log_transform_fmt(fmt);
	if (!fmt)
		abort();

	dprintf(_log_fd, "%s", get_color(lvl & L_MASK_LEVELS));
	va_start(ap, fmt);
	errno = orig_errno;		/* restore errno to support %m */
	vdprintf(_log_fd, fmt, ap);
	va_end(ap);
	dprintf(_log_fd, "%s", get_color(0));

	free((void *)fmt);

	if (!(lvl & L_NONL))
		dprintf(_log_fd, "\n");

finish:
	if (is_locked && lockf(_log_fd, F_ULOCK, 0) < 0) {
		/* noop; this branch is to avoid -Wunused-result warnings */
	}

	if ((lvl & L_PUSH))
		_log_push();

	errno = orig_errno;		/* ensure that errno is not altererd
					 * by the function */
}
