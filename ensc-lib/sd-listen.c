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

 Most part of this file were taken from systemd's sd-daemon.c
*/


#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "sd-listen.h"

#ifndef DISABLE_SYSTEMD

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include "compiler.h"
#include "type-utils.h"

static void unsetenv_all(bool unset_environment)
{

        if (!unset_environment)
                return;

        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
}

#define safe_atoX(_s, _res_ptr, _fn, _fn_type)				\
	do {								\
		char const	*s = (_s);				\
		_fn_type	res;					\
		char		*e;					\
									\
		errno = 0;						\
		res = _fn(s, &e, 0);					\
		if (errno > 0) {					\
			return -1;					\
		} else if (*s == '\0' || *e != '\0') {			\
			errno = EINVAL;					\
			return -1;					\
		} else if (!variable_is_signed(res) && *s == '-') {		\
			errno = EINVAL;					\
			return -1;					\
		} else if (!integer_safe_assign(*(_res_ptr), res)) {	\
			errno = ERANGE;					\
			return -1;					\
		} else {						\
			return 0;					\
		}							\
	} while (0)

static int safe_atoi(char const *str, int *ret)
{
	safe_atoX(str, ret, strtol, long);
}

static int safe_atolu(char const *str, unsigned long *ret)
{
	safe_atoX(str, ret, strtoul, unsigned long);
}

static int parse_pid(char const *s, pid_t * ret)
{
	unsigned long	pid;
	int		rc;

	rc = safe_atolu(s, &pid);
	if (rc < 0) {
		return rc;
	} else if (!integer_safe_assign(*ret, pid)) {
		errno = EINVAL;
		return -1;
	} else {
		return 0;
	}
}

static int fd_cloexec(int fd, bool ena)
{
	int	flags = fcntl(fd, F_GETFD, 0);

	if (flags < 0)
		return flags;

	if (ena)
		flags |= FD_CLOEXEC;
	else
		flags &= ~FD_CLOEXEC;

	return fcntl(fd, F_SETFD, flags);
}

_hidden_ int sd_listen_fds(int unset_environment)
{
        const char *e;
        int n, r, fd;
        pid_t pid;

        e = getenv("LISTEN_PID");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = parse_pid(e, &pid);
        if (r < 0)
                goto finish;

        /* Is this for us? */
        if (getpid() != pid) {
                r = 0;
                goto finish;
        }

        e = getenv("LISTEN_FDS");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = safe_atoi(e, &n);
        if (r < 0)
                goto finish;

	_Static_assert(SD_LISTEN_FDS_START < INT_MAX,
		       "SD_LISTEN_FDS_START out of range");
        if (n <= 0 || n > INT_MAX - SD_LISTEN_FDS_START) {
                r = -EINVAL;
                goto finish;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd ++) {
                r = fd_cloexec(fd, true);
                if (r < 0)
                        goto finish;
        }

        r = n;

finish:
        unsetenv_all(unset_environment);
        return r;
}

#endif	/* SYSTEMD_DISABLED */
