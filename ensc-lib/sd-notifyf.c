/*	--*- c -*--
 * Copyright (C) 2014 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef DISABLE_SYSTEMD

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "sd-notify.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "compiler.h"

_hidden_ int sd_notifyf(int unset_environment, const char *format, ...) 
{
        va_list ap;
        char *p = NULL;
        int r;

        va_start(ap, format);
        r = vasprintf(&p, format, ap);
        va_end(ap);

        if (r < 0 || !p)
                return -ENOMEM;

        r = sd_notify(unset_environment, p);
        free(p);

        return r;
}

#endif	/* DISABLE_SYSTEMD */
