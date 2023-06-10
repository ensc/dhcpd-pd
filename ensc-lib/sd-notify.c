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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "sd-notify.h"

#ifndef DISABLE_SYSTEMD

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <netinet/ip.h>
#include <sys/un.h>

#include "compiler.h"

union sockaddr_union {
        struct sockaddr		sa;
        struct sockaddr_in	in4;
        struct sockaddr_in6	in6;
        struct sockaddr_un	un;
        struct sockaddr_storage storage;
};

#ifndef offsetof
#  define offsetof(_type, _attr)	(__builtin_offsetof(_type, _attr))
#endif

_hidden_ int sd_notify_supported(void)
{
	const char *e;

	e = getenv("NOTIFY_SOCKET");
	if (!e)
		return 0;

	/* Must be an abstract socket, or an absolute path */
	if ((e[0] != '@' && e[0] != '/') || e[1] == 0)
		return 0;

	return 1;
}

_hidden_ int sd_notify(int unset_environment, const char *state)
{
        int fd = -1, r;
        struct msghdr msghdr;
        struct iovec iovec;
        union sockaddr_union sockaddr;
        const char *e;

        if (!state) {
                r = -EINVAL;
                goto finish;
        }

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        /* Must be an abstract socket, or an absolute path */
        if ((e[0] != '@' && e[0] != '/') || e[1] == 0) {
                r = -EINVAL;
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.sa.sa_family = AF_UNIX;
        strncpy(sockaddr.un.sun_path, e, sizeof(sockaddr.un.sun_path) - 1);

        if (sockaddr.un.sun_path[0] == '@')
                sockaddr.un.sun_path[0] = 0;

        memset(&iovec, 0, sizeof(iovec));
        iovec.iov_base = (char*) state;
        iovec.iov_len = strlen(state);

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_name = &sockaddr;
        msghdr.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(e);

        if (msghdr.msg_namelen > sizeof(struct sockaddr_un))
                msghdr.msg_namelen = sizeof(struct sockaddr_un);

        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0) {
                r = -errno;
                goto finish;
        }

        r = 1;

finish:
        if (unset_environment)
                unsetenv("NOTIFY_SOCKET");

        if (fd >= 0)
                close(fd);

        return r;
}

#endif	/* DISABLE_SYSTEMD */
