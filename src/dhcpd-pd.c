/*	--*- c -*--
 * Copyright (C) 2018 Enrico Scholz <enrico.scholz@ensc.de>
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/if.h>

#include "dhcpv6.h"
#include "dhcpv6-util.h"
#include "logging.h"

#define NUM_IAPD_PER_IFACE	(1)

#define LOG_DOMAIN		LOG_DOMAIN_MAIN

struct dhcp_session {
	int			fd;
	char const		*ifname;
	int			ifidx;
	struct dhcpv6_duid	duid;

	uint64_t		now;

	struct dhcp_iapd	iapd[NUM_IAPD_PER_IFACE];
};

union x_sockaddr {
	struct sockaddr		generic;
	struct sockaddr_in6	in6;
};

static int dhcp_session_reopen(struct dhcp_session *ses)
{
	int			ONE = 1;
	int			fd;
	int			idx;
	struct ifreq		ifreq = {};
	union x_sockaddr	addr = {
		.in6 = {
			.sin6_family	= AF_INET6,
			.sin6_port	= htons(546),
			.sin6_addr	= IN6ADDR_ANY_INIT,
		}
	};
	int			rc;

	if (ses->fd >= 0) {
		close(ses->fd);
		ses->fd = -1;
	}
	ses->ifidx = -1;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		pr_err("socket(): %s", strerror(errno));
		return EX_OSERR;
	}

	strcpy(ifreq.ifr_name, ses->ifname);
	rc = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (rc < 0) {
		pr_err("ioctl(SIOCGIFINDEX): %s", strerror(errno));
		rc = EX_OSFILE;
		goto err;
	}

	rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ONE, sizeof ONE);
	if (rc < 0) {
		pr_err("setsockopt(): %s", strerror(errno));
		rc = EX_OSFILE;
		goto err;
	}

	idx = ifreq.ifr_ifindex;
	addr.in6.sin6_scope_id = idx;

	rc = bind(fd, &addr.generic, sizeof addr);
	if (rc < 0) {
		pr_err("bind(): %s", strerror(errno));
		rc = EX_OSERR;
		goto err;
	}

	ses->ifidx = idx;
	ses->fd    = fd;

	return 0;

err:
	close(fd);
	return rc;
}

static int dhcp_session_open(struct dhcp_session *ses, char const *ifname)
{
	struct ifreq	ifreq;

	if (strlen(ifname) >= sizeof ifreq.ifr_name)
		return EX_USAGE;

	*ses = (struct dhcp_session) {
		.ifname	= ifname,
		.fd	= -1,
		.ifidx	= -1,
	};

	for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
		struct dhcp_iapd	*iapd = &ses->iapd[i];

		iapd->state = IAPD_STATE_INIT;
	}

	dhcpv6_duid_generate(&ses->duid);

	return dhcp_session_reopen(ses);
}

static void dhcp_handle_signal(struct dhcp_session *ses, int sig_fd)
{
	struct signalfd_siginfo	fdsi;
	ssize_t			l;

	l = read(sig_fd, &fdsi, sizeof fdsi);
	if (l < 0) {
		pr_err("read(<sig-fd>): %s", strerror(errno));
		return;
	}

	/* TODO */
}

static unsigned int read_status_code(void const *code_pkt, size_t len)
{
	unsigned int	res = read_be16(code_pkt);
	char const	*msg = code_pkt + 2;

	len -= 2;

	if (res == 0)
		pr_info("STATUS: %.*s", (int)len, msg);
	else
		pr_warn("STATUS %u: %.*s", res, (int)len, msg);

	return res;
}

static int dhcp_handle_response(struct dhcp_session *ses, struct dhcp_context *ctx,
				struct dhcpv6_message_hdr const *hdr, size_t len)
{
	size_t				tmp_len = len;
	struct dhcpv6_option_hdr const	*opt_clnt_id = NULL;
	int				rc;

	dhcpv6_foreach_option(opt, hdr, &tmp_len) {
		size_t		opt_len = dhcpv6_get_option_len(opt);
		void const	*opt_data = dhcpv6_get_option_data(opt);

		pr_debug("OPTION: %s",
			 dhcpv6_option_to_str(be16_to_cpu(opt->option)));

		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_CLIENTID:
			if (opt_clnt_id) {
				pr_err("duplicate CLIENTID");
				rc = -1;
				goto out_loop;
			}

			opt_clnt_id = opt;
			break;

		case DHCPV6_OPTION_SERVERID:
			if (ctx->server.opt) {
				pr_err("duplicate SERVERID");
				rc = -1;
				goto out_loop;
			} else if (opt_len > DHCPV6_MAX_DUID_SZ) {
				pr_err("SERVERID too large");
				rc = -1;
				goto out_loop;
			}

			ctx->server.opt = opt;
			break;

		case DHCPV6_OPTION_PREFERENCE:
			if (opt_len != 1) {
				pr_err("bad PREFERENCE");
				rc = -1;
				goto out_loop;
			}

			ctx->server.pref = read_be8(opt_data);
			break;

		case DHCPV6_OPTION_STATUS_CODE:
			if (opt_len < 2) {
				pr_err("bad STATUS CODE");
				rc = -1;
				goto out_loop;
			}

			ctx->status_code = read_status_code(opt_data, opt_len);
			break;

		default:
			rc = 0;
			break;
		}

	out_loop:
		if (rc < 0)
			break;
	}

	if (rc < 0)
		goto out;

	if (tmp_len != 0) {
		pr_err("extra data after last DHCP option");
		return -1;
	}

	if (!ctx->server.opt) {
		pr_err("SERVERID missing");
		return -1;
	}

	if (dhcpv6_duid_cmp_opt(&ses->duid, opt_clnt_id) != 0) {
		pr_err("CLIENTID missing or mismatch");
		return -1;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
		struct dhcp_iapd	*iapd = &ses->iapd[i];

		if (iapd->state == IAPD_STATE_UNUSED)
			continue;

		rc = dhcp_iapd_recv(iapd, ctx, hdr, len);
		if (rc < 0)
			break;
	}

out:
	return rc;
}

static int dhcp_read_response(struct dhcp_session *ses, struct dhcp_context *ctx)
{
	union {
		struct dhcpv6_message_hdr	hdr;
		unsigned char			buf[DHCPV6_MAX_MESSAGE_SZ];
	}			resp;
	struct in6_addr		local_addr;
	bool			have_local_addr = false;
	union {
		struct cmsghdr	align;
		unsigned char	raw[1024];
	}			cmbuf;
	struct iovec		msg_vec = {
		.iov_base	= &resp,
		.iov_len	= sizeof resp,
	};
	struct msghdr		msg = {
		.msg_name	= &ctx->server.addr,
		.msg_namelen	= sizeof ctx->server.addr,
		.msg_iov	= &msg_vec,
		.msg_iovlen	= 1,
		.msg_control	= cmbuf.raw,
		.msg_controllen	= sizeof cmbuf,
	};

	ssize_t			l;
	int			rc;

	ctx->server = (struct dhcpv6_server_info) {
		.pref	= 0
	};

	l = recvmsg(ses->fd, &msg, 0);
	if (l < 0) {
		pr_err("recvmsg(): %s", strerror(errno));
		return -1;
	}

	/* TODO: this check might violate the DHCPv6 RFC */
	if ((size_t)l >= sizeof resp) {
		pr_err("response too large");
		return 1;
	}

	if ((size_t)l < sizeof resp.hdr) {
		pr_err("response too small");
		return 1;
	}

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {

		if (cmsg->cmsg_level == IPPROTO_IPV6 ||
		    cmsg->cmsg_type  == IPV6_RECVPKTINFO) {
			struct in6_pktinfo const	*info;

			assert(cmsg->cmsg_len >= sizeof *info);

			info = (void *)CMSG_DATA(cmsg);
			/* sanity check: reject datagrams on unexpected
			 * interfaces */
			if (info->ipi6_ifindex != (unsigned int)ses->ifidx) {
				pr_err("bad ifidx");
				continue;
			}

			_Static_assert(sizeof local_addr == sizeof info->ipi6_addr,
				       "bad in6_pktinfo layout");

			memcpy(&local_addr, &info->ipi6_addr, sizeof local_addr);
			have_local_addr = true;
		}

		break;
	}

	if (!have_local_addr) {
		pr_err("failed to get local address from received datagram");
		return -1;
	}

	/* sanity check: reject datagrams to non link-local addresses */
	if (local_addr.s6_addr[0] != 0xfe || local_addr.s6_addr[1] != 0x80) {
		char	tmp[INET6_ADDRSTRLEN];

		pr_err("non link-local destination address %s",
		       inet_ntop(AF_INET6, &local_addr, tmp, sizeof tmp));

		return 1;
	}

	rc = 1;

	switch (resp.hdr.type) {
	case DHCPV6_TYPE_SOLICIT:
	case DHCPV6_TYPE_REQUEST:
	case DHCPV6_TYPE_CONFIRM:
	case DHCPV6_TYPE_RENEW:
	case DHCPV6_TYPE_REBIND:
	case DHCPV6_TYPE_RELEASE:
	case DHCPV6_TYPE_DECLINE:
	case DHCPV6_TYPE_INFORMATION_REQUEST:
		/* echo'ed clinet messages? Ignore them silently*/
		rc = 0;
		break;

	case DHCPV6_TYPE_ADVERTISE:
	case DHCPV6_TYPE_REPLY:
		rc = dhcp_handle_response(ses, ctx, &resp.hdr, l);
		if (rc < 0) {
			pr_warn("bad response from server; ignoring it");
			rc = 1;
		}
		break;
	}

	return rc;
}

static int dhcp_wait(struct dhcp_session *ses, struct dhcp_context *ctx)
{
	struct pollfd		pfds[2];
	struct pollfd		*pfd = &pfds[0];
	int			timeout = 0;
	int			rc;

	assert(!time_is_epoch(ctx->timeout));
	assert(time_cmp(ctx->timeout, ctx->now) > 0);

	*pfd++ = (struct pollfd) {
		.fd	= ctx->sig_fd,
		.events	= POLLIN,
	};

	if (time_is_infinity(ctx->timeout)) {
		timeout = -1;
	} else {
		*pfd++ = (struct pollfd) {
			.fd	= ctx->fd,
			.events	= POLLIN,
		};

		timeout = time_to_ms(time_sub(ctx->now, ctx->timeout));
	}

	rc = poll(pfds, pfd - &pfds[0], timeout);
	if (rc < 0) {
		pr_err("poll(): %s", strerror(errno));
		return -1;
	}

	for (size_t i = pfd - &pfds[0]; i > 0; --i) {
		if (pfds[i - 1].revents == 0)
			continue;

		if (pfds[i - 1].fd == ctx->sig_fd)
			ctx->sig_available = true;

		if (pfds[i - 1].fd == ctx->fd)
			ctx->data_available = true;
	}

	return 0;
}

#ifndef TESTSUITE
int	_log_fd = 2;
#endif

int main(int argc, char *argv[])
{
	char const		*iface = argv[1];
	char const		*script = argv[2];
	struct dhcp_session	session;
	sigset_t		sig_mask;
	int			sig_fd = -1;
	int			rc;

	logging_register_conversions();

	(void)script ;

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGHUP);

	if (sigprocmask(SIG_BLOCK, &sig_mask, NULL) == -1) {
		pr_err("sigprocmask(): %s", strerror(errno));
		rc = EX_OSERR;
		goto out;
	}

	sig_fd = signalfd(-1, &sig_mask, SFD_CLOEXEC);
	if (sig_fd < 0) {
		pr_err("signalfd(): %s", strerror(errno));
		rc = EX_OSERR;
		goto out;
	}

	rc = dhcp_session_open(&session, iface);
	if (rc)
		goto out;

	for (;;) {
		struct dhcp_context	ctx = {
			.fd		= session.fd,
			.sig_fd		= sig_fd,
			.now		= time_now(),
			.timeout	= TIME_INFINITY,
			.sig_available	= false,
			.data_available	= false,
		};

		struct dhcp_iapd	*next_iapd = NULL;

		for (size_t i = 0; i < ARRAY_SIZE(session.iapd); ++i) {
			struct dhcp_iapd	*iapd = &session.iapd[i];
			dhcp_time_t		tm;

			if (iapd->state == IAPD_STATE_UNUSED)
				continue;

			tm = dhcp_iapd_step(iapd, ctx.now);
			if (time_cmp(tm, ctx.timeout) < 0) {
				ctx.timeout = tm;
				next_iapd   = iapd;
			}
		}

		if (!next_iapd) {
			pr_warn("no IAPD; just waiting for signal...");
			ctx.sig_available = true;
		} else if (!time_is_epoch(ctx.timeout) &&
			   time_cmp(ctx.now, ctx.timeout) < 0) {
			rc = dhcp_wait(&session, &ctx);
		} else {
			rc = dhcp_iapd_run(next_iapd, &ctx);
		}

		if (rc < 0) {
			/* TODO: handle errors in a better way */
			sleep(5);
			continue;
		}

		rc = 0;

		if (ctx.data_available)
			dhcp_read_response(&session, &ctx);

		if (ctx.sig_available)
			dhcp_handle_signal(&session, sig_fd);
	}

out:
	return rc;
}
