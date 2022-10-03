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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/if.h>

#include <ensc-lib/sd-notify.h>

#include "dhcpv6.h"
#include "dhcpv6-util.h"
#include "logging.h"

#define NUM_IAPD_PER_IFACE	(1)

struct dhcp_session {
	int			fd;
	char const		*ifname;
	int			ifidx;
	struct in6_addr		ifaddr;
	struct dhcpv6_duid	duid;

	int			nl_fd;
	bool			link_is_up;
	bool			link_going_down;

	uint64_t		now;
	unsigned int		num_quit;
	bool			do_reopen;

	struct dhcp_iapd	iapd[NUM_IAPD_PER_IFACE];
};

#define LOG_DOMAIN	LOG_DOMAIN_NETLINK

static int dhcp_request_netlink_info(struct dhcp_session *ses)
{
	struct {
		struct nlmsghdr  nh;
		struct ifaddrmsg if_msg;
	}			req = {
		.nh	= {
			.nlmsg_len	= NLMSG_LENGTH(sizeof req.if_msg),
			.nlmsg_flags	= NLM_F_REQUEST | NLM_F_MATCH,
			.nlmsg_type	= RTM_GETADDR,
		},

		.if_msg	= {
			.ifa_family	= AF_INET6,
			.ifa_flags	= 0,
			.ifa_scope	= RT_SCOPE_LINK,
		},
	};
	ssize_t			l;

	req.if_msg.ifa_index = if_nametoindex(ses->ifname);
	if (req.if_msg.ifa_index == 0) {
		pr_warn("no such interface %s: %s", ses->ifname,
			strerror(errno));
		return 0;
	}

	assert(req.nh.nlmsg_len <= sizeof req);

	l = send(ses->nl_fd, &req, req.nh.nlmsg_len, 0);
	if (l < 0) {
		pr_err("send(<NETLINK>): %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int dhcp_init_netlink(struct dhcp_session *ses)
{
	struct sockaddr_nl	sa = {
		.nl_family	= AF_NETLINK,
		.nl_groups	= RTMGRP_IPV6_IFADDR,
	};
	int			fd;
	int			rc;


	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		pr_err("socket(<NETLINK>): %s", strerror(errno));
		return -1;
	}

	rc = bind(fd, (void *)&sa, sizeof sa);
	if (rc < 0) {
		pr_err("bind(<NETLINK>): %s", strerror(errno));
		close(fd);
		return -1;
	}

	ses->nl_fd = fd;

	dhcp_request_netlink_info(ses);

	return 0;
}

static int dhcp_handle_rtm_addr(struct dhcp_session *ses,
				 struct nlmsghdr const *hdr)
{
	char			if_buf[IF_NAMESIZE];
	char const		*if_name;
	struct ifaddrmsg const	*msg;
	size_t			len = hdr->nlmsg_len;
	struct in6_addr		addr;
	bool			have_addr = false;


	msg = NLMSG_DATA(hdr);
	if (len < NLMSG_LENGTH(sizeof *msg)) {
		pr_err("NETLINK: message too small (%zu)", len);
		return -1;
	}

	if (msg->ifa_family != AF_INET6) {
		/* should not happen */
		pr_warn("not IPv6");
		return -1;
	}

	if (msg->ifa_scope != RT_SCOPE_LINK) {
		pr_debug("no link-scope");
		return 0;
	}

	if (hdr->nlmsg_type == RTM_NEWADDR &&
	    (msg->ifa_flags & IFA_F_TENTATIVE)) {
		pr_debug("ignoring tentative state");
		return 0;
	}

	if_name = if_indextoname(msg->ifa_index, if_buf);
	if (!if_name) {
		pr_debug("can not map ifidx %d: %s",
			 msg->ifa_index, strerror(errno));
		return -1;
	}

	if (strcmp(if_name, ses->ifname) != 0) {
		pr_debug("not for us (%s)", if_name);
		return 0;
	}

	for (struct rtattr const *rta = IFA_RTA(msg); RTA_OK(rta, len);
	     rta = RTA_NEXT(rta, len)) {
		void const	*rta_data = RTA_DATA(rta);
		size_t		rta_len  = RTA_PAYLOAD(rta);

		switch (rta->rta_type) {
		case IFA_LOCAL:
			if (rta_len < sizeof addr) {
				pr_warn("insufficient space for IFA_ADDRESS");
			} else {
				memcpy(&addr, rta_data, sizeof addr);
				have_addr = true;
			}
			break;

		default:
			break;
		}
	}

	if (!have_addr) {
		pr_warn("no IFA_ADDRESS option");
		return 0;
	}

	if (hdr->nlmsg_type == RTM_NEWADDR) {
		ses->ifaddr = addr;
		ses->ifidx  = msg->ifa_index;
		ses->link_is_up = true;
		ses->do_reopen = true;
		pr_info("link is up with IP %pP", &addr);
	} else if (hdr->nlmsg_type == RTM_DELADDR &&
		   memcmp(&ses->ifaddr, &addr, sizeof ses->ifaddr) == 0) {
		ses->link_is_up = false;
		ses->link_going_down = true;
		pr_info("addr %pP removed from link", &addr);

		sd_notify(0, "RELOADING=1");
	}

	return 0;
}

static int dhcp_handle_netlink(struct dhcp_session *ses)
{
	unsigned char		raw_buf[64 * 1024];
	struct iovec		iov = {
		.iov_base	= raw_buf,
		.iov_len	= sizeof raw_buf,
	};
	struct sockaddr_nl	sa;
	struct msghdr		msg = {
		.msg_name	= &sa,
		.msg_namelen	= sizeof sa,
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
	};
	ssize_t			l;


	l = recvmsg(ses->nl_fd, &msg, 0);
	if (l < 0) {
		pr_err("recvmsg(>NETLINK): %s", strerror(errno));
		return -1;
	}

	for (struct nlmsghdr *nh = (void *)raw_buf; NLMSG_OK(nh, l);
	     nh = NLMSG_NEXT(nh, l)) {
		bool		do_break = false;

		switch (nh->nlmsg_type) {
		case NLMSG_DONE:
			do_break = true;
			break;

		case NLMSG_ERROR: {
			struct nlmsgerr const	*err = NLMSG_DATA(nh);
			pr_err("NETLINK: %s", strerror(-err->error));
			do_break = true;
			break;
		}

		case RTM_NEWADDR:
		case RTM_DELADDR:
			dhcp_handle_rtm_addr(ses, nh);
			break;

		default:
			pr_warn("NETLINK: unsupported type %d", nh->nlmsg_type);
			break;
		}

		if (do_break)
			break;
	}

	return 0;
}

#undef LOG_DOMAIN
#define LOG_DOMAIN		LOG_DOMAIN_MAIN

static int dhcp_session_reopen(struct dhcp_session *ses)
{
	int			ONE = 1;
	int			fd;
	struct sockaddr_in6	addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(546),
		.sin6_scope_id	= ses->ifidx,
		.sin6_addr	= ses->ifaddr,
	};
	int			rc;

	pr_debug("reopening session");

	if (ses->fd >= 0) {
		close(ses->fd);
		ses->fd = -1;
	}

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		pr_err("socket(): %s", strerror(errno));
		return EX_OSERR;
	}

	rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ONE, sizeof ONE);
	if (rc < 0) {
		pr_err("setsockopt(): %s", strerror(errno));
		rc = EX_OSERR;
		goto err;
	}

	rc = bind(fd, &addr, sizeof addr);
	if (rc < 0) {
		pr_err("bind(): %s", strerror(errno));
		rc = EX_OSERR;
		goto err;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
		struct dhcp_iapd	*iapd = &ses->iapd[i];

		iapd->do_request = true;
	}

	ses->fd        = fd;
	ses->do_reopen = false;

	sd_notify(0, "READY=1");

	return 0;

err:
	close(fd);
	return rc;
}

static int dhcp_session_open(struct dhcp_session *ses, char const *ifname)
{
	struct ifreq	ifreq;
	int		rc;

	if (strlen(ifname) >= sizeof ifreq.ifr_name)
		return EX_USAGE;

	*ses = (struct dhcp_session) {
		.ifname		= ifname,
		.fd		= -1,
		.nl_fd		= -1,
		.ifidx		= -1,
		.link_is_up	= false,
	};

	for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
		struct dhcp_iapd	*iapd = &ses->iapd[i];

		iapd->state = IAPD_STATE_INIT;
		iapd->id    = i + 1;
	}

	rc = dhcp_init_netlink(ses);
	if (rc < 0)
		return EX_OSERR;

	dhcpv6_duid_generate(&ses->duid);

	return 0;
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

	if ((size_t)l != sizeof fdsi) {
		pr_err("read(<>sig-fd>): unexpected number of bytes read (%zd vs %zu)",
		       l, sizeof fdsi);
		return;
	}

	pr_info("got signal %d", fdsi.ssi_signo);

	switch (fdsi.ssi_signo) {
	case SIGUSR1:
		for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
			struct dhcp_iapd	*iapd = &ses->iapd[i];

			iapd->do_request = true;
		}
		break;

	case SIGUSR2:
		for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
			struct dhcp_iapd	*iapd = &ses->iapd[i];

			iapd->do_release = true;
		}
		break;

	case SIGINT:
		for (size_t i = 0; i < ARRAY_SIZE(ses->iapd); ++i) {
			struct dhcp_iapd	*iapd = &ses->iapd[i];

			iapd->do_release = true;
			iapd->do_quit = true;
		}

		if (ses->num_quit == 0)
			sd_notify(0, "STOPPING=1");

		++ses->num_quit;
		break;
	}

	/* TODO */
}

static int dhcp_handle_response(struct dhcp_session *ses, struct dhcp_context *ctx,
				struct dhcpv6_message_hdr const *hdr, size_t len)
{
	size_t				tmp_len = len;
	struct dhcpv6_option_hdr const	*opt_clnt_id = NULL;
	int				rc;

	rc = 0;
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

		case DHCPV6_OPTION_UNICAST:
			if (opt_len != sizeof ctx->server.addr) {
				pr_warn("bad UNICAST option");
				rc = -1;
				goto out_loop;
			}

			ctx->server.is_unicast = true;

			/* TODO: store original server address somewhere? */
			memcpy(&ctx->server.addr, opt_data, sizeof ctx->server.addr);
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

			ctx->status_code = dhcpv6_read_status_code(opt_data, opt_len);
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

	/* will stay when all iapd[] slots are unused */
	rc = -1;

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

	pr_enter("");

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

	pr_debug("read %s(%d) on %pP from %pP",
		 dhcpv6_type_to_str(resp.hdr.type), resp.hdr.type,
		 &local_addr, &ctx->server.addr.sin6_addr);

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

	pr_leave("rc=%d", rc);

	return rc;
}

static int dhcp_wait(struct dhcp_session *ses, struct dhcp_context *ctx)
{
	struct pollfd		pfds[3];
	struct pollfd		*pfd = &pfds[0];
	int			timeout;
	int			rc;

	assert(time_is_epoch(ctx->timeout) ||
	       time_cmp(ctx->timeout, ctx->now) > 0);

	*pfd++ = (struct pollfd) {
		.fd	= ctx->sig_fd,
		.events	= POLLIN,
	};

	*pfd++ = (struct pollfd) {
		.fd	= ses->nl_fd,
		.events	= POLLIN,
	};

	if (time_is_epoch(ctx->timeout)) {
		timeout = 0;
	} else if (time_is_infinity(ctx->timeout) || ses->do_reopen) {
		timeout = -1;
	} else {
		dhcp_time_t	tm_delta = time_sub(ctx->timeout, ctx->now);

		if (!ctx->no_io) {
			*pfd++ = (struct pollfd) {
				.fd	= ctx->fd,
				.events	= POLLIN,
			};
		}

		timeout = time_to_ms(tm_delta);
	}

	pr_debug("waiting %dms", timeout);

	rc = poll(pfds, pfd - &pfds[0], timeout);
	if (rc < 0) {
		pr_err("poll(): %s", strerror(errno));
		return -1;
	}

	for (size_t i = pfd - &pfds[0]; i > 0; --i) {
		int		fd = pfds[i - 1].fd;
		if (pfds[i - 1].revents == 0)
			continue;

		if (fd == ctx->sig_fd)
			ctx->sig_available = true;

		if (fd == ctx->fd)
			ctx->data_available = true;

		if (fd == ses->nl_fd)
			ctx->nl_available = true;
	}

	pr_debug("sig=%d, data=%d, nl=%d",
		 ctx->sig_available, ctx->data_available, ctx->nl_available);

	return 0;
}

#ifndef TESTSUITE
int	_log_fd = 2;
#else
int main(int argc, char *argv[]);
#endif

int main(int argc, char *argv[])
{
	char const		*iface = argv[1];
	char const		*script = argv[2];
	struct dhcp_session	session;
	sigset_t		sig_mask;
	int			sig_fd = -1;
	int			rc;
	unsigned int		err_cnt = 0;

	logging_register_conversions();

	(void)script ;

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGHUP);
	sigaddset(&sig_mask, SIGUSR1);
	sigaddset(&sig_mask, SIGUSR2);
	sigaddset(&sig_mask, SIGINT);

	setenv("DHCP_INTERFACE", iface, 1);

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

	while (session.num_quit < 5) {
		struct dhcp_context	ctx = {
			.fd		= session.fd,
			.ifidx		= session.ifidx,
			.sig_fd		= sig_fd,
			.now		= time_now(),
			.timeout	= TIME_INFINITY,
			.sig_available	= false,
			.data_available	= false,
			.nl_available	= false,
			.client_id	= &session.duid,
			.script		= script,
		};

		struct dhcp_iapd	*next_iapd = NULL;
		bool			do_quit = session.num_quit > 0;

		pr_debug("==== now %pT ====", &ctx.now);

		if (session.link_is_up && !session.do_reopen) {
			for (size_t i = 0; i < ARRAY_SIZE(session.iapd); ++i) {
				struct dhcp_iapd	*iapd = &session.iapd[i];
				dhcp_time_t		tm;

				if (iapd->state == IAPD_STATE_UNUSED)
					continue;

				if (iapd->do_release)
					/* cancel quit */
					do_quit = false;

				tm = dhcp_iapd_step(iapd, &ctx);
				if (time_cmp(tm, ctx.timeout) < 0) {
					ctx.timeout = tm;
					next_iapd   = iapd;
				}
			}
		}

		if (!session.link_is_up ||
		    session.do_reopen ||
		    time_cmp(ctx.now, ctx.timeout) < 0) {
			if (do_quit) {
				/* ensure that we read the special 5x SIGUSR
				 * sequence */
				ctx.timeout = TIME_EPOCH;
			}

			rc = dhcp_wait(&session, &ctx);
			if (rc >= 0)
				err_cnt = 0;

			sd_notify(0, "WATCHDOG=1");
		} else if (!next_iapd) {
			/* this is prevented by program logic... */
			pr_err("INTERNAL ERROR: next_iapd is NULL\n");
			sleep(2);
		} else {
			rc = dhcp_iapd_run(next_iapd, &ctx);
			if (rc < 0)
				++err_cnt;

			if (rc < 0 && err_cnt > 5) {
				/* avoid log storms */
				pr_warn("unhandled error; sleeping some time...");

				ctx.timeout = time_add_s(ctx.now, 10);
				ctx.no_io   = true;

				dhcp_wait(&session, &ctx);
			}
		}

		if (ctx.data_available)
			dhcp_read_response(&session, &ctx);

		if (ctx.sig_available)
			dhcp_handle_signal(&session, sig_fd);

		if (ctx.nl_available)
			dhcp_handle_netlink(&session);

		if (ctx.err_no_net) {
			sd_notify(0, "RELOADING=1");
			session.do_reopen = true;
			session.link_is_up = false;

			sleep(1);

			dhcp_request_netlink_info(&session);

			rc = 0;
		}

		if (session.do_reopen && session.link_is_up)
			dhcp_session_reopen(&session);

		if (do_quit)
			break;
	}

out:
	return rc;
}
