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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#define _GNU_SOURCE

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>

#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <netinet/in.h>
#include <net/if.h>

#include <arpa/inet.h>

#include <openssl/sha.h>

#include "util.h"
#include "dhcpv6.h"

#define DUID_ENUM		22683
#define DUID_SALT0		"kABoBaUjLjs9SebQUpUyadljIA1gvxV9"
#define DUID_SALT1		"6SwjUAHolGTaFie7j6A2glABx93pnIkj"
#define SERIAL_FILE_CPU		"/sys/firmware/devicetree/base/serial-number"
#define SERIAL_FILE_MACHINE_ID	"/etc/machine-id"

#define TIME_INFINITY		((time_t)0)

struct dhcp6_buffer {
	void		*data;
	size_t		len;
	size_t		max_len;
};

struct dhcp6_request {
	struct dhcp6_buffer	buf;
	uint8_t			xmit_id[3];
};

enum dhcp_iaid_state {
	IAID_STATE_INIT,
	IAID_STATE_SOLICATE,
	IAID_STATE_SOLICATE_RETRY,
	IAID_STATE_ACTIVE,
	IAID_STATE_RENEWAL,
};

struct dhcp_iaid {
	uint32_t	id;
	unsigned long	t1;
	unsigned long	t2;

	unsigned long	pref_t1;
	unsigned long	pref_t2;

	struct in6_addr	addr;
	unsigned char	prefix_len;

	time_t		pref_tm;
	time_t		valid_tm;

	time_t		end_t;
	time_t		renew_t;

	uint64_t	base_t;
	unsigned long	rt;

	bool			addr_valid;

	enum dhcp_iaid_state	state;
	uint8_t			xmit_id[3];
};

enum dhcp_client_state {
	DHCP_CLNT_STATE_INIT,
	DHCP_CLNT_STATE_SOLICATE_REQ,
	DHCP_CLNT_STATE_SOLICATE_RESP,
	DHCP_CLNT_STATE_WAIT,
	DHCP_CLNT_STATE_ERROR,
};


struct dhcp_session {
	int		fd;
	char const	*ifname;
	int		ifidx;
	unsigned char	duid[64];
	size_t		duid_len;

	time_t		now;

	struct dhcp6_request	req;
	unsigned char		req_buf[8192];

	struct dhcp_iaid	iaid[1];
	size_t			num_iaid;

	enum dhcp_client_state	state;
	time_t			state_tm;
};

union x_sockaddr {
	struct sockaddr		generic;
	struct sockaddr_in6	in6;
};

static void *buffer_allocate(struct dhcp6_buffer *buf,
			     size_t len)
{
	void	*res;

	if (len > buf->max_len - buf->len)
		return NULL;

	res = buf->data + buf->len;
	buf->len += len;

	return res;
}

static bool buffer_init_subbuffer(struct dhcp6_buffer const *buf,
				  struct dhcp6_buffer *_tmp,
				  size_t offset)
{
	if (offset > buf->max_len - buf->len)
		return false;

	_tmp->max_len = buf->max_len - buf->len - offset;
	_tmp->data    = buf->data + buf->len + offset;

	return true;
}

static bool buffer_add_raw(struct dhcp6_buffer *buf, unsigned int code,
			   void const *data, size_t len, size_t extra_len)
{
	struct dhcpv6_option_hdr	*opt;

	opt = buffer_allocate(buf, sizeof *opt + len + extra_len);
	if (!opt)
		return false;

	*opt = (struct dhcpv6_option_hdr) {
		.option		= CPU_TO_BE16(code),
		.len		= CPU_TO_BE16(len + extra_len),
	};

	if (data)
		memcpy(&opt[1], data, len);

	return true;
}

static bool buffer_add_option(struct dhcp6_buffer *buf, unsigned int code,
			      void const *data, size_t len)
{
	return buffer_add_raw(buf, code, data, len, 0);
}

static void *request_allocate(struct dhcp6_request *req, size_t len)
{
	return buffer_allocate(&req->buf, len);
}

static int x_getrandom(void *buf, size_t len)
{
	while (len > 0) {
		ssize_t	l = getrandom(buf, len, 0);
		if (l < 0)
			break;

		if (l == 0)
			sleep(1);

		buf += l;
		len -= l;
	}

	return len == 0 ? 0 : -1;
}

static bool request_init(struct dhcp_session *ses,
			 struct dhcp6_request *req,
			 unsigned int type)
{
	struct dhcpv6_message_hdr	*hdr;

	(void)ses;

	req->buf.len = 0;
	req->buf.data = ses->req_buf;
	req->buf.max_len = sizeof ses->req_buf;

	memset(req->buf.data, 0, req->buf.max_len);

	x_getrandom(&req->xmit_id, sizeof req->xmit_id);

	_Static_assert(sizeof hdr->xmit_id == sizeof req->xmit_id,
		       "bad xmit_id specification");

	hdr = request_allocate(req, sizeof *hdr);
	if (!hdr)
		return false;

	hdr->type = type;
	memcpy(hdr->xmit_id, req->xmit_id, sizeof req->xmit_id);

	return true;
}

static bool request_finalize(struct dhcp_session const *ses,
			     struct dhcp6_request *req)
{
	(void)ses;
	(void)req;

	return true;
}

static bool request_add_option_uuid(struct dhcp_session const *ses,
				    struct dhcp6_request *req)
{
	if (ses->duid_len > sizeof ses->duid)
		abort();

	return buffer_add_option(&req->buf, DHCPV6_OPTION_CLIENTID,
				 ses->duid, ses->duid_len);
}

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
		perror("socket()");
		return EX_OSERR;
	}

	strcpy(ifreq.ifr_name, ses->ifname);
	rc = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (rc < 0) {
		perror("ioctl(SIOCGIFINDEX)");
		rc = EX_OSFILE;
		goto err;
	}

	rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ONE, sizeof ONE);
	if (rc < 0) {
		perror("setsockopt()");
		rc = EX_OSFILE;
		goto err;
	}

	idx = ifreq.ifr_ifindex;
	addr.in6.sin6_scope_id = idx;

	rc = bind(fd, &addr.generic, sizeof addr);
	if (rc < 0) {
		perror("bind()");
		rc = EX_OSERR;
		goto err;
	}

	ses->ifidx = idx;
	ses->fd    = fd;

	ses->iaid[0] = (struct dhcp_iaid) {
		.id	= 1,
	};
	ses->num_iaid = ARRAY_SIZE(ses->iaid);

	return 0;

err:
	close(fd);
	return rc;
}

static void fill_duid(struct dhcp_session *ses, void const *data, size_t len)
{
	SHA256_CTX	ctx;
	unsigned char	buf[SHA256_DIGEST_LENGTH];
	void		*p;
	uint16_t	type = htobe16(2);
	uint32_t	ent_num = htobe32(DUID_ENUM);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, DUID_SALT0, strlen(DUID_SALT0));
	SHA256_Update(&ctx, data, len);
	SHA256_Update(&ctx, DUID_SALT1, strlen(DUID_SALT1));
	SHA256_Final(buf, &ctx);

	p = ses->duid;
	p = mempcpy(p, &type, sizeof type);
	p = mempcpy(p, &ent_num, sizeof ent_num);
	p = mempcpy(p, buf, 10);

	ses->duid_len = (uintptr_t)p - (uintptr_t)ses->duid;
}

static bool dhcp_generate_duid_from_file(struct dhcp_session *ses,
					 char const *fname)
{
	char	buf[1024];
	ssize_t	len;

	int	fd;

	fd = open(fname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (len < 0)
		return false;

	buf[len] = '\0';
	if (strlen(buf) < 10)
		return false;

	fill_duid(ses, buf, len);
	return true;
}

static int dhcp_generate_duid(struct dhcp_session *ses)
{
	if (!dhcp_generate_duid_from_file(ses, SERIAL_FILE_CPU) &&
	    !dhcp_generate_duid_from_file(ses, SERIAL_FILE_MACHINE_ID)) {
		fprintf(stderr, "can not generate duid\n");
		return EX_UNAVAILABLE;
	}

	return 0;
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

	dhcp_generate_duid(ses);

	return dhcp_session_reopen(ses);
}

static int send_request(struct dhcp_session *ses)
{
	union x_sockaddr	addr = {
		.in6 = {
			.sin6_family	= AF_INET6,
			.sin6_port	= htons(547),
			.sin6_scope_id	= ses->ifidx,
		}
	};
	ssize_t			l;

	inet_pton(AF_INET6, "ff02::1:2", addr.in6.sin6_addr.s6_addr);

	l = sendto(ses->fd, ses->req.buf.data, ses->req.buf.len, 0,
		   &addr.generic, sizeof addr);
	if (l < 0) {
		perror("sendto()");
		return -1;
	}

	if ((size_t)l != ses->req.buf.len) {
		fprintf(stderr, "sent unexpected number of bytes (%zd vs. %zu)\n",
			l, ses->req.buf.len);
		return -1;
	}

	return 0;
}

static bool request_add_option_elapsed_time(struct dhcp_session *ses,
					    struct dhcp6_request *req)
{
	uint16_t	tm16;
	time_t		tm_delta;

	if (ses->state_tm == (time_t)-1) {
		ses->state_tm = ses->now;
	}

	tm_delta = ses->now - ses->state_tm;
	if (tm_delta > 0xffff)
		tm_delta = 0xffff;

	tm16 = htobe16(tm_delta);

	return buffer_add_option(&req->buf, DHCPV6_OPTION_ELAPSED_TIME,
				 &tm16, sizeof tm16);
}

static unsigned long rt_rand(unsigned long prev,
			     unsigned int lo, unsigned int hi)
{
	long	v = random() % (hi - lo) + lo;

	return prev * v / 100;
}

static uint64_t time_ms(void)
{
	uint64_t	now = time(NULL);

	now *= 1000;

	return now;
}

static int dhcp_solicate_send(struct dhcp_session *ses)
{
	size_t		num_iapd = 0;
	uint64_t	now = time_ms();

	ses->now = now / 1000;

	if (!request_init(ses, &ses->req, 1) ||
	    !request_add_option_uuid(ses, &ses->req) ||
	    !request_add_option_elapsed_time(ses, &ses->req)) {
		fprintf(stderr, "failed to create SOLICATE request\n");
		return -1;
	}

	(void)buffer_init_subbuffer;

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid		*iaid = &ses->iaid[i];

		struct dhcpv6_option_iapd	opt_iapd = {
			.id	= CPU_TO_BE32(iaid->id),
			.t1	= CPU_TO_BE32(iaid->pref_t1),
			.t2	= CPU_TO_BE32(iaid->pref_t2),
		};

		if (iaid->state == IAID_STATE_SOLICATE &&
		    iaid->base_t + iaid->rt <= now)
			iaid->state = IAID_STATE_SOLICATE_RETRY;

		if (iaid->state != IAID_STATE_INIT &&
		    iaid->state != IAID_STATE_SOLICATE_RETRY)
			continue;

		iaid->addr_valid = false;

		if (!buffer_add_option(&ses->req.buf, DHCPV6_OPTION_IA_PD,
				       &opt_iapd, sizeof opt_iapd)) {
			fprintf(stderr, "failed to create PD for IAID#%zu\n", i);
			return -1;
		}

		++num_iapd;
	}

	request_finalize(ses, &ses->req);

	if (num_iapd == 0)
		return 0;

	if (send_request(ses) < 0) {
		for (size_t i = 0; i < ses->num_iaid; ++i) {
			struct dhcp_iaid	*iaid = &ses->iaid[i];

			if (iaid->state == IAID_STATE_SOLICATE_RETRY)
				iaid->state = IAID_STATE_SOLICATE;
		}

		return -1;
	}

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid	*iaid = &ses->iaid[i];
		bool			is_sent = false;

		if (iaid->state == IAID_STATE_INIT) {
			is_sent      = true;
			iaid->rt     = rt_rand(1000, 100, 110);
		} else if (iaid->state == IAID_STATE_SOLICATE_RETRY) {
			is_sent      = true;
			iaid->rt     = rt_rand(iaid->rt, 90, 110);

			if (iaid->rt > 120000)
				iaid->rt = rt_rand(120000, 90, 110);
		}

		if (is_sent) {
			_Static_assert(sizeof iaid->xmit_id ==
				       sizeof ses->req.xmit_id,
				       "bad xmit-id layout");

			memcpy(iaid->xmit_id, ses->req.xmit_id, sizeof iaid->xmit_id);
			iaid->state  = IAID_STATE_SOLICATE;
			iaid->base_t = now;
		}
	}

	return 1;
}

enum dhcp_wait_result {
	DHCP_WAIT_NONE,
	DHCP_WAIT_SIGNAL,
	DHCP_WAIT_RESPONSE,
	DHCP_WAIT_TIMEOUT,
};

static enum dhcp_wait_result dhcp_wait(struct dhcp_session *ses, int sig_fd)
{
	uint64_t	next_iaid_tm = 0;
	struct pollfd	fds[2];
	struct pollfd	*pfd;
	uint64_t	now = time_ms();
	int		rc;
	int		timeout;

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid	*iaid = &ses->iaid[i];
		uint64_t		exp_t;

		switch (iaid->state) {
		case  IAID_STATE_SOLICATE:
			exp_t = iaid->base_t + iaid->rt;
			break;

		default:
			exp_t = 0;
			break;
		}

		if (next_iaid_tm == 0 || exp_t < next_iaid_tm)
			next_iaid_tm = exp_t;
	}

	pfd = &fds[0];

	*pfd++ = (struct pollfd) {
		.fd	= sig_fd,
		.events	= POLLIN,
	};

	if (next_iaid_tm == 0) {
		timeout = -1;
	} else {
		uint64_t	delta_tm;

		*pfd++ = (struct pollfd) {
			.fd	= ses->fd,
			.events	= POLLIN,
		};

		if (next_iaid_tm < now)
			delta_tm = 0;
		else
			delta_tm = next_iaid_tm - now;

		if ((uint64_t)(int)delta_tm != delta_tm)
			delta_tm = INT_MAX;

		timeout = delta_tm;
	}

	rc = poll(fds, pfd - &fds[0], timeout);
	if (rc < 0) {
		perror("poll()");
		return DHCP_WAIT_TIMEOUT;
	}

	for (size_t i = pfd - &fds[0]; i > 0; --i) {
		if (fds[i - 1].revents == 0)
			continue;

		if (fds[i - 1].fd == sig_fd)
			return DHCP_WAIT_SIGNAL;

		if (fds[i - 1].fd == ses->fd)
			return DHCP_WAIT_RESPONSE;
	}

	return DHCP_WAIT_TIMEOUT;
}

static time_t dhcp_relative_time(struct dhcp_session const *ses, be32_t tm)
{
	if (be32_to_cpu(tm) == 0xffffffff)
		return TIME_INFINITY;
	else
		return ses->now + be32_to_cpu(tm);
}

static int dhcp_handle_ia_pd(struct dhcp_session *ses,
			     struct dhcpv6_message_hdr const *msg,
			     struct dhcpv6_option_hdr const *hdr)
{
	struct dhcpv6_option_iapd const		*opt_iapd;
	struct dhcpv6_option_hdr const		*opt_first;
	size_t					len;
	struct dhcpv6_option_iaprefix const	*opt_prefix = NULL;
	struct dhcp_iaid			*iapd = NULL;

	opt_iapd  = dhcpv6_get_option_data(hdr);
	len	  = be16_to_cpu(hdr->len) - sizeof *opt_iapd;
	opt_first = dhcpv6_validated_option((void *)&opt_iapd[1], len);

	if (!opt_first) {
		fprintf(stderr, "bad IAPD layout; not embedded option\n");
		return -1;
	}

	if (be32_to_cpu(opt_iapd->t1) > be32_to_cpu(opt_iapd->t2) &&
	    be32_to_cpu(opt_iapd->t2) > 0) {
		/* RFC 3633: If a requesting router receives an IA_PD with T1
		   greater than T2, and both T1 and T2 are greater than 0, the
		   client discards the IA_PD option and processes the
		   remainder of the message as though the delegating router
		   had not included the IA_PD option. */
		return 0;
	}

	dhcpv6_foreach_option_next(opt, opt_first, &len) {
		struct dhcpv6_option_iaprefix const	*tmp;

		if (be16_to_cpu(opt->option) != DHCPV6_OPTION_IAPREFIX)
			continue;

		if (be16_to_cpu(opt->len) < sizeof *tmp) {
			fprintf(stderr, "malformed IAPREFIX option\n");
			return -1;
		}

		tmp = dhcpv6_get_option_data(opt);

		if (opt_prefix && opt_prefix->prefix_len > tmp->prefix_len)
			/* prefer the largest advertised prefix */
			continue;

		opt_prefix = tmp;
	}

	if (len > 0) {
		fprintf(stderr, "extra data in IA_PD\n");
		return -1;
	}

	if (!opt_prefix)
		/* debug("no prefix advertised") */
		return 0;

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid	*tmp = &ses->iaid[i];

		if (tmp->state != IAID_STATE_SOLICATE)
			continue;

		if (memcmp(tmp->xmit_id, msg->xmit_id, sizeof tmp->xmit_id) != 0)
			continue;

		if (be32_to_cpu(opt_iapd->id) != tmp->id)
			continue;

		if (iapd) {
			fprintf(stderr, "IAPD option matching multiple IAPD\n");
			return -1;
		}

		iapd = tmp;
	}

	if (!iapd) {
		fprintf(stderr, "no matching IAPD\n");
		return -1;
	}

	iapd->t1 = be32_to_cpu(opt_iapd->t1);
	iapd->t2 = be32_to_cpu(opt_iapd->t2);

	_Static_assert(sizeof iapd->addr == sizeof opt_prefix->prefix,
		       "bad iapd->prefix layout");

	memcpy(&iapd->addr, opt_prefix->prefix, sizeof iapd->addr);
	iapd->prefix_len = opt_prefix->prefix_len;

	iapd->pref_tm  = dhcp_relative_time(ses, opt_prefix->pref_lftm);
	iapd->valid_tm = dhcp_relative_time(ses, opt_prefix->valid_lftm);

	iapd->addr_valid = true;


}

static int dhcp_handle_advertise(struct dhcp_session *ses,
				 struct dhcpv6_message_hdr const *msg,
				 size_t len)
{
	int		rc;

	dhcpv6_foreach_option(opt, msg, &len) {
		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_IA_PD:
			rc = dhcp_handle_ia_pd(ses, msg, opt);
			break;

		default:
			rc = 0;
			break;
		}

		if (rc < 0)
			break;
	}

	if (rc < 0)
		goto out;

	if (len != 0) {
		fprintf(stderr, "extra data after last DHCP option\n");
		return -1;
	}

	rc = 0;

out:
	return rc;
}

static int dhcp_handle_reply(struct dhcp_session *ses,
			     struct dhcpv6_message_hdr const *hdr,
			     size_t len)
{
}

static int dhcp_read_response(struct dhcp_session *ses)
{
	union {
		struct dhcpv6_message_hdr	hdr;
		unsigned char			buf[16*1024];
	}			resp;
	union x_sockaddr	peer_addr;
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
		.msg_name	= &peer_addr,
		.msg_namelen	= sizeof peer_addr,
		.msg_iov	= &msg_vec,
		.msg_iovlen	= 1,
		.msg_control	= cmbuf.raw,
		.msg_controllen	= sizeof cmbuf,
	};

	ssize_t			l;

	l = recvmsg(ses->fd, &msg, 0);
	if (l < 0) {
		perror("recvmsg()");
	}

	ses->now = time(NULL);

	/* TODO: this check might violate the DHCPv6 RFC */
	if ((size_t)l >= sizeof resp) {
		fprintf(stderr, "response too large\n");
		return -1;
	}

	if ((size_t)l < sizeof resp.hdr) {
		fprintf(stderr, "response too small\n");
		return -1;
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
				fprintf(stderr, "bad ifidx\n");
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
		fprintf(stderr, "failed to get local address from received datagram\n");
		return -1;
	}

	/* sanity check: reject datagrams to non link-local addresses */
	if (local_addr.s6_addr[0] != 0xfe || local_addr.s6_addr[1] != 0x80) {
		char	tmp[INET6_ADDRSTRLEN];

		fprintf(stderr, "non link-local destination address %s\n",
			inet_ntop(AF_INET6, &local_addr, tmp, sizeof tmp));
		return -1;
	}

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
		return 0;

	case DHCPV6_TYPE_ADVERTISE:
		return dhcp_handle_advertise(ses, &resp.hdr, l);

	case DHCPV6_TYPE_REPLY:
		return dhcp_handle_reply(ses, &resp.hdr, 1);

		break;
	}

	return 0;
}

static void dhcp_validate_objects(struct dhcp_session *ses)
{
	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid	*iad = &ses->iaid[i];

		assert(iad->state != IAID_STATE_SOLICATE_RETRY);
	}
}

int main(int argc, char *argv[])
{
	char const		*iface = argv[1];
	char const		*script = argv[2];
	struct dhcp_session	session;
	sigset_t		sig_mask;
	int			sig_fd = -1;

	int		rc;


	(void)script ;

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGHUP);

	if (sigprocmask(SIG_BLOCK, &sig_mask, NULL) == -1) {
		perror("sigprocmask()");
		rc = EX_OSERR;
		goto out;
	}

	sig_fd = signalfd(-1, &sig_mask, SFD_CLOEXEC);
	if (sig_fd < 0) {
		perror("signalfd()");
		rc = EX_OSERR;
		goto out;
	}

	rc = dhcp_session_open(&session, iface);
	if (rc)
		goto out;


	for (;;) {
		enum dhcp_wait_result	wait_res = DHCP_WAIT_NONE;

		dhcp_validate_objects(&session);

		switch (session.state) {
		case DHCP_CLNT_STATE_INIT:
			session.state = DHCP_CLNT_STATE_SOLICATE_REQ;
			session.state_tm = (time_t)-1;
			rc = 0;
			break;

		case DHCP_CLNT_STATE_SOLICATE_REQ:
			rc = dhcp_solicate_send(&session);
			if (rc < 0) {
				session.state = DHCP_CLNT_STATE_ERROR;
			} else if (rc > 0) {
				session.state = DHCP_CLNT_STATE_SOLICATE_RESP;
			} else {
				session.state = DHCP_CLNT_STATE_WAIT;
			}

			break;

		case DHCP_CLNT_STATE_SOLICATE_RESP:
			wait_res = dhcp_wait(&session, sig_fd);
			/* TODO */
			break;


		case DHCP_CLNT_STATE_WAIT:
			break;

		case DHCP_CLNT_STATE_ERROR:
			break;
		}

		if (session.state == DHCP_CLNT_STATE_ERROR)
			break;

		switch (wait_res) {
		case DHCP_WAIT_RESPONSE:
			rc = dhcp_read_response(&session);
			break;

		case DHCP_WAIT_NONE:
			break;

		case DHCP_WAIT_SIGNAL:
			break;

		case DHCP_WAIT_TIMEOUT:
			fprintf(stderr, "timeout\n");
			break;

		}
	}

out:
	return rc;
}
