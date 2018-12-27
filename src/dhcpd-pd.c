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

#define MAX_SERVERID_SZ		128
#define DUID_ENUM		22683
#define DUID_SALT0		"kABoBaUjLjs9SebQUpUyadljIA1gvxV9"
#define DUID_SALT1		"6SwjUAHolGTaFie7j6A2glABx93pnIkj"
#define SERIAL_FILE_CPU		"/sys/firmware/devicetree/base/serial-number"
#define SERIAL_FILE_MACHINE_ID	"/etc/machine-id"

#define TIME_INFINITY		(~(uint64_t)0u)

#define pr_print(_lvl, _fmt, ...) do {					\
		if ((_lvl) <= msg_level()) {				\
			FILE *_fp = (_lvl) < 3 ? stderr : stdout;	\
			fprintf(_fp, _fmt, ##__VA_ARGS__);		\
			fprintf(_fp, "\n");				\
		}							\
	} while (0)

#define pr_debug(fmt, ...)	pr_print(9, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	pr_print(6, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	pr_print(3, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	pr_print(2, fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...)	pr_print(1, fmt, ##__VA_ARGS__)

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
	IAID_STATE_SOLICATE_DONE,
	IAID_STATE_REQUEST,
	IAID_STATE_REQUEST_RETRY,
	IAID_STATE_REQUEST_DONE,
	IAID_STATE_REQUEST_TIMEOUT,
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

	uint64_t	pref_tm;
	uint64_t	valid_tm;

	uint64_t	end_t;
	uint64_t	renew_t;

	uint64_t	base_t;
	unsigned long	rt;

	unsigned char	serverid[MAX_SERVERID_SZ];
	size_t		serverid_len;

	unsigned int		num_retry;

	struct sockaddr_in6	server_addr;
	unsigned int		server_pref;

	enum dhcp_iaid_state	state;
	uint8_t			xmit_id[3];
};

struct dhcp_session {
	int		fd;
	char const	*ifname;
	int		ifidx;
	unsigned char	duid[64];
	size_t		duid_len;

	uint64_t	now;

	struct dhcp6_request	req;
	unsigned char		req_buf[8192];

	struct dhcp_iaid	iaid[1];
	size_t			num_iaid;

	uint64_t		state_tm;
};

union x_sockaddr {
	struct sockaddr		generic;
	struct sockaddr_in6	in6;
};

inline static int msg_level(void)
{
	return 9;
}

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
		pr_err("can not generate duid");
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
		pr_err("sendto(): %s", strerror(errno));
		return -1;
	}

	if ((size_t)l != ses->req.buf.len) {
		pr_err("sent unexpected number of bytes (%zd vs. %zu)",
			l, ses->req.buf.len);
		return -1;
	}

	return 0;
}

static bool request_add_option_elapsed_time(struct dhcp_session *ses,
					    struct dhcp6_request *req)
{
	uint16_t	tm16;
	uint64_t	tm_delta;

	if (ses->state_tm == 0) {
		ses->state_tm = ses->now;
	}

	/* unit: 1/100s; internally we are using ms */
	tm_delta = (ses->now - ses->state_tm) / 10;
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

static uint64_t time_now_ms(void)
{
	struct timespec	ts;
	uint64_t	now;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	now  = ts.tv_sec;
	now *= 1000;
	now += ts.tv_nsec / 1000000;

	return now;
}

static char const *dhcp_iaid_state_dump(enum dhcp_iaid_state state)
{
	switch (state) {
	case IAID_STATE_RENEWAL: return "renewal";
	case IAID_STATE_ACTIVE: return "active";
	case IAID_STATE_SOLICATE_DONE: return "solicate-done";
	case IAID_STATE_SOLICATE_RETRY: return "solicate-retry";
	case IAID_STATE_SOLICATE: return "solicate";
	case IAID_STATE_INIT: return "init";
	}

	return "???";
}

struct dhcp_iaid_dump_buf {
	char			b[INET6_ADDRSTRLEN + 128];
};

struct dhcp_clnt_dump_buf {
	char			b[128];
};

static char const *dhcp_iaid_dump(struct dhcp_iaid const *iaid,
				  struct dhcp_iaid_dump_buf *buf)
{
	char	*ptr = buf->b;

	sprintf(ptr, "IAID#%04x (%s) ", iaid->id,
		dhcp_iaid_state_dump(iaid->state));

	ptr += strlen(ptr);

	inet_ntop(AF_INET6, &iaid->addr, ptr, INET6_ADDRSTRLEN);

	ptr += strlen(ptr);

	sprintf(ptr, "/%u", iaid->prefix_len);

	return buf->b;
}

static char const __attribute__((__unused__)) *
dhcp_client_dump(struct dhcp_session const *ses,
		 struct dhcp_clnt_dump_buf *buf)
{
	char	*ptr = buf->b;

	sprintf(ptr, "CLNT");

	return buf->b;
}

static void dhcp_iaid_new_state(struct dhcp_session *ses,
				struct dhcp_iaid *iaid,
				enum dhcp_iaid_state state)
{
	struct dhcp_iaid_dump_buf 	pr_buf_iaid;

	pr_debug("%s: new state %s",
		 dhcp_iaid_dump(iaid, &pr_buf_iaid),
		 dhcp_iaid_state_dump(state));

	iaid->state = state;
}

static void dhcp_iaid_finish(struct dhcp_session *ses,
			     struct dhcpv6_message_hdr const *msg,
			     bool do_force)
{
	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid		*tmp = &ses->iaid[i];

		(void)tmp;
	}
}

static int dhcp_iaid_cmp_serverid(struct dhcp_iaid const *a,
				  struct dhcp_iaid const *b)
{

	if (a->serverid_len < b->serverid_len)
		return -1;
	else if (a->serverid_len > b->serverid_len)
		return +1;
	else
		return memcmp(a->serverid, b->serverid, a->serverid_len);
}

static int dhcp_request_send(struct dhcp_session *ses)
{
	size_t			num_iapd = 0;
	uint64_t		now = time_now_ms();
	struct dhcp_iaid const	*first_iaid = NULL;

	ses->now = now;

	if (!request_init(ses, &ses->req, 1) ||
	    !request_add_option_uuid(ses, &ses->req) ||
	    !request_add_option_elapsed_time(ses, &ses->req)) {
		pr_err("failed to create SOLICATE request");
		return -1;
	}

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid		*iaid = &ses->iaid[i];

		if (first_iaid &&
		    dhcp_iaid_cmp_serverid(first_iaid, iaid) != 0) {
			pr_debug("skipping IAID#%zu due to different serverid", i);
			continue;
		}

		if (iaid->state == IAID_STATE_REQUEST &&
		    iaid->base_t + iaid->rt <= now) {
			dhcp_iaid_new_state(ses, iaid, IAID_STATE_REQUEST_RETRY);
			iaid->num_retry += 1;
		}

		if (iaid->state == IAID_STATE_REQUEST_RETRY &&
		    iaid->num_retry > 10) { /* REQ_MAX_RC */
			dhcp_iaid_new_state(ses, iaid, IAID_STATE_REQUEST_TIMEOUT);
			continue;
		}

		if (iaid->state == IAID_STATE_SOLICATE_DONE) {
			iaid->num_retry = 0;
			dhcp_iaid_new_state(ses, iaid, IAID_STATE_REQUEST);
		}
	};

}

static int dhcp_solicate_send(struct dhcp_session *ses)
{
	size_t		num_iapd = 0;
	uint64_t	now = time_now_ms();

	ses->now = now;

	if (!request_init(ses, &ses->req, 1) ||
	    !request_add_option_uuid(ses, &ses->req) ||
	    !request_add_option_elapsed_time(ses, &ses->req)) {
		pr_err("failed to create SOLICATE request");
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
			dhcp_iaid_new_state(ses, iaid, IAID_STATE_SOLICATE_RETRY);

		if (iaid->state != IAID_STATE_INIT &&
		    iaid->state != IAID_STATE_SOLICATE_RETRY)
			continue;

		if (!buffer_add_option(&ses->req.buf, DHCPV6_OPTION_IA_PD,
				       &opt_iapd, sizeof opt_iapd)) {
			pr_err("failed to create PD for IAID#%zu", i);
			return -1;
		}

		++num_iapd;
	}

	request_finalize(ses, &ses->req);

	if (num_iapd == 0) {
		pr_debug("no IAPD object found to send SOLICATE");
		return 0;
	}

	if (send_request(ses) < 0) {
		for (size_t i = 0; i < ses->num_iaid; ++i) {
			struct dhcp_iaid	*iaid = &ses->iaid[i];

			if (iaid->state == IAID_STATE_SOLICATE_RETRY)
				dhcp_iaid_new_state(ses, iaid, IAID_STATE_SOLICATE);
		}

		return -1;
	}

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid_dump_buf	pr_iaid;
		struct dhcp_iaid	*iaid = &ses->iaid[i];
		bool			is_sent = false;

		if (iaid->state == IAID_STATE_INIT) {
			is_sent      = true;
			iaid->rt     = rt_rand(1000, 100, 110);
		} else if (iaid->state == IAID_STATE_SOLICATE_RETRY) {
			is_sent      = true;
			iaid->rt     = rt_rand(iaid->rt, 190, 210);

			if (iaid->rt > 120000)
				iaid->rt = rt_rand(120000, 90, 110);
		}

		pr_debug("  %s: RT=%lu", dhcp_iaid_dump(iaid, &pr_iaid),
			 iaid->rt);

		if (is_sent) {
			_Static_assert(sizeof iaid->xmit_id ==
				       sizeof ses->req.xmit_id,
				       "bad xmit-id layout");

			memcpy(iaid->xmit_id, ses->req.xmit_id, sizeof iaid->xmit_id);
			dhcp_iaid_new_state(ses, iaid, IAID_STATE_SOLICATE);
			iaid->base_t = now;
		}
	}

	return 1;
}

enum dhcp_wait_result {
	DHCP_WAIT_NONE,
	DHCP_WAIT_SEND_SOLICATE,
	DHCP_WAIT_SEND_REQUEST,
	DHCP_WAIT_SIGNAL,
	DHCP_WAIT_RESPONSE,
	DHCP_WAIT_TIMEOUT,
};

static enum dhcp_wait_result dhcp_wait(struct dhcp_session *ses, int sig_fd)
{
	uint64_t		next_iaid_tm = TIME_INFINITY;
	struct pollfd		fds[2];
	struct pollfd		*pfd;
	uint64_t		now = time_now_ms();
	int			rc;
	int			timeout;
	enum dhcp_wait_result	res = DHCP_WAIT_NONE;

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid_dump_buf	pr_iad;
		struct dhcp_iaid		*iaid = &ses->iaid[i];
		uint64_t			exp_t;
		enum dhcp_wait_result		tmp_res;

		switch (iaid->state) {
		case IAID_STATE_INIT:
			tmp_res = DHCP_WAIT_SEND_SOLICATE;
			exp_t = 0;
			break;

		case IAID_STATE_SOLICATE:
			tmp_res = DHCP_WAIT_SEND_SOLICATE;
			exp_t = iaid->base_t + iaid->rt;
			break;

		case IAID_STATE_SOLICATE_DONE:
			tmp_res = DHCP_WAIT_SEND_REQUEST;
			exp_t = 0;
			break;

		default:
			exp_t = TIME_INFINITY;
			break;
		}

		pr_debug("%s: exp_t -> %lld/%llu (%lld) (%d)",
			 dhcp_iaid_dump(iaid, &pr_iad),
			 (unsigned long long)exp_t,
			 (unsigned long long)now,
			 (unsigned long long)(now - exp_t),
			 tmp_res);

		if (exp_t < next_iaid_tm) {
			next_iaid_tm = exp_t;
			res = tmp_res;
		}
	}

	if (next_iaid_tm == 0)
		return res;

	pfd = &fds[0];

	*pfd++ = (struct pollfd) {
		.fd	= sig_fd,
		.events	= POLLIN,
	};

	if (next_iaid_tm == TIME_INFINITY) {
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
		pr_err("poll(): %s", strerror(errno));
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

static uint64_t dhcp_relative_time(struct dhcp_session const *ses, be32_t tm)
{
	if (be32_to_cpu(tm) == 0xffffffff)
		return TIME_INFINITY;
	else
		return ses->now + be32_to_cpu(tm) * 1000;
}

struct dhcp_server_info {
	struct dhcpv6_option_hdr const *opt;
	struct sockaddr_in6		addr;
	unsigned int			pref;
};

static int dhcp_handle_ia_pd(struct dhcp_session *ses,
			     struct dhcp_server_info const *server,
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
		pr_err("bad IAPD layout; not embedded option");
		return -1;
	}

	if (be32_to_cpu(opt_iapd->t1) > be32_to_cpu(opt_iapd->t2) &&
	    be32_to_cpu(opt_iapd->t2) > 0) {
		/* RFC 3633: If a requesting router receives an IA_PD with T1
		   greater than T2, and both T1 and T2 are greater than 0, the
		   client discards the IA_PD option and processes the
		   remainder of the message as though the delegating router
		   had not included the IA_PD option. */
		pr_debug("bad T1/T2 (%u, %u)\n",
			 be32_to_cpu(opt_iapd->t1),
			 be32_to_cpu(opt_iapd->t2));

		return 0;
	}

	dhcpv6_foreach_option_next(opt, opt_first, &len) {
		struct dhcpv6_option_iaprefix const	*tmp;

		pr_debug("EMBOPTION: %s(+%u)",
			 dhcpv6_option_to_str(be16_to_cpu(opt->option)),
			 be16_to_cpu(opt->len));

		if (be16_to_cpu(opt->option) != DHCPV6_OPTION_IAPREFIX) {
			pr_debug("  not IAPREFIX");
			continue;
		}

		if (be16_to_cpu(opt->len) < sizeof *tmp) {
			pr_err("malformed IAPREFIX option");
			return -1;
		}

		tmp = dhcpv6_get_option_data(opt);

		if (opt_prefix && opt_prefix->prefix_len > tmp->prefix_len)
			/* prefer the largest advertised prefix */
			continue;

		opt_prefix = tmp;
	}

	if (len > 0) {
		pr_err("extra data in IA_PD");
		return -1;
	}

	if (!opt_prefix) {
		pr_debug("no prefix advertised");
		return 0;
	}

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp_iaid		*tmp = &ses->iaid[i];
		struct dhcp_iaid_dump_buf	pr_iapd;

		pr_debug("%s: checking whether matching with IAPREFIX",
			 dhcp_iaid_dump(tmp, &pr_iapd));

		if (tmp->state != IAID_STATE_SOLICATE) {
			pr_debug("  not in SOLICATE state");
			continue;
		}

		if (memcmp(tmp->xmit_id, msg->xmit_id, sizeof tmp->xmit_id) != 0) {
			pr_debug("  xmit-id mismatch");
			continue;
		}

		if (be32_to_cpu(opt_iapd->id) != tmp->id) {
			pr_debug("  id mismatch");
			continue;
		}

		if (iapd->server_pref > server->pref) {
			pr_debug("IAPD: ignoring message from less prioritzed server");
			continue;
		}

		if (iapd) {
			pr_err("IAPD option matching multiple IAPD");
			return -1;
		}

		iapd = tmp;
	}

	if (!iapd) {
		pr_err("no matching IAPD");
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
	iapd->server_pref = server->pref;
	iapd->server_addr = server->addr;

	dhcp_iaid_new_state(ses, iapd, IAID_STATE_SOLICATE_DONE);

	return 0;
}

static int dhcp_handle_advertise(struct dhcp_session *ses,
				 struct dhcp_server_info *server,
				 struct dhcpv6_message_hdr const *msg,
				 size_t len)
{
	int		rc;
	size_t				tmp_len = len;
	struct dhcpv6_option_hdr const	*opt_clnt_id = NULL;

	dhcpv6_foreach_option(opt, msg, &tmp_len) {
		uint8_t			preference;

		pr_debug("OPTION: %s",
			 dhcpv6_option_to_str(be16_to_cpu(opt->option)));

		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_CLIENTID:
			if (opt_clnt_id) {
				pr_err("duplicate CLIENTID");
				rc = -1;
			}

			opt_clnt_id = opt;
			break;

		case DHCPV6_OPTION_SERVERID:
			if (server->opt) {
				pr_err("duplicate SERVERID");
				rc = -1;
			} else if (be16_to_cpu(opt->len) > MAX_SERVERID_SZ) {
				pr_err("SERVERID too large");
				rc = -1;
			} else {
				server->opt = opt;
			}
			break;

		case DHCPV6_OPTION_PREFERENCE:
			if (be16_to_cpu(opt->len) != 1)
				pr_err("bad PREFERENCE");

			memcpy(&preference, dhcpv6_get_option_data(opt),
			       sizeof preference);

			server->pref = preference;

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

	if (tmp_len != 0) {
		pr_err("extra data after last DHCP option");
		return -1;
	}

	if (!opt_clnt_id) {
		pr_err("missing CLIENTID in ADVERTISE");
		return -1;
	}

	if (!server->opt) {
		pr_err("missing SERVERID in ADVERTISE");
		return -1;
	}

	if (be16_to_cpu(opt_clnt_id->len) != ses->duid_len ||
	    !dhcpv6_get_option_data(opt_clnt_id) ||
	    memcmp(dhcpv6_get_option_data(opt_clnt_id),
		   ses->duid, ses->duid_len) != 0) {
		pr_err("CLIENTID mismatch");
		return -1;
	}

	tmp_len = len;
	dhcpv6_foreach_option(opt, msg, &tmp_len) {
		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_IA_PD:
			rc = dhcp_handle_ia_pd(ses, server, msg, opt);
			break;

		default:
			rc = 0;
			break;
		}

		if (rc < 0)
			break;
	}

	dhcp_iaid_finish(ses, msg, server->pref == 255);

	rc = 0;

out:
	if (rc < 0)
		pr_err("failed to handle ADVERTISE");

	return rc;
}

static int dhcp_handle_reply(struct dhcp_session *ses,
			     struct dhcpv6_message_hdr const *hdr,
			     size_t len)
{
	/* TODO */
	return 0;
}

static int dhcp_read_response(struct dhcp_session *ses)
{
	union {
		struct dhcpv6_message_hdr	hdr;
		unsigned char			buf[16*1024];
	}			resp;
	struct in6_addr		local_addr;
	bool			have_local_addr = false;
	union {
		struct cmsghdr	align;
		unsigned char	raw[1024];
	}			cmbuf;
	struct dhcp_server_info	server = {
		.opt		= NULL,
		.pref		= 0,
	};
	struct iovec		msg_vec = {
		.iov_base	= &resp,
		.iov_len	= sizeof resp,
	};
	struct msghdr		msg = {
		.msg_name	= &server.addr,
		.msg_namelen	= sizeof server.addr,
		.msg_iov	= &msg_vec,
		.msg_iovlen	= 1,
		.msg_control	= cmbuf.raw,
		.msg_controllen	= sizeof cmbuf,
	};

	ssize_t			l;
	int			rc;

	l = recvmsg(ses->fd, &msg, 0);
	if (l < 0) {
		pr_err("recvmsg(): %s", strerror(errno));
	}

	ses->now = time_now_ms();

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

	pr_debug("DHCPV6: received %s", dhcpv6_type_to_str(resp.hdr.type));

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
		rc = dhcp_handle_advertise(ses, &server, &resp.hdr, l);
		if (rc < 0) {
			pr_warn("bad ADVERTISE");
			rc = 0;
		}
		break;

	case DHCPV6_TYPE_REPLY:
		rc = dhcp_handle_reply(ses, &resp.hdr, 1);
		if (rc < 0) {
			pr_warn("bad REPLY");
			rc = 0;
		}
		break;
	}

	return rc;
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
	int			rc;


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

	session.state_tm = 0;

	for (;;) {
		enum dhcp_wait_result	wait_res = DHCP_WAIT_NONE;

		dhcp_validate_objects(&session);

		wait_res = dhcp_wait(&session, sig_fd);

		switch (wait_res) {
		case DHCP_WAIT_RESPONSE:
			rc = dhcp_read_response(&session);
			break;

		case DHCP_WAIT_NONE:
			break;

		case DHCP_WAIT_SIGNAL:
			break;

		case DHCP_WAIT_SEND_SOLICATE:
			rc = dhcp_solicate_send(&session);
			break;

		case DHCP_WAIT_SEND_REQUEST:
			rc = dhcp_request_send(&session);
			break;

		case DHCP_WAIT_TIMEOUT:
			pr_err("timeout");
			sleep(1);
			break;
		}

		if (rc < 0)
			break;
	}

	rc = 0;

out:
	return rc;
}
