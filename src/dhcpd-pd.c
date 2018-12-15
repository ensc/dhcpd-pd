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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>

#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <netinet/in.h>
#include <net/if.h>

#include <arpa/inet.h>

#include <openssl/sha.h>

#define DUID_ENUM	22683
#define DUID_SALT0	"kABoBaUjLjs9SebQUpUyadljIA1gvxV9"
#define DUID_SALT1	"6SwjUAHolGTaFie7j6A2glABx93pnIkj"
#define SERIAL_FILE_CPU	"/sys/firmware/devicetree/base/serial-number"
#define SERIAL_FILE_MACHINE_ID	"/etc/machine-id"

#define ARRAY_SIZE(_a)	((sizeof (_a)) / (sizeof (_a)[0]))

struct be16 {
	uint16_t	v;
};
typedef struct be16	be16_t;

struct be32 {
	uint32_t	v;
};
typedef struct be32	be32_t;

#pragma pack(push)
struct dhcpv6_hdr {
	uint8_t		msg_type;
	uint8_t		xmit_id[3];
};

struct dhcpv6_option_hdr {
	be16_t		option;
	be16_t		len;
};

struct dhcpv6_option_iapd {
	be32_t		id;
	be32_t		t1;
	be32_t		t2;
};

struct dhcpv6_option_iaprefix {
	be32_t		pref_lftm;
	be32_t		valid_lftm;
	uint8_t		prefix_len;
	uint8_t		prefix[16];
};
#pragma pack(pop)

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
	IAID_STATE_ACTIVE,
	IAID_STATE_RENEWAL,
};

struct dhcp_iaid {
	uint32_t	id;
	unsigned long	t1;
	unsigned long	t2;

	struct in6_addr	addr;
	unsigned char	prefix_len;

	time_t		end_t;
	time_t		renew_t;
	time_t		exp_t;

	enum dhcp_iaid_state	state;
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

	struct dhcp6_request	req;
	unsigned char		req_buf[8192];

	struct dhcp_iaid	iaid[1];
	size_t			num_iaid;

	enum dhcp_client_state	state;
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
		.option.v	= htobe16(code),
		.len.v		= htobe16(len + extra_len),
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
	struct dhcpv6_hdr	*hdr;

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

	hdr->msg_type = type;
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

	return buffer_add_option(&req->buf, 1, ses->duid, ses->duid_len);
}

static int dhcp_session_reopen(struct dhcp_session *ses)
{
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
		.id	= 0,
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

static int dhcp_do_solicate(struct dhcp_session *ses)
{
	size_t		num_iapd = 0;

	if (!request_init(ses, &ses->req, 1) ||
	    !request_add_option_uuid(ses, &ses->req)) {
		fprintf(stderr, "failed to create SOLICATE request\n");
		return -1;
	}

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		struct dhcp6_buffer	req_pd;
		struct dhcp6_buffer	req_opt;
		struct dhcpv6_option_iaprefix	opt_iaprefix = {
			.pref_lftm.v	= htobe32(0xffffffffu),
			.valid_lftm.v	= htobe32(0xffffffffu),
			.prefix_len	= ses->iaid[i].prefix_len,
		};
		struct dhcpv6_option_iapd	opt_iapd = {
			.id.v		= htobe32(ses->iaid[i].id),
			.t1.v		= htobe32(ses->iaid[i].t1),
			.t2.v		= htobe32(ses->iaid[i].t2),
		};

		if (ses->iaid[i].state != IAID_STATE_INIT)
			continue;

		_Static_assert(sizeof ses->iaid[i].addr == sizeof opt_iaprefix.prefix,
			       "bad 'opt_iaprefix' layout\n");

		memcpy(opt_iaprefix.prefix, &ses->iaid[i].addr,
		       sizeof ses->iaid[i].addr);

		if (!buffer_init_subbuffer(&ses->req.buf, &req_pd, 0) ||
		    !buffer_init_subbuffer(&req_pd,  &req_opt, 4 + sizeof opt_iapd) ||
		    !buffer_add_option(&req_opt, 26, &opt_iaprefix, sizeof opt_iaprefix) ||
		    !buffer_add_raw(&req_pd, 25, &opt_iapd, sizeof opt_iapd, req_opt.len) ||
		    !request_allocate(&ses->req, req_pd.len)) {
			fprintf(stderr, "failed to create PD for IAID#%zu\n", i);
			return -1;
		}

		++num_iapd;
	}

	request_finalize(ses, &ses->req);

	if (num_iapd == 0)
		return 0;

	if (send_request(ses) < 0)
		return -1;

	for (size_t i = 0; i < ses->num_iaid; ++i) {
		if (ses->iaid[i].state == IAID_STATE_INIT) {
			ses->iaid[i].state = IAID_STATE_SOLICATE;
			/* TODO: check RFC for recommended timeout */
			ses->iaid[i].exp_t = time(NULL) + 5;
		}
	}

	return 1;
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
		switch (session.state) {
		case DHCP_CLNT_STATE_INIT:
			session.state = DHCP_CLNT_STATE_SOLICATE_REQ;
			rc = 0;
			break;

		case DHCP_CLNT_STATE_SOLICATE_REQ:
			rc = dhcp_do_solicate(&session);
			if (rc < 0) {
				session.state = DHCP_CLNT_STATE_ERROR;
			} else if (rc > 0) {
				session.state = DHCP_CLNT_STATE_SOLICATE_RESP;
			} else {
				session.state = DHCP_CLNT_STATE_WAIT;
			}

			break;

		case DHCP_CLNT_STATE_SOLICATE_RESP:
			/* TODO */
			break;


		case DHCP_CLNT_STATE_WAIT:
			break;

		case DHCP_CLNT_STATE_ERROR:
			break;
		}

		if (session.state == DHCP_CLNT_STATE_ERROR)
			break;
	}

out:
	return rc;
}
