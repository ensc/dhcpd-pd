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

#ifndef H_ENSC_DHCP_PD_DHCPV6_UTIL_H
#define H_ENSC_DHCP_PD_DHCPV6_UTIL_H

#include <assert.h>
#include <string.h>
#include <netinet/in.h>

#include "duid.h"
#include "time.h"

#include "dhcpv6.h"

#ifdef TESTSUITE
#  define TEST_ONLY(_statement)		_statement
#else
#  define TEST_ONLY(_statement)
#endif

#define DHCPV6_IAPREFIX_PER_IAPD	(1)
#define DHCPV6_MAX_MESSAGE_SZ		((size_t)(16 * 1024))

/*****************/

enum dhcpv6_reliability_result {
	DHCPV6_RELIABILITY_FIRST,
	DHCPV6_RELIABILITY_NEXT,
	DHCPV6_RELIABILITY_TIMEOUT,
};

struct dhcpv6_reliability_parm {
	unsigned int		irt;
	unsigned int		mrc;
	unsigned int		mrt;
	unsigned int		mrd;
};

/** https://tools.ietf.org/html/rfc3315#section-14 */
struct dhcpv6_reliability {
	dhcp_time_t		start_t;
	dhcp_time_t		rt_t;
	unsigned int		rt;
	unsigned int		num_tries;

	struct dhcpv6_reliability_parm const	*parm;
};

inline static dhcp_time_t
dhcpv6_reliability_get_rt(struct dhcpv6_reliability const *rel)
{
	return time_add_ms(rel->rt_t, rel->rt);
}

void dhcpv6_reliability_init(struct dhcpv6_reliability *rel,
			     struct dhcpv6_reliability_parm const *parm,
			     dhcp_time_t now);
bool dhcpv6_reliability_check(struct dhcpv6_reliability const *rel,
			      dhcp_time_t now);
void dhcpv6_reliability_next(struct dhcpv6_reliability *rel, dhcp_time_t now);

/*****************/

struct dhcpv6_transmission {
	dhcp_time_t		time;
	unsigned char		xmit_id[3];
};

void dhcpv6_transmission_init(struct dhcpv6_transmission *xmit, dhcp_time_t now);

/****************/

struct dhcpv6_server {
	/* https://tools.ietf.org/html/rfc3315#section-22.3 */
	struct dhcpv6_duid		id;
	struct in6_addr			addr;
	bool				has_id;

	bool				is_unicast;

	/* preference; https://tools.ietf.org/html/rfc3315#section-22.8 */
	unsigned int			preference;
};

struct dhcpv6_server_info {
	struct dhcpv6_option_hdr const *opt;
	struct sockaddr_in6		addr;
	unsigned int			pref;
	bool				is_unicast;
};

/***************/

struct dhcpv6_network {
	struct in6_addr			prefix;
	TEST_ONLY(uint8_t		_rsrvd[3]);
	uint8_t				len;
};

/**
 *  Return:
 *  -1 on error; 1 when bits outside of @len are; 0 on success
 */
int dhcpv6_network_assign(struct dhcpv6_network *a,
			  void const *prefix, unsigned int len);
void dhcpv6_network_zero(struct dhcpv6_network *a);

int dhcpv6_network_cmp(struct dhcpv6_network const *a,
		       struct dhcpv6_network const *b);

/**
 *   Our preferences for the IA prefix
 */

struct dhcp_iaprefix_pref {
	uint32_t			pref_lt;
	uint32_t			valid_lt;
	struct dhcpv6_network		net;
	bool				is_set;
};

struct dhcp_iapd;
struct dhcp_iaprefix {
	/* https://tools.ietf.org/html/rfc3633#section-10 */
	uint32_t			pref_lt;
	uint32_t			valid_lt;
	struct dhcpv6_network		net;
	struct dhcp_iaprefix_pref	preferences;

	dhcp_time_t			lease_tm;

	struct dhcp_iapd		*iapd;
};

/****************/

struct dhcp_context {
	int				fd;
	int				sig_fd;
	int				ifidx;

	dhcp_time_t			now;
	dhcp_time_t			timeout;

	char const			*script;
	struct dhcpv6_duid const	*client_id;

	bool				sig_available;
	bool				data_available;
	bool				nl_available;
	bool				err_no_net;
	bool				no_io;

	struct dhcpv6_server_info	server;
	enum dhcpv6_status_code		status_code;
};

/****************/

/**
 *   Our preferences for the IAPD
 */
struct dhcp_iapd_pref {
	uint32_t			t1;
	uint32_t			t2;
	bool				is_set;
};

enum dhcp_iapd_state {
	IAPD_STATE_NONE,
	IAPD_STATE_UNUSED,
	IAPD_STATE_INIT,
	IAPD_STATE_SOLICIT_INIT,
	IAPD_STATE_SOLICIT,
	IAPD_STATE_REQUEST_INIT,
	IAPD_STATE_REQUEST,
	IAPD_STATE_ACTIVE_INIT,
	IAPD_STATE_ACTIVE,
	IAPD_STATE_RENEW_INIT,
	IAPD_STATE_RENEW,
	IAPD_STATE_REBIND_INIT,
	IAPD_STATE_REBIND,
	IAPD_STATE_RELEASE_INIT,
	IAPD_STATE_RELEASE,
};

enum dhcp_iapd_iostate {
	IAPD_IOSTATE_NONE,
	IAPD_IOSTATE_WAIT,
	IAPD_IOSTATE_SEND,
	IAPD_IOSTATE_RECV,
	IAPD_IOSTATE_DONE,
	IAPD_IOSTATE_ERROR,
	IAPD_IOSTATE_TIMEOUT,
};

struct dhcp_iapd {
	/* https://tools.ietf.org/html/rfc3633#section-9 */
	uint32_t			id;

	struct {
		dhcp_time_t		lease_tm;
		uint32_t		t1;
		uint32_t		t2;
	}				active, pending;

	struct dhcpv6_server		server;

	enum dhcp_iapd_state		state;
	enum dhcp_iapd_iostate		iostate;

	struct dhcpv6_reliability	reliability;

	struct dhcpv6_transmission	xmit;
	struct dhcp_iapd_pref		preferences;

	bool				do_release:1;
	bool				do_quit:1;
	bool				do_renew:1;
	bool				do_request:1;

	struct {
		struct dhcp_iaprefix	active;
		struct dhcp_iaprefix	pending;
	}				iaprefix[DHCPV6_IAPREFIX_PER_IAPD];
};

struct dhcpv6_message_hdr;

void		dhcp_iapd_init(struct dhcp_iapd *iapd, uint32_t id);
dhcp_time_t	dhcp_iapd_step(struct dhcp_iapd *iapd, struct dhcp_context *ctx);
int		dhcp_iapd_run(struct dhcp_iapd *iapd, struct dhcp_context *ctx);
int		dhcp_iapd_recv(struct dhcp_iapd *iapd, struct dhcp_context *ctx,
			       struct dhcpv6_message_hdr const *hdr, size_t len);
int		dhcp_iapd_run_script(struct dhcp_iapd const *iapd,
				     struct dhcp_context *ctx,
				     char const *state_id);

unsigned int	dhcpv6_read_status_code(void const *code_pkt, size_t len);

inline static bool dhcp_iaprefix_is_used(struct dhcp_iaprefix const *iaprefix)
{
	/* TODO: improve this check? */
	return iaprefix->net.len != 0;
}


#endif	/* H_ENSC_DHCP_PD_DHCPV6_UTIL_H */
