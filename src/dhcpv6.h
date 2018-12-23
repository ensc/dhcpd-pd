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

#ifndef H_ENSC_DHCP_PD_DHCPV6_H
#define H_ENSC_DHCP_PD_DHCPV6_H

#include <stdlib.h>
#include <stdint.h>
#include "util.h"

enum {
	DHCPV6_TYPE_SOLICIT			= 1,
	DHCPV6_TYPE_ADVERTISE			= 2,
	DHCPV6_TYPE_REQUEST			= 3,
	DHCPV6_TYPE_CONFIRM			= 4,
	DHCPV6_TYPE_RENEW			= 5,
	DHCPV6_TYPE_REBIND			= 6,
	DHCPV6_TYPE_REPLY			= 7,
	DHCPV6_TYPE_RELEASE			= 8,
	DHCPV6_TYPE_DECLINE			= 9,
	DHCPV6_TYPE_INFORMATION_REQUEST		= 11,
};

enum {
	DHCPV6_OPTION_CLIENTID			= 1,
	DHCPV6_OPTION_ELAPSED_TIME		= 8,
	DHCPV6_OPTION_IA_PD			= 25,
	DHCPV6_OPTION_IAPREFIX			= 26,

};

#pragma pack(push)
struct dhcpv6_message_hdr {
	uint8_t		type;
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

inline static void const *
dhcpv6_get_option_data(struct dhcpv6_option_hdr const *opt)
{
	return &opt[1];
}

inline static struct dhcpv6_option_hdr const *
dhcpv6_validated_option(struct dhcpv6_option_hdr const *opt, size_t len)
{
	if (len < sizeof *opt)
		return NULL;

	len -= sizeof *opt;
	if (be16_to_cpu(opt->len) > len)
		return NULL;

	return opt;
}

inline static struct dhcpv6_option_hdr const *
dhcpv6_first_option(struct dhcpv6_message_hdr const *msg, size_t *len)
{
	if (sizeof *msg >= *len)
		return NULL;

	*len -= sizeof *msg;
	return dhcpv6_validated_option((void *)&msg[1], *len);
}

inline static struct dhcpv6_option_hdr const *
dhcpv6_next_option(struct dhcpv6_option_hdr const *opt, size_t *len)
{
	size_t	opt_len = sizeof *opt + be16_to_cpu(opt->len);
	struct dhcpv6_option_hdr const *res;

	if (opt_len > *len)
		return NULL;

	*len -= opt_len;
	res   = (void *)((uintptr_t)opt + opt_len);
	return dhcpv6_validated_option(res, *len);
}

#define dhcpv6_foreach_option_next(_opt, _next, _len) \
	for (struct dhcpv6_option_hdr const *_opt = (_next);	\
	     _opt; _opt = dhcpv6_next_option(_opt, _len))

#define dhcpv6_foreach_option(_opt, _msg, _len) \
	dhcpv6_foreach_option_next(_opt, dhcpv6_first_option(_msg, _len), _len)


#endif	/* H_ENSC_DHCP_PD_DHCPV6_H */
