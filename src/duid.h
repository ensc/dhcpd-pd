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

#ifndef H_ENSC_DHCP_DUID_H
#define H_ENSC_DHCP_DUID_H

#include <stdlib.h>

#define DHCPV6_MAX_DUID_SZ		128

/**
 *  DUID; https://tools.ietf.org/html/rfc3315#section-9
 */
struct dhcpv6_duid {
	unsigned char		id[DHCPV6_MAX_DUID_SZ];
	size_t			len;
};

inline static void dhcpv6_duid_validate(struct dhcpv6_duid const *a)
{
	assert(a->len <= sizeof a->id);
}

inline static int dhcpv6_duid_cmp(struct dhcpv6_duid const *a,
				  struct dhcpv6_duid const *b)
{
	dhcpv6_duid_validate(a);
	dhcpv6_duid_validate(b);

	if (a->len < b->len)
		return -1;
	else if (a->len > b->len)
		return +1;
	else
		return memcmp(a->id, b->id, a->len);
}

struct dhcpv6_option_hdr;
int dhcpv6_duid_cmp_opt(struct dhcpv6_duid const *a,
			struct dhcpv6_option_hdr const *b);

void dhcpv6_duid_from_opt(struct dhcpv6_duid *a,
			  struct dhcpv6_option_hdr const *b);

int dhcpv6_duid_generate(struct dhcpv6_duid *duid);

#endif	/* H_ENSC_DHCP_DUID_H */
