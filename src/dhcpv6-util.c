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

#include "dhcpv6-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>

#include "logging.h"

#define LOG_DOMAIN	LOG_DOMAIN_RELIABILITY

static unsigned long rt_rand(unsigned long prev,
			     unsigned int lo, unsigned int hi)
{
	long	v = random() % (hi - lo) + lo;

	return prev * v / 100;
}

void dhcpv6_reliability_init(struct dhcpv6_reliability *rel,
			     struct dhcpv6_reliability_parm const *parm,
			     dhcp_time_t now)
{
	rel->start_t = now;
	rel->rt_t    = now;
	rel->parm    = parm;
	rel->num_tries = 0;
}

bool
dhcpv6_reliability_check(struct dhcpv6_reliability const *rel,
			 dhcp_time_t now)
{
	struct dhcpv6_reliability_parm const *parm = rel->parm;

	if (parm->mrc != 0 && rel->num_tries > parm->mrc) {
		pr_warn("RELIABILITY: MRC %d exceeded", rel->num_tries);
		return false;
	}

	if (parm->mrd != 0) {
		dhcp_time_t	tm_exp = time_add_ms(rel->start_t, parm->mrd);

		if (time_cmp(tm_exp, now) < 0) {
			pr_warn("RELIABILITY: MRD exceeded");
			return false;
		}
	}

	return true;
}

void
dhcpv6_reliability_next(struct dhcpv6_reliability *rel, dhcp_time_t now)
{
	struct dhcpv6_reliability_parm const *parm = rel->parm;

	++rel->num_tries;
	rel->rt_t = now;

	if (rel->num_tries == 1) {
		rel->rt = rt_rand(parm->irt, 100, 110);
	} else {
		rel->rt = rt_rand(rel->rt, 190, 210);
		if (parm->mrt != 0 && rel->rt > parm->mrt)
			rel->rt = rt_rand(parm->mrt, 90, 110);
	}
}

#undef LOG_DOMAIN

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

void dhcpv6_transmission_init(struct dhcpv6_transmission *xmit, dhcp_time_t now)
{
	xmit->time = now;
	x_getrandom(&xmit->xmit_id, sizeof xmit->xmit_id);
}

int dhcpv6_network_assign(struct dhcpv6_network *a,
			  void const *addr, unsigned int len)
{
	unsigned int	num_octets = len / 8;
	unsigned int	num_bits = len % 8;
	uint8_t const	*in = addr;
	uint8_t		*out = a->prefix;
	int		rc = 0;

	if (len > 128)
		return -1;

	a->len = len;
	memcpy(out, in, num_octets);
	out += num_octets;
	in  += num_octets;

	if (num_bits > 0) {
		uint8_t		tmp = *in;

		tmp >>= (8 - num_bits);
		tmp <<= (8 - num_bits);

		if (tmp != *in)
			rc = 1;

		*out++ = tmp;
		++in;
		++num_octets;
	}

	assert(num_octets <= 16);

	memset(out, 0, 16 - num_octets);

	while (num_octets < 16 && rc == 0) {
		if (*in != 0)
			rc = 1;

		++in;
		++num_octets;
	}

	return rc;
}

int dhcpv6_network_cmp(struct dhcpv6_network const *a,
		       struct dhcpv6_network const *b)
{
	assert(a->len <= 8 * sizeof a->prefix);
	assert(b->len <= 8 * sizeof b->prefix);

	if (a->len < b->len)
		return -1;
	else if (a->len > b->len)
		return +1;
	else
		return memcmp(a->prefix, b->prefix, sizeof a->prefix);
}

void dhcpv6_network_zero(struct dhcpv6_network *a)
{
	a->len = 0;
	memset(a->prefix, 0, sizeof a->prefix);
}

#define LOG_DOMAIN	LOG_DOMAIN_PKT

unsigned int dhcpv6_read_status_code(void const *code_pkt, size_t len)
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
