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

#undef NDEBUG

#include <assert.h>
#include <arpa/inet.h>

#include "../src/dhcpv6-util.h"

#define TEST_ASSIGN_EXP(_net, _len, _exp, _rc) do {			\
		struct dhcpv6_network	net = {				\
			.len	= 250,					\
			._rsrvd	= { 0x23, 0x42, 0x66 },			\
			.prefix	= { 1, 2, 3, 4, 5, 6, 7, 8,		\
				    9, 10, 11, 12, 13, 14, 15, 16 }	\
		};							\
		struct in6_addr		inp;				\
		struct in6_addr		exp;				\
		int			rc;				\
									\
		rc = inet_pton(AF_INET6, (_net), &inp);			\
		assert(rc == 1);					\
									\
		rc = inet_pton(AF_INET6, (_exp), &exp);			\
		assert(rc == 1);					\
									\
		rc = dhcpv6_network_assign(&net, &inp, (_len));		\
		assert(rc == (_rc));					\
		if ((_rc) < 0)						\
			break;						\
									\
		assert(net.len == (_len));				\
		assert(memcmp(net._rsrvd, "\x23\x42\x66", 3) == 0);	\
		assert(memcmp(net.prefix, &exp, 16) == 0);		\
									\
		assert(dhcpv6_network_cmp(&net, &net) == 0);		\
	} while (0)

#define TEST_ASSIGN(_net, _len, _exp, _rc) do {				\
		TEST_ASSIGN_EXP(_net, _len, _exp, _rc);			\
		if ((_rc) < 0)						\
			break;						\
		TEST_ASSIGN_EXP(_exp, _len, _exp, 0);			\
	} while (0)

static void test_00(void)
{
	TEST_ASSIGN("aaaa:bbbb:cccc:dddd:eeee:ffff:9999:8888",  0, "::", 1);
	TEST_ASSIGN("1aaa:bbbb:cccc:dddd:eeee:ffff:9999:8888",  4, "1000::", 1);
	TEST_ASSIGN("1800::"                                 ,  4, "1000::", 1);
	TEST_ASSIGN("1f00::"                                 ,  7, "1e00::", 1);
	TEST_ASSIGN("12aa:bbbb:cccc:dddd:eeee:ffff:9999:8888",  8, "1200::", 1);
	TEST_ASSIGN("12fa:bbbb:cccc:dddd:eeee:ffff:9999:8888",  9, "1280::", 1);
	TEST_ASSIGN("123a:bbbb:cccc:dddd:eeee:ffff:9999:8888", 12, "1230::", 1);
	TEST_ASSIGN("123a:bbbb:cccc:dddd:eeee:ffff:9999:888f", 128,
		    "123a:bbbb:cccc:dddd:eeee:ffff:9999:888f", 0);
	TEST_ASSIGN("123a:bbbb:cccc:dddd:eeee:ffff:9999:888f", 127,
		    "123a:bbbb:cccc:dddd:eeee:ffff:9999:888e", 1);
	TEST_ASSIGN("123a:bbbb:cccc:dddd:eeee:ffff:9999:888f", 129, "::", -1);
}

static void test_01(void)
{
	struct dhcpv6_network	net;

	dhcpv6_network_zero(&net);

	assert(net.len == 0);
	assert(memcmp(net.prefix, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0);
}

static void test_02(void)
{
	struct dhcpv6_network	net_a;
	struct dhcpv6_network	net_b;
	struct dhcpv6_network	net_c;
	int			rc;

	struct in6_addr		ip_a;
	struct in6_addr		ip_b;
	struct in6_addr		ip_c;

	rc = inet_pton(AF_INET6, "aaaa:0001::", &ip_a);
	assert(rc == 1);

	rc = inet_pton(AF_INET6, "aaaa:0002::", &ip_b);
	assert(rc == 1);

	rc = inet_pton(AF_INET6, "aaaa:0003::", &ip_c);
	assert(rc == 1);

	rc = dhcpv6_network_assign(&net_a, &ip_a, 32);
	assert(rc == 0);

	rc = dhcpv6_network_assign(&net_b, &ip_b, 31);
	assert(rc == 0);

	rc = dhcpv6_network_assign(&net_c, &ip_c, 32);
	assert(rc == 0);

	assert(dhcpv6_network_cmp(&net_a, &net_a) == 0);
	assert(dhcpv6_network_cmp(&net_b, &net_b) == 0);
	assert(dhcpv6_network_cmp(&net_c, &net_c) == 0);

	assert(dhcpv6_network_cmp(&net_a, &net_b) > 0);
	assert(dhcpv6_network_cmp(&net_b, &net_a) < 0);
	assert(dhcpv6_network_cmp(&net_a, &net_c) != 0);
	assert(dhcpv6_network_cmp(&net_b, &net_c) < 0);
}

int main(void)
{
	test_00();
	test_01();
	test_02();
}
