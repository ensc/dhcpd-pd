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

#include "../src/logging.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>
#include "../src/dhcpv6-util.h"

static int x_sprintf(char *buf, char const *fmt, ...)
	__attribute__((__format__(printf, 2, 3)));


static int x_sprintf(char *buf, char const *fmt, ...)
{
	va_list 	ap;
	char const	*tmp = log_transform_fmt(fmt);
	int		len;

	va_start(ap, fmt);
	len = vsprintf(buf, tmp, ap);
	va_end(ap);

	free((void *)tmp);

	return len;
}

#define TEST(_fmt, _exp) do {				\
		char const	*out;			\
		out = log_transform_fmt((_fmt));	\
		assert(strcmp(out, (_exp)) == 0);	\
		free((void *)out);			\
	} while (0)

static void test_00(void)
{
	TEST("", "");
	TEST("a", "a");
	TEST("%%", "%%");
	TEST("%", "%");
	TEST("a%", "a%");
	TEST("%s", "%s");
	TEST("%pX", "%pX");
	TEST("%pI", "%pI");

	TEST("%pT", "%T");
	TEST("%pN", "%N");
}

#undef TEST

static void test_01(void)
{
	struct dhcpv6_network	net;
	dhcp_time_t		tm_a = TIME_INFINITY;
	dhcp_time_t		tm_b = TIME_EPOCH;
	dhcp_time_t		tm_c = { 23042 };
	dhcp_time_t		tm_d = { (uint64_t)(4) * 365 * 24 * 3600 * 1000 +
					 8 * 24 * 3600 * 1000 +
					 15 * 3600 * 1000 +
					 16 * 60 * 1000 +
					 23 * 1000 +
					 42 };
	char			buf[100];
	int			rc;

	rc = inet_pton(AF_INET6, "1234:5678:9abc:def0:3210:7654:ba98:fedc",
		       &net.prefix);
	assert(rc == 1);

	x_sprintf(buf, "%pP", &net.prefix);
	assert(strcmp(buf, "1234:5678:9abc:def0:3210:7654:ba98:fedc") == 0);

	net.len = 4;

	x_sprintf(buf, "%pN", &net);
	assert(strcmp(buf, "1234:5678:9abc:def0:3210:7654:ba98:fedc/4") == 0);

	x_sprintf(buf, "%pT", &tm_a);
	assert(strcmp(buf, "INF") == 0);

	x_sprintf(buf, "%pT", &tm_b);
	assert(strcmp(buf, "EPOCH") == 0);

	x_sprintf(buf, "%pT", &tm_c);
	assert(strcmp(buf, "23.042") == 0);

	x_sprintf(buf, "%pG", &tm_c);
	assert(strcmp(buf, "23.042") == 0);

	x_sprintf(buf, "%pT", &tm_d);
	assert(strcmp(buf, "4Y8D 15:16:23.042") == 0);
}

static void test_02(void)
{
	char			buf[100];

	x_sprintf(buf, "%pP", NULL);
	assert(strcmp(buf, "<null>") == 0);

	x_sprintf(buf, "%pN", NULL);
	assert(strcmp(buf, "<null>") == 0);

	x_sprintf(buf, "%pR", NULL);
	assert(strcmp(buf, "<null>") == 0);

	x_sprintf(buf, "%pT", NULL);
	assert(strcmp(buf, "<null>") == 0);

	x_sprintf(buf, "%pG", NULL);
	assert(strcmp(buf, "<null>") == 0);

	x_sprintf(buf, "%pA", NULL);
	assert(strcmp(buf, "<null>") == 0);
}

#undef main
int main(void)
{
	logging_register_conversions();

	test_00();
	test_01();
	test_02();
}
