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
#include <unistd.h>
#include "../src/time.h"

void test_00(void)
{
	dhcp_time_t		tm_a = TIME_EPOCH;
	dhcp_time_t		tm_b = TIME_INFINITY;
	dhcp_time_t		tm_c;

	assert(time_is_epoch(tm_a));
	assert(!time_is_epoch(tm_b));

	assert(!time_is_infinity(tm_a));
	assert(time_is_infinity(tm_b));

	assert(time_cmp(tm_a, tm_b) < 0);
	assert(time_cmp(tm_b, tm_a) > 0);
	assert(time_cmp(tm_a, tm_a) == 0);
	assert(time_cmp(tm_b, tm_b) == 0);

	tm_c = time_min(tm_a, tm_b);
	assert(time_cmp(tm_c, tm_a) == 0);

	tm_c = time_min(tm_b, tm_a);
	assert(time_cmp(tm_c, tm_a) == 0);

	tm_c = time_add_s(tm_a, 666);
	assert(time_cmp(tm_c, tm_a) == 0);

	tm_c = time_add_s(tm_b, 666);
	assert(time_cmp(tm_c, tm_b) == 0);

	tm_c = time_sub(tm_b, tm_a);
	assert(time_is_infinity(tm_c));

	tm_c = time_add_lt(tm_a, 1);
	assert(time_is_epoch(tm_c));

	tm_c = time_add_lt(tm_b, 1);
	assert(time_is_infinity(tm_c));
}

void test_01(void)
{
	dhcp_time_t		tm_a = { 23 };
	dhcp_time_t		tm_b = { 42 };
	dhcp_time_t		tm_c;

	assert(!time_is_epoch(tm_a));
	assert(!time_is_epoch(tm_b));

	assert(!time_is_infinity(tm_a));
	assert(!time_is_infinity(tm_b));

	assert(time_cmp(tm_a, tm_b) < 0);
	assert(time_cmp(tm_b, tm_a) > 0);
	assert(time_cmp(tm_a, tm_a) == 0);
	assert(time_cmp(tm_b, tm_b) == 0);

	tm_c = time_min(tm_a, tm_b);
	assert(time_cmp(tm_c, tm_a) == 0);

	tm_c = time_min(tm_b, tm_a);
	assert(time_cmp(tm_c, tm_a) == 0);

	tm_c = time_add_s(tm_a, 666);
	assert(time_cmp(tm_c, tm_a) > 0);
	assert(time_cmp(tm_a, tm_c) < 0);

	tm_c = time_sub(tm_b, tm_a);
	assert(time_to_ms(tm_c) == 19);

	tm_c = time_add_lt(tm_a, 1);
	assert(time_to_ms(tm_c) == 1023);

	tm_c = time_add_lt(tm_a, 0xffffffff);
	assert(time_is_infinity(tm_c));
}

void test_02(void)
{
	dhcp_time_t		tm_a = time_now();
	dhcp_time_t		tm_b;

	usleep(10000);
	tm_b = time_now();

	assert(time_cmp(tm_a, tm_b) < 0);
}

int main(void)
{
	test_00();
	test_01();
	test_02();
}
