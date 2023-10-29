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
#include <stdlib.h>
#include "../src/time.h"

/* XXX: keep it synchronized with time.c */
#define EXTRA_DAILY_TM	(30 * 60)

static void test_00(void)
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

	tm_c = time_add_lt(tm_a, 1, 100);
	assert(time_is_epoch(tm_c));

	tm_c = time_add_lt(tm_b, 1, 100);
	assert(time_is_infinity(tm_c));
}

static void test_01(void)
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

	tm_c = time_add_lt(tm_a, 1, 100);
	assert(time_to_ms(tm_c) == 1023);

	tm_c = time_add_lt(tm_a, 0xffffffff, 100);
	assert(time_is_infinity(tm_c));

	tm_c = time_add_lt(tm_a, 0xffffffff, 40);
	assert(time_is_infinity(tm_c));
}

static void test_02(void)
{
	dhcp_time_t		tm_a = time_now();
	dhcp_time_t		tm_b;

	usleep(10000);
	tm_b = time_now();

	assert(time_cmp(tm_a, tm_b) < 0);
}

#include <stdio.h>

static void test_03(void)
{
	struct tm	tm = {
		.tm_sec		= 59,
		.tm_min		= 58,
		.tm_hour	=  3,

		.tm_mday	=  1,
		.tm_mon		=  0,
		.tm_year	= 2023 - 1900,

		.tm_isdst	= -1,
	};

	time_t		now = mktime(&tm);

	assert(time_max_lt(now,  -1) == 0);
	assert(time_max_lt(now, 500) == 1 * 3600 + 1 * 60 + 1  +  EXTRA_DAILY_TM);
	assert(time_max_lt(now, 100) == 25 * 3600 + EXTRA_DAILY_TM - (3 * 3600 + 58 * 60 + 59));

	/* TODO: check DST wrap */
}

static void test_04(void)
{
	struct tm	tm = {
		.tm_sec		= 59,
		.tm_min		= 58,
		.tm_hour	=  3,

		.tm_mday	= 31,
		.tm_mon		= 11,
		.tm_year	= 2023 - 1900,

		.tm_isdst	= -1,
	};

	time_t		now = mktime(&tm);

	assert(time_max_lt(now,  -1) == 0);
	assert(time_max_lt(now, 500) == 1 * 3600 + 1 * 60 + 1  +  EXTRA_DAILY_TM);
	assert(time_max_lt(now, 100) == 25 * 3600 + EXTRA_DAILY_TM - (3 * 3600 + 58 * 60 + 59));
}

static void test_05(void)
{
	/* CEST -> CET DST change */

	/* Sat Mar 25 12:00:00 CET 2023 */
	assert(time_max_lt(1679742000, 500) == 1679799600 - 1679742000 + EXTRA_DAILY_TM);

	/* Sun Mar 26 01:00:00 CET 2023 */
	assert(time_max_lt(1679788800, 500) == 1679799600 - 1679788800 + EXTRA_DAILY_TM);

	/* Sun Mar 26 12:00:00 CEST 2023 */
	assert(time_max_lt(1679824800, 500) == 1679886000 - 1679824800 + EXTRA_DAILY_TM);


	/* Sat Oct 28 12:00:00 CEST 2023 */
	assert(time_max_lt(1698487200, 500) == 1698552000 - 1698487200 + EXTRA_DAILY_TM);

	/* Sun Oct 29 01:00:00 CEST 2023 */
	assert(time_max_lt(1698534000, 500) == 1698552000 - 1698534000 + EXTRA_DAILY_TM);

	/* Sun Oct 29 12:00:00 CET 2023 */
	assert(time_max_lt(1698577200, 500) == 1698638400 - 1698577200 + EXTRA_DAILY_TM);
}

#undef main
int main(void)
{
	setenv("TZ", "Europe/Berlin", 1);

	test_00();
	test_01();
	test_02();
	test_03();
	test_04();
	test_05();
}
