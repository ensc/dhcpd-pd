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

#ifndef H_ENSC_DHCP_TIME_H
#define H_ENSC_DHCP_TIME_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define TIME_EPOCH		((dhcp_time_t){  (uint64_t)0u })
#define TIME_INFINITY		((dhcp_time_t){ ~(uint64_t)0u })

struct _dhcp_time {
	uint64_t		tm;
};
typedef struct _dhcp_time	dhcp_time_t;

dhcp_time_t time_now(void);
dhcp_time_t time_get_margin(dhcp_time_t a, dhcp_time_t b,
			    unsigned int margin_pct);

inline static int		time_cmp(dhcp_time_t a, dhcp_time_t b)
{
	if (a.tm < b.tm)
		return -1;
	else if (a.tm > b.tm)
		return +1;
	else
		return 0;
}

inline static bool		time_is_infinity(dhcp_time_t a)
{
	return time_cmp(a, TIME_INFINITY) == 0;
}

inline static bool		time_is_epoch(dhcp_time_t a)
{
	return time_cmp(a, TIME_EPOCH) == 0;
}

inline static dhcp_time_t	time_min(dhcp_time_t a, dhcp_time_t b)
{
	if (time_cmp(a, b) < 0)
		return a;
	else
		return b;
}

inline static uint64_t		time_to_ms(dhcp_time_t t)
{
	return t.tm;
}

inline static dhcp_time_t time_add_ms(dhcp_time_t a, unsigned int b_ms)
{
	if (time_is_infinity(a) || time_is_epoch(a))
		return a;
	else
		return (dhcp_time_t){ a.tm + b_ms };
}

inline static dhcp_time_t time_add_s(dhcp_time_t a, unsigned int b_s)
{
	return time_add_ms(a, b_s * 1000);
}

inline static dhcp_time_t time_sub(dhcp_time_t a, dhcp_time_t b)
{
	assert(time_cmp(a, b) >= 0);
	assert(!time_is_infinity(a) || !time_is_infinity(b));

	if (time_is_infinity(a) && !time_is_infinity(b))
		return TIME_INFINITY;
	else
		return (dhcp_time_t){ a.tm - b.tm };
}

/* https://tools.ietf.org/html/rfc3633#section-10 */
inline static dhcp_time_t time_add_lt(dhcp_time_t a, uint32_t b,
				      unsigned int margin)
{
	if (b == 0xffffffff)
		return TIME_INFINITY;
	else if (b == 0)
		return TIME_EPOCH;
	else {
		uint64_t tmp = b;
		tmp *= margin;
		tmp /= 100;

		return time_add_s(a, tmp);
	}
}

#endif	/* H_ENSC_DHCP_TIME_H */
