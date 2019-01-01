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

#include "time.h"

#include <time.h>

dhcp_time_t time_now(void)
{
	struct timespec	ts;
	uint64_t	now;

	clock_gettime(CLOCK_BOOTTIME, &ts);

	now  = ts.tv_sec;
	now *= 1000;
	now += ts.tv_nsec / 1000000;

	return (dhcp_time_t){ now };
}

dhcp_time_t time_get_margin(dhcp_time_t a, dhcp_time_t b,
			    unsigned int margin_pct)
{
	uint64_t	delta;

	assert(time_cmp(a, b) < 0);

	delta = time_sub(b, a).tm;
	delta *= margin_pct;
	delta /= 100;

	return time_add_ms(a, delta);
}
