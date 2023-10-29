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

#include "logging.h"

/* add some extra time to the daily-reconnect limit; prevents RENEW storms
   shortyly before this time and compensates some jitter */
#define EXTRA_DAILY_TM	(30 * 60)

#define LOG_DOMAIN	LOG_DOMAIN_TIME

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

static time_t get_hhmm(struct tm const *base_tm, unsigned int hhmm,
		       time_t offset)
{
	struct tm	tm = {
		.tm_mday	= base_tm->tm_mday,
		.tm_mon		= base_tm->tm_mon,
		.tm_year	= base_tm->tm_year,
		.tm_hour	= offset == 0 ? hhmm / 100 : 0,
		.tm_min		= offset == 0 ? hhmm % 100 : 0,
		.tm_isdst	= -1,
	};

	time_t		t;

	t = mktime(&tm);
	if (offset == 0)
		return t;

	t += offset;
	localtime_r(&t, &tm);

	tm.tm_hour = hhmm / 100;
	tm.tm_min  = hhmm % 100;

	return mktime(&tm);
}

uint32_t time_max_lt(time_t now, int daily_renew)
{
	struct tm	tm;
	time_t		renew_tm;

	if (daily_renew < 0)
		return 0;

	localtime_r(&now, &tm);

	pr_debug("now=%04u-%02u-%02u %02u:%02u:%02u %s; renew=%04u",
		 tm.tm_year + 1900, tm.tm_mon, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone,
		 daily_renew);

	renew_tm = get_hhmm(&tm, daily_renew, 0);
	if (renew_tm < now)
	    renew_tm = get_hhmm(&tm, daily_renew, 24 * 3600);

	if (renew_tm < now) {
	    pr_warn("failed to find renew time");
	    return -1;
	}

	pr_debug("renew_tm=%llu", (unsigned long long)renew_tm);

	return renew_tm - now + EXTRA_DAILY_TM;
}
