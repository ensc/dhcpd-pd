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

#include "../src/dhcpv6-util.h"

#undef main
int main(void)
{
	struct dhcpv6_reliability			rel;
	static struct dhcpv6_reliability_parm const	PARM = {
		.irt	= 1000,
		.mrc	= 6,
		.mrt	= 10000,
		.mrd	= 100000,
	};
	dhcp_time_t		now = { 1000 };
	dhcp_time_t		tm_expired = { 101001 };

	dhcpv6_reliability_init(&rel, &PARM, now);

	assert(dhcpv6_reliability_check(&rel, now));
	assert(!dhcpv6_reliability_check(&rel, tm_expired));

	for (unsigned int i = 0; i < 1000; ++i) {
		unsigned int	rt;

		dhcpv6_reliability_init(&rel, &PARM, now);

		/* #1 */
		assert(dhcpv6_reliability_next(&rel, now));

		assert(rel.num_retries == 1);
		assert(rel.rt >= 1000);
		assert(rel.rt <= 1100);

		rt = rel.rt;

		/* #2: around 2000 */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 2);
		assert(rel.rt >= rt * 190 / 100);
		assert(rel.rt <= rt * 210 / 100);

		rt = rel.rt;

		/* #3: around 4000 */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 3);
		assert(rel.rt >= rt * 190 / 100);
		assert(rel.rt <= rt * 210 / 100);

		rt = rel.rt;

		/* #4: around 8000 */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 4);
		assert(rel.rt >= rt * 190 / 100);
		assert(rel.rt <= rt * 210 / 100);

		rt = PARM.mrt;

		/* #5: MRT reached */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 5);
		assert(rel.rt >= rt *  90 / 100);
		assert(rel.rt <= rt * 110 / 100);

		/* #6: MRT reached */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 6);
		assert(rel.rt >= rt *  90 / 100);
		assert(rel.rt <= rt * 110 / 100);

		/* #7: MRT reached */
		assert(dhcpv6_reliability_next(&rel, now));
		assert(rel.num_retries == 7);
		assert(rel.rt >= rt *  90 / 100);
		assert(rel.rt <= rt * 110 / 100);

		assert(!dhcpv6_reliability_next(&rel, now));
	}

	dhcpv6_reliability_init(&rel, &PARM, now);
	assert(dhcpv6_reliability_next(&rel, now));
	assert(dhcpv6_reliability_next(&rel, now));


}
