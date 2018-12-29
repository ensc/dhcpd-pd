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
#include "../src/dhcpv6-util.h"

int main(void)
{
	struct dhcpv6_transmission	xmit = {
		.time		= { 23 },
		.xmit_id	= { 1, 2, 3 },
	};
	dhcp_time_t			now = { 1000 };

	assert(xmit.time.tm == 23);
	assert(xmit.xmit_id[0] == 1);
	assert(xmit.xmit_id[1] == 2);
	assert(xmit.xmit_id[2] == 3);

	dhcpv6_transmission_init(&xmit, now);

	assert(xmit.time.tm == 1000);
	/* TODO: there is a small chance that getrandom() delivers such
	 * values...  */
	assert(xmit.xmit_id[0] != 1 ||
	       xmit.xmit_id[1] != 2 ||
	       xmit.xmit_id[2] != 3);
}
