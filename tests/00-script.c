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

#include "../src/script.c"

static void test_00(void)
{
	struct env_buf		env = { };
	struct dhcp_iapd	iapd = {
	};
	struct dhcp_context	ctx = {
	};

	dhcp_iapd_exec_fill_globals();
	dhcp_iapd_fill_env(&env, &iapd, &ctx, "TEST");
}

#undef main
int main(void)
{
	test_00();
}
