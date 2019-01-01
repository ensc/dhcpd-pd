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

#include "../src/buffer.h"

#define CANARY_A	"abcd1234ABCD9876"
#define CANARY_B	"dcba4321DCBA6789"

static void test_00()
{
	struct {
		unsigned char	a[16];
		char		buf[1024];
		unsigned char	b[16];
	} __attribute__((__packed__))	tmp;

	struct dhcp_buffer	buf = {
		.data		= tmp.buf,
		.max_len	= sizeof tmp.buf,
	};
	struct dhcp_buffer	subbuf;

	bool			rc;

	memcpy(tmp.a, CANARY_A, sizeof tmp.a);
	memcpy(tmp.b, CANARY_B, sizeof tmp.b);
	memset(tmp.buf, 42, sizeof tmp.buf);

	assert(buffer_allocate(&buf, 1) != NULL);
	assert(buffer_allocate(&buf, 999) != NULL);
	assert(buffer_allocate(&buf, 23) != NULL);
	assert(buffer_allocate(&buf, 1) != NULL);
	assert(buffer_allocate(&buf, 1) == NULL);

	assert(memcmp(tmp.a, CANARY_A, sizeof tmp.a) == 0);
	assert(memcmp(tmp.b, CANARY_B, sizeof tmp.b) == 0);

	buf.len = 0;

	rc = buffer_add_raw(&buf, 23, "test", 4, 0);
	assert(rc);
	assert(memcmp(tmp.buf, "\x00\x17\x00\x04test", 8) == 0);
	assert(buf.len == 8);

	rc = buffer_add_raw(&buf, 0x23, "foo", 3, 2);
	assert(rc);
	assert(memcmp(tmp.buf,     "\x00\x17\x00\x04test",        8) == 0);
	assert(memcmp(tmp.buf + 8, "\x00\x23\x00\x05""foo\x2a\x2a", 9) == 0);
	assert(buf.len == 8 + 9);

	rc = buffer_init_subbuffer(&buf, &subbuf, 10);
	assert(rc);
	assert(subbuf.max_len == 1024 - 8 - 9 - 10 - 4);
	assert(subbuf.data    == tmp.buf + 8 + 9 + 10 + 4);
	assert(subbuf.len     == 0);

	rc = buffer_add_option(&subbuf, 0x55, "xyz", 3);
	assert(rc);
	assert(memcmp(tmp.buf + 8 + 9 + 10 + 4, "\x00\x55\x00\x03xyz", 7) == 0);
	assert(subbuf.len     == 7);

	/* len: 3 (opt) + 10 (offset) + 7 (subopt) */
	rc = buffer_add_raw(&buf, 0x66, "zyx", 3, 10 + subbuf.len);
	assert(rc);
	assert(memcmp(tmp.buf + 8 + 9,          "\x00\x66\x00\x14zyx", 7) == 0);
	assert(memcmp(tmp.buf + 8 + 9 + 7,      "\x2a\x2a\x2a\x2a\x2a\x2a\x2a", 7)  == 0);
	assert(memcmp(tmp.buf + 8 + 9 + 10 + 4, "\x00\x55\x00\x03xyz", 7) == 0);
	assert(buf.len == 8 + 9 + 24);

	rc = buffer_add_option(&buf, 0x77, "XXX", 3);
	assert(rc);
	assert(memcmp(tmp.buf + 8 + 9 + 24,     "\x00\x77\x00\x03XXX", 7) == 0);
	assert(memcmp(tmp.buf + 8 + 9 + 10 + 4, "\x00\x55\x00\x03xyz", 7) == 0);
}

#undef main
int main(void)
{
	test_00();
}
