/*	--*- c -*--
 * Copyright (C) 2019 Enrico Scholz <enrico.scholz@ensc.de>
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

#include <sysexits.h>
#include <stdio.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static void show_help(void)
{
	printf("Usage: net6-combine <prefix> <len> <id> <id-bits>\n");
}

static struct in6_addr do_combine(struct in6_addr const *prefix,
				  unsigned int prefix_len,
				  uint64_t id,
				  unsigned int id_bits)
{
	uint64_t	num_prefix[2];
	uint64_t	num_mask[2];
	uint64_t	num_bits[2];
	unsigned int	sft;
	struct in6_addr	res;

	assert(prefix_len <= 128);
	assert(id_bits <= 64);
	assert(prefix_len + id_bits <= 128);

	memcpy(num_prefix, prefix->s6_addr, sizeof num_prefix);

	num_prefix[0] = be64toh(num_prefix[0]);
	num_prefix[1] = be64toh(num_prefix[1]);

	num_mask[0] = ~(uint64_t)0;
	if (prefix_len <= 64) {
		num_mask[0] <<= 64 - prefix_len;
		num_mask[1]   = 0;
	} else {
		num_mask[1]   = ~(uint64_t)0;
		num_mask[1] <<= 128 - prefix_len;
	}

	sft = 128 - prefix_len - id_bits;

	if (sft <= 64) {
		num_bits[1] = id << sft;
		num_bits[0] = id >> (64 - sft);
	} else {
		num_bits[1] = 0;
		num_bits[0] = id << (sft - 64);
	}

	num_prefix[0] &= num_mask[0];
	num_prefix[0] |= num_bits[0];

	num_prefix[1] &= num_mask[1];
	num_prefix[1] |= num_bits[1];

	num_prefix[0] = htobe64(num_prefix[0]);
	num_prefix[1] = htobe64(num_prefix[1]);

	memcpy(res.s6_addr, num_prefix, sizeof res.s6_addr);

	return res;
}

int main(int argc, char *argv[])
{
	struct in6_addr		addr;
	unsigned int		pos;
	uint64_t		id;
	unsigned int		id_bits;
	int			rc;
	char			res_buf[INET6_ADDRSTRLEN];

	if (argc > 1 && strcmp(argv[1], "--help") == 0) {
		show_help();
		return EX_OK;
	}

	if (argc != 5) {
		fprintf(stderr, "bad number of arguments; use --help\n");
		return EX_USAGE;
	}

	rc = inet_pton(AF_INET6, argv[1], &addr);
	if (rc != 1) {
		fprintf(stderr, "failed to convert '%s' to ipv6 address\n",
			argv[1]);
		return EX_DATAERR;
	}

	pos     = atoi(argv[2]);
	id      = strtoull(argv[3], NULL, 0);
	id_bits = atoi(argv[4]);

	if (id_bits > 56) {
		fprintf(stderr, "too much bits in id\n");
		return EX_DATAERR;
	}

	if (pos > 128 || id_bits > 128 - pos) {
		fprintf(stderr, "resulting net too large\n");
		return EX_DATAERR;
	}

	addr = do_combine(&addr, pos, id, id_bits);
	inet_ntop(AF_INET6, &addr, res_buf, sizeof res_buf);

	printf("%s\n", res_buf);
}
