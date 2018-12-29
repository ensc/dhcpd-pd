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

#include "dhcpv6-util.h"

#include <fcntl.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "logging.h"
#include "dhcpv6.h"

#define DUID_ENUM		22683
#define DUID_SALT0		"kABoBaUjLjs9SebQUpUyadljIA1gvxV9"
#define DUID_SALT1		"6SwjUAHolGTaFie7j6A2glABx93pnIkj"
#define SERIAL_FILE_CPU		"/sys/firmware/devicetree/base/serial-number"
#define SERIAL_FILE_MACHINE_ID	"/etc/machine-id"

#define LOG_DOMAIN	LOG_DOMAIN_DUID

static void fill_duid(struct dhcpv6_duid *duid, void const *data, size_t len)
{
	SHA256_CTX	ctx;
	unsigned char	buf[SHA256_DIGEST_LENGTH];
	void		*p;
	uint16_t	type = htobe16(2);
	uint32_t	ent_num = htobe32(DUID_ENUM);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, DUID_SALT0, strlen(DUID_SALT0));
	SHA256_Update(&ctx, data, len);
	SHA256_Update(&ctx, DUID_SALT1, strlen(DUID_SALT1));
	SHA256_Final(buf, &ctx);

	_Static_assert(sizeof duid->id >= sizeof type + sizeof ent_num + 10,
		       "insufficient space");

	p = duid->id;
	p = mempcpy(p, &type, sizeof type);
	p = mempcpy(p, &ent_num, sizeof ent_num);
	p = mempcpy(p, buf, 10);

	duid->len = (uintptr_t)p - (uintptr_t)duid->id;
}

static bool generate_from_file(struct dhcpv6_duid *duid, char const *fname)
{
	char	buf[1024];
	ssize_t	len;

	int	fd;

	fd = open(fname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (len < 0)
		return false;

	buf[len] = '\0';
	if (strlen(buf) < 10)
		return false;

	fill_duid(duid, buf, len);
	return true;
}

int dhcpv6_duid_generate(struct dhcpv6_duid *duid)
{
	if (!generate_from_file(duid, SERIAL_FILE_CPU) &&
	    !generate_from_file(duid, SERIAL_FILE_MACHINE_ID)) {
		pr_err("can not generate duid");
		return -1;
	}

	dhcpv6_duid_validate(duid);

	return 0;
}

int dhcpv6_duid_cmp_opt(struct dhcpv6_duid const *a,
			struct dhcpv6_option_hdr const *b)
{
	void const	*data;
	size_t		len;

	dhcpv6_duid_validate(a);

	if (!b)
		return +1;

	data = dhcpv6_get_option_data(b);
	len  = dhcpv6_get_option_len(b);

	if (a->len < len)
		return -1;
	else if (a->len > len)
		return +1;
	else
		return memcmp(a->id, data, len);
}
