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

#include "buffer.h"

#include <string.h>

#include "dhcpv6.h"

void *buffer_allocate(struct dhcp_buffer *buf, size_t len)
{
	void	*res;

	if (len > buf->max_len - buf->len)
		return NULL;

	res = buf->data + buf->len;
	buf->len += len;

	return res;
}

bool buffer_add_raw(struct dhcp_buffer *buf, unsigned int code,
		    void const *data, size_t len, size_t extra_len)
{
	struct dhcpv6_option_hdr	*opt;

	opt = buffer_allocate(buf, sizeof *opt + len + extra_len);
	if (!opt)
		return false;

	*opt = (struct dhcpv6_option_hdr) {
		.option		= CPU_TO_BE16(code),
		.len		= CPU_TO_BE16(len + extra_len),
	};

	if (data)
		memcpy(&opt[1], data, len);

	return true;
}

bool buffer_init_subbuffer(struct dhcp_buffer const *buf,
			   struct dhcp_buffer *_tmp, size_t offset)
{
	if (offset > buf->max_len - buf->len)
		return false;

	_tmp->max_len = buf->max_len - buf->len - offset;
	_tmp->data    = buf->data + buf->len + offset;

	return true;
}
