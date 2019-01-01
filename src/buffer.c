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
#include "dhcpv6-util.h"

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
	struct dhcpv6_option_hdr	*opt;

	offset += sizeof *opt;

	if (offset > buf->max_len - buf->len)
		return false;

	_tmp->max_len = buf->max_len - buf->len - offset;
	_tmp->data    = buf->data + buf->len + offset;
	_tmp->len     = 0;

	return true;
}

static bool buffer_add_elapsed_time(struct dhcp_buffer *buf,
				    struct dhcp_context *ctx,
				    struct dhcpv6_transmission const *xmit)
{
	dhcp_time_t	delta = time_sub(ctx->now, xmit->time);

	/* unit is 1/100s */
	uint64_t	ms = time_to_ms(delta) / 100;
	uint16_t	tm16;

	if (ms > 0xffff)
		ms = 0xffff;

	tm16 = htobe16(ms);

	return buffer_add_option(buf, DHCPV6_OPTION_ELAPSED_TIME,
				 &tm16, sizeof tm16);
}

bool request_init(struct dhcp_buffer *buf, enum dhcpv6_type type,
		  struct dhcp_context *ctx,
		  struct dhcpv6_transmission const *xmit)
{
	struct dhcpv6_message_hdr	*hdr;

	_Static_assert(sizeof hdr->xmit_id == sizeof xmit->xmit_id,
		       "xmit-id layout mismatch");

	assert(buf->len == 0);

	hdr = buffer_allocate(buf, sizeof *hdr);
	if (!hdr)
		return false;

	hdr->type = type;
	memcpy(hdr->xmit_id, xmit->xmit_id, sizeof xmit->xmit_id);

	return (buffer_add_duid(buf, DHCPV6_OPTION_CLIENTID, ctx->client_id) &&
		buffer_add_elapsed_time(buf, ctx, xmit));
}
