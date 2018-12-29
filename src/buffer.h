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

#ifndef H_ENSC_DHCP_BUFFER_H
#define H_ENSC_DHCP_BUFFER_H

#include <stdlib.h>
#include <stdbool.h>

struct dhcp_buffer {
	void		*data;
	size_t		len;
	size_t		max_len;
};

bool buffer_init_subbuffer(struct dhcp_buffer const *buf,
			   struct dhcp_buffer *_tmp, size_t offset);

void *buffer_allocate(struct dhcp_buffer *buf, size_t len);
bool buffer_add_raw(struct dhcp_buffer *buf, unsigned int code,
		    void const *data, size_t len, size_t extra_len);

inline static bool buffer_add_option(struct dhcp_buffer *buf, unsigned int code,
				     void const *data, size_t len)
{
	return buffer_add_raw(buf, code, data, len, 0);
}

#endif	/* H_ENSC_DHCP_BUFFER_H */
