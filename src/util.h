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

#ifndef H_ENSC_DHCP_PD_UTIL_H
#define H_ENSC_DHCP_PD_UTIL_H

#include <stdint.h>
#include <endian.h>

struct be16 {
	uint16_t	vx;
};
typedef struct be16	be16_t;

struct be32 {
	uint32_t	vx;
};
typedef struct be32	be32_t;

#define CPU_TO_BE16(_v) (struct be16){ .vx = htobe16(_v) }
inline static uint16_t	be16_to_cpu(struct be16 v)
{
	return be16toh(v.vx);
}

#define CPU_TO_BE32(_v) (struct be32){ .vx = htobe32(_v) }
inline static uint32_t	be32_to_cpu(struct be32 v)
{
	return be32toh(v.vx);
}

inline static uint16_t read_be8(void const *mem)
{
	uint8_t	tmp;

	memcpy(&tmp, mem, sizeof tmp);
	return tmp;
}

inline static uint16_t read_be16(void const *mem)
{
	uint16_t	tmp;

	memcpy(&tmp, mem, sizeof tmp);
	return be16toh(tmp);
}

inline static uint32_t read_be32(void const *mem)
{
	uint32_t	tmp;

	memcpy(&tmp, mem, sizeof tmp);
	return be32toh(tmp);
}

#endif	/* H_ENSC_DHCP_PD_UTIL_H */
