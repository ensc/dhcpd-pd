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

#ifndef H_ENSC_DHCP_PD_LOGGING_H
#define H_ENSC_DHCP_PD_LOGGING_H

#include "../ensc-lib/logging.h"

enum {
	LOG_DOMAIN_RELIABILITY,
	LOG_DOMAIN_IAPD,
	LOG_DOMAIN_MAIN,
	LOG_DOMAIN_DUID,
};

#define pr_debug(fmt, ...)	log_msg(L_DEBUG, LOG_DOMAIN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	log_msg(L_INFO,  LOG_DOMAIN, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	log_msg(L_WARN,  LOG_DOMAIN, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	log_msg(L_ERR,   LOG_DOMAIN, fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...)	log_msg(L_PANIC, LOG_DOMAIN, fmt, ##__VA_ARGS__)

#define pr_trace(fmt, ...)	log_msg(L_DEBUG1 | L_PUSH, LOG_DOMAIN, fmt, ##__VA_ARGS__)


#endif	/* H_ENSC_DHCP_PD_LOGGING_H */
