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

#include "logging.h"

#include <string.h>
#include <stdlib.h>

static char const		SPECIFIERS[256] = {
	['d']	= 1,
	['i']	= 1,

	['o']	= 1,
	['u']	= 1,
	['x']	= 1,
	['X']	= 1,

	['e']	= 1,

	['f']	= 1,
	['F']	= 1,

	['g']	= 1,

	['a']	= 1,

#if 0
	/* double with 'E' notation */
	['E']	= 1,
	/* double -> uppercase hex */
	['A']	= 1,
	/* double */
	['G']	= 1,
#endif

	['c']	= 1,
	['s']	= 1,
	['C']	= 1,
	['S']	= 1,
	['p']	= 1,
	['n']	= 1,
	['m']	= 1,

	['%']	= 1,

	['A']	= 2,
	['P']	= 2,
	['N']	= 2,
	['R']	= 2,
	['T']	= 2,
	['E']	= 2,
	['G']	= 2,
};

inline static bool is_local_mod(unsigned char c)
{
	return SPECIFIERS[c] == 2;
}

char const *log_transform_fmt(char const *fmt)
{
	char		*tmp = strdup(fmt);
	char		*out = tmp;
	char const	*in  = fmt;
	bool		is_fmt = false;


	if (!tmp)
		return NULL;

	while (*in) {
		unsigned char	c = *in++;

		if (is_fmt) {
			if (c == 'p' && is_local_mod(*in))
				c = *in++;
			else {
				if (SPECIFIERS[c])
					is_fmt = false;
			}
		} else {
			if (c == '%')
				is_fmt = true;
		}

		*out++ = c;
	}

	*out = '\0';

	return tmp;
}

#include <stdio.h>
#include <printf.h>
#include <arpa/inet.h>

#pragma GCC diagnostic ignored "-Wformat-extra-args"
#pragma GCC diagnostic ignored "-Wformat"

static int get_width(struct printf_info const *info)
{
	return info->left ? -info->width : info->width;
}

static int print_null(FILE *stream, struct printf_info const *info)
{
	return fprintf(stream, "%*s", get_width(info), "<null>");
}

static int print_ipv6(FILE *stream, struct printf_info const *info,
		      void const * const *args)
{
	char				buf[INET6_ADDRSTRLEN];
	struct in6_addr const * const *	addr_arg = args[0];

	if (!*addr_arg)
		return print_null(stream, info);

	inet_ntop(AF_INET6, *addr_arg, buf, sizeof buf);

	return fprintf(stream, "%*s", get_width(info), buf);
}

static int print_ipv6_arginfo(struct printf_info const *info, size_t n,
			      int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(struct in6_addr *);

	return 1;
}

#include "time.h"

#define PRINT_TIME_SZ	(3 * sizeof(uint64_t) + sizeof "Y364D 23:59:59.9999")

static uint64_t		g_startup_time;

static int _print_time(FILE *stream, struct printf_info const *info,
		       dhcp_time_t const * const *time_arg,
		       uint64_t tm_offs)
{
	dhcp_time_t			time;
	char				buf[PRINT_TIME_SZ];
	char				*str;

	if (!*time_arg)
		return print_null(stream, info);

	time = **time_arg;
	if (time_is_infinity(time))
		str = "INF";
	else if (time_is_epoch(time))
		str = "EPOCH";
	else {
		static uint64_t const	TM_MIN  = 60 * 1000;
		static uint64_t const	TM_HOUR = TM_MIN * 60;
		static uint64_t const	TM_DAY  = TM_HOUR * 24;
		static uint64_t const	TM_YEAR = TM_DAY * (uint64_t)365;

		uint64_t		tm = time_to_ms(time) - tm_offs;
		char			*ptr = buf;
		bool			need_part = false;

		if (tm >= TM_YEAR) {
			ptr += sprintf(ptr, "%lluY",
				       (unsigned long long)(tm / TM_YEAR));
			tm  %= TM_YEAR;
		}

		if (tm >= TM_DAY) {
			ptr += sprintf(ptr, "%luD",
				       (unsigned long)(tm / TM_DAY));
			tm  %= TM_DAY;
		}

		if (tm >= TM_HOUR || need_part) {
			if (ptr != buf)
				*ptr++ = ' ';

			ptr += sprintf(ptr, "%02lu:",
				       (unsigned long)(tm / TM_HOUR));
			tm  %= TM_HOUR;
			need_part = true;
		}

		if (tm >= TM_MIN || need_part) {
			ptr += sprintf(ptr, "%02lu:",
				       (unsigned long)(tm / TM_MIN));
			tm  %= TM_MIN;
			need_part = true;
		}

		(void)need_part;

		ptr += sprintf(ptr, "%02lu.", (unsigned long)(tm / 1000));
		ptr += sprintf(ptr, "%03u",   (unsigned int)(tm % 1000));

		(void)ptr;

		str = buf;
	}

	return fprintf(stream, "%*s", get_width(info), str);
}

static int print_time(FILE *stream, struct printf_info const *info,
		      void const * const *args)
{
	return _print_time(stream, info, args[0], g_startup_time);
}

static int print_timeabs(FILE *stream, struct printf_info const *info,
			 void const * const *args)
{
	return _print_time(stream, info, args[0], 0);
}

static int print_time_arginfo(struct printf_info const *info, size_t n,
				  int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(dhcp_time_t *);

	return 1;
}

#include "dhcpv6-util.h"

#define PRINT_RELIABILITY_SZ	(2 * PRINT_TIME_SZ +		\
				 2 * 3 * sizeof(unsigned int) + \
				 sizeof ": + ")

static int print_reliability(FILE *stream, struct printf_info const *info,
			     void const * const *args)
{
	struct dhcpv6_reliability const * const *	rel_arg = args[0];
	struct dhcpv6_reliability const *		rel = *rel_arg;
	char						buf[PRINT_RELIABILITY_SZ];

	if (!rel)
		return print_null(stream, info);

	sprintf(buf, "%T: %T+%u %u", &rel->start_t, &rel->rt_t, rel->rt, rel->num_tries);

	return fprintf(stream, "%*s", get_width(info), buf);
}

static int print_reliability_arginfo(struct printf_info const *info, size_t n,
				     int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(struct dhcpv6_reliability *);

	return 1;
}

/* struct dhcpv6_network */

#define PRINT_IPV6_NET_SZ	(INET6_ADDRSTRLEN + 3 * sizeof(uint8_t) + sizeof "/")

static int print_ipv6_net(FILE *stream, struct printf_info const *info,
		      void const * const *args)
{
	struct dhcpv6_network const * const *	addr_arg = args[0];
	char					buf[PRINT_IPV6_NET_SZ];

	if (!*addr_arg)
		return print_null(stream, info);

	inet_ntop(AF_INET6, &(*addr_arg)->prefix, buf, sizeof buf);
	sprintf(buf + strlen(buf), "/%d", (*addr_arg)->len);

	return fprintf(stream, "%*s", get_width(info), buf);
}

static int print_ipv6_net_arginfo(struct printf_info const *info, size_t n,
				  int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(struct dhcpv6_network *);

	return 1;
}

/* struct dhcpv6_iaprefix */

#define PRINT_IAPREFIX_SZ	(PRINT_IPV6_NET_SZ +			\
				 PRINT_TIME_SZ +			\
				 2 * 3 * sizeof(unsigned int) +		\
				 sizeof " tm: (pref:, valid:)")

static int print_iaprefix(FILE *stream, struct printf_info const *info,
			  void const * const *args)
{
	struct dhcp_iaprefix const * const *	iaprefix_arg = args[0];
	struct dhcp_iaprefix const *		iaprefix = *iaprefix_arg;
	char					buf[PRINT_IAPREFIX_SZ];
	char					*ptr = buf;

	if (!iaprefix)
		return print_null(stream, info);

	ptr += sprintf(ptr, "%N tm:%T (pref:%u, valid:%u)",
		       &iaprefix->net, &iaprefix->lease_tm,
		       iaprefix->pref_lt, iaprefix->valid_lt);

	(void)ptr;

	return fprintf(stream, "%*s", get_width(info), buf);
}

static int print_iaprefix_arginfo(struct printf_info const *info, size_t n,
				   int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(struct dhcpv6_iaprefix *);

	return 1;
}

/* struct dhcpv6_iapd */

#define PRINT_IAPD_STATE_SZ	(sizeof "SOLICIT-INIT")

static char const *dhcp_iapd_state_to_str(enum dhcp_iapd_state s, char *tmp_buf)
{
#       define STATE_ELEM(_st) \
	[IAPD_STATE_ ## _st] = { .state = IAPD_STATE_ ## _st, .name = # _st }

	static struct {
		enum dhcp_iapd_state	state;
		char const		*name;
	} const			STATES[] = {
		STATE_ELEM(NONE),
		STATE_ELEM(UNUSED),
		STATE_ELEM(INIT),
		STATE_ELEM(SOLICIT_INIT),
		STATE_ELEM(SOLICIT),
		STATE_ELEM(REQUEST_INIT),
		STATE_ELEM(REQUEST),
		STATE_ELEM(ACTIVE_INIT),
		STATE_ELEM(ACTIVE),
		STATE_ELEM(RENEW_INIT),
		STATE_ELEM(RENEW),
		STATE_ELEM(REBIND_INIT),
		STATE_ELEM(REBIND),
		STATE_ELEM(RELEASE_INIT),
		STATE_ELEM(RELEASE),
	};
#       undef STATE_ELEM


	if (s >= ARRAY_SIZE(STATES)) {
		sprintf(tmp_buf, "?%u", s);
		return tmp_buf;
	}

	return STATES[s].name;
}

#define PRINT_IAPD_IOSTATE_SZ	(sizeof "?" + 3 * sizeof(unsigned int))

static char const *dhcp_iapd_iostate_to_str(enum dhcp_iapd_iostate s, char *tmp_buf)
{
#       define STATE_ELEM(_st) \
	[IAPD_IOSTATE_ ## _st] = { .state = IAPD_IOSTATE_ ## _st, .name = # _st }

	static struct {
		enum dhcp_iapd_iostate	state;
		char const		*name;
	} const			STATES[] = {
		STATE_ELEM(NONE),
		STATE_ELEM(WAIT),
		STATE_ELEM(SEND),
		STATE_ELEM(RECV),
		STATE_ELEM(DONE),
		STATE_ELEM(ERROR),
		STATE_ELEM(TIMEOUT),
	};
#       undef STATE_ELEM


	if (s >= ARRAY_SIZE(STATES)) {
		sprintf(tmp_buf, "?%u", s);
		return tmp_buf;
	}

	return STATES[s].name;
}

#define PRINT_IAPD_SZ		(3 * sizeof(unsigned int) +		\
				 PRINT_IAPD_STATE_SZ +			\
				 PRINT_IAPD_IOSTATE_SZ +		\
				 2 * PRINT_TIME_SZ +			\
				 4 * 3 * sizeof(unsigned int) +		\
				 INET6_ADDRSTRLEN +			\
				 sizeof " (/), tm:  -> , T1: -> , T2: -> , server: quit release")

static int print_iapd(FILE *stream, struct printf_info const *info,
		      void const * const *args)
{
	struct dhcp_iapd const * const *	iapd_arg = args[0];
	struct dhcp_iapd const *		iapd = *iapd_arg;
	char					buf[PRINT_IAPREFIX_SZ];
	char					*ptr = buf;
	char					state_buf[PRINT_IAPD_STATE_SZ];
	char					iostate_buf[PRINT_IAPD_IOSTATE_SZ];

	if (!iapd)
		return print_null(stream, info);

	ptr += sprintf(ptr, "%u (%s/%s)%s%s, tm: %T -> %T, T1:%u -> %u, T2:%u -> %u, server: %P (%u)",
		       iapd->id,
		       dhcp_iapd_state_to_str(iapd->state, state_buf),
		       dhcp_iapd_iostate_to_str(iapd->iostate, iostate_buf),
		       iapd->do_release ? " release" : "",
		       iapd->do_quit ? " quit" : "",
		       &iapd->pending.lease_tm, &iapd->active.lease_tm,
		       iapd->pending.t1, iapd->active.t1,
		       iapd->pending.t2, iapd->active.t2,
		       &iapd->server.addr, &iapd->server.preference);

	(void)ptr;

	return fprintf(stream, "%*s", get_width(info), buf);
}

static int print_iapd_arginfo(struct printf_info const *info, size_t n,
				   int *argtypes, int *sizes)
{
	argtypes[0] = PA_POINTER;
	sizes[0] = sizeof(struct dhcpv6_iapd *);

	return 1;
}

void logging_register_conversions(void)
{
#ifndef TESTSUITE
	g_startup_time = time_to_ms(time_now());
#else
	g_startup_time = 0;
#endif

	register_printf_specifier('P', print_ipv6, print_ipv6_arginfo);
	register_printf_specifier('N', print_ipv6_net, print_ipv6_net_arginfo);
	register_printf_specifier('R', print_iaprefix, print_iaprefix_arginfo);
	register_printf_specifier('T', print_time, print_time_arginfo);
	register_printf_specifier('G', print_timeabs, print_time_arginfo);
	register_printf_specifier('A', print_iapd, print_iapd_arginfo);
	register_printf_specifier('E', print_reliability, print_reliability_arginfo);
}
