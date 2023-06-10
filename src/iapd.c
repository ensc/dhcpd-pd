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

#include <errno.h>
#include <arpa/inet.h>
#include <sys/param.h>

#include "../ensc-lib/compiler.h"

#include "logging.h"
#include "dhcpv6.h"
#include "buffer.h"

struct dhcp_states {
	char const		*name;
	enum dhcp_iapd_state	rel_to;		/* reliability timeout */
	enum dhcp_iapd_state	pref_to;	/* prefered lifetime timeout */
	enum dhcp_iapd_state	valid_to;	/* valid lifetime timeout */
	enum dhcp_iapd_state	t1_to;		/* T1 timeout */
	enum dhcp_iapd_state	t2_to;		/* T2 timeout */
	enum dhcp_iapd_state	done;		/* done */
	enum dhcp_iapd_state	error;		/* done */

	bool			req_serverid;	/* matching SERVERID required */
	bool			no_io;
	unsigned int		tm_margin;
};

static struct dhcp_states const	STATES[] = {
	[IAPD_STATE_INIT] = {
		.name		= "INIT",
		.done		= IAPD_STATE_SOLICIT_INIT,
		.no_io		= true,
	},

	[IAPD_STATE_SOLICIT_INIT] = {
		.name		= "SOLICIT-INIT",
		.done		= IAPD_STATE_SOLICIT,
		.no_io		= true,
	},

	[IAPD_STATE_SOLICIT]	= {
		.name		= "SOLICIT",
		.rel_to		= IAPD_STATE_INIT,
		.done		= IAPD_STATE_REQUEST_INIT,
		.error		= IAPD_STATE_SOLICIT_INIT,
	},

	[IAPD_STATE_REQUEST_INIT] = {
		.name		= "REQUEST-INIT",
		.done		= IAPD_STATE_REQUEST,
		.no_io		= true,
	},

	[IAPD_STATE_REQUEST]	= {
		.name		= "REQUEST",
		.rel_to		= IAPD_STATE_SOLICIT_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_SOLICIT_INIT,
		.req_serverid	= true,
	},

	[IAPD_STATE_ACTIVE_INIT] = {
		.name		= "ACTIVE-INIT",
		.done		= IAPD_STATE_ACTIVE,
		.no_io		= true,
	},

	[IAPD_STATE_ACTIVE] = {
		.name		= "ACTIVE",
		.pref_to	= IAPD_STATE_RENEW_INIT,
		.valid_to	= IAPD_STATE_SOLICIT_INIT,
		.t1_to		= IAPD_STATE_RENEW_INIT,
		.t2_to		= IAPD_STATE_REBIND_INIT,
		.tm_margin	= 80,
	},

	[IAPD_STATE_RENEW_INIT] = {
		.name		= "RENEW-INIT",
		.done		= IAPD_STATE_RENEW,
		.no_io		= true,
	},

	[IAPD_STATE_RENEW] = {
		.name		= "RENEW",
		.rel_to		= IAPD_STATE_SOLICIT_INIT,
		.valid_to	= IAPD_STATE_SOLICIT_INIT,
		.t2_to		= IAPD_STATE_REBIND_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_REBIND_INIT,
		.tm_margin	= 100,
		.req_serverid	= true,
	},

	[IAPD_STATE_REBIND_INIT] = {
		.name		= "REBIND-INIT",
		.done		= IAPD_STATE_REBIND,
		.no_io		= true,
	},

	[IAPD_STATE_REBIND] = {
		.name		= "REBIND",
		.rel_to		= IAPD_STATE_SOLICIT_INIT,
		.valid_to	= IAPD_STATE_SOLICIT_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_SOLICIT_INIT,
		.tm_margin	= 100,
	},

	[IAPD_STATE_RELEASE_INIT] = {
		.name		= "RELEASE-INIT",
		.done		= IAPD_STATE_RELEASE,
		.no_io		= true,
	},

	[IAPD_STATE_RELEASE] = {
		.name		= "RELEASE",
		.rel_to		= IAPD_STATE_INIT,
		.done		= IAPD_STATE_SOLICIT_INIT,
		.tm_margin	= 100,
		.req_serverid	= true,
	},
};

/** https://tools.ietf.org/html/rfc3315#section-5.5 */

/** https://tools.ietf.org/html/rfc3315#section-17.1.2 */
static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_solicit = {
	.irt	= 1000,
	.mrt	= 120000,
	.mrc	= 0,
	.mrd	= 0,
};

/** https://tools.ietf.org/html/rfc3315#section-18.1.1 */
static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_request = {
	.irt	= 1000,
	.mrt	= 30000,
	.mrc	= 10,
	.mrd	= 0,
};

static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_renew = {
	.irt	= 1000,
	.mrt	= 60000,
	.mrc	= 0,
	.mrd	= 0,			/* will be checked in code */
};

static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_rebind = {
	.irt	= 1000,
	.mrt	= 60000,
	.mrc	= 0,
	.mrd	= 0,			/* will be checked in code */
};

static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_release = {
	.irt	= 1000,
	.mrt	= 0,
	.mrc	= 5,
	.mrd	= 0,			/* will be checked in code */
};

static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_confirm = {
	.irt	= 1000,
	.mrt	= 4000,
	.mrc	= 0,
	.mrd	= 10000,
};

#define LOG_DOMAIN	LOG_DOMAIN_IAPREFIX

static void dhcp_iaprefix_validate(struct dhcp_iaprefix const *prefix)
{
	assert(prefix->net.len <= 64);
	assert(prefix->pref_lt <= prefix->valid_lt);
	assert(!time_is_infinity(prefix->lease_tm));
}

static void dhcp_iaprefix_init(struct dhcp_iaprefix *prefix,
			       struct dhcp_context const *ctx,
			       dhcp_time_t now, bool init_addr)
{
	if (prefix->preferences.is_set) {
		prefix->pref_lt    = prefix->preferences.pref_lt;
		prefix->valid_lt   = prefix->preferences.valid_lt;

		if (init_addr) {
			prefix->net = prefix->preferences.net;
		}
	} else {
		prefix->pref_lt    = 0xffffffff;
		prefix->valid_lt   = 0xffffffff;

		if (init_addr)
			dhcpv6_network_zero(&prefix->net);
	}

	if (ctx->max_lt > 0) {
		prefix->pref_lt  = MIN(prefix->pref_lt,  ctx->max_lt);
		prefix->valid_lt = MIN(prefix->valid_lt, ctx->max_lt);
	}

	prefix->lease_tm = TIME_EPOCH;

	dhcp_iaprefix_validate(prefix);
}

enum iapd_prefix_selection {
	IAPD_PREFIX_SEL_NONE,
	IAPD_PREFIX_SEL_ACTIVE,
	IAPD_PREFIX_SEL_PENDING,
	IAPD_PREFIX_SEL_PREF,
};

static struct dhcp_iaprefix *get_iaprefix(struct dhcp_iapd *iapd,
					  size_t idx,
					  enum iapd_prefix_selection sel)
{
	switch (sel) {
	case IAPD_PREFIX_SEL_ACTIVE:
		return &iapd->iaprefix[idx].active;
	case IAPD_PREFIX_SEL_PENDING:
		return &iapd->iaprefix[idx].pending;
	case IAPD_PREFIX_SEL_PREF:
		return &iapd->iaprefix[idx].pending;
	case IAPD_PREFIX_SEL_NONE:
		return NULL;
	}

	pr_err("fallthrough; bad sel %d", sel);
	return NULL;
}

static bool buffer_add_iaprefix(struct dhcp_buffer *buf,
				struct dhcp_iaprefix const *iaprefix,
				enum iapd_prefix_selection sel)
{
	struct dhcpv6_option_iaprefix	opt;
	struct in6_addr const		*net;

	if (sel != IAPD_PREFIX_SEL_PREF) {
		opt = (struct dhcpv6_option_iaprefix) {
			.pref_lftm	= CPU_TO_BE32(iaprefix->pref_lt),
			.valid_lftm	= CPU_TO_BE32(iaprefix->valid_lt),
			.prefix_len	= iaprefix->net.len,
		};

		_Static_assert(sizeof opt.prefix == sizeof iaprefix->net.prefix,
			       "iaprefix prefex layout mismatch");

		net = &iaprefix->net.prefix;
	} else if (iaprefix->preferences.is_set) {
		opt = (struct dhcpv6_option_iaprefix) {
			.pref_lftm	= CPU_TO_BE32(iaprefix->preferences.pref_lt),
			.valid_lftm	= CPU_TO_BE32(iaprefix->preferences.valid_lt),
			.prefix_len	= iaprefix->preferences.net.len,
		};

		_Static_assert(sizeof opt.prefix ==
			       sizeof iaprefix->preferences.net.prefix,
			       "iaprefix.prefix layout mismatch");

		net = &iaprefix->preferences.net.prefix;
	} else {
		opt = (struct dhcpv6_option_iaprefix) {
			.pref_lftm	= CPU_TO_BE32(0),
			.valid_lftm	= CPU_TO_BE32(0),
			.prefix_len	= 0,
		};

		net = NULL;
	}

	if (net)
		memcpy(opt.prefix, net, sizeof opt.prefix);

	return buffer_add_option(buf, DHCPV6_OPTION_IAPREFIX, &opt, sizeof opt);
}

#undef LOG_DOMAIN

#define LOG_DOMAIN	LOG_DOMAIN_IAPD

static dhcp_time_t dhcp_iapd_min_valid_tm(struct dhcp_iapd const *iapd,
					  unsigned int margin)
{
	dhcp_time_t	res = TIME_INFINITY;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].active;
		dhcp_time_t			tm;

		if (!dhcp_iaprefix_is_used(prefix))
			continue;

		tm = time_add_lt(prefix->lease_tm, prefix->valid_lt, margin);

		if (time_cmp(tm, res) < 0)
			res = tm;
	}

	return res;
}

static dhcp_time_t dhcp_iapd_min_pref_tm(struct dhcp_iapd const *iapd,
					 unsigned int margin)
{
	dhcp_time_t	res = TIME_INFINITY;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].active;
		dhcp_time_t			tm;

		if (!dhcp_iaprefix_is_used(prefix))
			continue;

		tm = time_add_lt(prefix->lease_tm, prefix->pref_lt, margin);

		if (time_cmp(tm, res) < 0)
			res = tm;
	}

	return res;
}

static void dhcp_iapd_validate(struct dhcp_iapd const *iapd)
{
	struct dhcp_states const	*state = &STATES[iapd->state];

	assert(iapd->state < ARRAY_SIZE(STATES));
	assert(iapd->iostate <= IAPD_IOSTATE_TIMEOUT);
	assert(!state->req_serverid || iapd->server.has_id);
	assert(iapd->active.t1 <= iapd->active.t2);
	assert(iapd->pending.t1 <= iapd->pending.t2);

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		dhcp_iaprefix_validate(&iapd->iaprefix[i].active);
		dhcp_iaprefix_validate(&iapd->iaprefix[i].pending);
	}
}

static bool is_reliability_timeout_complete(struct dhcp_iapd const *iapd,
					    dhcp_time_t now)
{
	struct dhcpv6_reliability const	*rel = &iapd->reliability;

	/* https://tools.ietf.org/html/rfc3315#section-17.1.2 */

	/* For SOLICIT state: wait at least one RT time for the first message
	 * to arrive*/
	if (iapd->state != IAPD_STATE_SOLICIT ||
	    iapd->iostate != IAPD_IOSTATE_RECV ||
	    time_cmp(now, dhcpv6_reliability_get_irt(rel)) < 0)
		return false;

	/* TODO: do further checks? */
	return iapd->server.has_id;
}

static void finish_ia_pd(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned int	num_prefix = 0;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].pending;

		if (!dhcp_iaprefix_is_used(prefix))
			continue;

		++num_prefix;
	}

	if (iapd->state == IAPD_STATE_RELEASE)
		/* add a dummy prefix for RELEASE */
		++num_prefix;

	if (num_prefix == 0) {
		pr_warn("IAPD: finished without valid prefix (%pA)", iapd);
		iapd->iostate = IAPD_IOSTATE_ERROR;
	} else {
		pr_debug(">>>>>>>>>> IAPD finished: %pA", iapd);
		iapd->iostate = IAPD_IOSTATE_DONE;
	}

	if (iapd->iostate == IAPD_IOSTATE_DONE)
		dhcp_iapd_run_script(iapd, ctx, STATES[iapd->state].name);
}

dhcp_time_t dhcp_iapd_step(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	dhcp_time_t			now = ctx->now;
	dhcp_time_t			timeout = TIME_INFINITY;
	struct dhcpv6_reliability	*rel = &iapd->reliability;
	struct dhcp_states const	*state = &STATES[iapd->state];

	pr_enter("%pA, reliability [%pE]", iapd, rel);

	dhcp_iapd_validate(iapd);
	assert(state->tm_margin != 0 ||
	       (state->t1_to == IAPD_STATE_NONE &&
		state->t2_to == IAPD_STATE_NONE &&
		state->pref_to == IAPD_STATE_NONE &&
		state->valid_to == IAPD_STATE_NONE));

	if (iapd->state == IAPD_STATE_UNUSED)
		return TIME_INFINITY;

	/* check #1: test T2 */
	if (state->t2_to != IAPD_STATE_NONE) {
		dhcp_time_t	tm = time_add_lt(iapd->active.lease_tm,
						 iapd->active.t2, 100);

		if (time_cmp(tm, now) < 0) {
			pr_debug("%s T2 reached; going to %s", state->name,
				 STATES[state->t2_to].name);
			iapd->state = state->t2_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}

		timeout = time_min(timeout, tm);
	}

	/* check #2: test valid-tm of all iaprefix */
	if (state->valid_to != IAPD_STATE_NONE) {
		dhcp_time_t	to;

		to = dhcp_iapd_min_valid_tm(iapd, state->tm_margin);
		if (time_cmp(to, now) < 0) {
			pr_debug("%s valid tm %pT reached; going to %s",
				 state->name, &to, STATES[state->valid_to].name);
			iapd->state = state->valid_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}

		timeout = time_min(timeout, to);
	}

	/* check #3: test T1 */
	if (state->t1_to != IAPD_STATE_NONE) {
		dhcp_time_t	tm = time_add_lt(iapd->active.lease_tm,
						 iapd->active.t1, 100);

		if (time_cmp(tm, now) < 0) {
			pr_debug("%s T1 reached; going to %s", state->name,
				 STATES[state->t1_to].name);
			iapd->state = state->t1_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}

		timeout = time_min(timeout, tm);
	}

	/* check #4: test pref-tm of all iaprefix */
	if (state->pref_to != IAPD_STATE_NONE) {
		dhcp_time_t	to;

		to = dhcp_iapd_min_pref_tm(iapd, state->tm_margin);

		if (time_cmp(to, now) < 0) {
			pr_warn("%s pref tm %pT reached; going to %s",
				state->name, &to, STATES[state->pref_to].name);
			iapd->state = state->pref_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}

		timeout = time_min(timeout, to);
	}

	/* check #5: check for transmission timeouts */
	if (state->rel_to != IAPD_STATE_NONE) {
		if (!dhcpv6_reliability_check(rel, now)) {
			pr_warn("%s retry timeout (%pE); going to %s",
				state->name, rel,
				STATES[state->rel_to].name);
			iapd->state = state->rel_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}
	}

	if (is_reliability_timeout_complete(iapd, now))
		finish_ia_pd(iapd, ctx);

	/* handling of INIT */

	switch (iapd->state) {
	case IAPD_STATE_NONE:
	case IAPD_STATE_UNUSED:
		pr_err("invalid state");
		abort();

	case IAPD_STATE_INIT:
		for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
			dhcp_iaprefix_init(&iapd->iaprefix[i].active,  ctx, now, true);
			dhcp_iaprefix_init(&iapd->iaprefix[i].pending, ctx, now, true);

			iapd->iaprefix[i].active.iapd = iapd;
			iapd->iaprefix[i].pending.iapd = iapd;
		}

		iapd->active.t1 = 0;
		iapd->active.t2 = 0;
		iapd->active.lease_tm = TIME_EPOCH;

		dhcp_iapd_run_script(iapd, ctx, "INIT");

		break;

	case IAPD_STATE_SOLICIT_INIT:
		iapd->do_release = false;
		iapd->do_renew   = false;
		iapd->do_request = false;
		iapd->pending.t1 = 0;
		iapd->pending.t2 = 0;
		iapd->pending.lease_tm = TIME_EPOCH;

		dhcpv6_transmission_init(&iapd->xmit, now);

		for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i)
			dhcp_iaprefix_init(&iapd->iaprefix[i].pending, ctx, now, false);

		iapd->server.has_id = false;

		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_solicit, now);
		break;

	case IAPD_STATE_REQUEST_INIT:
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_request, now);
		iapd->do_request = false;
		iapd->do_renew   = false;
		break;

	case IAPD_STATE_ACTIVE_INIT:
		for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i)
			iapd->iaprefix[i].active = iapd->iaprefix[i].pending;

		iapd->active = iapd->pending;
		dhcp_iapd_run_script(iapd, ctx, "ACTIVE");
		break;

	case IAPD_STATE_RENEW_INIT:
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_renew, now);
		dhcpv6_transmission_init(&iapd->xmit, now);
		iapd->do_renew = false;
		break;

	case IAPD_STATE_REBIND_INIT:
		/* https://tools.ietf.org/html/rfc3633#section-12.1
		 *
		 * "... with the exception that the retransmission parameters
		 * should be set as for the Confirm message"
		 */
		(void)dhcpv6_reliability_parm_rebind;
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_confirm, now);
		dhcpv6_transmission_init(&iapd->xmit, now);
		iapd->server.has_id = false;
		break;

	case IAPD_STATE_RELEASE_INIT:
		dhcp_iapd_run_script(iapd, ctx, "PRE-RELEASE");
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_release, now);
		dhcpv6_transmission_init(&iapd->xmit, now);
		break;

	case IAPD_STATE_RELEASE:
		if (iapd->iostate == IAPD_IOSTATE_DONE) {
			iapd->active.t1 = 0;
			iapd->active.t2 = 0;
			iapd->active.lease_tm = TIME_EPOCH;

			for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
				struct dhcp_iaprefix	*prefix = &iapd->iaprefix[i].active;

				prefix->net.len  = 0;
				prefix->pref_lt  = 0;
				prefix->valid_lt = 0;
				prefix->lease_tm = TIME_EPOCH;
			}
		};
		break;

	case IAPD_STATE_REQUEST:
		if (iapd->iostate == IAPD_IOSTATE_DONE) {
			if (!time_is_epoch(iapd->active.lease_tm))
				dhcp_iapd_run_script(iapd, ctx, "OLDINFO");

			for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
				struct dhcp_iaprefix	*prefix = &iapd->iaprefix[i].active;

				if (!dhcp_iaprefix_is_used(prefix))
					continue;

				pr_info("got net %pN", &prefix->net);
			}
		}
		break;

	case IAPD_STATE_ACTIVE:
	case IAPD_STATE_SOLICIT:
	case IAPD_STATE_REBIND:
	case IAPD_STATE_RENEW:
		break;
	}

	if (iapd->state == IAPD_STATE_SOLICIT_INIT && iapd->do_quit) {
		iapd->iostate = IAPD_IOSTATE_WAIT;
		timeout = TIME_EPOCH;
	} else if (state->no_io) {
		iapd->iostate = IAPD_IOSTATE_DONE;
	}

	/* regular iostate transition */

	switch (iapd->iostate) {
	case IAPD_IOSTATE_RECV: {
		dhcp_time_t	to = dhcpv6_reliability_get_rt(rel);

		if (time_cmp(to, now) < 0) {
			pr_warn("%s timeout; retrying", state->name);
			iapd->iostate = IAPD_IOSTATE_SEND;
			goto out;
		}

		/* https://tools.ietf.org/html/rfc3315#section-17.1.2
		 *
		 * see is_reliability_timeout_complete() too */
		if (iapd->state == IAPD_STATE_SOLICIT && iapd->server.has_id) {
			to = dhcpv6_reliability_get_irt(rel);
			/* we should not reach this because times do not
			 * change between is_reliability_timeout_complete()
			 * and this check... */
			if (time_cmp(to, now) < 0) {
				pr_err("INTERNAL ERROR: initial SOLICIT timeout raced");
				to = now;
			}
		}

		timeout = time_min(timeout, to);
		break;
	}

	case IAPD_IOSTATE_DONE:
		assert(state->done != IAPD_STATE_NONE);

		iapd->state = state->done;
		if (STATES[iapd->state].no_io ||
		    STATES[iapd->state].done == IAPD_STATE_NONE)
			iapd->iostate = IAPD_IOSTATE_NONE;
		else
			iapd->iostate = IAPD_IOSTATE_SEND;

		break;

	case IAPD_IOSTATE_ERROR:
		assert(state->error != IAPD_STATE_NONE);

		iapd->state = state->error;
		if (STATES[iapd->state].done == IAPD_STATE_NONE)
			iapd->iostate = IAPD_IOSTATE_WAIT;
		else
			iapd->iostate = IAPD_IOSTATE_SEND;

		break;

	case IAPD_IOSTATE_WAIT:
		if (iapd->do_release) {
			dhcp_iapd_run_script(iapd, ctx, "FORCE-RELEASE");
			iapd->state   = IAPD_STATE_RELEASE_INIT;
			iapd->iostate = IAPD_IOSTATE_NONE;
		} else if (iapd->do_request && iapd->server.has_id) {
			dhcp_iapd_run_script(iapd, ctx, "FORCE-REQUEST");
			iapd->state   = IAPD_STATE_REQUEST_INIT;
			iapd->iostate = IAPD_IOSTATE_NONE;
		} else if (iapd->do_renew && iapd->server.has_id) {
			dhcp_iapd_run_script(iapd, ctx, "FORCE-RENEW");
			iapd->state   = IAPD_STATE_RENEW_INIT;
			iapd->iostate = IAPD_IOSTATE_NONE;
		} else if (iapd->do_request || iapd->do_renew) {
			dhcp_iapd_run_script(iapd, ctx, "FORCE-SOLICIT");
			iapd->state   = IAPD_STATE_SOLICIT_INIT;
			iapd->iostate = IAPD_IOSTATE_NONE;
		}
		break;

	case IAPD_IOSTATE_NONE:
	case IAPD_IOSTATE_SEND:
	case IAPD_IOSTATE_TIMEOUT:
		break;
	}

out:
	dhcp_iapd_validate(iapd);

	pr_leave("%pA; timeout %pT", iapd, &timeout);

	switch (iapd->iostate) {
	case IAPD_IOSTATE_SEND:
	case IAPD_IOSTATE_NONE:
	case IAPD_IOSTATE_DONE:
	case IAPD_IOSTATE_ERROR:
	case IAPD_IOSTATE_TIMEOUT:
		return TIME_EPOCH;

	case IAPD_IOSTATE_RECV:
	case IAPD_IOSTATE_WAIT:
		return timeout;
	}

	abort();
}

static void handle_iaprefix_noprefixavail(struct dhcp_iapd *iapd)
{
	enum iapd_prefix_selection	sel;

	switch (iapd->state) {
	case IAPD_STATE_REQUEST:
		sel = IAPD_PREFIX_SEL_PENDING;
		break;

	case IAPD_STATE_RENEW:
		/* on no-prefix-available during RENEW, reset lifetimes which
		   will trigger the condition in check #3 */
		sel = IAPD_PREFIX_SEL_ACTIVE;
		break;

	default:
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix	*tmp = get_iaprefix(iapd, i, sel);

		tmp->pref_lt  = 0;
		tmp->valid_lt = 0;

		switch (iapd->state) {
		case IAPD_STATE_REQUEST:
			tmp->lease_tm = TIME_EPOCH;
			tmp->net.len  = 0;
			memset(&tmp->net.prefix, 0, sizeof tmp->net.prefix);
			break;

		default:
			break;
		}
	}

	iapd->iostate = IAPD_IOSTATE_ERROR;
}

static uint32_t get_be32_lt(struct dhcp_context const *ctx, be32_t lt_)
{
	uint32_t	lt = be32_to_cpu(lt_);

	if (ctx->max_lt > 0 && ctx->max_lt < lt)
		return ctx->max_lt;
	else
		return lt;
}

/**
 *
 *  Return:
 *  0 on success, -1 on error, +1 when prefix can not be registered
 */
static int handle_ia_prefix(struct dhcp_iapd *iapd, struct dhcp_context *ctx,
			    struct dhcpv6_option_iaprefix const *opt_prefix,
			    size_t len)
{
	struct dhcpv6_option_hdr const		*opt_first;
	struct dhcp_iaprefix	*prefix = NULL;
	uint32_t		valid_lt = get_be32_lt(ctx, opt_prefix->valid_lftm);
	uint32_t		pref_lt = get_be32_lt(ctx, opt_prefix->pref_lftm);

	dhcp_time_t		valid_tm = time_add_lt(ctx->now, valid_lt, 100);
	dhcp_time_t		pref_tm = time_add_lt(ctx->now, pref_lt, 100);
	unsigned int		status_code = 0;

	struct dhcpv6_network	net;
	int			rc;

	if (pref_lt > valid_lt) {
		pr_warn("IAPREFIX pref-lt > valid-lt (%u, %u)", pref_lt,
			valid_lt);
		return -1;
	}

	if (valid_lt == 0 && iapd->state != IAPD_STATE_REQUEST) {
		pr_warn("IAPREFIX valid-lt is zero");
		return -1;
	}

	len -= sizeof *opt_prefix;
	opt_first = dhcpv6_validated_option((void *)&opt_prefix[1], len);

	if (len > 0 && !opt_first) {
		pr_err("IAPRERFIX: bad layout");
		return -1;
	}

	rc = 0;
	dhcpv6_foreach_option_next(opt, opt_first, &len) {
		unsigned int		emb_code  = be16_to_cpu(opt->option);
		unsigned int		emb_len   = dhcpv6_get_option_len(opt);
		void const		*emb_data = dhcpv6_get_option_data(opt);

		pr_debug("IAPREFIX EMBOPTION: %s(+%u)",
			 dhcpv6_option_to_str(emb_code), emb_len);

		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_STATUS_CODE:
			if (emb_len < 2) {
				pr_err("bad STATUS CODE");
				rc = -1;
			} else {
				status_code = dhcpv6_read_status_code(emb_data, emb_len);
			}

			break;

		default:
			pr_warn("unsupported EMBOPTION %s(%d)+%u",
				dhcpv6_option_to_str(emb_code), emb_code,
				emb_len);
			break;
		}

		if (rc < 0)
			break;
	}

	if (rc < 0)
		return -1;

	switch (status_code) {
	case DHCPV6_STATUS_CODE_SUCCESS:
		break;

	case DHCPV6_STATUS_CODE_NOPREFIXAVAIL:
		handle_iaprefix_noprefixavail(iapd);
		return -1;

	default:
		return -1;
	}

	rc = dhcpv6_network_assign(&net, opt_prefix->prefix,
				   opt_prefix->prefix_len);
	if (rc < 0) {
		pr_warn("IAPREFIX bad prefix (len %d)", opt_prefix->prefix_len);
		return -1;
	}

	if (net.len == 0) {
		pr_warn("IAPREFIX: invalid network %pN", &net);
		return -1;
	}

	/* find a slot for the prefix; check for (in this order):
	 *
	 * 1. the same network
	 * 2. outdated prefixes
	 * 3. prefixes with smaller networks
	 * 4. prefixes with lower valid-lt
	 * 5. prefixes with lower pref-lt
	 */
	/* TODO: in case of "same network": check lifetimes too? */
	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix		*tmp = &iapd->iaprefix[i].pending;
		dhcp_time_t			tmp_valid =
			time_add_lt(tmp->lease_tm, tmp->valid_lt, 100);
		dhcp_time_t			tmp_pref =
			time_add_lt(tmp->lease_tm, tmp->pref_lt, 100);

		dhcp_iaprefix_validate(tmp);

		if (dhcpv6_network_cmp(&tmp->net, &net) == 0)
			prefix = tmp;
		else if (time_cmp(tmp_valid, ctx->now) < 0 ||
			 tmp->net.len < net.len ||
			 time_cmp(tmp_valid, valid_tm) < 0 ||
			 time_cmp(tmp_pref, pref_tm))
			prefix = tmp;
		else
			continue;

		break;
	}

	if (!prefix) {
		pr_warn("IAPREFIX: no free slot for prefix");
		return 1;
	}

	prefix->net = net;
	prefix->pref_lt = pref_lt;
	prefix->valid_lt = valid_lt;
	prefix->lease_tm = ctx->now;

	pr_debug("iaprefix: %pR", prefix);

	dhcp_iaprefix_validate(prefix);
	dhcp_iapd_validate(iapd);

	return 0;
}

static int handle_ia_pd(struct dhcp_iapd *iapd, struct dhcp_context *ctx,
			struct dhcpv6_option_iapd const *opt_iapd,
			size_t len)
{
	struct dhcpv6_option_hdr const		*opt_first;
	int					rc;
	unsigned int				status_code = DHCPV6_STATUS_CODE_SUCCESS;

	pr_debug("IAPD: handling incoming data");

	if (len < sizeof *opt_iapd) {
		pr_warn("IAPD: too small IA_PD option");
		return -1;
	}

	if (be32_to_cpu(opt_iapd->id) != iapd->id) {
		pr_warn("IAPD: id mismatch");
		return 1;
	}

	len -= sizeof *opt_iapd;
	opt_first = dhcpv6_validated_option((void *)&opt_iapd[1], len);

	if (!opt_first) {
		pr_err("IAPD: bad layout; no embedded option");
		return -1;
	}

	if (be32_to_cpu(opt_iapd->t1) > be32_to_cpu(opt_iapd->t2) &&
	    be32_to_cpu(opt_iapd->t2) > 0) {
		/* RFC 3633: If a requesting router receives an IA_PD with T1
		   greater than T2, and both T1 and T2 are greater than 0, the
		   client discards the IA_PD option and processes the
		   remainder of the message as though the delegating router
		   had not included the IA_PD option. */
		pr_debug("bad T1/T2 (%u, %u)\n",
			 be32_to_cpu(opt_iapd->t1),
			 be32_to_cpu(opt_iapd->t2));

		return 0;
	}

	rc = 0;
	dhcpv6_foreach_option_next(opt, opt_first, &len) {
		struct dhcpv6_option_iaprefix const	*tmp;
		unsigned int		emb_code  = be16_to_cpu(opt->option);
		unsigned int		emb_len   = dhcpv6_get_option_len(opt);
		void const		*emb_data = dhcpv6_get_option_data(opt);

		pr_debug("EMBOPTION: %s(+%u)",
			 dhcpv6_option_to_str(emb_code), emb_len);

		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_IAPREFIX:
			if (emb_len < sizeof *tmp) {
				pr_warn("malformed IAPREFIX option");
				rc = -1;
			} else {
				rc = handle_ia_prefix(iapd, ctx, emb_data, emb_len);
			}
			break;

		case DHCPV6_OPTION_STATUS_CODE:
			if (emb_len < 2) {
				pr_err("bad STATUS CODE");
				rc = -1;
			} else {
				status_code = dhcpv6_read_status_code(emb_data, emb_len);
			}

			break;

		default:
			pr_warn("unsupported EMBOPTION %s(%d)+%u",
				dhcpv6_option_to_str(emb_code), emb_code,
				emb_len);
			break;
		}

		if (rc < 0)
			break;
	}

	if (rc < 0)
		goto out;

	switch (status_code) {
	case DHCPV6_STATUS_CODE_SUCCESS:
		break;

	case DHCPV6_STATUS_CODE_NOPREFIXAVAIL:
		handle_iaprefix_noprefixavail(iapd);
		rc = -1;
		break;

	default:
		pr_warn("resetting lease time");

		if (iapd->state == IAPD_STATE_RENEW ||
		    iapd->state == IAPD_STATE_REBIND) {
			iapd->active.lease_tm = TIME_EPOCH;
			rc = -1;
		}
		break;
	}

	if (rc < 0)
		goto out;

	iapd->pending.t1 = get_be32_lt(ctx, opt_iapd->t1);
	iapd->pending.t2 = get_be32_lt(ctx, opt_iapd->t2);
	iapd->pending.lease_tm = ctx->now;

	switch (iapd->state) {
	case IAPD_STATE_SOLICIT:
	case IAPD_STATE_REBIND:
		dhcpv6_duid_from_opt(&iapd->server.id, ctx->server.opt);

		iapd->server.addr = ctx->server.addr.sin6_addr;
		iapd->server.preference = ctx->server.pref;
		iapd->server.has_id = true;
		iapd->server.is_unicast = ctx->server.is_unicast;
		break;

	case IAPD_STATE_REQUEST:
	case IAPD_STATE_RENEW:
		break;

	default:
		abort();
		break;
	}

out:
	dhcp_iapd_validate(iapd);

	return rc;
}

int dhcp_iapd_recv(struct dhcp_iapd *iapd, struct dhcp_context *ctx,
		   struct dhcpv6_message_hdr const *hdr, size_t len)
{
	struct dhcp_states const	*state = &STATES[iapd->state];
	size_t				tmp_len = len;
	bool				resp_matching;
	int				rc;

	pr_enter("%pA", iapd);

	assert(ctx->server.opt != NULL);
	dhcp_iapd_validate(iapd);

	switch (hdr->type) {
	case DHCPV6_TYPE_ADVERTISE:
		resp_matching = iapd->state == IAPD_STATE_SOLICIT;
		break;

	case DHCPV6_TYPE_REPLY:
		resp_matching = (iapd->state == IAPD_STATE_REQUEST ||
				 iapd->state == IAPD_STATE_RELEASE ||
				 iapd->state == IAPD_STATE_RENEW ||
				 iapd->state == IAPD_STATE_REBIND);
		break;

	default:
		resp_matching = false;
		break;
	}

	if (!resp_matching) {
		pr_warn("response does not match IAPD state");
		return 1;
	}

	if (iapd->iostate != IAPD_IOSTATE_RECV) {
		pr_warn("not in RECV state");
		return 1;
	}

	if (memcmp(iapd->xmit.xmit_id, hdr->xmit_id, sizeof hdr->xmit_id) != 0) {
		pr_debug("xmit id mismatch");
		return 1;
	}

	if (dhcpv6_duid_cmp_opt(&iapd->server.id, ctx->server.opt) != 0) {
		if (state->req_serverid) {
			pr_debug("SERVERID mismatch");
			return 1;
		}

		if (iapd->server.preference < ctx->server.pref) {
			pr_debug("response from server with lower preference; ignoring");
			return 1;
		}
	}

	switch (ctx->status_code) {
	case DHCPV6_STATUS_CODE_SUCCESS:
		break;

	case DHCPV6_STATUS_CODE_NOADDRSAVAIL:
		/* https://tools.ietf.org/html/rfc3315#section-17.1.3 */
		if (iapd->state == IAPD_STATE_SOLICIT) {
			pr_info("SOLICIT:  no addrs available; ignoring");
			return 1;
		}

		iapd->iostate = IAPD_IOSTATE_ERROR;
		pr_warn("no addrs available");
		return 1;

	default:
		iapd->iostate = IAPD_IOSTATE_ERROR;
		pr_warn("bad status code from serer: %d", ctx->status_code);
		return 1;
	}

	rc = 0;
	dhcpv6_foreach_option(opt, hdr, &tmp_len) {
		switch (be16_to_cpu(opt->option)) {
		case DHCPV6_OPTION_IA_PD:
			rc = handle_ia_pd(iapd, ctx,
					  dhcpv6_get_option_data(opt),
					  dhcpv6_get_option_len(opt));
			break;
		}

		if (rc < 0)
			break;
	}

	if (rc < 0)
		goto out;

	if (ctx->server.pref == 255 ||
	    iapd->state == IAPD_STATE_RELEASE ||
	    iapd->state == IAPD_STATE_REQUEST ||
	    iapd->state == IAPD_STATE_RENEW)
		finish_ia_pd(iapd, ctx);

out:
	pr_leave("%pA; rc=%d", iapd, rc);

	dhcp_iapd_validate(iapd);

	return rc;
}

static bool fill_iapd_option(struct dhcp_buffer *buf,
			     struct dhcp_iapd *iapd,
			     struct dhcpv6_option_iapd const *opt_iapd,
			     enum iapd_prefix_selection sel)
{
	size_t			offset = sizeof *opt_iapd;

	if (sel == IAPD_PREFIX_SEL_NONE)
		return buffer_add_option(buf, DHCPV6_OPTION_IA_PD,
					 opt_iapd, sizeof *opt_iapd);

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_buffer		buf_iaprefix;
		struct dhcp_iaprefix const	*iaprefix = get_iaprefix(iapd, i, sel);

		if (!iaprefix)
			continue;

		/* TODO: create some abstraction for this test */
		if (sel != IAPD_PREFIX_SEL_PREF &&
		    !dhcp_iaprefix_is_used(iaprefix))
			continue;

		pr_debug("adding IAPREFIX %pR", iaprefix);

		if (!buffer_init_subbuffer(buf, &buf_iaprefix, offset) ||
		    !buffer_add_iaprefix(&buf_iaprefix, iaprefix, sel)) {
			pr_err("failed to add iaprefix buffer");
			return false;
		}

		offset += buf_iaprefix.len;
	}

	return buffer_add_raw(buf, DHCPV6_OPTION_IA_PD, opt_iapd,
			      sizeof *opt_iapd, offset - sizeof *opt_iapd);
}

static int send_dhcp_buffer(struct dhcp_iapd *iapd,
			    struct dhcp_context *ctx,
			    struct dhcp_buffer const *buf,
			    struct dhcpv6_server const *server)
{
	struct sockaddr_in6	addr = {
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(547),
		.sin6_scope_id	= ctx->ifidx,
	};
	ssize_t			l;

	pr_debug("sending dhcp buffer of size %zu", buf->len);

	assert(iapd->iostate == IAPD_IOSTATE_SEND);

	dhcpv6_reliability_next(&iapd->reliability, ctx->now);

	if (server && server->is_unicast)
		addr.sin6_addr = server->addr;
	else
		inet_pton(AF_INET6, "ff02::1:2", &addr.sin6_addr);

	l = sendto(ctx->fd, buf->data, buf->len, 0, &addr, sizeof addr);
	if (l < 0) {
		if (errno == ENETUNREACH)
			ctx->err_no_net = true;

		pr_err("sendto(): %s", strerror(errno));
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	if ((size_t)l != buf->len) {
		pr_err("sendto(): sent unexpected number of bytes (%zd vs. %zu)",
		       l, buf->len);
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	iapd->iostate = IAPD_IOSTATE_RECV;

	return 0;
}

struct uint32_2 {
	uint32_t	t1;
	uint32_t	t2;
};

static struct uint32_2 get_iapd_pref(struct dhcp_iapd const *iapd,
				     struct dhcp_context const *ctx)
{
	struct uint32_2	t = {
		.t1	= 0,
		.t2	= 0,
	};

	if (iapd->preferences.is_set) {
		t.t1 = iapd->preferences.t1;
		t.t2 = iapd->preferences.t2;
	}

	if (ctx->max_lt > 0) {
		t.t1 = MIN(t.t1, ctx->max_lt);
		t.t1 = MIN(t.t2, ctx->max_lt);
	}

	return t;
}

static int send_solicit(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned char		raw[DHCPV6_MAX_DUID_SZ + 512];
	struct dhcp_buffer	buf = {
		.data		= raw,
		.len		= 0,
		.max_len	= sizeof raw,
	};

	struct uint32_2		t = get_iapd_pref(iapd, ctx);

	struct dhcpv6_option_iapd	opt_iapd = {
		.id	= CPU_TO_BE32(iapd->id),
		.t1	= CPU_TO_BE32(t.t1),
		.t2	= CPU_TO_BE32(t.t2),
	};

	int			rc;

	if (!request_init(&buf, DHCPV6_TYPE_SOLICIT, ctx, &iapd->xmit) ||
	    !fill_iapd_option(&buf, iapd, &opt_iapd, IAPD_PREFIX_SEL_PREF)) {
		pr_err("SOLICIT: failed to initialize DHCPv6 message");
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	rc = send_dhcp_buffer(iapd, ctx, &buf, NULL);
	if (rc < 0)
		return -1;

	return 0;
}

static int send_request(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned char		raw[DHCPV6_MAX_DUID_SZ + 512];
	struct dhcp_buffer	buf = {
		.data		= raw,
		.len		= 0,
		.max_len	= sizeof raw,
	};

	struct dhcpv6_option_iapd	opt_iapd = {
		.id	= CPU_TO_BE32(iapd->id),
		.t1	= CPU_TO_BE32(iapd->pending.t1),
		.t2	= CPU_TO_BE32(iapd->pending.t2),
	};

	int			rc;

	if (!request_init(&buf, DHCPV6_TYPE_REQUEST, ctx, &iapd->xmit) ||
	    !buffer_add_duid(&buf, DHCPV6_OPTION_SERVERID, &iapd->server.id) ||
	    !fill_iapd_option(&buf, iapd, &opt_iapd, IAPD_PREFIX_SEL_PENDING)) {
		pr_err("REQUEST: failed to initialize DHCPv6 message");
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	rc = send_dhcp_buffer(iapd, ctx, &buf, &iapd->server);
	if (rc < 0)
		return -1;

	return 0;
}

static int send_renew(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned char		raw[DHCPV6_MAX_DUID_SZ + 512];
	struct dhcp_buffer	buf = {
		.data		= raw,
		.len		= 0,
		.max_len	= sizeof raw,
	};

	struct dhcpv6_option_iapd	opt_iapd = {
		.id	= CPU_TO_BE32(iapd->id),
		.t1	= CPU_TO_BE32(iapd->active.t1),
		.t2	= CPU_TO_BE32(iapd->active.t2),
	};

	int			rc;

	if (!request_init(&buf, DHCPV6_TYPE_RENEW, ctx, &iapd->xmit) ||
	    !buffer_add_duid(&buf, DHCPV6_OPTION_SERVERID, &iapd->server.id) ||
	    !fill_iapd_option(&buf, iapd, &opt_iapd, IAPD_PREFIX_SEL_ACTIVE)) {
		pr_err("RENEW: failed to initialize DHCPv6 message");
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	rc = send_dhcp_buffer(iapd, ctx, &buf, &iapd->server);
	if (rc < 0)
		return -1;

	return 0;
}


static int send_rebind(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned char		raw[DHCPV6_MAX_DUID_SZ + 512];
	struct dhcp_buffer	buf = {
		.data		= raw,
		.len		= 0,
		.max_len	= sizeof raw,
	};

	struct dhcpv6_option_iapd	opt_iapd = {
		.id	= CPU_TO_BE32(iapd->id),
		.t1	= CPU_TO_BE32(iapd->active.t1),
		.t2	= CPU_TO_BE32(iapd->active.t2),
	};

	int			rc;

	if (!request_init(&buf, DHCPV6_TYPE_REBIND, ctx, &iapd->xmit) ||
	    !fill_iapd_option(&buf, iapd, &opt_iapd, IAPD_PREFIX_SEL_ACTIVE)) {
		pr_err("REBIND: failed to initialize DHCPv6 message");
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	rc = send_dhcp_buffer(iapd, ctx, &buf, NULL);
	if (rc < 0)
		return -1;

	return 0;
}

static int send_release(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned char		raw[DHCPV6_MAX_DUID_SZ + 512];
	struct dhcp_buffer	buf = {
		.data		= raw,
		.len		= 0,
		.max_len	= sizeof raw,
	};

	struct dhcpv6_option_iapd	opt_iapd = {
		.id	= CPU_TO_BE32(iapd->id),
		.t1	= CPU_TO_BE32(iapd->active.t1),
		.t2	= CPU_TO_BE32(iapd->active.t2),
	};

	int			rc;

	if (!request_init(&buf, DHCPV6_TYPE_RELEASE, ctx, &iapd->xmit) ||
	    !buffer_add_duid(&buf, DHCPV6_OPTION_SERVERID, &iapd->server.id) ||
	    !fill_iapd_option(&buf, iapd, &opt_iapd, IAPD_PREFIX_SEL_ACTIVE)) {
		pr_err("RELEASE: failed to initialize DHCPv6 message");
		iapd->iostate = IAPD_IOSTATE_ERROR;
		return -1;
	}

	rc = send_dhcp_buffer(iapd, ctx, &buf, &iapd->server);
	if (rc < 0)
		return -1;

	return 0;
}

int dhcp_iapd_run(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	struct dhcp_states const	*state = &STATES[iapd->state];
	int				rc;

	pr_enter("%pA", iapd);

	rc = -1;
	switch (iapd->state) {
	case IAPD_STATE_SOLICIT:
		if (iapd->iostate == IAPD_IOSTATE_SEND)
			rc = send_solicit(iapd, ctx);

		break;

	case IAPD_STATE_REQUEST:
		if (iapd->iostate == IAPD_IOSTATE_SEND)
			rc = send_request(iapd, ctx);

		break;

	case IAPD_STATE_RENEW:
		if (iapd->iostate == IAPD_IOSTATE_SEND)
			rc = send_renew(iapd, ctx);

		break;

	case IAPD_STATE_REBIND:
		if (iapd->iostate == IAPD_IOSTATE_SEND)
			rc = send_rebind(iapd, ctx);

		break;

	case IAPD_STATE_RELEASE:
		if (!iapd->server.has_id) {
			iapd->iostate = IAPD_IOSTATE_DONE;
			rc = 0;
		} else if (iapd->iostate == IAPD_IOSTATE_SEND) {
			rc = send_release(iapd, ctx);
		}

		break;

	case IAPD_STATE_ACTIVE:
		if (iapd->iostate == IAPD_IOSTATE_NONE) {
			iapd->iostate = IAPD_IOSTATE_WAIT;
			rc = 0;
		} else if (iapd->iostate == IAPD_IOSTATE_WAIT) {
			rc = 0;
		}
		break;

	default:
		if (state->no_io)
			rc = 0;
		break;
	};

	if (rc < 0)
		goto out;

out:
	pr_leave("%pA; rc=%d", iapd, rc);
	dhcp_iapd_validate(iapd);

	/* TODO */
	return rc;
}
