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

#include <stdbool.h>
#include <stdlib.h>
#include <sys/param.h>

#include "../ensc-lib/compiler.h"

#include "logging.h"
#include "dhcpv6.h"

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
};

static struct dhcp_states const	STATES[] = {
	[IAPD_STATE_INIT] = {
		.name		= "INIT",
		.done		= IAPD_STATE_SOLICATE_INIT,
		.no_io		= true,
	},

	[IAPD_STATE_SOLICATE_INIT] = {
		.name		= "SOLICATE-INIT",
		.done		= IAPD_STATE_SOLICATE,
		.no_io		= true,
	},

	[IAPD_STATE_SOLICATE]	= {
		.name		= "SOLICATE",
		.rel_to		= IAPD_STATE_INIT,
		.done		= IAPD_STATE_REQUEST_INIT,
		.error		= IAPD_STATE_SOLICATE_INIT,
	},

	[IAPD_STATE_REQUEST_INIT] = {
		.name		= "REQUEST-INIT",
		.done		= IAPD_STATE_REQUEST,
		.no_io		= true,
	},

	[IAPD_STATE_REQUEST]	= {
		.name		= "REQUEST",
		.rel_to		= IAPD_STATE_SOLICATE_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_SOLICATE_INIT,
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
		.valid_to	= IAPD_STATE_SOLICATE_INIT,
		.t1_to		= IAPD_STATE_RENEW_INIT,
		.t2_to		= IAPD_STATE_REBIND_INIT,
	},

	[IAPD_STATE_RENEW_INIT] = {
		.name		= "RENEW-INIT",
		.done		= IAPD_STATE_RENEW,
		.no_io		= true,
	},

	[IAPD_STATE_RENEW] = {
		.name		= "RENEW",
		.rel_to		= IAPD_STATE_SOLICATE_INIT,
		.valid_to	= IAPD_STATE_SOLICATE_INIT,
		.t2_to		= IAPD_STATE_REBIND_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_REBIND_INIT,
		.req_serverid	= true,
	},

	[IAPD_STATE_REBIND_INIT] = {
		.name		= "REBIND-INIT",
		.done		= IAPD_STATE_RENEW,
		.no_io		= true,
	},

	[IAPD_STATE_REBIND] = {
		.name		= "REBIND",
		.rel_to		= IAPD_STATE_SOLICATE_INIT,
		.valid_to	= IAPD_STATE_SOLICATE_INIT,
		.done		= IAPD_STATE_ACTIVE_INIT,
		.error		= IAPD_STATE_SOLICATE_INIT,
	},
};

/** https://tools.ietf.org/html/rfc3315#section-5.5 */

/** https://tools.ietf.org/html/rfc3315#section-17.1.2 */
static struct dhcpv6_reliability_parm const	dhcpv6_reliability_parm_solicate = {
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

static void dhcp_iaprefix_validate(struct dhcp_iaprefix const *prefix)
{
	assert(time_cmp(prefix->pref_tm, prefix->valid_tm) <= 0);
	assert(prefix->net.len <= 64);
	assert(prefix->pref_lt <= prefix->valid_lt);
}

static void dhcp_iaprefix_init(struct dhcp_iaprefix *prefix, dhcp_time_t now,
			       bool init_addr)
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

	prefix->pref_tm = TIME_EPOCH;
	prefix->valid_tm = TIME_EPOCH;

	dhcp_iaprefix_validate(prefix);
}

#define LOG_DOMAIN	LOG_DOMAIN_IAPD

static dhcp_time_t dhcp_iapd_min_valid_tm(struct dhcp_iapd const *iapd)
{
	dhcp_time_t	res = TIME_INFINITY;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].active;

		if (time_cmp(prefix->valid_tm, res) < 0)
			res = prefix->valid_tm;
	}

	return res;
}

static dhcp_time_t dhcp_iapd_min_pref_tm(struct dhcp_iapd const *iapd)
{
	dhcp_time_t	res = TIME_INFINITY;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].active;

		if (time_cmp(prefix->pref_tm, res) < 0)
			res = prefix->pref_tm;
	}

	return res;
}

static void dhcp_iapd_validate(struct dhcp_iapd const *iapd)
{
	struct dhcp_states const	*state = &STATES[iapd->state];

	assert(iapd->state < ARRAY_SIZE(STATES));
	assert(iapd->iostate <= IAPD_IOSTATE_TIMEOUT);
	assert(!state->req_serverid || iapd->server.has_id);
	assert(time_cmp(iapd->active.lease_t1, iapd->active.lease_t2) <= 0);
	assert(time_cmp(iapd->pending.lease_t1, iapd->pending.lease_t2) <= 0);

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		dhcp_iaprefix_validate(&iapd->iaprefix[i].active);
		dhcp_iaprefix_validate(&iapd->iaprefix[i].pending);
	}
}

dhcp_time_t dhcp_iapd_step(struct dhcp_iapd *iapd, dhcp_time_t now)
{
	dhcp_time_t			timeout = TIME_INFINITY;
	struct dhcpv6_reliability	*rel = &iapd->reliability;
	struct dhcp_states const	*state = &STATES[iapd->state];

	pr_enter("%pA", iapd);

	dhcp_iapd_validate(iapd);

	if (iapd->state == IAPD_STATE_UNUSED)
		return TIME_INFINITY;

	/* check #1: test T2 */
	if (state->t2_to != IAPD_STATE_NONE) {
		if (time_cmp(iapd->active.lease_t2, now) < 0) {
			pr_warn("%s T2 reached; going to %s", state->name,
				STATES[state->t2_to].name);
			iapd->state = state->t2_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}			

		timeout = time_min(timeout, iapd->active.lease_t2);
	}

	/* check #2: test valid-tm of all iaprefix */
	if (state->valid_to != IAPD_STATE_NONE) {
		dhcp_time_t	to;

		to = dhcp_iapd_min_valid_tm(iapd);
		
		if (time_cmp(to, now) < 0) {
			pr_warn("%s valid tm reached; going to %s", state->name,
				STATES[state->valid_to].name);
			iapd->state = state->valid_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}			

		timeout = time_min(timeout, to);
	}

	/* check #3: test T1 */
	if (state->t1_to != IAPD_STATE_NONE) {
		if (time_cmp(iapd->active.lease_t1, now) < 0) {
			pr_warn("%s T1 reached; going to %s", state->name,
				STATES[state->t1_to].name);
			iapd->state = state->t1_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}			

		timeout = time_min(timeout, iapd->active.lease_t1);
	}

	/* check #4: test pref-tm of all iaprefix */
	if (state->pref_to != IAPD_STATE_NONE) {
		dhcp_time_t	to;

		to = dhcp_iapd_min_pref_tm(iapd);
		
		if (time_cmp(to, now) < 0) {
			pr_warn("%s pref tm reached; going to %s", state->name,
				STATES[state->pref_to].name);
			iapd->state = state->pref_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}			

		timeout = time_min(timeout, to);
	}

	/* check #5: check for transmission timeouts */
	if (state->rel_to != IAPD_STATE_NONE) {
		if (!dhcpv6_reliability_check(rel, now)) {
			pr_warn("%s retry timeout; going to %s", state->name,
				STATES[state->rel_to].name);
			iapd->state = state->rel_to;
			iapd->iostate = IAPD_IOSTATE_TIMEOUT;
			goto out;
		}
	}

	/* handling of INIT */

	switch (iapd->state) {
	case IAPD_STATE_NONE:
	case IAPD_STATE_UNUSED:
		pr_err("invalid state");
		abort();
		
	case IAPD_STATE_INIT:
		for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
			dhcp_iaprefix_init(&iapd->iaprefix[i].active,  now, true);
			dhcp_iaprefix_init(&iapd->iaprefix[i].pending, now, true);

			iapd->iaprefix[i].active.iapd = iapd;
			iapd->iaprefix[i].pending.iapd = iapd;
		}

		iapd->active.t1 = 0;
		iapd->active.t2 = 0;
		iapd->active.lease_t1 = TIME_EPOCH;
		iapd->active.lease_t2 = TIME_EPOCH;

		break;

	case IAPD_STATE_SOLICATE_INIT:
		if (iapd->preferences.is_set) {
			iapd->pending.t1 = iapd->preferences.t1;
			iapd->pending.t2 = iapd->preferences.t2;
		} else {
			iapd->pending.t1 = 0;
			iapd->pending.t2 = 0;
		}

		iapd->pending.lease_t1 = TIME_EPOCH;
		iapd->pending.lease_t2 = TIME_EPOCH;

		dhcpv6_transmission_init(&iapd->xmit, now);

		for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i)
			dhcp_iaprefix_init(&iapd->iaprefix[i].pending, now, false);

		iapd->server.has_id = false;

		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_solicate, now);
		break;

	case IAPD_STATE_REQUEST_INIT:
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_request, now);
		break;

	case IAPD_STATE_ACTIVE_INIT:
		break;
	
	case IAPD_STATE_RENEW_INIT:
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_renew, now);
		dhcpv6_transmission_init(&iapd->xmit, now);
		break;

	case IAPD_STATE_REBIND_INIT:
		dhcpv6_reliability_init(rel, &dhcpv6_reliability_parm_rebind, now);
		dhcpv6_transmission_init(&iapd->xmit, now);
		iapd->server.has_id = false;
		break;

	case IAPD_STATE_SOLICATE:
	case IAPD_STATE_ACTIVE:
	case IAPD_STATE_REBIND:
	case IAPD_STATE_RENEW:
	case IAPD_STATE_REQUEST:
		break;
	}

	if (state->no_io)
		iapd->iostate = IAPD_IOSTATE_DONE;

	/* regular iostate transition */

	switch (iapd->iostate) {
	case IAPD_IOSTATE_RECV: {
		dhcp_time_t	to = dhcpv6_reliability_get_rt(rel);

		if (time_cmp(to, now) < 0) {
			pr_warn("%s timeout; retrying", state->name);
			iapd->iostate = IAPD_IOSTATE_SEND;
			goto out;
		}

		timeout = time_min(timeout, to);
		break;
	}

	case IAPD_IOSTATE_DONE:
		assert(state->done != IAPD_STATE_NONE);

		iapd->state = state->done;
		if (STATES[iapd->state].no_io)
			iapd->iostate = IAPD_IOSTATE_NONE;
		else if (STATES[iapd->state].done == IAPD_STATE_NONE)
			iapd->iostate = IAPD_IOSTATE_WAIT;
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

	case IAPD_IOSTATE_NONE:
	case IAPD_IOSTATE_WAIT:
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

static void finish_ia_pd(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	unsigned int	num_prefix = 0;

	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].pending;

		if (!time_is_epoch(prefix->valid_tm))
			continue;

		++num_prefix;
	}

	if (num_prefix == 0) {
		pr_warn("IAPD: finished without valid prefix");
		iapd->iostate = IAPD_IOSTATE_ERROR;
	} else {
		pr_debug("IAPD: finished");
		iapd->iostate = IAPD_IOSTATE_DONE;
	}

	pr_debug("IAPD finished: %pA", iapd);
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
	struct dhcp_iaprefix	*prefix = NULL;
	uint32_t		valid_lt = be32_to_cpu(opt_prefix->valid_lftm);
	uint32_t		pref_lt = be32_to_cpu(opt_prefix->pref_lftm);

	dhcp_time_t		valid_tm = time_add_lt(ctx->now, valid_lt);
	dhcp_time_t		pref_tm = time_add_lt(ctx->now, pref_lt);

	struct dhcpv6_network	net;
	int			rc;

	if (pref_lt > valid_lt) {
		pr_warn("IAPREFIX pref-lt > valid-lt (%u, %u)", pref_lt,
			valid_lt);
		return -1;
	}

	if (valid_lt == 0) {
		pr_warn("IAPREFIX valid-lt is zero");
		return -1;
	}

	rc = dhcpv6_network_assign(&net, opt_prefix->prefix,
				   opt_prefix->prefix_len);
	if (rc < 0) {
		pr_warn("IAPREFIX bad prefix (len %d)", opt_prefix->prefix_len);
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

		dhcp_iaprefix_validate(tmp);

		if (dhcpv6_network_cmp(&tmp->net, &net) == 0)
			prefix = tmp;
		else if (time_cmp(tmp->valid_tm, ctx->now) < 0 ||
			 tmp->net.len < net.len ||
			 time_cmp(tmp->valid_tm, valid_tm) < 0 ||
			 time_cmp(tmp->pref_tm, pref_tm))
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
	prefix->pref_tm = pref_tm;
	prefix->valid_tm = valid_tm;

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

		default:
			pr_warn("unsupported EMOPTION %s(%d)+%u",
				dhcpv6_option_to_str(emb_code), emb_code,
				emb_len);
			break;
		}

		if (rc < 0)
			break;
	}

	if (rc < 0)
		goto out;

	iapd->pending.t1 = be32_to_cpu(opt_iapd->t1);
	iapd->pending.t2 = be32_to_cpu(opt_iapd->t2);


out:
	dhcp_iapd_validate(iapd);

	return rc;
}

int dhcp_iapd_recv(struct dhcp_iapd *iapd, struct dhcp_context *ctx,
		   struct dhcpv6_message_hdr const *hdr, size_t len)
{
	struct dhcp_states const	*state = &STATES[iapd->state];
	size_t				tmp_len = len;
	int				rc;

	pr_enter("%pA", iapd);

	assert(ctx->server.opt != NULL);
	dhcp_iapd_validate(iapd);

	if (iapd->iostate != IAPD_IOSTATE_RECV) {
		pr_debug("not in RECV state");
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
		if (iapd->state == IAPD_STATE_SOLICATE) {
			pr_info("SOLICATE:  no addrs available; ignoring");
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

	if (ctx->server.pref == 255)
		finish_ia_pd(iapd, ctx);

out:
	pr_leave("%pA; rc=%d", iapd, rc);

	dhcp_iapd_validate(iapd);

	return rc;
}


int dhcp_iapd_run(struct dhcp_iapd *iapd, struct dhcp_context *ctx)
{
	pr_enter("%pA", iapd);

	pr_leave("%pA", iapd);
	dhcp_iapd_validate(iapd);

	/* TODO */
	return -1;
}
