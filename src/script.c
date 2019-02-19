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

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <ensc-lib/compiler.h>

#include "dhcpv6-util.h"
#include "logging.h"

#define LOG_DOMAIN		LOG_DOMAIN_SCRIPT

struct env_buf {
	size_t		*env;
	size_t		env_cnt;
	size_t		env_allocated;

	char		*strbuf;
	size_t		str_len;
	size_t		str_allocated;

	char const	*prefix;
};

static void x_env_allocate(struct env_buf *env, size_t cnt)
{
	if (env->str_len + cnt > env->str_allocated) {
		size_t	new_len = (env->str_len + cnt) * 180 / 100 + 10;
		char	*tmp = realloc(env->strbuf, new_len * sizeof tmp[0]);

		if (!tmp)
			abort();

		env->strbuf = tmp;
		env->str_allocated = new_len;
	}
}

static void x_env_new(struct env_buf *env)
{
	if (env->env_cnt >= env->env_allocated) {
		size_t	new_len = env->env_cnt * 180 / 100 + 10;
		size_t	*tmp = realloc(env->env, new_len * sizeof tmp[0]);

		if (!tmp)
			abort();

		env->env = tmp;
		env->env_allocated = new_len;
	}

	env->env[env->env_cnt] = env->str_len;
	env->env_cnt += 1;
}

static void x_env_append(struct env_buf *env, void const *data, size_t len)
{
	x_env_allocate(env, len);

	memcpy(env->strbuf + env->str_len, data, len);
	env->str_len += len;
}

static void x_env_uint(struct env_buf *env, char const *key, uintmax_t val)
{
	char		buf[3 * sizeof val + 2];
	size_t		l_key = strlen(key);
	size_t		l_val = sprintf(buf, "=%" PRIuMAX, val);

	x_env_new(env);

	if (env->prefix)
		x_env_append(env, env->prefix, strlen(env->prefix));

	x_env_append(env, key, l_key);
	x_env_append(env, buf, l_val + 1);
}

static void x_env_str(struct env_buf *env, char const *key, char const *val)
{
	size_t		l_key = strlen(key);
	size_t		l_val = strlen(val);

	x_env_new(env);
	x_env_allocate(env, l_key + l_val + 2);

	if (env->prefix)
		x_env_append(env, env->prefix, strlen(env->prefix));

	x_env_append(env, key, l_key);
	x_env_append(env, "=", 1);
	x_env_append(env, val, l_val + 1);
}

static void x_env_actual_env(struct env_buf *env, char const *key)
{
	char const	*val = getenv(key);

	if (val)
		x_env_str(env, key, val);
}

static void x_env_ipaddr(struct env_buf *env, char const *key,
			 struct in6_addr const *addr)
{
	char		buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, buf, sizeof buf);
	x_env_str(env, key, buf);
}

static uint64_t		g_tm_delta_ms;

static void x_env_time(struct env_buf *env, char const *key, dhcp_time_t tm)
{
	if (time_is_epoch(tm))
		x_env_str(env, key, "0");
	else if (time_is_infinity(tm))
		x_env_str(env, key, "-1");
	else
		x_env_uint(env, key, (g_tm_delta_ms + time_to_ms(tm)) / 1000);
}

static char **x_env_finalize(struct env_buf const *env)
{
	char **res;

	res = calloc(env->env_cnt + 1, sizeof res[0]);
	if (!res)
		abort();

	for (size_t i = 0; i < env->env_cnt; ++i)
		res[i] = &env->strbuf[env->env[i]];

	res[env->env_cnt] = NULL;

	return res;
}

static void dhcp_iapd_exec_fill_globals(void)
{
	struct timeval	tv_real;
	struct timespec	ts_boot;

	uint64_t	msec_real;
	uint64_t	msec_boot;

	clock_gettime(CLOCK_BOOTTIME, &ts_boot);
	gettimeofday(&tv_real, NULL);

	msec_real  = tv_real.tv_sec;
	msec_real *= 1000;
	msec_real += tv_real.tv_usec / 1000;

	msec_boot  = ts_boot.tv_sec;
	msec_boot *= 1000;
	msec_boot += ts_boot.tv_nsec / 1000000;

	assert(msec_real >= msec_boot);

	g_tm_delta_ms = msec_real - msec_boot;
}

static void _unused_ dhcp_iapd_free_env(struct env_buf *env)
{
	free(env->env);
	free(env->strbuf);
}

static void dhcp_iapd_fill_env(struct env_buf *env,
			       struct dhcp_iapd const *iapd,
			       struct dhcp_context *ctx,
			       char const *state_id)
{
	size_t			num_prefix;

	x_env_actual_env(env, "PATH");
	x_env_actual_env(env, "HOME");
	x_env_actual_env(env, "TERM");
	x_env_actual_env(env, "DHCP_INTERFACE");

	x_env_str(env, "DHCP_OP", state_id);
	x_env_time(env, "DHCP_NOW", ctx->now);

	x_env_uint(env, "DHCP_IAPD_ID", iapd->id);
	x_env_time(env, "DHCP_IAPD_TM", iapd->active.lease_tm);
	x_env_time(env, "DHCP_IAPD_T1", time_add_lt(iapd->active.lease_tm, iapd->active.t1, 100));
	x_env_time(env, "DHCP_IAPD_T2", time_add_lt(iapd->active.lease_tm, iapd->active.t2, 100));
	x_env_uint(env, "DHCP_IAPD_T1_SEC", iapd->active.t1);
	x_env_uint(env, "DHCP_IAPD_T2_SEC", iapd->active.t2);

	if (iapd->server.has_id) {
		x_env_ipaddr(env, "DHCP_SERVER_ADDR", &iapd->server.addr);
		x_env_uint(env, "DHCP_SERVER_PREF", iapd->server.preference);
	}

	num_prefix = 0;
	for (size_t i = 0; i < ARRAY_SIZE(iapd->iaprefix); ++i) {
		struct dhcp_iaprefix const	*prefix = &iapd->iaprefix[i].active;
		char				buf[3 * sizeof(size_t) + sizeof "DHCP_IAPREFIX_"];

		if (!dhcp_iaprefix_is_used(prefix))
			continue;

		sprintf(buf, "DHCP_IAPREFIX_%zu_", num_prefix);
		env->prefix = buf;

		x_env_time  (env, "TM",           prefix->lease_tm);
		x_env_time  (env, "LT_PREF",      time_add_lt(prefix->lease_tm, prefix->pref_lt, 100));
		x_env_time  (env, "LT_VALID",     time_add_lt(prefix->lease_tm, prefix->valid_lt, 100));
		x_env_uint  (env, "LT_PREF_SEC",  prefix->pref_lt);
		x_env_uint  (env, "LT_VALID_SEC", prefix->valid_lt);
		x_env_ipaddr(env, "NET_ADDR",     &prefix->net.prefix);
		x_env_uint  (env, "NET_LEN",      prefix->net.len);

		env->prefix = NULL;
		++num_prefix;
	}

	x_env_uint(env, "DHCP_IAPREFIX_NUM", num_prefix);
}

static void dhcp_iapd_exec_script(struct dhcp_iapd const *iapd,
				  struct dhcp_context *ctx,
				  char const *state_id)
{
	struct env_buf		env = { };

	dhcp_iapd_exec_fill_globals();
	dhcp_iapd_fill_env(&env, iapd, ctx, state_id);

	x_env_append(&env, "\0", 1);

	execle(ctx->script, ctx->script, state_id, NULL, x_env_finalize(&env));
	pr_err("execle(): %s", strerror(errno));
	dhcp_iapd_free_env(&env);
}

int dhcp_iapd_run_script(struct dhcp_iapd const *iapd,
			 struct dhcp_context *ctx,
			 char const *state_id)
{
	int		ctrl_fd[2] = { -1, -1 };
	pid_t		pid;
	int		rc;
	int		status;

	rc = pipe2(ctrl_fd, O_CLOEXEC);
	if (rc < 0) {
		pr_err("pipe(): %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_err("fork(): %s", strerror(errno));
		rc = -1;
		close(ctrl_fd[1]);
		close(ctrl_fd[0]);
		goto out;
	}

	if (pid == 0) {
		ssize_t		l;

		close(ctrl_fd[0]);

		dhcp_iapd_exec_script(iapd, ctx, state_id);
		l = write(ctrl_fd[1], "E", 1);
		(void)l;
		_exit(1);
	}

	close(ctrl_fd[1]);
	if (waitpid(pid, &status, 0) < 0) {
		pr_err("waitpid(): %s", strerror(errno));
		rc = -1;
	} else {
		char		c;
		ssize_t		l;

		l = read(ctrl_fd[0], &c, 1);
		close(ctrl_fd[0]);

		rc = -1;
		if (l == 1) {
			pr_err("failed to exec script");
		} else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			pr_err("script failed with %04x", status);
		} else {
			pr_debug("script finished");
			rc = 0;
		}
	}

out:
	return rc;
}
