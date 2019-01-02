/*	--*- c -*--
 * Copyright (C) 2014 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
   Copyright 2010 Lennart Poettering
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

Most parts of this header was taken from systemd's <sd-daemon.h>
 */

#ifndef H_ENSC_SD_NOTIFY_H
#define H_ENSC_SD_NOTIFY_H

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#include "sd-common.h"

ENSC_SYSTEMD_FN(int sd_notify_supported(void),, return 0);

/*
  Informs systemd about changed daemon state. This takes a number of
  newline separated environment-style variable assignments in a
  string. The following variables are known:

     READY=1      Tells systemd that daemon startup is finished (only
                  relevant for services of Type=notify). The passed
                  argument is a boolean "1" or "0". Since there is
                  little value in signaling non-readiness the only
                  value daemons should send is "READY=1".

     STATUS=...   Passes a single-line status string back to systemd
                  that describes the daemon state. This is free-from
                  and can be used for various purposes: general state
                  feedback, fsck-like programs could pass completion
                  percentages and failing programs could pass a human
                  readable error message. Example: "STATUS=Completed
                  66% of file system check..."

     ERRNO=...    If a daemon fails, the errno-style error code,
                  formatted as string. Example: "ERRNO=2" for ENOENT.

     BUSERROR=... If a daemon fails, the D-Bus error-style error
                  code. Example: "BUSERROR=org.freedesktop.DBus.Error.TimedOut"

     MAINPID=...  The main pid of a daemon, in case systemd did not
                  fork off the process itself. Example: "MAINPID=4711"

     WATCHDOG=1   Tells systemd to update the watchdog timestamp.
                  Services using this feature should do this in
                  regular intervals. A watchdog framework can use the
                  timestamps to detect failed services.

  Daemons can choose to send additional variables. However, it is
  recommended to prefix variable names not listed above with X_.

  Returns a negative errno-style error code on failure. Returns > 0
  if systemd could be notified, 0 if it couldn't possibly because
  systemd is not running.

  Example: When a daemon finished starting up, it could issue this
  call to notify systemd about it:

     sd_notify(0, "READY=1");

  See sd_notifyf() for more complete examples.

  See sd_notify(3) for more information.
*/
ENSC_SYSTEMD_FN(int sd_notify(int unset_environment, const char *state),,
		return 0);

/*
  Similar to sd_notify() but takes a format string.

  Example 1: A daemon could send the following after initialization:

     sd_notifyf(0, "READY=1\n"
                   "STATUS=Processing requests...\n"
                   "MAINPID=%lu",
                   (unsigned long) getpid());

  Example 2: A daemon could send the following shortly before
  exiting, on failure:

     sd_notifyf(0, "STATUS=Failed to start up: %s\n"
                   "ERRNO=%i",
                   strerror(errno),
                   errno);

  See sd_notifyf(3) for more information.
*/
ENSC_SYSTEMD_FN(int sd_notifyf(int unset_environment,
			       const char *format, ...),
		_sd_printf_attr_(2,3),
		return 0);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif	/* H_ENSC_SD_NOTIFY_H */
