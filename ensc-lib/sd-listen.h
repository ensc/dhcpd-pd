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

#ifndef H_ENSC_SD_LISTEN_H
#define H_ENSC_SD_LISTEN_H

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#include "sd-common.h"

#define SD_LISTEN_FDS_START 3

/*
  Returns how many file descriptors have been passed, or a negative
  errno code on failure. Optionally, removes the $LISTEN_FDS and
  $LISTEN_PID file descriptors from the environment (recommended, but
  problematic in threaded environments). If r is the return value of
  this function you'll find the file descriptors passed as fds
  SD_LISTEN_FDS_START to SD_LISTEN_FDS_START+r-1. Returns a negative
  errno style error code on failure. This function call ensures that
  the FD_CLOEXEC flag is set for the passed file descriptors, to make
  sure they are not passed on to child processes. If FD_CLOEXEC shall
  not be set, the caller needs to unset it after this call for all file
  descriptors that are used.

  See sd_listen_fds(3) for more information.
*/
ENSC_SYSTEMD_FN(int sd_listen_fds(int unset_environment),, return 0);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif	/* H_ENSC_SD_LISTEN_H */
