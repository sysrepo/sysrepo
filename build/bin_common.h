/**
 * @file bin_common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common binaries header
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _BIN_COMMON_H
#define _BIN_COMMON_H

/** sysrepo version */
#define SR_VERSION "2.2.36"

/** sysrepo soversion */
#define SR_SOVERSION "7.13.13"

/** directory with datastore and/or notification plugins */
#define SR_PLG_PATH "/usr/local/lib/sysrepo/plugins"

/** sysrepo-plugind working directory. */
#define SRPD_WORK_DIR "/"

/** sysrepo-plugind plugins directory */
#define SRPD_PLG_PATH "/usr/local/lib/sysrepo-plugind/plugins"

/** path to tar executable */
#define SRPD_TAR_BINARY "/usr/bin/tar"

/** whether mkstemps is found on the system */
#define SR_HAVE_MKSTEMPS

/** whether libsystemd is installed, decides general support for systemd */
/* #undef SR_HAVE_SYSTEMD */

#endif
