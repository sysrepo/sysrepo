/**
 * @file config.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief configuration header
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <pthread.h>
#include <time.h>

#include "sr_cond/sr_cond_futex.h"

/*
 * If the compiler supports attribute to mark objects as hidden, mark all
 * objects as hidden and export only objects explicitly marked to be part of
 * the public API.
 */
#define API __attribute__((visibility("default")))

/** use access() if eaccess() is not available (it may adversely affect access control, however) */
#define SR_HAVE_EACCESS
#ifndef SR_HAVE_EACCESS
# define eaccess access
#endif

/** directory with datastore and/or notification plugins */
#define SR_PLG_PATH "/usr/local/lib/sysrepo/plugins"

/** plugin extension */
#if defined __linux__ || defined __unix__
# define SR_PLG_SUFFIX ".so"
# define SR_PLG_SUFFIX_LEN 3
#elif defined __APPLE__
# define SR_PLG_SUFFIX ".dylib"
# define SR_PLG_SUFFIX_LEN 6
#else
# error "Unknown platform that is not *nix neither macOS"
#endif

/** UID of the superuser that can execute sensitive functions */
#define SR_SU_UID 0

/** name of the user with unrestricted access bypassing NACM */
#define SR_NACM_RECOVERY_USER "root"

/** implemented ietf-yang-library revision */
#define SR_YANGLIB_REVISION 2019-01-04

/** main sysrepo repository path; prefix of all other paths by default */
#define SR_REPO_PATH "//home/hytec/gnb407/du_bin/intel/liboam/oam_du/cm/sysrepo/run/SysrepoInstaller/PKG/sysrepo/build/repository"

/** environment variable overriding the compiled-in value */
#define SR_REPO_PATH_ENV "SYSREPO_REPOSITORY_PATH"

/** if not set, defaults to "SR_REPO_PATH/data" */
#define SR_STARTUP_PATH ""

/** if not set, defaults to "SR_REPO_PATH/data/notif" */
#define SR_NOTIFICATION_PATH ""

/** if not set, defaults to "SR_REPO_PATH/yang" */
#define SR_YANG_PATH ""

/** where SHM files are stored */
#define SR_SHM_DIR "/dev/shm"

/** default prefix for SHM files in /dev/shm */
#define SR_SHM_PREFIX_DEFAULT "sr"

/** environment variable for setting a custom prefix for SHM files */
#define SR_SHM_PREFIX_ENV "SYSREPO_SHM_PREFIX"

/** group to own all directories/files */
#define SR_GROUP ""

/** umask modifying all the permissions below */
#define SR_UMASK 00000

/** permissions of directories for sysrepo files */
#define SR_DIR_PERM 00777

/** permissions of sysrepo plugin directory */
#define SR_PLG_DIR_PERM 00770

/** permissions of used YANG modules */
#define SR_YANG_PERM 00644

/** default permissions of stored notifications and data files */
#define SR_FILE_PERM 00600

/** permissions of data files of "sysrepo" internal module, it includes all the metadata */
#define SR_INTMOD_MAIN_FILE_PERM 00666

/** permissions of data files of "ietf-netconf-acm" and "sysrepo-monitoring" internal NACM modules */
#define SR_INTMOD_NACM_SRMON_FILE_PERM 00600

/** default permissions of data files of internal modules that have no data or features */
#define SR_INTMOD_NODATA_FILE_PERM 00444

/** default permission of data files of internal modules with some data or features */
#define SR_INTMOD_WITHDATA_FILE_PERM 00644

#endif /* _CONFIG_H */
