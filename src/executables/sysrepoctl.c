/**
 * @file sysrepoctl.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepoctl tool
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

#define _GNU_SOURCE

#include "compat.h"

#include <assert.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libyang/libyang.h>

#include "bin_common.h"
#include "sysrepo.h"

#define SRCTL_LIST_NAME "Module Name"
#define SRCTL_LIST_REVISION "Revision"
#define SRCTL_LIST_FLAGS "Flags"
#define SRCTL_LIST_OWNER "Startup Owner"
#define SRCTL_LIST_START_PERMS "Startup Perms"
#define SRCTL_LIST_RUN_PERMS "Running Perms"
#define SRCTL_LIST_SUBMODS "Submodules"
#define SRCTL_LIST_FEATURES "Features"

struct list_item {
    char *name;
    char *revision;
    const char *impl_flag;
    int replay;
    char *owner;
    mode_t start_perms;
    mode_t run_perms;
    char *submodules;
    char *features;
};

struct change_item {
    const char *module_name;
    const char **features;
    const char **dis_features;
    int replay;
    const char *owner;
    const char *group;
    mode_t perms;
    int mod_ds;
};

sr_log_level_t log_level = SR_LL_ERR;

static void
version_print(void)
{
    printf(
            "sysrepoctl - sysrepo YANG schema manipulation tool, compiled with libsysrepo v%s (SO v%s)\n"
            "\n",
            SR_VERSION, SR_SOVERSION);
}

static void
help_print(void)
{
    printf(
            "Usage:\n"
            "  sysrepoctl <operation> [options]\n"
            "\n"
            "Available operations:\n"
            "  -h, --help           Print usage help.\n"
            "  -V, --version        Print only information about sysrepo version.\n"
            "  -l, --list           List YANG modules in sysrepo.\n"
            "  -i, --install <path> Install the specified schema into sysrepo. Can be in either YANG or YIN format.\n"
            "                       Can be specified multiple times to install several modules. All the options\n"
            "                       will affect the module of the last operation and can be specified for each.\n"
            "  -u, --uninstall <module>\n"
            "                       Uninstall the specified module from sysrepo. Can be specified multiple times\n"
            "                       to uninstall several modules.\n"
            "  -c, --change <module>\n"
            "                       Change access rights, features, or replay support of the specified module.\n"
            "                       Use special \":ALL\" module name to change the access rights or replay support\n"
            "                       of all the modules.\n"
            "  -U, --update <path>  Update the specified module in sysrepo. Can be in either YANG or YIN format.\n"
            "                       Can be specified multiple times to update several modules.\n"
            "  -L, --plugin-list    List loaded sysrepo plugins.\n"
            "  -P, --plugin-install <path>\n"
            "                       Install a datastore or notification sysrepo plugin. The plugin is simply copied\n"
            "                       to the designated plugin directory.\n"
            "\n"
            "Available options:\n"
            "  -s, --search-dirs <dir-path> [:<dir-path>...]\n"
            "                       Directories to search for include/import modules. Directory with already-installed\n"
            "                       modules is always searched. Accepted by install, update op.\n"
            "  -e, --enable-feature <feature-name>\n"
            "                       Enabled specific feature or use '*' for all the features. Can be specified multiple\n"
            "                       times. Accepted by install, change op.\n"
            "  -d, --disable-feature <feature-name>\n"
            "                       Disable specific feature. Can be specified multiple times. Accepted by change op.\n"
            "  -r, --replay <state> Change replay support (storing notifications) for this module to on/off or 1/0.\n"
            "                       Accepted by change op.\n"
            "  -o, --owner <user>   Set filesystem owner of a module. Accepted by change, install op.\n"
            "  -g, --group <group>  Set filesystem group of a module. Accepted by change, install op.\n"
            "  -p, --permissions <permissions>\n"
            "                       Set filesystem permissions of a module (chmod format). Accepted by change,\n"
            "                       install op.\n"
            "  -D, --datastore <mod-datastore>\n"
            "                       Apply operation to a module datastore (startup, running, candidate, operational,\n"
            "                       or notification) or \":ALL\" (default) the datastores. Accepted by change op\n"
            "                       if permissions are being changed.\n"
            "  -m, --module-plugin <mod-datastore>:<plugin-name>\n"
            "                       Set specific module datastore plugin for a module datastore (startup, running,\n"
            "                       candidate, operational, factory-default, or notification), can be specified multiple\n"
            "                       times for different module datastores. Accepted by install op.\n"
            "  -I, --init-data <path>\n"
            "                       Initial data in a file with XML or JSON extension to be set for module(s),\n"
            "                       useful when there are mandatory top-level nodes. Accepted by install op.\n"
            "  -f, --force          Force the specific operation. Accepted by uninstall op.\n"
            "  -v, --verbosity <level>\n"
            "                       Change verbosity to a level (none, error, warning, info, debug) or\n"
            "                       number (0, 1, 2, 3, 4). Accepted by all op.\n"
            "\n");
}

static void
error_print(int sr_error, const char *format, ...)
{
    va_list ap;
    char msg[2048];

    if (!sr_error) {
        sprintf(msg, "sysrepoctl error: %s\n", format);
    } else {
        sprintf(msg, "sysrepoctl error: %s (%s)\n", format, sr_strerror(sr_error));
    }

    va_start(ap, format);
    vfprintf(stderr, msg, ap);
    va_end(ap);

    if (log_level < SR_LL_INF) {
        fprintf(stderr, "For more details you may try to increase the verbosity up to \"-v3\".\n");
    }
}

static void
error_operation(int operation, int opt)
{
    if (!operation) {
        error_print(0, "Operation must be specified before the parameter -%c", opt);
    } else {
        error_print(0, "Invalid parameter -%c for the operation '%c'", opt, operation);
    }
}

static int
new_iitem(const char *optarg, sr_install_mod_t **iitems, uint32_t *iitem_count)
{
    sr_install_mod_t *iitem;

    *iitems = realloc(*iitems, (*iitem_count + 1) * sizeof **iitems);
    if (!*iitems) {
        return 1;
    }
    iitem = &(*iitems)[*iitem_count];
    memset(iitem, 0, sizeof *iitem);
    ++(*iitem_count);

    iitem->schema_path = optarg;
    return 0;
}

static int
new_str(const char *optarg, const char ***strs)
{
    uint32_t count;

    for (count = 0; *strs && (*strs)[count]; ++count) {}

    *strs = realloc(*strs, (count + 2) * sizeof **strs);
    if (!*strs) {
        return 1;
    }

    (*strs)[count++] = optarg;
    (*strs)[count] = NULL;
    return 0;
}

static int
set_replay(const char *optarg, int *replay)
{
    if (!strcmp(optarg, "on") || !strcmp(optarg, "1")) {
        *replay = 1;
    } else if (!strcmp(optarg, "off") || !strcmp(optarg, "0")) {
        *replay = 0;
    } else {
        error_print(0, "Invalid replay support \"%s\"", optarg);
        return 1;
    }

    return 0;
}

static int
set_owner(const char *optarg, const char **owner)
{
    if (*owner) {
        error_print(0, "Owner already specified");
        return 1;
    }

    *owner = optarg;
    return 0;
}

static int
set_group(const char *optarg, const char **group)
{
    if (*group) {
        error_print(0, "Group already specified");
        return 1;
    }

    *group = optarg;
    return 0;
}

static int
set_perms(const char *optarg, mode_t *perms)
{
    char *ptr;

    if (*perms) {
        error_print(0, "Permissions already specified");
        return 1;
    }

    *perms = strtoul(optarg, &ptr, 8);
    if (ptr[0]) {
        error_print(0, "Invalid permissions \"%s\"", optarg);
        return 1;
    }

    return 0;
}

static int
set_datastore(const char *optarg, int *mod_ds)
{
    if (*mod_ds != SR_MOD_DS_PLUGIN_COUNT) {
        error_print(0, "Datastore already specified");
        return 1;
    }

    if (!strcmp(optarg, "running")) {
        *mod_ds = SR_DS_RUNNING;
    } else if (!strcmp(optarg, "startup")) {
        *mod_ds = SR_DS_STARTUP;
    } else if (!strcmp(optarg, "candidate")) {
        *mod_ds = SR_DS_CANDIDATE;
    } else if (!strcmp(optarg, "operational")) {
        *mod_ds = SR_DS_OPERATIONAL;
    } else if (!strcmp(optarg, "factory-default")) {
        *mod_ds = SR_DS_FACTORY_DEFAULT;
    } else if (!strcmp(optarg, "notification")) {
        *mod_ds = SR_MOD_DS_NOTIF;
    } else if (strcmp(optarg, ":ALL")) {
        error_print(0, "Unknown datastore \"%s\"", optarg);
        return 1;
    }

    return 0;
}

static int
set_module_ds(const char *optarg, sr_module_ds_t *module_ds)
{
    char *ptr;
    int module_ds_idx;

    if (!(ptr = strchr(optarg, ':'))) {
        error_print(0, "Invalid module-plugin parameter \"%s\"", optarg);
        return 1;
    }
    if (!strncmp(optarg, "running", ptr - optarg)) {
        module_ds_idx = SR_DS_RUNNING;
    } else if (!strncmp(optarg, "startup", ptr - optarg)) {
        module_ds_idx = SR_DS_STARTUP;
    } else if (!strncmp(optarg, "candidate", ptr - optarg)) {
        module_ds_idx = SR_DS_CANDIDATE;
    } else if (!strncmp(optarg, "operational", ptr - optarg)) {
        module_ds_idx = SR_DS_OPERATIONAL;
    } else if (!strncmp(optarg, "factory-default", ptr - optarg)) {
        module_ds_idx = SR_DS_FACTORY_DEFAULT;
    } else if (!strncmp(optarg, "notification", ptr - optarg)) {
        module_ds_idx = SR_MOD_DS_NOTIF;
    } else {
        error_print(0, "Unknown datastore \"%.*s\"", (int)(ptr - optarg), optarg);
        return 1;
    }

    module_ds->plugin_name[module_ds_idx] = ptr + 1;
    return 0;
}

static int
srctl_list_collect(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, struct list_item **list, size_t *list_count)
{
    struct list_item *cur_item;
    const struct lys_module *ly_mod;
    const struct lysp_feature *f;
    char *owner, *group;
    const char *str;
    int ret = SR_ERR_OK, enabled;
    uint32_t idx = 0, idx2;
    LY_ARRAY_COUNT_TYPE u;

    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!strcmp(ly_mod->name, "sysrepo")) {
            continue;
        }

        /* new module */
        *list = realloc(*list, (*list_count + 1) * sizeof **list);
        cur_item = &(*list)[*list_count];
        ++(*list_count);

        /* init */
        memset(cur_item, 0, sizeof *cur_item);
        cur_item->impl_flag = "";
        cur_item->submodules = strdup("");
        cur_item->features = strdup("");

        /* name and revision */
        cur_item->name = strdup(ly_mod->name);
        cur_item->revision = ly_mod->revision ? strdup(ly_mod->revision) : strdup("");

        if (ly_mod->implemented) {
            /* replay-support */
            ret = sr_get_module_replay_support(conn, ly_mod->name, NULL, &enabled);
            if (ret != SR_ERR_OK) {
                return ret;
            }
            cur_item->replay = enabled;
        } else {
            /* replay-support */
            cur_item->replay = 0;
        }

        /* enabled features */
        f = NULL;
        idx2 = 0;
        while ((f = lysp_feature_next(f, ly_mod->parsed, &idx2))) {
            if (!(f->flags & LYS_FENABLED)) {
                /* disabled, skip */
                continue;
            }

            cur_item->features = realloc(cur_item->features, strlen(cur_item->features) + strlen(f->name) + 2);
            if (cur_item->features[0]) {
                strcat(cur_item->features, " ");
            }
            strcat(cur_item->features, f->name);
        }

        if (ly_mod->implemented) {
            /* conformance */
            cur_item->impl_flag = "I";

            /* owner and permissions */
            ret = sr_get_module_ds_access(conn, cur_item->name, SR_DS_STARTUP, &owner, &group, &cur_item->start_perms);
            if (ret != SR_ERR_OK) {
                return ret;
            }
            ret = sr_get_module_ds_access(conn, cur_item->name, SR_DS_RUNNING, NULL, NULL, &cur_item->run_perms);
            if (ret != SR_ERR_OK) {
                return ret;
            }
            cur_item->owner = malloc(strlen(owner) + 1 + strlen(group) + 1);
            sprintf(cur_item->owner, "%s:%s", owner, group);
            free(owner);
            free(group);
        } else {
            /* conformance */
            cur_item->impl_flag = "i";

            /* owner and permissions */
            cur_item->start_perms = 0;
            cur_item->run_perms = 0;
            cur_item->owner = strdup("");
        }

        /* learn submodules */
        LY_ARRAY_FOR(ly_mod->parsed->includes, u) {
            str = ly_mod->parsed->includes[u].submodule->name;
            cur_item->submodules = realloc(cur_item->submodules, strlen(cur_item->submodules) + 1 + strlen(str) + 1);
            if (u) {
                strcat(cur_item->submodules, " ");
            }
            strcat(cur_item->submodules, str);
        }
    }

    return SR_ERR_OK;
}

static int
srctl_list_cmp(const void *ptr1, const void *ptr2)
{
    struct list_item *item1, *item2;

    item1 = (struct list_item *)ptr1;
    item2 = (struct list_item *)ptr2;

    /* sort alphabetically */
    return strcmp(item1->name, item2->name);
}

static int
srctl_list(sr_conn_ctx_t *conn)
{
    int ret = SR_ERR_OK;
    const struct ly_ctx *ly_ctx;
    char flags_str[5], s_perm_str[12], r_perm_str[12];
    struct list_item *list = NULL;
    size_t i, line_len, list_count = 0;
    int max_name_len, max_owner_len, max_submod_len, max_feat_len;
    int rev_len, flag_len, s_perm_len, r_perm_len;

    /* acquire context */
    ly_ctx = sr_acquire_context(conn);

    /* collect all modules */
    if ((ret = srctl_list_collect(conn, ly_ctx, &list, &list_count))) {
        goto cleanup;
    }

    /* sort */
    qsort(list, list_count, sizeof *list, srctl_list_cmp);

    /* learn max lengths */
    max_name_len = strlen(SRCTL_LIST_NAME);
    rev_len = 10;
    flag_len = strlen(SRCTL_LIST_FLAGS);
    max_owner_len = strlen(SRCTL_LIST_OWNER);
    s_perm_len = strlen(SRCTL_LIST_START_PERMS);
    r_perm_len = strlen(SRCTL_LIST_RUN_PERMS);
    max_submod_len = strlen(SRCTL_LIST_SUBMODS);
    max_feat_len = strlen(SRCTL_LIST_FEATURES);
    for (i = 0; i < list_count; ++i) {
        if ((int)strlen(list[i].name) > max_name_len) {
            max_name_len = strlen(list[i].name);
        }
        if ((int)strlen(list[i].owner) > max_owner_len) {
            max_owner_len = strlen(list[i].owner);
        }
        if ((int)strlen(list[i].submodules) > max_submod_len) {
            max_submod_len = strlen(list[i].submodules);
        }
        if ((int)strlen(list[i].features) > max_feat_len) {
            max_feat_len = strlen(list[i].features);
        }
    }

    /* print repository info */
    printf("Sysrepo repository: %s\n\n", sr_get_repo_path());

    /* print header */
    printf("%-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s\n", max_name_len, SRCTL_LIST_NAME, rev_len,
            SRCTL_LIST_REVISION, flag_len, SRCTL_LIST_FLAGS, max_owner_len, SRCTL_LIST_OWNER,
            s_perm_len, SRCTL_LIST_START_PERMS, r_perm_len, SRCTL_LIST_RUN_PERMS,
            max_submod_len, SRCTL_LIST_SUBMODS, max_feat_len, SRCTL_LIST_FEATURES);

    /* print ruler */
    line_len = max_name_len + 3 + rev_len + 3 + flag_len + 3 + max_owner_len + 3 + s_perm_len + 3 + r_perm_len + 3 +
            max_submod_len + 3 + max_feat_len;
    for (i = 0; i < line_len; ++i) {
        printf("-");
    }
    printf("\n");

    /* print modules */
    for (i = 0; i < list_count; ++i) {
        sprintf(flags_str, "%s%s", list[i].impl_flag, list[i].replay ? "R" : " ");
        if (!strcmp(list[i].impl_flag, "I")) {
            sprintf(s_perm_str, "%03o", list[i].start_perms);
            sprintf(r_perm_str, "%03o", list[i].run_perms);
        } else {
            s_perm_str[0] = '\0';
            r_perm_str[0] = '\0';
        }
        printf("%-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s\n", max_name_len, list[i].name,
                rev_len, list[i].revision, flag_len, flags_str, max_owner_len, list[i].owner, s_perm_len, s_perm_str,
                r_perm_len, r_perm_str, max_submod_len, list[i].submodules, max_feat_len, list[i].features);
    }

    /* print flag legend */
    printf("\nFlags meaning: I - Installed/i - Imported; R - Replay support\n\n");

cleanup:
    sr_release_context(conn);
    for (i = 0; i < list_count; ++i) {
        free(list[i].name);
        free(list[i].revision);
        free(list[i].owner);
        free(list[i].submodules);
        free(list[i].features);
    }
    free(list);
    return ret;
}

static int
srctl_change(sr_conn_ctx_t *conn, struct change_item *citem)
{
    int r = 0, i;

    if (!strcmp(citem->module_name, ":ALL")) {
        /* all the modules */
        if (citem->features || citem->dis_features) {
            error_print(0, "To enable/disable features, the module must be specified");
            r = 1;
            goto cleanup;
        }
        citem->module_name = NULL;
    }

    /* change owner, group, and/or permissions */
    if (citem->owner || citem->group || citem->perms) {
        if (citem->mod_ds == SR_MOD_DS_PLUGIN_COUNT) {
            for (i = 0; i < SR_MOD_DS_PLUGIN_COUNT; ++i) {
                if ((r = sr_set_module_ds_access(conn, citem->module_name, i, citem->owner, citem->group, citem->perms))) {
                    if (citem->module_name) {
                        error_print(r, "Failed to change module \"%s\" access", citem->module_name);
                    } else {
                        error_print(r, "Failed to change modules access");
                    }
                    goto cleanup;
                }
            }
        } else if ((r = sr_set_module_ds_access(conn, citem->module_name, citem->mod_ds, citem->owner, citem->group,
                citem->perms))) {
            if (citem->module_name) {
                error_print(r, "Failed to change module \"%s\" access", citem->module_name);
            } else {
                error_print(r, "Failed to change modules access");
            }
            goto cleanup;
        }
    }

    /* change enabled features */
    for (i = 0; citem->features && citem->features[i]; ++i) {
        if ((r = sr_enable_module_feature(conn, citem->module_name, citem->features[i]))) {
            error_print(r, "Failed to enable feature \"%s\"", citem->features[i]);
            goto cleanup;
        }
    }

    /* change disabled features */
    for (i = 0; citem->dis_features && citem->dis_features[i]; ++i) {
        if ((r = sr_disable_module_feature(conn, citem->module_name, citem->dis_features[i]))) {
            error_print(r, "Failed to disable feature \"%s\"", citem->dis_features[i]);
            goto cleanup;
        }
    }

    /* change replay */
    if (citem->replay != -1) {
        if ((r = sr_set_module_replay_support(conn, citem->module_name, citem->replay))) {
            error_print(r, "Failed to change replay support");
            goto cleanup;
        }
    }

cleanup:
    return r;
}

static int
srctl_plugin_list(sr_conn_ctx_t *conn)
{
    int ret = SR_ERR_OK;
    const char **ds_plugins = NULL, **ntf_plugins = NULL;
    uint32_t i;

    if ((ret = sr_get_plugins(conn, &ds_plugins, &ntf_plugins))) {
        goto cleanup;
    }

    printf("Datastore plugins:\n");
    for (i = 0; ds_plugins[i]; ++i) {
        printf("\t%s\n", ds_plugins[i]);
    }

    printf("\nNotification plugins:\n");
    for (i = 0; ntf_plugins[i]; ++i) {
        printf("\t%s\n", ntf_plugins[i]);
    }

cleanup:
    free(ds_plugins);
    free(ntf_plugins);
    return ret;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_install_mod_t *iitems = NULL;
    uint32_t i, iitem_count = 0;
    struct change_item citem = {.replay = -1, .mod_ds = SR_MOD_DS_PLUGIN_COUNT};
    const char *file_path = NULL, *search_dirs = NULL, **module_names = NULL, *data_path = NULL;
    char *ptr;
    int r, rc = EXIT_FAILURE, opt, operation = 0, force = 0;
    struct option options[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"version",         no_argument,       NULL, 'V'},
        {"list",            no_argument,       NULL, 'l'},
        {"install",         required_argument, NULL, 'i'},
        {"uninstall",       required_argument, NULL, 'u'},
        {"change",          required_argument, NULL, 'c'},
        {"update",          required_argument, NULL, 'U'},
        {"plugin-list",     no_argument,       NULL, 'L'},
        {"plugin-install",  required_argument, NULL, 'P'},
        {"search-dirs",     required_argument, NULL, 's'},
        {"enable-feature",  required_argument, NULL, 'e'},
        {"disable-feature", required_argument, NULL, 'd'},
        {"replay",          required_argument, NULL, 'r'},
        {"owner",           required_argument, NULL, 'o'},
        {"group",           required_argument, NULL, 'g'},
        {"permissions",     required_argument, NULL, 'p'},
        {"datastore",       required_argument, NULL, 'D'},
        {"module-plugin",   required_argument, NULL, 'm'},
        {"init-data",       required_argument, NULL, 'I'},
        {"force",           no_argument,       NULL, 'f'},
        {"verbosity",       required_argument, NULL, 'v'},
        {NULL,              0,                 NULL, 0},
    };

    if (argc == 1) {
        help_print();
        goto cleanup;
    }

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hVli:u:c:U:LP:s:e:d:r:o:g:p:D:m:I:fv:", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            /* help */
            version_print();
            help_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'V':
            /* version */
            version_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'l':
            /* list */
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'l';
            break;
        case 'i':
            /* install */
            if (operation && (operation != 'i')) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'i';
            if (new_iitem(optarg, &iitems, &iitem_count)) {
                goto cleanup;
            }
            break;
        case 'u':
            /* uninstall */
            if (operation && (operation != 'u')) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'u';
            if (new_str(optarg, &module_names)) {
                goto cleanup;
            }
            break;
        case 'c':
            /* change */
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'c';
            citem.module_name = optarg;
            break;
        case 'U':
            /* update */
            if (operation && (operation != 'U')) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'U';
            if (new_str(optarg, &module_names)) {
                goto cleanup;
            }
            break;
        case 'L':
            /* plugin-list */
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'L';
            break;
        case 'P':
            /* plugin-install */
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            operation = 'P';
            file_path = optarg;
            break;
        case 's':
            /* search-dirs */
            if (search_dirs) {
                error_print(0, "Search dirs already specified");
                goto cleanup;
            }
            search_dirs = optarg;
            break;
        case 'e':
            /* enable-feature */
            if (operation == 'i') {
                if (new_str(optarg, &iitems[iitem_count - 1].features)) {
                    goto cleanup;
                }
            } else if (operation == 'c') {
                if (new_str(optarg, &citem.features)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'd':
            /* disable-feature */
            if (operation == 'c') {
                if (new_str(optarg, &citem.dis_features)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'r':
            /* replay */
            if (operation == 'c') {
                if (set_replay(optarg, &citem.replay)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'o':
            /* owner */
            if (operation == 'i') {
                if (set_owner(optarg, &iitems[iitem_count - 1].owner)) {
                    goto cleanup;
                }
            } else if (operation == 'c') {
                if (set_owner(optarg, &citem.owner)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'g':
            /* group */
            if (operation == 'i') {
                if (set_group(optarg, &iitems[iitem_count - 1].group)) {
                    goto cleanup;
                }
            } else if (operation == 'c') {
                if (set_group(optarg, &citem.group)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'p':
            /* permissions */
            if (operation == 'i') {
                if (set_perms(optarg, &iitems[iitem_count - 1].perm)) {
                    goto cleanup;
                }
            } else if (operation == 'c') {
                if (set_perms(optarg, &citem.perms)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'D':
            /* datastore */
            if (operation == 'c') {
                if (set_datastore(optarg, &citem.mod_ds)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'm':
            /* module-plugin */
            if (operation == 'i') {
                if (set_module_ds(optarg, &iitems[iitem_count - 1].module_ds)) {
                    goto cleanup;
                }
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'I':
            /* init-data */
            if (operation == 'i') {
                data_path = optarg;
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'f':
            /* force */
            if (operation == 'u') {
                force = 1;
            } else {
                error_operation(operation, opt);
                goto cleanup;
            }
            break;
        case 'v':
            /* verbosity */
            if (!strcmp(optarg, "none")) {
                log_level = SR_LL_NONE;
            } else if (!strcmp(optarg, "error")) {
                log_level = SR_LL_ERR;
            } else if (!strcmp(optarg, "warning")) {
                log_level = SR_LL_WRN;
            } else if (!strcmp(optarg, "info")) {
                log_level = SR_LL_INF;
            } else if (!strcmp(optarg, "debug")) {
                log_level = SR_LL_DBG;
            } else if ((strlen(optarg) == 1) && (optarg[0] >= '0') && (optarg[0] <= '4')) {
                log_level = atoi(optarg);
            } else {
                error_print(0, "Invalid verbosity \"%s\"", optarg);
                goto cleanup;
            }
            break;
        default:
            error_print(0, "Invalid option or missing argument: -%c", optopt);
            goto cleanup;
        }
    }

    /* check for additional argument */
    if (optind < argc) {
        error_print(0, "Redundant parameters (%s)", argv[optind]);
        goto cleanup;
    }

    /* set logging */
    sr_log_stderr(log_level);

    if (operation != 'P') {
        /* create connection */
        if ((r = sr_connect(0, &conn))) {
            error_print(r, "Failed to connect");
            goto cleanup;
        }
    }

    /* perform the operation */
    switch (operation) {
    case 'l':
        /* list */
        if ((r = srctl_list(conn))) {
            error_print(r, "Failed to list modules");
            goto cleanup;
        }
        break;
    case 'i':
        /* install */
        if ((r = sr_install_modules2(conn, iitems, iitem_count, search_dirs, NULL, data_path, 0))) {
            error_print(r, "Failed to install modules");
            goto cleanup;
        }
        break;
    case 'u':
        /* uninstall */
        if ((r = sr_remove_modules(conn, module_names, force))) {
            error_print(r, "Failed to uninstall modules");
            goto cleanup;
        }
        break;
    case 'c':
        /* change */
        if ((r = srctl_change(conn, &citem))) {
            goto cleanup;
        }
        break;
    case 'U':
        /* update */
        if ((r = sr_update_modules(conn, module_names, search_dirs))) {
            error_print(r, "Failed to update modules");
            goto cleanup;
        }
        break;
    case 'L':
        /* plugin-list */
        if ((r = srctl_plugin_list(conn))) {
            error_print(r, "Failed to list plugins");
            goto cleanup;
        }
        break;
    case 'P':
        /* plugin-install */
        if (asprintf(&ptr, "/bin/mkdir -p \"%s\" && /bin/cp -- \"%s\" %s", SR_PLG_PATH, file_path, SR_PLG_PATH) == -1) {
            error_print(0, "Memory allocation failed");
            goto cleanup;
        }
        r = system(ptr);
        free(ptr);
        if (!WIFEXITED(r) || WEXITSTATUS(r)) {
            error_print(0, "Failed to install the plugin");
            goto cleanup;
        }
        break;
    case 0:
        error_print(0, "No operation specified");
        goto cleanup;
    default:
        error_print(0, "Internal");
        goto cleanup;
    }

    rc = EXIT_SUCCESS;

cleanup:
    sr_disconnect(conn);
    for (i = 0; i < iitem_count; ++i) {
        free(iitems[i].features);
    }
    free(iitems);
    free(citem.features);
    free(citem.dis_features);
    free(module_names);
    return rc;
}
