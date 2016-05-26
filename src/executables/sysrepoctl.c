/**
 * @file sysrepoctl.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo control tool (sysrepoctl) implementation.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "client_library.h"

/**
 * @brief Macro to iterate via all references to the module identified by NAME and REVISION
 *        inside the given libyang context. Use with opening curly bracket '{'.
 *
 * @param CTX libyang context.
 * @param NAME Module name.
 * @param REVISION Revision date.
 * @param ITER Iterator (pointer to lys_module struct)
 */
#define MODULE_ITER(CTX, NAME, REVISION, ITER)  \
    for (uint32_t idx = 0; NULL != (ITER = ly_ctx_get_module_iter(CTX, &idx)); )       \
        if ((NULL != ITER->name) && (0 == strcmp(ITER->name, NAME)))                   \
            if ((NULL == REVISION) ||                                                  \
                ((ITER->rev_size > 0) && (0 == strcmp(ITER->rev[0].date, REVISION))))  \

/**
 * @brief Helper structure used for storing uid and gid of module's owner
 * and group respectively.
 */
typedef struct srctl_module_owner_s {
    uid_t owner;
    gid_t group;
} srctl_module_owner_t;

static char *srctl_schema_search_dir = SR_SCHEMA_SEARCH_DIR;
static char *srctl_data_search_dir = SR_DATA_SEARCH_DIR;
static bool custom_repository = false;
const char * const data_files_ext[] = { SR_STARTUP_FILE_EXT,
                                        SR_RUNNING_FILE_EXT,
                                        SR_STARTUP_FILE_EXT SR_LOCK_FILE_EXT,
                                        SR_RUNNING_FILE_EXT SR_LOCK_FILE_EXT,
                                        SR_PERSIST_FILE_EXT,
                                        SR_CANDIDATE_FILE_EXT SR_LOCK_FILE_EXT};


/**
 * @brief Connects to sysrepo and starts a session.
 */
static int
srctl_open_session(sr_conn_ctx_t **connection_p, sr_session_ctx_t **session_p)
{
    int rc = SR_ERR_OK;

    rc = sr_connect("sysrepoctl", SR_CONN_DEFAULT, connection_p);
    if (SR_ERR_OK == rc) {
        rc = sr_session_start(*connection_p, SR_DS_STARTUP, SR_SESS_DEFAULT, session_p);
    }
    return rc;
}

/**
 * @brief Reports (prints to stderr) the error stored within the session or given one.
 */
static void
srctl_report_error(sr_session_ctx_t *session, int rc)
{
    const sr_error_info_t *error = NULL;

    if (NULL == session) {
        fprintf(stderr, "Error: %s\n", sr_strerror(rc));
    } else {
        sr_get_last_error(session, &error);
        fprintf(stderr, "Error: %s\n", error->message);
    }
}

/**
 * @brief Prints the owner user and group ot the model installed in sysrepo.
 */
static void
srctl_print_module_owner(const char *module_name, char *buff)
{
    char file_name[PATH_MAX] = { 0, };
    struct stat info;
    int ret = 0;

    snprintf(file_name, PATH_MAX, "%s%s%s", srctl_data_search_dir, module_name, SR_STARTUP_FILE_EXT);

    ret = stat(file_name, &info);
    if (0 == ret) {
        struct passwd *pw = getpwuid(info.st_uid);
        struct group  *gr = getgrgid(info.st_gid);
        snprintf(buff, PATH_MAX, "%s:%s", pw->pw_name, gr->gr_name);
    } else {
        snprintf(buff, PATH_MAX, " ");
    }
}

/**
 * @brief Prints the permissions of the model installed in sysrepo.
 */
static void
srctl_print_module_permissions(const char *module_name, char *buff)
{
    char file_name[PATH_MAX] = { 0, };
    struct stat info;
    int statchmod = 0;
    int ret = 0;

    snprintf(file_name, PATH_MAX, "%s%s%s", srctl_data_search_dir, module_name, SR_STARTUP_FILE_EXT);

    ret = stat(file_name, &info);
    if (0 == ret) {
        statchmod = info.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
        snprintf(buff, PATH_MAX, "%o", statchmod);
    } else {
        snprintf(buff, PATH_MAX, " ");
    }
}

/**
 * @brief Performs the --list operation.
 */
static int
srctl_list_modules()
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_schema_t *schemas = NULL;
    size_t schema_cnt = 0;
    char buff[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    printf("Sysrepo schema directory: %s\n", SR_SCHEMA_SEARCH_DIR);
    printf("Sysrepo data directory:   %s\n", SR_DATA_SEARCH_DIR);
    printf("(Do not alter contents of these directories manually)\n");

    rc = srctl_open_session(&connection, &session);

    if (SR_ERR_OK == rc) {
        rc = sr_list_schemas(session, &schemas, &schema_cnt);
    }

    printf("\n%-30s| %-11s| %-20s| %-12s| %-30s| %s\n",
            "Module Name", "Revision", "Data Owner", "Permissions", "Submodules", "Enabled Features");
    printf("---------------------------------------------------------------------------------------------------------------------------------\n");

    if (SR_ERR_OK == rc) {
        for (size_t i = 0; i < schema_cnt; i++) {
            printf("%-30s| %-11s| ", schemas[i].module_name,
                    (NULL == schemas[i].revision.revision ? "" : schemas[i].revision.revision));
            /* print owner */
            srctl_print_module_owner(schemas[i].module_name, buff);
            printf("%-20s| ", buff);
            /* print permissions */
            srctl_print_module_permissions(schemas[i].module_name, buff);
            printf("%-12s| ", buff);
            /* print submodules */
            size_t printed = 0;
            for (size_t j = 0; j < schemas[i].submodule_count; j++) {
                printed += printf(" %s", schemas[i].submodules[j].submodule_name);
            }
            for (size_t j = printed; j < 30; j++) printf(" ");
            /* print enabled features */
            printf("|");
            for (size_t j = 0; j < schemas[i].enabled_feature_cnt; j++) {
                printf(" %s", schemas[i].enabled_features[j]);
            }
            printf("\n");
        }
        printf("\n");
        sr_free_schemas(schemas, schema_cnt);
    } else {
        srctl_report_error(session, rc);
    }
    sr_disconnect(connection);

    return rc;
}

/**
 * @brief Extracts the path to the directory with the file out of the file path.
 */
static char *
srctl_get_dir_path(const char *file_path)
{
    char *slash = NULL, *result = NULL;

    result = strdup(file_path);
    if (NULL != result) {
        slash = strrchr(result, '/');
        if (NULL != slash) {
            *slash = '\0';
        } else if (strlen(result) > 0) {
            result[0] = '.';
            result[1] = '\0';
        } else {
            free(result);
            result = NULL;
        }
    }

    return result;
}

/**
 * @brief Generates the YANG file path from module name and optional revision date.
 */
static void
srctl_get_yang_path(const char *module_name, const char *revision_date, char *yang_path, size_t path_max_len)
{
    if (NULL != revision_date) {
        snprintf(yang_path, path_max_len, "%s%s@%s%s", srctl_schema_search_dir, module_name, revision_date, SR_SCHEMA_YANG_FILE_EXT);
    } else {
        snprintf(yang_path, path_max_len, "%s%s%s", srctl_schema_search_dir, module_name, SR_SCHEMA_YANG_FILE_EXT);
    }
}

/**
 * @brief Generates the YIN file path from module name and optional revision date.
 */
static void
srctl_get_yin_path(const char *module_name, const char *revision_date, char *yin_path, size_t path_max_len)
{
    if (NULL != revision_date) {
        snprintf(yin_path, PATH_MAX, "%s%s@%s%s", srctl_schema_search_dir, module_name, revision_date, SR_SCHEMA_YIN_FILE_EXT);
    } else {
        snprintf(yin_path, PATH_MAX, "%s%s%s", srctl_schema_search_dir, module_name, SR_SCHEMA_YIN_FILE_EXT);
    }
}

/**
 * @brief Create data file at the given path.
 */
static int
srctl_file_create(const char *path, void *arg)
{
    (void)arg;
    printf("Installing data file '%s' ...\n", path);
    int fd = open(path, O_WRONLY | O_CREAT, 0666);
    return fd == -1 ? -1 : close(fd);
}

/**
 * @brief Change owner of the data file at the given path.
 */
static int
srctl_file_chown(const char *path, void *arg)
{
    srctl_module_owner_t *owner_id = (srctl_module_owner_t *)arg;
    return chown(path, owner_id->owner, owner_id->group);
}

/**
 * @brief Change permissions of the data file at the given path.
 */
static int
srctl_file_chmod(const char *path, void *arg)
{
    // TODO: avoid using the external chmod command
    char cmd[PATH_MAX] = { 0, };
    snprintf(cmd, PATH_MAX, "chmod %s %s", (const char *)arg, path);
    return system(cmd);
}

/**
 * @brief Remove data file from the given path.
 */
static int
srctl_file_remove(const char *path, void *arg)
{
    (void)arg;
    int ret = 0;

    ret = unlink(path);
    if (0 != ret) {
        return (errno == ENOENT ? 0 : ret);
    } else {
        printf("Deleted the data file '%s'.\n", path);
    }
    return 0;
}

/**
 * @brief Apply the given command on all data files of the given module.
 */
static int
srctl_data_files_apply(const char *module_name, int (*command) (const char *, void *), void *arg, bool continue_on_error)
{
    char path[PATH_MAX] = { 0, };
    int rc = 0, ret = 0;

    for (size_t i = 0; i < sizeof(data_files_ext) / sizeof(data_files_ext[0]); ++i) {
        snprintf(path, PATH_MAX, "%s%s%s", srctl_data_search_dir, module_name, data_files_ext[i]);
        ret = command(path, arg);
        if (0 != ret) {
            rc = ret;
            if (!continue_on_error)
                break;
        }
    }

    return rc;
}

/**
 * @brief Change owner and/or permissions of the given module.
 */
static int
srctl_module_change(const char *module_name, const char *owner, const char *permissions)
{
    int ret = 0;
    char *colon = NULL;
    struct passwd *pwd = NULL;
    struct group *group = NULL;
    srctl_module_owner_t owner_id = { -1, -1 };

    /* update owner if requested */
    if (NULL != owner) {
        colon = strchr(owner, ':');
        if (NULL != colon && strlen(colon+1)) {
            /* try to get group ID */
            group = getgrnam(colon+1);
            if (NULL == group) {
                fprintf(stderr, "Error: Unable to obtain GID for the group '%s'.\n", colon+1);
                goto fail;
            }
            owner_id.group = group->gr_gid;
        }
        if (NULL != colon) {
            *colon = '\0';
        }
        if (NULL == colon || owner < colon) {
            /* try to get user ID */
            pwd = getpwnam(owner);
            if (NULL == pwd) {
                fprintf(stderr, "Error: Unable to obtain UID for the user '%s'.\n", owner);
                goto fail;
            }
            owner_id.owner = pwd->pw_uid;
        }
        ret = srctl_data_files_apply(module_name, srctl_file_chown, (void *)&owner_id, true);
        if (0 != ret) {
            if (NULL != colon) {
                *colon = ':'; /* restore the value of input string */
            }
            fprintf(stderr, "Error: Unable to change owner to '%s' for module '%s'.\n", owner, module_name);
            goto fail;
        }
    }

    /* update permissions if requested */
    if (NULL != permissions) {
        ret = srctl_data_files_apply(module_name, srctl_file_chmod, (void *)permissions, true);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to change permissions to '%s' for module '%s'.\n", permissions, module_name);
            goto fail;
        }
    }

    return SR_ERR_OK;

fail:
    return SR_ERR_INTERNAL;
}

/**
 * @brief Performs the --change operation.
 */
static int
srctl_change(const char *module_name, const char *owner, const char *permissions)
{
    if (NULL == module_name) {
        fprintf(stderr, "Error: Module must be specified for --change operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    if (NULL == owner && NULL == permissions) {
        fprintf(stderr, "Either --owner or --permissions option must be specified for --change operation.\n");
        return SR_ERR_INVAL_ARG;
    }

    printf("Changing ownership/permissions of the module '%s'.\n", module_name);
    int rc = srctl_module_change(module_name, owner, permissions);
    if (SR_ERR_OK == rc) {
        printf("Operation completed successfully.\n");
    } else {
        printf("Operation was cancelled.\n");
    }
    return rc;
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
srctl_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    return;
}

/**
 * @brief Initializes libyang ctx with all schemas installed in sysrepo.
 */
static int
srctl_ly_init(struct ly_ctx **ly_ctx)
{
    DIR *dp = NULL;
    struct dirent *ep = NULL;
    char schema_filename[PATH_MAX] = { 0, };

    *ly_ctx = ly_ctx_new(srctl_schema_search_dir);
    if (NULL == *ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
        return SR_ERR_INVAL_ARG;
    }
    ly_set_log_clb(srctl_ly_log_cb, 0);

    dp = opendir(srctl_schema_search_dir);
    if (NULL == dp) {
        fprintf(stderr, "Error by opening schema directory: %s.\n", strerror(errno));
        return SR_ERR_INVAL_ARG;
    }
    while (NULL != (ep = readdir(dp))) {
        if (sr_str_ends_with(ep->d_name, SR_SCHEMA_YIN_FILE_EXT) || sr_str_ends_with(ep->d_name, SR_SCHEMA_YANG_FILE_EXT)) {
            snprintf(schema_filename, PATH_MAX, "%s%s", srctl_schema_search_dir, ep->d_name);
            lys_parse_path(*ly_ctx, schema_filename, sr_str_ends_with(ep->d_name, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG);
        }
    }
    closedir(dp);

    return SR_ERR_OK;
}

/**
 * @brief Genarates YANG file path from YIN file path and vice versa
 * (new string will be allocated, should be freed by the caller).
 */
static const char *
srctl_get_compl_schema_file(const char *orig_filepath)
{
    const char *yang_filepath = NULL;
    char *dot = NULL;

    if (NULL != orig_filepath) {
        yang_filepath = calloc(strlen(orig_filepath) + 2, sizeof(*yang_filepath));
        strcpy((char*)yang_filepath, orig_filepath);
        dot = strrchr(yang_filepath, '.');
        if (NULL != dot) {
            strcpy(dot, sr_str_ends_with(orig_filepath, SR_SCHEMA_YIN_FILE_EXT) ? SR_SCHEMA_YANG_FILE_EXT : SR_SCHEMA_YIN_FILE_EXT);
        }
    }

    return yang_filepath;
}

/**
 * @brief Deletes the schema files.
 */
static int
srctl_schema_file_delete(const char *schema_file)
{
    const char *compl_file = NULL;
    int ret = 0, rc = SR_ERR_OK;

    ret = unlink(schema_file);
    if (0 != ret) {
        if (errno != ENOENT) {
            fprintf(stderr, "Error: Unable to delete the schema file '%s'.\n", schema_file);
            rc = SR_ERR_INTERNAL;
        }
    } else {
        printf("Deleted the schema file '%s'.\n", schema_file);
    }

    compl_file = srctl_get_compl_schema_file(schema_file);
    ret = unlink(compl_file);
    if (0 != ret) {
        if (errno != ENOENT) {
            fprintf(stderr, "Error: Unable to delete the schema file '%s'.\n", compl_file);
            rc = SR_ERR_INTERNAL;
        }
    } else {
        printf("Deleted the schema file '%s'.\n", compl_file);
    }
    free((void*)compl_file);

    return rc;
}

/**
 * @brief Deletes data files of a given module.
 */
static int
srctl_data_uninstall(const char *module_name)
{
    int ret = 0;

    ret = srctl_data_files_apply(module_name, srctl_file_remove, NULL, true);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to delete all data files.\n");
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

/**
 * @brief Performs the --uninstall operation.
 */
static int
srctl_uninstall(const char *module_name, const char *revision)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *module = NULL;
    int rc = SR_ERR_OK;

    if (NULL == module_name) {
        fprintf(stderr, "Error: Module must be specified for --uninstall operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    printf("Uninstalling the module '%s'.\n", module_name);

    /* init libyang context */
    rc = srctl_ly_init(&ly_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Failed to initialize libyang context.\n");
        goto fail;
    }

    /* find matching module to uninstall */
    MODULE_ITER(ly_ctx, module_name, revision, module) {
         /* uninstall all submodules */
         for (size_t i = 0; i < module->inc_size; i++) {
             rc = srctl_schema_file_delete(module->inc[i].submodule->filepath);
             if (SR_ERR_OK != rc) {
                 fprintf(stderr, "Warning: Submodule schema delete was unsuccessful, continuing.\n");
             }
         }
         /* uninstall the module */
         rc = srctl_schema_file_delete(module->filepath);
         if (SR_ERR_OK != rc) {
             fprintf(stderr, "Error: Module schema delete was unsuccessful.\n");
             goto fail;
         }
    }

    if (!custom_repository) {
        /* disable in sysrepo */
        rc = srctl_open_session(&connection, &session);
        if (SR_ERR_OK == rc) {
            rc = sr_module_install(session, module_name, revision, false);
        }
        if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
            srctl_report_error(session, rc);
            sr_disconnect(connection);
            goto fail;
        }
        sr_disconnect(connection);
    }

    /* delete data files */
    rc = srctl_data_uninstall(module_name);
    if (SR_ERR_OK != rc) {
        goto fail;
    }

    printf("Operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail:
    printf("Uninstall operation cancelled.\n");

cleanup:
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Installs specified schema files to sysrepo.
 */
static int
srctl_schema_install(const struct lys_module *module, const char *yang_src, const char *yin_src)
{
    char yang_dst[PATH_MAX] = { 0, }, yin_dst[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    const char *yang_path = NULL, *yin_path = NULL;
    int ret = 0, rc = SR_ERR_OK;

    if (NULL != yang_src) {
        /* install YANG */
        if (-1 != access(yang_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yang_path(module->name, module->rev[0].date, yang_dst, PATH_MAX);
            printf("Installing the YANG file to '%s' ...\n", yang_dst);
            snprintf(cmd, PATH_MAX, "cp %s %s", yang_src, yang_dst);
            ret = system(cmd);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to install the YANG file to '%s'.\n", yang_dst);
                yang_dst[0] = '\0';
                goto fail;
            }
        }
    }

    if (NULL != yin_src) {
        /* install YIN */
        if (-1 != access(yin_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yin_path(module->name, module->rev[0].date, yin_dst, PATH_MAX);
            printf("Installing the YIN file to '%s' ...\n", yin_dst);
            snprintf(cmd, PATH_MAX, "cp %s %s", yin_src, yin_dst);
            ret = system(cmd);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to install the YIN file to '%s'.\n", yin_dst);
                yin_dst[0] = '\0';
                goto fail;
            }
        }
    }

    /* install dependent YANG / YIN files */
    for (size_t i = 0; i < module->inc_size; i++) {
        printf("Resolving dependency: '%s' includes '%s'...\n", module->name, module->inc[i].submodule->name);
        if (sr_str_ends_with(module->inc[i].submodule->filepath, SR_SCHEMA_YANG_FILE_EXT)) {
            yang_path = module->inc[i].submodule->filepath;
            yin_path = NULL;
        } else {
            yang_path = NULL;
            yin_path = module->inc[i].submodule->filepath;
        }
        rc = srctl_schema_install((const struct lys_module *)module->inc[i].submodule, yang_path, yin_path);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->inc[i].submodule->name);
            goto fail;
        }
    }
    for (size_t i = 0; i < module->imp_size; i++) {
        if (NULL == module->imp[i].module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        printf("Resolving dependency: '%s' imports '%s' ...\n", module->name, module->imp[i].module->name);
        if (sr_str_ends_with(module->imp[i].module->filepath, SR_SCHEMA_YANG_FILE_EXT)) {
            yang_path = module->imp[i].module->filepath;
            yin_path = NULL;
        } else {
            yang_path = NULL;
            yin_path = module->imp[i].module->filepath;
        }
        rc = srctl_schema_install(module->imp[i].module, yang_path, yin_path);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->imp[i].module->name);
            goto fail;
        }
    }

    return SR_ERR_OK;

fail:
    printf("Installation of schema files cancelled for module '%s', reverting...\n", module->name);
    if ('\0' != yang_dst[0]) {
        ret = unlink(yang_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", yang_dst);
        }
    }
    if ('\0' != yin_dst[0]) {
        ret = unlink(yin_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", yin_dst);
        }
    }

    return SR_ERR_INTERNAL;
}

/**
 * @brief Returns true if the passed module defines any data-carrying elements and not only data types and identities.
 */
static bool
srctl_module_has_data(const struct lys_module *module)
{
    struct lys_node *iter = NULL;

    /* submodules don't have data tree, the data nodes are placed in the main module altogether */
    if (module->type) {
        return false;
    }

    /* iterate through top-level nodes */
    LY_TREE_FOR(module->data, iter) {
        if (((LYS_CONFIG_R & iter->flags) /* operational data */ ||
             ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST | LYS_CHOICE) & iter->nodetype) /* data-carrying */) &&
            !(LYS_AUGMENT & iter->nodetype) /* not an augment */) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Installs data files for given module and its dependencies (with already installed schema).
 */
static int
srctl_data_install(const struct lys_module *module, const char *owner, const char *permissions)
{
    int ret = 0, rc = SR_ERR_OK;

    /* install data files only if module can contain any data */
    if (srctl_module_has_data(module)) {
        printf("Installing data files for module %s...\n", module->name);
        ret = srctl_data_files_apply(module->name, srctl_file_create, NULL, false);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to install data files.\n");
            rc = SR_ERR_INTERNAL;
            goto fail;
        }

        rc = srctl_module_change(module->name, owner, permissions);
        if (SR_ERR_OK != rc) {
            goto fail;
        }
    } else {
        printf("Skipping installation of data files for module '%s'...\n", module->name);
    }

    /* install data files for imported module */
    for (size_t i = 0; i < module->imp_size; i++) {
        if (NULL == module->imp[i].module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        printf("Resolving dependency: '%s' imports '%s' ...\n", module->name, module->imp[i].module->name);
        rc = srctl_data_install(module->imp[i].module, owner, permissions);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->imp[i].module->name);
            goto fail;
        }
    }

    goto cleanup;

fail:
    printf("Installation of data files cancelled for module '%s', reverting...\n", module->name);
    srctl_data_uninstall(module->name);

cleanup:
    return rc;
}

/**
 * @brief Performs the --install operation.
 */
static int
srctl_install(const char *yang, const char *yin, const char *owner, const char *permissions, const char *search_dir)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *module;
    bool local_search_dir = false;
    char schema_dst[PATH_MAX] = { 0, };
    int rc = SR_ERR_INTERNAL, ret = 0;

    if (NULL == yang && NULL == yin) {
        fprintf(stderr, "Error: Either YANG or YIN file must be specified for --install operation.\n");
        goto fail;
    }
    printf("Installing a new module from file '%s' ...\n", (NULL != yang) ? yang : yin);

    /* extract the search directory path */
    if (NULL == search_dir) {
        search_dir = srctl_get_dir_path((NULL != yang) ? yang : yin);
        if (NULL == search_dir) {
            fprintf(stderr, "Error: Unable to extract search directory path.\n");
            goto fail;
        }
        local_search_dir = true;
    }

    /* init libyang context */
    ly_ctx = ly_ctx_new(search_dir);
    if (NULL == ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
        goto fail;
    }

    /* load the module into libyang ctx to get module information */
    module = lys_parse_path(ly_ctx, (NULL != yin) ? yin : yang, (NULL != yin) ? LYS_IN_YIN : LYS_IN_YANG);
    if (NULL == module) {
        fprintf(stderr, "Error: Unable to load the module by libyang.\n");
        goto fail;
     }

    /* Install schema files */
    rc = srctl_schema_install(module, yang, yin);
    if (SR_ERR_OK != rc) {
        goto fail;
    }

    /* Install data files */
    rc = srctl_data_install(module, owner, permissions);
    if (SR_ERR_OK != rc) {
        goto fail_data;
    }

    /* Notify sysrepo about the change */
    if (!custom_repository) {
        printf("Notifying sysrepo about the change ...\n");
        rc = srctl_open_session(&connection, &session);
        if (SR_ERR_OK == rc) {
            rc = sr_module_install(session, module->name, module->rev[0].date, true);
        }
        if (SR_ERR_OK != rc) {
            srctl_report_error(session, rc);
            goto fail_notif;
        }
    }

    printf("Install operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail_notif:
    srctl_data_uninstall(module->name);
fail_data:
    if (NULL != yang) {
        srctl_get_yang_path(module->name, module->rev[0].date, schema_dst, PATH_MAX);
        ret = unlink(schema_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", schema_dst);
        } else {
            printf("Deleted the schema file '%s'.\n", schema_dst);
        }
    }
    if (NULL != yin) {
        srctl_get_yin_path(module->name, module->rev[0].date, schema_dst, PATH_MAX);
        ret = unlink(schema_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", schema_dst);
        } else {
            printf("Deleted the schema file '%s'.\n", schema_dst);
        }
    }
fail:
    printf("Install operation cancelled.\n");

cleanup:
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    ly_ctx_destroy(ly_ctx, NULL);
    if (local_search_dir) {
        free((char*)search_dir);
    }
    return rc;
}

/**
 * @brief Performs the --init operation.
 */
static int
srctl_init(const char *module_name, const char *revision, const char *owner, const char *permissions)
{
    int rc = SR_ERR_OK;
    struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *module = NULL;

    if (NULL == module_name) {
        fprintf(stderr, "Error: Module must be specified for --init operation.\n");
        rc = SR_ERR_INVAL_ARG;
        goto fail;
    }

    /* init libyang context */
    rc = srctl_ly_init(&ly_ctx);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    /* find matching module to initialize */
    MODULE_ITER(ly_ctx, module_name, revision, module) {
        rc = srctl_data_install(module, owner, permissions);
        if (SR_ERR_OK != rc) {
            goto fail;
        }
        break;
    }

    printf("Init operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail:
    printf("Init operation cancelled.\n");

cleanup:
    return rc;
}

/**
 * @brief Performs the --feature-enable or --feature-disable operation.
 */
static int
srctl_feature_change(const char *module_name, const char *feature_name, bool enable)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    if (NULL == module_name) {
        fprintf(stderr, "Error: Module must be specified for --%s operation.\n",
                enable ? "feature-enable" : "feature-disable");
        return SR_ERR_INVAL_ARG;
    }
    printf("%s feature '%s' in the module '%s'.\n", enable ? "Enabling" : "Disabling", feature_name, module_name);

    rc = srctl_open_session(&connection, &session);

    if (SR_ERR_OK == rc) {
        rc = sr_feature_enable(session, module_name, feature_name, enable);
    }

    if (SR_ERR_OK == rc) {
        printf("Operation completed successfully.\n");
    } else {
        srctl_report_error(session, rc);
    }
    sr_disconnect(connection);

    return rc;
}

/**
 * @brief Performs the --dump and --import operations.
 */
static int
srctl_dump_import(const char *module_name, const char *format, bool dump)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    char data_filename[PATH_MAX] = { 0, };
    int fd = 0, ret = 0, rc = SR_ERR_OK;
    LYD_FORMAT dump_format = LYD_XML;

    if (NULL == module_name) {
        fprintf(stderr, "Error: Module must be specified for --dump operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    if (NULL != format) {
        if (0 == strcmp(format, "xml")) {
            dump_format = LYD_XML;
        } else if (0 == strcmp(format, "json")) {
            dump_format = LYD_JSON;
        } else {
            fprintf(stderr, "Error: Unknown dump format specified: '%s'.\n", format);
            return SR_ERR_INVAL_ARG;
        }
    }

    rc = srctl_ly_init(&ly_ctx);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    snprintf(data_filename, PATH_MAX, "%s%s%s", srctl_data_search_dir, module_name, SR_STARTUP_FILE_EXT);

    fd = open(data_filename, dump ? O_RDONLY : (O_RDWR | O_TRUNC));
    if (-1 == fd) {
        fprintf(stderr, "Error: Unable to open the data file '%s': %s.\n", data_filename, strerror(errno));
        ly_ctx_destroy(ly_ctx, NULL);
        return SR_ERR_INVAL_ARG;
    }
    sr_lock_fd(fd, false, true);

    if (dump) {
        /* dump data */
        data_tree = lyd_parse_fd(ly_ctx, fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
        if (NULL == data_tree && LY_SUCCESS != ly_errno) {
            fprintf(stderr, "Error: Unable to parse the data file '%s': %s.\n", data_filename, ly_errmsg());
            rc = SR_ERR_INTERNAL;
        } else {
            ret = lyd_print_fd(STDOUT_FILENO, data_tree, dump_format, LYP_WITHSIBLINGS | LYP_FORMAT);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to print the data: %s.\n", ly_errmsg());
                rc = SR_ERR_INTERNAL;
            }
        }
    } else {
        /* import data */
        data_tree = lyd_parse_fd(ly_ctx, STDIN_FILENO, dump_format, LYD_OPT_STRICT | LYD_OPT_CONFIG);
        if (NULL == data_tree && LY_SUCCESS != ly_errno) {
            fprintf(stderr, "Error: Unable to parse the data: %s.\n", ly_errmsg());
            rc = SR_ERR_INTERNAL;
        } else {
            ret = lyd_print_fd(fd, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to print the data to file '%s': %s.\n", data_filename, ly_errmsg());
                rc = SR_ERR_INTERNAL;
            }
        }
    }

    sr_unlock_fd(fd);
    close(fd);
    ly_ctx_destroy(ly_ctx, NULL);

    return ret;
}

/**
 * @brief Performs the --version operation.
 */
static void
srctl_print_version()
{
    printf("sysrepoctl - sysrepo control tool, version %s\n\n", SR_VERSION);
}

/**
 * @brief Performs the --help operation.
 */
static void
srctl_print_help()
{
    srctl_print_version();

    printf("Usage:\n");
    printf("  sysrepoctl [operation-option] [other-options]\n\n");
    printf("Available operation-options:\n");
    printf("  -h, --help             Prints usage help.\n");
    printf("  -v, --version          Prints version.\n");
    printf("  -l, --list             Lists YANG modules installed in sysrepo.\n");
    printf("  -i, --install          Installs specified schema into sysrepo (--yang or --yin must be specified).\n");
    printf("  -I, --init             Initializes already installed YANG/YIN schema (--module must be specified).\n");
    printf("  -u, --uninstall        Uninstalls specified schema from sysrepo (--module must be specified).\n");
    printf("  -c, --change           Changes specified module in sysrepo (--module must be specified).\n");
    printf("  -e, --feature-enable   Enables a feature within a module in sysrepo (feature name is the argument, --module must be specified).\n");
    printf("  -d, --feature-disable  Disables a feature within a module in sysrepo (feature name is the argument, --module must be specified).\n");
    printf("  -x, --dump             Dumps startup datastore data of specified module (argument speciefies the format: xml or json, --module must be specified).\n");
    printf("  -t, --import           Imports data of specified module into startup datastore (argument speciefies the format: xml or json, --module must be specified).\n");
    printf("\n");
    printf("Available other-options:\n");
    printf("  -g, --yang             Path to the file with schema in YANG format (--install operation).\n");
    printf("  -n, --yin              Path to the file with schema in YIN format (--install operation).\n");
    printf("  -m, --module           Name of the module to be operated on (--init, --uninstall, --change, --feature-enable, --feature-disable, --dump, --import operations).\n");
    printf("  -r, --revision         Revision of the module to be operated on (--init, --uninstall operations).\n");
    printf("  -o, --owner            Owner user and group of the module's data in chown format (--install, --init, --change operations).\n");
    printf("  -p, --permissions      Access permissions of the module's data in chmod format (--install, --init, --change operations).\n");
    printf("  -s, --search-dir       Directory to search for included/imported modules. Defaults to the directory with the YANG file being installed. (--install operation).\n");
    printf("\n");
    printf("Examples:\n");
    printf("  1) Install a new module by specifying YANG file, ownership and access permissions:\n");
    printf("     sysrepoctl --install --yang=/home/user/ietf-interfaces.yang --owner=admin:admin --permissions=644\n\n");
    printf("  2) Change the ownership and permissions of an existing YANG module:\n");
    printf("     sysrepoctl --change --module=ietf-interfaces --owner=admin:admin --permissions=644\n\n");
    printf("  3) Enable a feature within a YANG module:\n");
    printf("     sysrepoctl --feature-enable=if-mib --module=ietf-interfaces\n\n");
    printf("  4) Dump startup datastore data of a YANG module into a file in XML format:\n");
    printf("     sysrepoctl --dump=xml --module=ietf-interfaces > dump_file.txt\n\n");
    printf("  5) Import startup datastore data of a YANG module from a file in XML format:\n");
    printf("     sysrepoctl --import=xml --module=ietf-interfaces < dump_file.txt\n\n");
}

/**
 * @brief Main routine of the sysrepo control tool.
 */
int
main(int argc, char* argv[])
{
    int c = 0, operation = 0;
    char *feature_name = NULL, *dump_format = NULL;
    char *yang = NULL, *yin = NULL, *module = NULL, *revision = NULL;
    char *owner = NULL, *permissions = NULL;
    char *search_dir = NULL;
    char local_schema_search_dir[PATH_MAX] = { 0, }, local_data_search_dir[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    struct option longopts[] = {
       { "help",            no_argument,       NULL, 'h' },
       { "version",         no_argument,       NULL, 'v' },
       { "list",            no_argument,       NULL, 'l' },
       { "install",         no_argument,       NULL, 'i' },
       { "init",            no_argument,       NULL, 'I' },
       { "uninstall",       no_argument,       NULL, 'u' },
       { "change",          no_argument,       NULL, 'c' },
       { "feature-enable",  required_argument, NULL, 'e' },
       { "feature-disable", required_argument, NULL, 'd' },
       { "dump",            optional_argument, NULL, 'x' },
       { "import",          optional_argument, NULL, 't' },

       { "yang",            required_argument, NULL, 'g' },
       { "yin",             required_argument, NULL, 'n' },
       { "module",          required_argument, NULL, 'm' },
       { "revision",        required_argument, NULL, 'r' },

       { "owner",           required_argument, NULL, 'o' },
       { "permissions",     required_argument, NULL, 'p' },
       { "search-dir",      required_argument, NULL, 's' },
       { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "hvliIuce:d:x:t:g:n:m:r:o:p:s:0:W;", longopts, NULL)) != -1) {
        switch (c) {
            case 'h':
                srctl_print_help();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                srctl_print_version();
                exit(EXIT_SUCCESS);
                break;
            case 'l':
            case 'i':
            case 'u':
            case 'c':
            case 'I':
                operation = c;
                break;
            case 'e':
            case 'd':
                operation = c;
                feature_name = optarg;
                break;
            case 'x':
            case 't':
                operation = c;
                dump_format = optarg;
                break;
            case 'g':
                yang = optarg;
                break;
            case 'n':
                yin = optarg;
                break;
            case 'm':
                module = optarg;
                break;
            case 'r':
                revision = optarg;
                break;
            case 'o':
                owner = optarg;
                break;
            case 'p':
                permissions = optarg;
                break;
            case 's':
                search_dir = optarg;
                break;
            case '0':
                /* 'hidden' option - custom repository location */
                strncpy(local_schema_search_dir, optarg, PATH_MAX - 6);
                strncpy(local_data_search_dir, optarg, PATH_MAX - 6);
                strcat(local_schema_search_dir, "/yang/");
                strcat(local_data_search_dir, "/data/");
                srctl_schema_search_dir = local_schema_search_dir;
                srctl_data_search_dir = local_data_search_dir;
                custom_repository = true;
                break;
            case ':':
                /* missing option argument */
                fprintf(stderr, "%s: option `-%c' requires an argument\n", argv[0], optopt);
                break;
            case '?':
            default:
                /* invalid option */
                fprintf(stderr, "%s: option `-%c' is invalid. Exiting.\n", argv[0], optopt);
                exit(EXIT_FAILURE);
                break;
        }
    }

    switch (operation) {
        case 'l':
            rc = srctl_list_modules();
            break;
        case 'i':
            rc = srctl_install(yang, yin, owner, permissions, search_dir);
            break;
        case 'I':
            rc = srctl_init(module, revision, owner, permissions);
            break;
        case 'u':
            rc = srctl_uninstall(module, revision);
            break;
        case 'c':
            rc = srctl_change(module, owner, permissions);
            break;
        case 'e':
            rc = srctl_feature_change(module, feature_name, true);
            break;
        case 'd':
            rc = srctl_feature_change(module, feature_name, false);
            break;
        case 'x':
            rc = srctl_dump_import(module, dump_format, true);
            break;
        case 't':
            rc = srctl_dump_import(module, dump_format, false);
            break;
        default:
            srctl_print_help();
    }

    return (SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE;
}
