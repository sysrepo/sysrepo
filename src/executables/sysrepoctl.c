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
#include "module_dependencies.h"

/**
 * @brief Helper structure used for storing uid and gid of module's owner
 * and group respectively.
 */
typedef struct srctl_module_owner_s {
    uid_t owner;
    gid_t group;
} srctl_module_owner_t;

static int srctl_log_level = -1;
static char *srctl_schema_search_dir = SR_SCHEMA_SEARCH_DIR;
static char *srctl_data_search_dir = SR_DATA_SEARCH_DIR;
static char *srctl_internal_schema_search_dir = SR_INTERNAL_SCHEMA_SEARCH_DIR;
static char *srctl_internal_data_search_dir = SR_INTERNAL_DATA_SEARCH_DIR;
static bool custom_repository = false;

static const char * const data_files_ext[] = { SR_STARTUP_FILE_EXT,
                                               SR_RUNNING_FILE_EXT,
                                               SR_STARTUP_FILE_EXT SR_LOCK_FILE_EXT,
                                               SR_RUNNING_FILE_EXT SR_LOCK_FILE_EXT,
                                               SR_PERSIST_FILE_EXT};



/**
 * @brief Connects to sysrepo and starts a session.
 */
static int
srctl_open_session(bool daemon_required, sr_conn_ctx_t **connection_p, sr_session_ctx_t **session_p)
{
    int rc = SR_ERR_OK;

    if (daemon_required) {
        /* do not report failed connection to sysrepo *daemon* */
        sr_log_stderr(SR_LL_NONE);
    }
    rc = sr_connect("sysrepoctl", daemon_required ? SR_CONN_DAEMON_REQUIRED : SR_CONN_DEFAULT, connection_p);
    if (daemon_required) {
        /* re-enable logging */
        if ((srctl_log_level >= SR_LL_NONE) && (srctl_log_level <= SR_LL_DBG)) {
            sr_log_stderr(srctl_log_level);
        }
    }
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
        if(pw && gr) {
            snprintf(buff, PATH_MAX, "%s:%s", pw->pw_name, gr->gr_name);
        } else {
            snprintf(buff, PATH_MAX, "%d:%d", info.st_uid, info.st_gid);
        }
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
    size_t schema_cnt = 0, max_mod_name = 0, i;
    char buff[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    printf("Sysrepo schema directory: %s\n", SR_SCHEMA_SEARCH_DIR);
    printf("Sysrepo data directory:   %s\n", SR_DATA_SEARCH_DIR);
    printf("(Do not alter contents of these directories manually)\n");

    rc = srctl_open_session(false, &connection, &session);

    if (SR_ERR_OK == rc) {
        rc = sr_list_schemas(session, &schemas, &schema_cnt);
    }

    if (SR_ERR_OK == rc) {
        for (i = 0; i < schema_cnt; ++i) {
            if (strlen(schemas[i].module_name) > max_mod_name) {
                max_mod_name = strlen(schemas[i].module_name);
            }
        }

        printf("\n%-*s| %-11s| %-12s| %-20s| %-12s| %-30s| %s\n", (int)max_mod_name + 1,
               "Module Name", "Revision", "Conformance", "Data Owner", "Permissions", "Submodules", "Enabled Features");
        printf("----------------------------------------------------------------------------------------------------"
               "-------------------------------------------\n");
        for (size_t i = 0; i < schema_cnt; i++) {
            printf("%-*s| %-11s| ", (int)max_mod_name + 1, schemas[i].module_name,
                    (NULL == schemas[i].revision.revision ? "" : schemas[i].revision.revision));

            /* print conformance */
            if (schemas[i].installed) {
                printf("Installed   | ");
            } else if (schemas[i].implemented) {
                printf("Implemented | ");
            } else {
                printf("Imported    | ");
            }

            /* print owner */
            if (schemas[i].implemented) {
                srctl_print_module_owner(schemas[i].module_name, buff);
            } else {
                buff[0] = '\0';
            }
            printf("%-20s| ", buff);

            /* print permissions */
            if (schemas[i].implemented) {
                srctl_print_module_permissions(schemas[i].module_name, buff);
            } else {
                buff[0] = '\0';
            }
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
    mode_t old_umask = 0;
    old_umask = umask(0);
    int fd = open(path, O_WRONLY | O_CREAT, 0666);
    umask(old_umask);
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
 * @brief Updates subscription socket directory permissions according to the file
 * permissions set on the data file.
 */
static int
srctl_update_socket_dir_permissions(const char *module_name)
{
    char path[PATH_MAX] = { 0, };
    mode_t old_umask = 0;
    int ret = 0, rc = SR_ERR_OK;

    /* create the parent directory if it does not exist */
    strncat(path, SR_SUBSCRIPTIONS_SOCKET_DIR, PATH_MAX - 1);
    strncat(path, "/", PATH_MAX - strlen(path) - 1);

    old_umask = umask(0);
    ret = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
    umask(old_umask);
    if (-1 == ret && EEXIST != errno) {
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", path, sr_strerror_safe(errno));
    }

    /* create the module directory if it does not exist */
    strncat(path, module_name, PATH_MAX - strlen(path) - 1);
    strncat(path, "/", PATH_MAX - strlen(path) - 1);
    old_umask = umask(0);
    ret = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
    umask(old_umask);
    if (-1 == ret && EEXIST != errno) {
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", path, sr_strerror_safe(errno));
    }

    /* set the permissions on module's socket directory */
    rc = sr_set_data_file_permissions(path, true, srctl_data_search_dir, module_name, true);
    CHECK_RC_LOG_RETURN(rc, "Unable to set socket directory permissions for '%s'.", path);

    return rc;
}

/**
 * @brief Change owner and/or permissions of the given module.
 */
static int
srctl_module_change_permissions(const char *module_name, const char *owner, const char *permissions)
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

    if (!custom_repository) {
        /* update socket directory permissions (if not executed by build) */
        ret = srctl_update_socket_dir_permissions(module_name);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to update socket directory permissions for module '%s'.\n", module_name);
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
    int rc = srctl_module_change_permissions(module_name, owner, permissions);
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
    switch (level) {
        case LY_LLERR:
            SR_LOG_ERR("libyang: %s", msg);
            break;
        case LY_LLWRN:
            SR_LOG_WRN("libyang: %s", msg);
            break;
        case LY_LLVRB:
            SR_LOG_INF("libyang: %s", msg);
            break;
        case LY_LLDBG:
            SR_LOG_DBG("libyang: %s", msg);
            break;
        default:
            break;
    }
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
    } else {
        printf("Deleted the data files for module '%s'.\n", module_name);
    }

    return SR_ERR_OK;
}

/**
 * @brief Performs the --uninstall operation.
 */
static int
srctl_uninstall(char **module_names, char **revisions, int count)
{
    int rc = SR_ERR_INTERNAL, i;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;
    char **filepaths = NULL;
    md_module_key_t *module_key = NULL;
    sr_list_t *implicitly_removed = NULL;

    if (NULL == module_names || NULL == module_names[0]) {
        fprintf(stderr, "Error: Modules must be specified for --uninstall operation.\n");
        return SR_ERR_INVAL_ARG;
    }

    printf("Uninstalling the module ");
    for (i = 0; i < count; ++i) {
        printf("%s", module_names[i]);
    }
    printf("...\n");

    /* init module dependencies context */
    rc = md_init(srctl_schema_search_dir, srctl_internal_schema_search_dir, srctl_internal_data_search_dir,
                 true, &md_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Failed to initialize module dependencies context.\n");
        goto fail;
    }

    /**
     * Note: Module should be removed from the dependency graph before the schema files so
     * that the repository will remain in correct state even if the uninstallation fails
     * in-progress.
     */
    filepaths = calloc(count, sizeof *filepaths);
    CHECK_NULL_NOMEM_GOTO(filepaths, rc, fail);
    for (i = 0; i < count; ++i) {
        /* search for the module to uninstall */
        rc = md_get_module_info(md_ctx, module_names[i], revisions[i], NULL, &module);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Module '%s@%s' is not installed.\n", module_names[i],
                    revisions[i] ? revisions[i] : "<latest>");
            goto fail;
        }

        filepaths[i] = strdup(module->filepath);
        CHECK_NULL_NOMEM_GOTO(filepaths[i], rc, fail);
    }

    /* try to remove the module from the dependency graph */
    rc = md_remove_modules(md_ctx, (const char * const *)module_names, (const char * const *)revisions, count, &implicitly_removed);
    if (SR_ERR_INVAL_ARG == rc) {
        fprintf(stderr, "Error: Uninstalling the module would leave the repository in a state "
                               "with unresolved inter-module dependencies.\n");
        goto fail;
    }
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to remove the module from the dependency graph.\n");
        goto fail;
    }

    /* notify sysrepo about the change */
    for (i = 0; i < count; ++i) {
        if (!custom_repository) {
            /* disable in sysrepo */
            rc = srctl_open_session(true, &connection, &session);
            if (SR_ERR_OK == rc) {
                rc = sr_module_install(session, module_names[i], revisions[i], NULL, false);
                if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
                    srctl_report_error(session, rc);
                    fprintf(stderr, "Module can not be uninstalled because it is being used.\n");
                }
                sr_disconnect(connection);
                CHECK_RC_LOG_GOTO(rc, fail, "Failed to uninstall module %s", module_names[i]);
            }
        }
    }

    rc = md_flush(md_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to apply the changes made in the dependency graph.\n");
        goto fail;
    }

    /* unlock and release the internal data file with dependencies */
    md_destroy(md_ctx);
    md_ctx = NULL;

    for (i = 0; i < count; ++i) {
        /* uninstall the module */
        rc = srctl_schema_file_delete(filepaths[i]);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Warning: Module schema delete was unsuccessful, continuing.\n");
        }

        /* delete data files */
        rc = srctl_data_uninstall(module_names[i]);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Warning: data files removal was unsuccessful, continuing.\n");
        }
    }

    /* uninstall (sub)modules that are no longer needed */
    for (size_t i = 0; NULL != implicitly_removed && i < implicitly_removed->count; ++i) {
        module_key = (md_module_key_t *)implicitly_removed->data[i];
        printf("Automatically removing no longer needed module '%s'.\n", module_key->name);
        rc = srctl_schema_file_delete(module_key->filepath);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Warning: Module schema delete was unsuccessful, continuing.\n");
        }
        (void)srctl_data_uninstall(module_key->name); /* ignore errors */
    }

    printf("Uninstall operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail:
    printf("Uninstall operation failed.\n");

cleanup:
    if (filepaths) {
        for (i = 0; i < count; ++i) {
            free(filepaths[i]);
        }
    }
    free(filepaths);
    md_destroy(md_ctx);
    md_free_module_key_list(implicitly_removed);
    return rc;
}

/**
 * @brief Check if two file paths refer to the same file.
 */
bool
srctl_same_file(const char *file1, const char *file2)
{
    struct stat stat1, stat2;
    if(stat(file1, &stat1) < 0) return false;
    if(stat(file2, &stat2) < 0) return false;
    return (stat1.st_dev == stat2.st_dev) && (stat1.st_ino == stat2.st_ino);
}

/**
 * @brief Installs specified schema files to sysrepo.
 */
static int
srctl_schema_install(const struct lys_module *module, const char *yang_src, const char *yin_src)
{
    char yang_dst[PATH_MAX - 17] = { 0, }, yin_dst[PATH_MAX - 17] = { 0, }, cmd[PATH_MAX] = { 0, };
    const char *yang_path = NULL, *yin_path = NULL;
    int ret = 0, rc = SR_ERR_OK;

    if (NULL != yang_src) {
        /* install YANG */
        if (-1 != access(yang_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yang_path(module->name, module->rev[0].date, yang_dst, PATH_MAX - 17);
            if (srctl_same_file(yang_src, yang_dst)) {
                rc = SR_ERR_DATA_EXISTS;
                printf("Schema of the module %s is already installed, skipping...\n", module->name);
            } else {
                printf("Installing the YANG file to '%s'...\n", yang_dst);
                snprintf(cmd, PATH_MAX, "install -m 644 %s %s", yang_src, yang_dst);
                ret = system(cmd);
                if (0 != ret) {
                    fprintf(stderr, "Error: Unable to install the YANG file to '%s'.\n", yang_dst);
                    yang_dst[0] = '\0';
                    goto fail;
                }
            }
        }
    }

    if (NULL != yin_src) {
        /* install YIN */
        if (-1 != access(yin_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yin_path(module->name, module->rev[0].date, yin_dst, PATH_MAX - 17);
            if (srctl_same_file(yin_src, yin_dst)) {
                rc = SR_ERR_DATA_EXISTS;
                printf("Schema of the module %s is already installed, skipping...\n", module->name);
            } else {
                printf("Installing the YIN file to '%s'...\n", yin_dst);
                snprintf(cmd, PATH_MAX, "install -m 644 %s %s", yin_src, yin_dst);
                ret = system(cmd);
                if (0 != ret) {
                    fprintf(stderr, "Error: Unable to install the YIN file to '%s'.\n", yin_dst);
                    yin_dst[0] = '\0';
                    goto fail;
                }
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
        ret = srctl_schema_install((const struct lys_module *)module->inc[i].submodule, yang_path, yin_path);
        if (SR_ERR_OK != ret && SR_ERR_DATA_EXISTS != ret) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->inc[i].submodule->name);
            goto fail;
        }
    }
    for (size_t i = 0; i < module->imp_size; i++) {
        if (NULL == module->imp[i].module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        printf("Resolving dependency: '%s' imports '%s'...\n", module->name, module->imp[i].module->name);
        if (sr_str_ends_with(module->imp[i].module->filepath, SR_SCHEMA_YANG_FILE_EXT)) {
            yang_path = module->imp[i].module->filepath;
            yin_path = NULL;
        } else {
            yang_path = NULL;
            yin_path = module->imp[i].module->filepath;
        }
        ret = srctl_schema_install(module->imp[i].module, yang_path, yin_path);
        if (SR_ERR_OK != ret && SR_ERR_DATA_EXISTS != ret) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->imp[i].module->name);
            goto fail;
        }
    }

    return rc;

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
 * @brief Installs data files for given module and its dependencies (with already installed schema).
 */
static int
srctl_data_install(const struct lys_module *module, const char *owner, const char *permissions)
{
    int ret = 0, rc = SR_ERR_OK;

    /* install data files only if module can contain any data */
    if (module->implemented && sr_lys_module_has_data(module)) {
        printf("Installing data files for module '%s'...\n", module->name);
        ret = srctl_data_files_apply(module->name, srctl_file_create, NULL, false);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to install data files.\n");
            rc = SR_ERR_INTERNAL;
            goto fail;
        }

        rc = srctl_module_change_permissions(module->name, owner, permissions);
        if (SR_ERR_OK != rc) {
            goto fail;
        }
    } else {
        printf("Skipping installation of data files for module '%s'...\n", module->name);
        if (module->features_size > 0) {
            char path[PATH_MAX] = { 0, };
            /* install only persist file */
            snprintf(path, PATH_MAX, "%s%s%s", srctl_data_search_dir, module->name, SR_PERSIST_FILE_EXT);
            ret = srctl_file_create(path, NULL);
            if (0 != ret) {
                rc = SR_ERR_INTERNAL;
                goto fail;
            }
        }
    }

    /* install data files for imported module */
    for (size_t i = 0; i < module->imp_size; i++) {
        if (NULL == module->imp[i].module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        printf("Resolving dependency: '%s' imports '%s'...\n", module->name, module->imp[i].module->name);
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
srctl_install(const char *yang, const char *yin, const char *owner, const char *permissions, char **search_dirs, int search_dir_count)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    struct ly_ctx *ly_ctx = NULL;
    md_ctx_t *md_ctx = NULL;
    const struct lys_module *mod;
    bool local_search_dir = false;
    char schema_dst[PATH_MAX] = { 0, };
    int rc = SR_ERR_INTERNAL, rc_schema = SR_ERR_INTERNAL, ret = 0;
    md_module_t *module = NULL;
    sr_llist_node_t *module_ll_node = NULL;

    if (NULL == yang && NULL == yin) {
        fprintf(stderr, "Error: Either YANG or YIN file must be specified for --install operation.\n");
        goto fail;
    }
    printf("Installing a new module from file '%s'...\n", (NULL != yang) ? yang : yin);

    /* extract the search directory path */
    if (NULL == search_dirs) {
        search_dirs = calloc(1, sizeof *search_dirs);
        search_dirs[0] = srctl_get_dir_path((NULL != yang) ? yang : yin);
        if (NULL == search_dirs[0]) {
            fprintf(stderr, "Error: Unable to extract search directory path.\n");
            free(search_dirs);
            goto fail;
        }
        search_dir_count = 1;
        local_search_dir = true;
    }

    /* init libyang context */
    ly_ctx = ly_ctx_new(search_dirs[0], LY_CTX_NOYANGLIBRARY);
    if (NULL == ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context.\n");
        goto fail;
    }
    for (int i = 1; i < search_dir_count; ++i) {
        ly_ctx_set_searchdir(ly_ctx, search_dirs[i]);
    }

    /* init module dependencies context */
    ret = md_init(srctl_schema_search_dir, srctl_internal_schema_search_dir,
            srctl_internal_data_search_dir, true, &md_ctx);
    if (SR_ERR_OK != ret) {
        fprintf(stderr, "Error: Failed to initialize module dependencies context.\n");
        goto fail;
    }

    /* load the module into libyang ctx to get module information */
    mod = lys_parse_path(ly_ctx, (NULL != yin) ? yin : yang, (NULL != yin) ? LYS_IN_YIN : LYS_IN_YANG);
    if (NULL == mod) {
        fprintf(stderr, "Error: Unable to load the module by libyang.\n");
        goto fail;
    }

    /* check namespace duplication */
    module_ll_node = md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *)module_ll_node->data;

        if (!strcmp(module->ns, mod->ns) && strcmp(module->name, mod->name)) {
            fprintf(stderr, "Error: Module '%s' with namespace '%s' already in context.\n", module->name, module->ns);
            goto fail;
        }

        module_ll_node = module_ll_node->next;
    }

    /* install schema files */
    rc_schema = srctl_schema_install(mod, yang, yin);
    if (SR_ERR_OK != rc_schema && SR_ERR_DATA_EXISTS != rc_schema) {
        rc = rc_schema;
        goto fail_schema;
    }

    /* update dependencies */
    if (NULL != yin) {
        srctl_get_yin_path(mod->name, mod->rev[0].date, schema_dst, PATH_MAX);
    } else if (NULL != yang) {
        srctl_get_yang_path(mod->name, mod->rev[0].date, schema_dst, PATH_MAX);
    }
    rc = md_insert_module(md_ctx, schema_dst, NULL);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to insert the module into the dependency graph.\n");
        goto fail_schema;
    }
    rc = md_flush(md_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to apply the changes made in the dependency graph.\n");
        goto fail_schema;
    }

    /* unlock and release the internal data file with dependencies */
    md_destroy(md_ctx);
    md_ctx = NULL;

    /* install data files */
    rc = srctl_data_install(mod, owner, permissions);
    if (SR_ERR_OK != rc) {
        goto fail_data;
    }

    /* Notify sysrepo about the change */
    if (!custom_repository) {
        printf("Notifying sysrepo about the change...\n");
        rc = srctl_open_session(true, &connection, &session);
        if (SR_ERR_OK == rc) {
            rc = sr_module_install(session, mod->name, mod->rev[0].date, mod->filepath, true);
            if (SR_ERR_OK != rc) {
                if (SR_ERR_RESTART_NEEDED == rc) {
                    fprintf(stderr, "Error: sysrepod must be restarted (or stopped) before previously uninstalled "
                            "module '%s' can be reinstalled.\n", mod->name);
                } else {
                    srctl_report_error(session, rc);
                }
                goto fail_notif;
            }
        }
    }

    printf("Install operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail_notif:
fail_data:
    /* remove from dependency list */
    rc = md_init(srctl_schema_search_dir, srctl_internal_schema_search_dir,
                 srctl_internal_data_search_dir, true, &md_ctx);
    if (SR_ERR_OK == rc) {
        rc = md_remove_modules(md_ctx, &mod->name, (const char * const *)&mod->rev[0].date, 1, NULL);
    }
    if (SR_ERR_OK == rc) {
        md_flush(md_ctx);
    }
    md_destroy(md_ctx);
    md_ctx = NULL;

    srctl_data_uninstall(mod->name);
fail_schema:
    printf("Reverting the install operation...\n");
    /* remove both yang and yin schema files */
    if (NULL != yang && SR_ERR_DATA_EXISTS != rc_schema) {
        srctl_get_yang_path(mod->name, mod->rev[0].date, schema_dst, PATH_MAX);
        ret = unlink(schema_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", schema_dst);
        } else {
            printf("Deleted the schema file '%s'.\n", schema_dst);
        }
    }
    if (NULL != yin && SR_ERR_DATA_EXISTS != rc_schema) {
        srctl_get_yin_path(mod->name, mod->rev[0].date, schema_dst, PATH_MAX);
        ret = unlink(schema_dst);
        if (0 != ret && ENOENT != errno) {
            fprintf(stderr, "Error: Unable to revert the installation of the schema file '%s'.\n", schema_dst);
        } else {
            printf("Deleted the schema file '%s'.\n", schema_dst);
        }
    }
fail:
    printf("Install operation failed.\n");

cleanup:
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    md_destroy(md_ctx);
    ly_ctx_destroy(ly_ctx, NULL);
    if (local_search_dir) {
        for (int i = 0; i < search_dir_count; ++i) {
            free(search_dirs[i]);
        }
        free(search_dirs);
    }
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

    rc = srctl_open_session(false, &connection, &session);

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
    printf("  -l, --list             Lists YANG modules installed in sysrepo (note that Conformance Installed implies also Implemented).\n");
    printf("  -i, --install          Installs specified schema into sysrepo (--yang or --yin must be specified).\n");
    printf("  -u, --uninstall        Uninstalls specified schema from sysrepo (--module must be specified).\n");
    printf("  -c, --change           Changes specified module in sysrepo (--module must be specified).\n");
    printf("  -e, --feature-enable   Enables a feature within a module in sysrepo (feature name is the argument, --module must be specified).\n");
    printf("  -d, --feature-disable  Disables a feature within a module in sysrepo (feature name is the argument, --module must be specified).\n");
    printf("\n");
    printf("Available other-options:\n");
    printf("  -L, --level            Set verbosity level of logging ([0 - 4], 0 = all logging turned off).\n");
    printf("  -g, --yang             Path to the file with schema in YANG format (--install operation).\n");
    printf("  -n, --yin              Path to the file with schema in YIN format (--install operation).\n");
    printf("  -m, --module           Name of the module to be operated on (--change, --feature-enable, --feature-disable operations,\n");
    printf("                         --uninstall - several modules can be delimited with \',\').\n");
    printf("  -r, --revision         Revision of the module to be operated on (--uninstall operations - several revisions\n");
    printf("                         can be delimited with \',\', for no revision use \'-\').\n");
    printf("  -o, --owner            Owner user and group of the module's data in chown format (--install, --change operations).\n");
    printf("  -p, --permissions      Access permissions of the module's data in chmod format (--install, --change operations).\n");
    printf("  -s, --search-dir       Directory to search for included/imported modules. Defaults to the directory with the YANG file being installed. (--install operation).\n");
    printf("                         Can be specified multiple times.\n");
    printf("  -S, --search-installed Search for included/imported modules in sysrepo schema directory. (--install operation).\n");
    printf("\n");
    printf("Examples:\n");
    printf("  1) Install a new module by specifying YANG file, ownership and access permissions:\n");
    printf("     sysrepoctl --install --yang=/home/user/ietf-interfaces.yang --owner=admin:admin --permissions=644\n\n");
    printf("  2) Change the ownership and permissions of an existing YANG module:\n");
    printf("     sysrepoctl --change --module=ietf-interfaces --owner=admin:admin --permissions=644\n\n");
    printf("  3) Enable a feature within a YANG module:\n");
    printf("     sysrepoctl --feature-enable=if-mib --module=ietf-interfaces\n\n");
    printf("  4) Uninstall 2 modules, second one is without revision:\n");
    printf("     sysrepoctl --uninstall --module=mod-a,mod-b --revision=2035-05-05,-\n\n");
}

/**
 * @brief Main routine of the sysrepo control tool.
 */
int
main(int argc, char* argv[])
{
    int c = 0, operation = 0, count = 0;
    char *feature_name = NULL, *ptr = NULL;
    char *yang = NULL, *yin = NULL, *module = NULL, *revision = NULL;
    char *owner = NULL, *permissions = NULL;
    char **search_dirs = NULL, **modules = NULL, **revisions = NULL;
    int search_dir_count = 0;
    char local_schema_search_dir[PATH_MAX] = { 0, }, local_data_search_dir[PATH_MAX] = { 0, };
    char local_internal_schema_search_dir[PATH_MAX] = { 0, }, local_internal_data_search_dir[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;
    int search_installed = 0;

    struct option longopts[] = {
       { "help",            no_argument,       NULL, 'h' },
       { "version",         no_argument,       NULL, 'v' },
       { "list",            no_argument,       NULL, 'l' },
       { "install",         no_argument,       NULL, 'i' },
       { "uninstall",       no_argument,       NULL, 'u' },
       { "change",          no_argument,       NULL, 'c' },
       { "feature-enable",  required_argument, NULL, 'e' },
       { "feature-disable", required_argument, NULL, 'd' },

       { "level",           required_argument, NULL, 'L' },
       { "yang",            required_argument, NULL, 'g' },
       { "yin",             required_argument, NULL, 'n' },
       { "module",          required_argument, NULL, 'm' },
       { "revision",        required_argument, NULL, 'r' },

       { "owner",           required_argument, NULL, 'o' },
       { "permissions",     required_argument, NULL, 'p' },
       { "search-dir",      required_argument, NULL, 's' },
       { "search-installed",no_argument,       NULL, 'S' },
       { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "hvliuce:d:L:g:n:m:r:o:p:s:S0:W;", longopts, NULL)) != -1) {
        switch (c) {
            case 'h':
                srctl_print_help();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                srctl_print_version();
                exit(EXIT_SUCCESS);
                break;
            case 'L':
                srctl_log_level = atoi(optarg);
                break;
            case 'l':
            case 'i':
            case 'u':
            case 'c':
                operation = c;
                break;
            case 'e':
            case 'd':
                operation = c;
                feature_name = optarg;
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
                ++search_dir_count;
                search_dirs = realloc(search_dirs, search_dir_count * sizeof *search_dirs);
                if (!search_dirs) {
                    fprintf(stderr, "%s: memory allocation failed. Exiting.\n", argv[0]);
                    return EXIT_FAILURE;
                }
                search_dirs[search_dir_count - 1] = optarg;
                break;
            case 'S':
                search_installed = 1;
                break;
            case '0':
                /* 'hidden' option - custom repository location */
                strncpy(local_schema_search_dir, optarg, PATH_MAX - 6);
                strncpy(local_data_search_dir, optarg, PATH_MAX - 6);
                strncpy(local_internal_schema_search_dir, optarg, PATH_MAX - 15);
                strncpy(local_internal_data_search_dir, optarg, PATH_MAX - 15);
                strcat(local_schema_search_dir, "/yang/");
                strcat(local_data_search_dir, "/data/");
                strcat(local_internal_schema_search_dir, "/yang/internal");
                strcat(local_internal_data_search_dir, "/data/internal");
                srctl_schema_search_dir = local_schema_search_dir;
                srctl_data_search_dir = local_data_search_dir;
                srctl_internal_schema_search_dir = local_internal_schema_search_dir;
                srctl_internal_data_search_dir = local_internal_data_search_dir;
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

    if (search_installed) {
        search_dirs = calloc(1, sizeof *search_dirs);
        search_dirs[0] = srctl_schema_search_dir;
        search_dir_count = 1;
    }

    /* set log levels */
    sr_log_stderr(SR_LL_ERR);
    sr_log_syslog(SR_LL_NONE);
    if ((srctl_log_level >= SR_LL_NONE) && (srctl_log_level <= SR_LL_DBG)) {
        sr_log_stderr(srctl_log_level);
    }
    ly_set_log_clb(srctl_ly_log_cb, 0);

    /* select operation */
    switch (operation) {
        case 'l':
            rc = srctl_list_modules();
            break;
        case 'i':
            rc = srctl_install(yang, yin, owner, permissions, search_dirs, search_dir_count);
            break;
        case 'u':
            if (!module || !strchr(module, ',')) {
                rc = srctl_uninstall(&module, &revision, 1);
            } else {
                count = 1;
                for (ptr = module; ptr[0]; ++ptr) {
                    if (ptr[0] == ',') {
                        ++count;
                    }
                }

                modules = calloc(count, sizeof *modules);
                revisions = calloc(count, sizeof *revisions);
                if (!modules || !revisions) {
                    fprintf(stderr, "%s: memory allocation failed. Exiting.\n", argv[0]);
                    return EXIT_FAILURE;
                }

                for (ptr = strtok(module, ","), c = 0; ptr; ptr = strtok(NULL, ","), ++c) {
                    modules[c] = strdup(ptr);
                    if (!modules[c]) {
                        fprintf(stderr, "%s: memory allocation failed. Exiting.\n", argv[0]);
                        rc = SR_ERR_INTERNAL;
                        goto fail;
                    }
                }

                if (revision) {
                    for (ptr = strtok(revision, ","), c = 0; ptr; ptr = strtok(NULL, ","), ++c) {
                        if (c == count) {
                            /* too many revisions, invalid write */
                            ++c;
                            break;
                        }
                        if (strcmp(ptr, "-") != 0) {
                            revisions[c] = strdup(ptr);
                            if (!revisions[c]) {
                                fprintf(stderr, "%s: memory allocation failed. Exiting.\n", argv[0]);
                                rc = SR_ERR_INTERNAL;
                                goto fail;
                            }
                        }
                    }
                    if (c != count) {
                        fprintf(stderr, "%s: option `--revision' includes different number of revisions than modules. Exiting.\n", argv[0]);
                        rc = SR_ERR_INTERNAL;
                        goto fail;
                    }
                }

                rc = srctl_uninstall(modules, revisions, count);
            }
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
        default:
            srctl_print_help();
    }

fail:
    if (modules) {
        for (c = 0; c < count; ++c) {
            free(modules[c]);
        }
        free(modules);
    }
    if (revisions) {
        for (c = 0; c < count; ++c) {
            free(revisions[c]);
        }
        free(revisions);
    }
    free(search_dirs);
    return (SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE;
}
