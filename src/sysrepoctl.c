/**
 * @file sysrepoctl.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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

static char *srctl_schema_search_dir = SR_SCHEMA_SEARCH_DIR;
static char *srctl_data_search_dir = SR_DATA_SEARCH_DIR;
static bool custom_repository = false;

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
 * @brief Gets filename without the extension (new string will be allocated, should be freed by the caller).
 */
static char *
srctl_get_file_base_name(const char *file_path)
{
    char *slash = NULL, *dot = NULL, *result = NULL;

    slash = strrchr(file_path, '/');
    if (NULL != slash) {
        result = strdup(slash + 1);
    } else {
        result = strdup(file_path);
    }

    if (NULL != result) {
        dot = strrchr(result, '.');
    }
    if (NULL != dot) {
        *dot = '\0';
    }

    return result;
}

/* forward-declartion */
static char *srctl_yin_generate(const char *search_dir, const char *dst_dir, const char *yang_file);

/**
 * @brief Generates YIN files out of the all dependent models of given YANG file.
 */
static void
srctl_dependent_yins_generate(const char *search_dir, const char *dst_dir, const char *yang_path)
{
    char command[PATH_MAX] = { 0, };
    char filename[PATH_MAX] = { 0, };
    DIR *dp;
    struct dirent *ep;
    char *ext = NULL, *strtok_tmp = NULL;

    dp = opendir(search_dir);
    if (NULL == dp) {
        return;
    }

    /* list dependent YINs */
    snprintf(command, PATH_MAX, "pyang --path=%s --no-path-recurse --format=depend %s",
            search_dir, yang_path);
    FILE *fp = popen(command, "r");
    if (fp != NULL) {
        while (fgets(command, sizeof(command)-1, fp) != NULL) {
            char *token = strtok_r(command, ": \n", &strtok_tmp);
            size_t cnt = 0;
            while(NULL != token) {
                /* first token contains the 'target' part - skip it */
                if (0 != cnt++) {
                    /* compare dependent module name with the files in search_dir */
                    rewinddir(dp);
                    while (NULL != (ep = readdir(dp))) {
                        if (0 == strncmp(ep->d_name, token, strlen(token))) {
                            ext = strrchr(ep->d_name, '.');
                            if (NULL != ext && 0 == strcmp(ext, ".yang")) {
                                /* matching YANG file found */
                                snprintf(filename, PATH_MAX, "%s/%s", search_dir, ep->d_name);
                                srctl_yin_generate(search_dir, dst_dir, filename);
                            }
                        }
                    }
                }
                /* get next token */
                token = strtok_r(NULL, ": \n", &strtok_tmp);
           }
        }
        pclose(fp);
    }

    closedir(dp);
}

/**
 * @brief Generates YIN file out of the given YANG file.
 */
static char *
srctl_yin_generate(const char *search_dir, const char *dst_dir, const char *yang_file)
{
    char *file_base_name = NULL, *yin_file = NULL;
    char command[PATH_MAX] = { 0, };
    size_t len = 0;
    int ret = 0;

    file_base_name = srctl_get_file_base_name(yang_file);
    if (NULL == file_base_name) {
        return NULL;
    }

    len = snprintf(NULL, 0, "%s%s.yin", dst_dir, file_base_name);
    yin_file = calloc(len + 1, sizeof(*yin_file));
    if (NULL == yin_file) {
        free(file_base_name);
        return NULL;
    }
    snprintf(yin_file, len + 1, "%s%s.yin", dst_dir, file_base_name);

    if (-1 == access(yin_file, F_OK)) {
        /* if the yin does not already exists */
        snprintf(command, PATH_MAX, "pyang --path=%s --no-path-recurse --format=yin --output=%s %s",
                search_dir, yin_file, yang_file);
        printf("Generating YIN from '%s' ...\n", yang_file);
        ret = system(command);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to generate the YIN file.\n");
            free(yin_file);
            yin_file = NULL;
        }
    }

    if (NULL != yin_file) {
        snprintf(command, PATH_MAX, "cp %s %s", yang_file, dst_dir);
        ret = system(command);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to install the YIN file to '%s'.\n", dst_dir);
            free(yin_file);
            yin_file = NULL;
        }
    }

    if (NULL != yin_file) {
        srctl_dependent_yins_generate(search_dir, dst_dir, yang_file);
    }

    free(file_base_name);
    return yin_file;
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
 * @brief Alters all data files of given module with given command.
 */
static int
srctl_data_files_alter(const char *module_name, const char *command, bool continue_on_error)
{
    char cmd[PATH_MAX] = { 0, };
    int ret = 0, last_err = 0;

    snprintf(cmd, PATH_MAX, "%s %s%s%s", command, srctl_data_search_dir, module_name, SR_STARTUP_FILE_EXT);
    ret = system(cmd);
    if (0 != ret) { if (continue_on_error) last_err = ret; else return ret; }
    snprintf(cmd, PATH_MAX, "%s %s%s%s", command, srctl_data_search_dir, module_name, SR_RUNNING_FILE_EXT);
    ret = system(cmd);
    if (0 != ret) { if (continue_on_error) last_err = ret; else return ret; }
    snprintf(cmd, PATH_MAX, "%s %s%s%s%s", command, srctl_data_search_dir, module_name, SR_STARTUP_FILE_EXT, SR_LOCK_FILE_EXT);
    ret = system(cmd);
    if (0 != ret) { if (continue_on_error) last_err = ret; else return ret; }
    snprintf(cmd, PATH_MAX, "%s %s%s%s%s", command, srctl_data_search_dir, module_name, SR_RUNNING_FILE_EXT, SR_LOCK_FILE_EXT);
    ret = system(cmd);
    if (0 != ret) { if (continue_on_error) last_err = ret; else return ret; }
    snprintf(cmd, PATH_MAX, "%s %s%s%s", command, srctl_data_search_dir, module_name, SR_PERSIST_FILE_EXT);
    ret = system(cmd);
    if (0 != ret) { if (continue_on_error) last_err = ret; else return ret; }

    return last_err;
}

/**
 * @brief Genarates YANG file path from YIN file path (new string will be allocated, should be freed by the caller).
 */
static const char *
srctl_yang_filepath_from_yin_filepath(const char *yin_filepath)
{
    const char *yang_filepath = NULL;
    char *dot = NULL;

    if (NULL != yin_filepath) {
        yang_filepath = calloc(strlen(yin_filepath) + 2, sizeof(*yang_filepath));
        strcpy((char*)yang_filepath, yin_filepath);
        dot = strrchr(yang_filepath, '.');
        if (NULL != dot) {
            strncpy(dot, ".yang", 6);
        }
    }

    return yang_filepath;
}

/**
 * @brief Installs specified schema files to sysrepo ad return module information.
 */
static int
srctl_schema_install(struct ly_ctx *ly_ctx, const char *yang_src, const char *yin_src,
        const struct lys_module *module_in, const char **module_name, const char **revision_date)
{
    const struct lys_module *module = NULL;
    char yang_dst[PATH_MAX] = { 0, }, yin_dst[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    const char *tmp_name = NULL, *tmp_rev = NULL, *yang_name;
    int ret = 0, rc = SR_ERR_OK;

    if (NULL != module_in) {
        /* libyang module passed in */
        module = module_in;
    } else {
        /* load the module into libyang ctx to get module information */
        module = lys_parse_path(ly_ctx, (NULL != yin_src) ? yin_src : yang_src,
                (NULL != yin_src) ? LYS_IN_YIN : LYS_IN_YANG);
        if (NULL == module) {
            fprintf(stderr, "Error: Unable to load the module by libyang.\n");
            goto fail;
        }
    }
    *module_name = module->name;
    if (module->rev_size > 0) {
        *revision_date = module->rev[0].date;
    }

    if (NULL != yang_src) {
        /* install YANG */
        if (-1 != access(yang_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yang_path(*module_name, *revision_date, yang_dst, PATH_MAX);
            printf("Installing the YANG file to '%s' ...\n", yang_dst);
            snprintf(cmd, PATH_MAX, "cp -u %s %s", yang_src, yang_dst);
            ret = system(cmd);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to install the YANG file to '%s'.\n", yang_dst);
                goto fail;
            }
        }
    }

    if (NULL != yin_src) {
        /* install YIN */
        if (-1 != access(yin_src, F_OK)) {
            /* only if the source file actually exists */
            srctl_get_yin_path(*module_name, *revision_date, yin_dst, PATH_MAX);
            printf("Installing the YIN file to '%s' ...\n", yin_dst);
            snprintf(cmd, PATH_MAX, "cp -u %s %s", yin_src, yin_dst);
            ret = system(cmd);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to install the YIN file to '%s'.\n", yin_dst);
                goto fail;
            }
        }
    }

    /* install dependent YANG and YIN files */
    for (size_t i = 0; i < module->inc_size; i++) {
        printf("Resolving dependency: '%s' includes '%s'...\n", *module_name, module->inc[i].submodule->name);
        yang_name = srctl_yang_filepath_from_yin_filepath(module->inc[i].submodule->filepath);
        rc = srctl_schema_install(ly_ctx, yang_name, module->inc[i].submodule->filepath,
                (const struct lys_module *)module->inc[i].submodule, &tmp_name, &tmp_rev);
        free((void*)yang_name);
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
        printf("Resolving dependency: '%s' imports '%s' ...\n", *module_name, module->imp[i].module->name);
        yang_name = srctl_yang_filepath_from_yin_filepath(module->imp[i].module->filepath);
        rc = srctl_schema_install(ly_ctx, yang_name, module->imp[i].module->filepath,
                (const struct lys_module *)module->imp[i].module, &tmp_name, &tmp_rev);
        free((void*)yang_name);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Unable to resolve the dependency on '%s'.\n", module->imp[i].module->name);
            goto fail;
        }
    }

    return SR_ERR_OK;

fail:
    if ('\0' != yang_dst[0]) {
        snprintf(cmd, PATH_MAX, "rm -f %s", yang_dst);
        system(cmd);
    }
    if ('\0' != yin_dst[0]) {
        snprintf(cmd, PATH_MAX, "rm -f %s", yin_dst);
        system(cmd);
    }

    return SR_ERR_INTERNAL;
}

/**
 * @brief Performs the --install operation.
 */
static int
srctl_install(const char *yang, const char *yin, const char *owner, const char *permissions, const char *search_dir)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    char tmp_dir[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    const char *module_name = NULL, *revision_date = NULL;
    char *tmp_yin = NULL;
    struct ly_ctx *ly_ctx = NULL;
    bool local_search_dir = false;
    int ret = 0, rc = SR_ERR_OK;

    if (NULL == yang && NULL == yin) {
        fprintf(stderr, "Error: Either YANG or YIN file must be specified for --install operation.\n");
        goto fail;
    }
    printf("Installing a new module from file '%s' ...\n", (NULL != yang) ? yang : yin);

    if (NULL == search_dir) {
        search_dir = srctl_get_dir_path((NULL != yang) ? yang : yin);
        if (NULL == search_dir) {
            fprintf(stderr, "Error: Unable to extract search directory path.\n");
            goto fail;
        }
        local_search_dir = true;
    }

    /* generate YIN if not provided */
    if (NULL == yin) {
        /* check if pyang is installed */
        ret = system("pyang --version > /dev/null");
        if (0 != ret) {
            fprintf(stderr, "Error: Pyang not found. Install it, or use --yin option to specify YIN file.\n");
            goto fail;
        }
        snprintf(tmp_dir, PATH_MAX, "/tmp/sysrepoctl-%d/", getpid());
        snprintf(cmd, PATH_MAX, "mkdir %s", tmp_dir);
        ret = system(cmd);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to create temprary working directory.\n");
            goto fail;
        }
        /* generate the YIN file */
        tmp_yin = srctl_yin_generate(search_dir, tmp_dir, yang);
        if (NULL == tmp_yin) {
            fprintf(stderr, "Error: Unable to generate the YIN file.\n");
            goto fail;
        }
    }

    /* init libyang context */
    ly_ctx = ly_ctx_new((NULL != yin) ? search_dir : tmp_dir);
    if (NULL == ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
        goto fail;
    }

    /* Install schema files */
    rc = srctl_schema_install(ly_ctx, yang, ((NULL != yin) ? yin : tmp_yin), NULL, &module_name, &revision_date);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to install schema files.\n");
        goto fail;
    }

    printf("Installing data files ...\n");
    ret = srctl_data_files_alter(module_name, "touch", false);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to install data files.\n");
        goto fail;
    }

    /* update permissions if requested */
    if (NULL != owner) {
        snprintf(cmd, PATH_MAX, "chown %s", owner);
        ret = srctl_data_files_alter(module_name, cmd, true);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to change owner to '%s'.\n", owner);
            goto fail;
        }
    }
    if (NULL != permissions) {
        snprintf(cmd, PATH_MAX, "chmod %s", permissions);
        ret = srctl_data_files_alter(module_name, cmd, true);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to change permissions to '%s'.\n", permissions);
            goto fail;
        }
    }

    if (!custom_repository) {
        printf("Notifying sysrepo about the change ...\n");
        rc = srctl_open_session(&connection, &session);
        if (SR_ERR_OK == rc) {
            rc = sr_module_install(session, module_name, revision_date, true);
        }
        if (SR_ERR_OK != rc) {
            srctl_report_error(session, rc);
            goto fail;
        }
    }

    printf("Install operation completed successfully.\n");
    rc = SR_ERR_OK;
    goto cleanup;

fail:
    fprintf(stderr, "Install operation cancelled.\n");
    if (NULL != module_name) {
        srctl_data_files_alter(module_name, "rm -f", true);
    }
    rc = SR_ERR_INTERNAL;

cleanup:
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    free(tmp_yin);
    ly_ctx_destroy(ly_ctx, NULL);
    if (local_search_dir) {
        free((char*)search_dir);
    }
    if ('\0' != tmp_dir[0]) {
        snprintf(cmd, PATH_MAX, "rm -r %s", tmp_dir);
        system(cmd);
    }
    return rc;
}

/**
 * @brief Deletes the schema files.
 */
static int
srctl_schema_file_delete(const char *schema_file)
{
    char cmd[PATH_MAX] = { 0, };
    const char *yang_file = NULL;
    int ret = 0, rc = SR_ERR_OK;

    printf("Deleting the YIN file %s ...\n", schema_file);
    snprintf(cmd, PATH_MAX, "rm -f %s", schema_file);
    ret = system(cmd);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to delete the YIN file '%s'.\n", schema_file);
        rc = SR_ERR_INTERNAL;
    }

    yang_file = srctl_yang_filepath_from_yin_filepath(schema_file);
    if (-1 != access(yang_file, F_OK)) {
        printf("Deleting the YANG file %s ...\n", yang_file);
        snprintf(cmd, PATH_MAX, "rm -f %s", yang_file);
        ret = system(cmd);
        if (0 != ret) {
            fprintf(stderr, "Error: Unable to delete the YANG file '%s'.\n", yang_file);
            rc = SR_ERR_INTERNAL;
        }
    }
    free((void*)yang_file);

    return rc;
}

/**
 * @brief Uninstalls the schema file and all submodules referenced from the schema.
 */
static int
srctl_schema_file_uninstall(struct ly_ctx *ly_ctx, const char *schema_file)
{
    const struct lys_module *module = NULL;
    int rc = SR_ERR_OK;

    /* delete all submodules */
    module = lys_parse_path(ly_ctx, schema_file, LYS_IN_YIN);
    if (NULL != module) {
        for (size_t i = 0; i < module->inc_size; i++) {
            rc = srctl_schema_file_delete(module->inc[i].submodule->filepath);
            if (SR_ERR_OK != rc) {
                fprintf(stderr, "Warning: Submodule cleanup was unsccessfull, continuing.\n");
            }
        }
    }

    /* delete the main module */
    rc = srctl_schema_file_delete(schema_file);

    return rc;
}

/**
 * @brief Uninstalls a schema identified by module name and revision date.
 */
static int
srctl_schema_uninstall(struct ly_ctx *ly_ctx, const char *module_name, const char *revision_date)
{
    char schema_file[PATH_MAX] = { 0, }, *ext = NULL;
    DIR *dp;
    struct dirent *ep;
    int rc = SR_ERR_OK;

    if (NULL != revision_date) {
        /* delete module's YANG and YIN files of specified revision */
        srctl_get_yin_path(module_name, revision_date, schema_file, PATH_MAX);
        rc = srctl_schema_file_uninstall(ly_ctx, schema_file);
    } else {
        /* delete module's YANG and YIN files of all revisions */
        dp = opendir(srctl_schema_search_dir);
        if (NULL == dp) {
            fprintf(stderr, "Error: %s.\n", strerror(errno));
            return SR_ERR_INTERNAL;
        }
        while (NULL != (ep = readdir(dp))) {
            if (0 == strncmp(ep->d_name, module_name, strlen(module_name))) {
                ext = strrchr(ep->d_name, '.');
                if (NULL != ext && 0 == strcmp(ext, ".yin")) {
                    snprintf(schema_file, PATH_MAX, "%s%s", srctl_schema_search_dir, ep->d_name);
                    rc = srctl_schema_file_uninstall(ly_ctx, schema_file);
                }
            }
        }
        closedir(dp);
    }

    return rc;
}

/**
 * @brief Performs the --uninstall operation.
 */
static int
srctl_uninstall(const char *module, const char *revision)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    struct ly_ctx *ly_ctx = NULL;
    int ret = 0, rc = SR_ERR_OK;

    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --uninstall operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    printf("Uninstalling the module '%s'.\n", module);

    /* init libyang context */
    ly_ctx = ly_ctx_new(srctl_schema_search_dir);
    if (NULL == ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
        return SR_ERR_INIT_FAILED;
    }

    /* delete schema files */
    rc = srctl_schema_uninstall(ly_ctx, module, revision);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to uninstall schemas.\n");
        return rc;
    }

    if (!custom_repository) {
        /* disable in sysrepo */
        rc = srctl_open_session(&connection, &session);
        if (SR_ERR_OK == rc) {
            rc = sr_module_install(session, module, revision, false);
        }
        if (SR_ERR_OK != rc && SR_ERR_NOT_FOUND != rc) {
            srctl_report_error(session, rc);
            sr_disconnect(connection);
            return rc;
        }
        sr_disconnect(connection);
    }

    /* delete data files */
    printf("Deleting data files ...\n");
    // TODO: lock data file, fail if it is already locked

    ret = srctl_data_files_alter(module, "rm -f", true);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to delete data files. However, schemas has been successfully uninstalled.\n");
        return SR_ERR_INTERNAL;
    }

    printf("Operation completed successfully.\n");

    return SR_ERR_OK;
}

/**
 * @brief Performs the --change operation.
 */
static int
srctl_change(const char *module, const char *revision, const char *owner, const char *permissions)
{
    char cmd[PATH_MAX] = { 0, };
    int ret1 = 0, ret2 = 0;

    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --change operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    if (NULL == owner && NULL == permissions) {
        fprintf(stderr, "Either --owner or --permissions option must be specified for --change operation.\n");
        return SR_ERR_INVAL_ARG;
    }
    printf("Changing ownership/permissions of the module '%s'.\n", module);

    if (NULL != owner) {
        snprintf(cmd, PATH_MAX, "chown %s", owner);
        ret1 = srctl_data_files_alter(module, cmd, true);
    }
    if (NULL != permissions) {
        snprintf(cmd, PATH_MAX, "chmod %s", permissions);
        ret2 = srctl_data_files_alter(module, cmd, true);
    }

    if (0 != ret1 || 0 != ret2) {
        fprintf(stderr, "Some part of the change operation failed, see the errors above.\n");
        return SR_ERR_INTERNAL;
    } else {
        printf("Operation completed successfully.\n");
        return SR_ERR_OK;
    }
}

/**
 * @brief Performs the --feature-enable or --feature-disable operation.
 */
static int
srctl_feature_change(const char *module, const char *feature_name, bool enable)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --%s operation.\n",
                enable ? "feature-enable" : "feature-disable");
        return SR_ERR_INVAL_ARG;
    }
    printf("%s feature '%s' in the module '%s'.\n", enable ? "Enabling" : "Disabling", feature_name, module);

    rc = srctl_open_session(&connection, &session);

    if (SR_ERR_OK == rc) {
        rc = sr_feature_enable(session, module, feature_name, enable);
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
    DIR *dp;
    struct dirent *ep;
    char *ext = NULL, schema_filename[PATH_MAX] = { 0, };

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
        ext = strrchr(ep->d_name, '.');
        if (NULL != ext && 0 == strcmp(ext, ".yin")) {
            snprintf(schema_filename, PATH_MAX, "%s%s", srctl_schema_search_dir, ep->d_name);
            lys_parse_path(*ly_ctx, schema_filename, LYS_IN_YIN);
        }
    }
    closedir(dp);

    return SR_ERR_OK;
}

/**
 * @brief Performs the --dump and --import operations.
 */
static int
srctl_dump_import(const char *module, const char *format, bool dump)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    char data_filename[PATH_MAX] = { 0, };
    int fd = 0, ret = 0, rc = SR_ERR_OK;
    LYD_FORMAT dump_format = LYD_XML;

    if (NULL == module) {
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

    snprintf(data_filename, PATH_MAX, "%s%s%s", srctl_data_search_dir, module, SR_STARTUP_FILE_EXT);

    fd = open(data_filename, dump ? O_RDONLY : (O_WRONLY | O_TRUNC));
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
    printf("  -m, --module           Name of the module to be operated on (--uninstall, --change, --feature-enable, --feature-disable, --dump, --import operations).\n");
    printf("  -r, --revision         Revision of the module to be operated on (--uninstall operation).\n");
    printf("  -o, --owner            Owner user and group of the module's data in chown format (--install, --change operations).\n");
    printf("  -p, --permissions      Access permissions of the module's data in chmod format (--install, --change operations).\n");
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

    while ((c = getopt_long(argc, argv, "hvliuce:d:x:t:g:n:m:r:o:p:s:0:W;", longopts, NULL)) != -1) {
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
        case 'u':
            rc = srctl_uninstall(module, revision);
            break;
        case 'c':
            rc = srctl_change(module, revision, owner, permissions);
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
