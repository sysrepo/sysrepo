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
#include <libyang/libyang.h>

#include "sr_common.h"
#include "client_library.h"

static int
srctl_get_session(sr_conn_ctx_t **connection_p, sr_session_ctx_t **session_p)
{
    int rc = SR_ERR_OK;

    rc = sr_connect("sysrepoctl", SR_CONN_DEFAULT, connection_p);
    if (SR_ERR_OK == rc) {
        rc = sr_session_start(*connection_p, SR_DS_STARTUP, SR_SESS_DEFAULT, session_p);
    }

    if (SR_ERR_OK != rc) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void
srctl_report_error(sr_session_ctx_t *session, int rc)
{
    if (NULL == session) {
        fprintf(stderr, "Error: %s\n", sr_strerror(rc));
    } else {
        const sr_error_info_t *error = NULL;
        sr_get_last_error(session, &error);
        fprintf(stderr, "Error: %s\n", error->message);
    }
}

static int
srctl_list_modules()
{
    printf("Sysrepo schema directory: %s\n", SR_SCHEMA_SEARCH_DIR);
    printf("Sysrepo data directory:   %s\n", SR_DATA_SEARCH_DIR);

    // TODO
    printf("This operation is not yet implemented.\n");

    return EXIT_SUCCESS;
}

static char *
srctl_get_filename_no_ext(const char *file_path)
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

static char *
srctl_yin_generate(const char *yang_file)
{
    char *file_name = NULL, *yin_file = NULL;
    char command[PATH_MAX] = { 0, };
    size_t len = 0;
    int ret = 0;

    file_name = srctl_get_filename_no_ext(yang_file);
    len = snprintf(NULL, 0, "/tmp/%s.yin.%d", file_name, getpid());
    yin_file = calloc(len + 1, sizeof(*yin_file));
    if (NULL != yin_file) {
        snprintf(yin_file, len + 1, "/tmp/%s.yin.%d", file_name, getpid());
    }
    free(file_name);

    snprintf(command, PATH_MAX, "pyang --path=%s --format=yin --output=%s %s", SR_SCHEMA_SEARCH_DIR, yin_file, yang_file);
    ret = system(command);
    if (0 != ret) {
        free(yin_file);
        return NULL;
    }
    return yin_file;
}

static void
srctl_get_yang_path(const char *module_name, const char *revision_date, char *yang_path, size_t path_max_len)
{
    if (NULL != revision_date) {
        snprintf(yang_path, path_max_len, "%s%s@%s%s", SR_SCHEMA_SEARCH_DIR, module_name, revision_date, SR_SCHEMA_YANG_FILE_EXT);
    } else {
        snprintf(yang_path, path_max_len, "%s%s%s", SR_SCHEMA_SEARCH_DIR, module_name, SR_SCHEMA_YANG_FILE_EXT);
    }
}

static void
srctl_get_yin_path(const char *module_name, const char *revision_date, char *yin_path, size_t path_max_len)
{
    if (NULL != revision_date) {
        snprintf(yin_path, PATH_MAX, "%s%s@%s%s", SR_SCHEMA_SEARCH_DIR, module_name, revision_date, SR_SCHEMA_YIN_FILE_EXT);
    } else {
        snprintf(yin_path, PATH_MAX, "%s%s%s", SR_SCHEMA_SEARCH_DIR, module_name, SR_SCHEMA_YIN_FILE_EXT);
    }
}

static int
srctl_data_files_alter(const char *module_name, const char *revision_date, const char *command)
{
    char cmd[PATH_MAX] = { 0, };
    int ret = 0;

    if (NULL != revision_date) {
        snprintf(cmd, PATH_MAX, "%s %s%s@%s%s", command, SR_DATA_SEARCH_DIR, module_name, revision_date, SR_STARTUP_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s@%s%s", command, SR_DATA_SEARCH_DIR, module_name, revision_date, SR_RUNNING_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s@%s%s%s", command, SR_DATA_SEARCH_DIR, module_name, revision_date, SR_STARTUP_FILE_EXT, SR_LOCK_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s@%s%s%s", command, SR_DATA_SEARCH_DIR, module_name, revision_date, SR_RUNNING_FILE_EXT, SR_LOCK_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
    } else {
        snprintf(cmd, PATH_MAX, "%s %s%s%s", command, SR_DATA_SEARCH_DIR, module_name, SR_STARTUP_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s%s", command, SR_DATA_SEARCH_DIR, module_name, SR_RUNNING_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s%s%s", command, SR_DATA_SEARCH_DIR, module_name, SR_STARTUP_FILE_EXT, SR_LOCK_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
        snprintf(cmd, PATH_MAX, "%s %s%s%s%s", command, SR_DATA_SEARCH_DIR, module_name, SR_RUNNING_FILE_EXT, SR_LOCK_FILE_EXT);
        ret = system(cmd);
        if (0 != ret) return ret;
    }

    return ret;
}

static int
srctl_install(const char *yang, const char *yin, const char *owner, const char *permissions)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    char yang_dst[PATH_MAX] = { 0, }, yin_dst[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    char *tmp_yin = NULL, *module_name = NULL, *revision_date = NULL;
    struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *module = NULL;
    int ret = 0;

    if (NULL == yang) {
        fprintf(stderr, "Error: YANG file must be specified for --install operation.\n");
        goto fail;
    }
    printf("Installing a new module from YANG file '%s'.\n", yang);

    /* generate YIN if not provided */
    if (NULL == yin) {
        /* check if pyang is installed */
        ret = system("pyang --version > /dev/null");
        if (0 != ret) {
            fprintf(stderr, "Error: Pyang not found. Install it, or use --yin option to specify YIN file.\n");
            goto fail;
        }
        /* generate the YIN file */
        tmp_yin = srctl_yin_generate(yang);
        if (NULL == tmp_yin) {
            fprintf(stderr, "Error: Unable to generate the YIN file.\n");
            goto fail;
        }
    }

    /* load the module into libyang to get module name and latest revision date */
    ly_ctx = ly_ctx_new(SR_SCHEMA_SEARCH_DIR);
    if (NULL != ly_ctx) {
        module = lys_parse_path(ly_ctx, (yin ? yin : tmp_yin), LYS_IN_YIN);
    }
    if (NULL == module) {
        fprintf(stderr, "Error: Unable to load the module in libyang.\n");
        goto fail;
    }
    module_name = (char*)module->name;
    if (module->rev_size > 0) {
        revision_date = module->rev[0].date;
    }

    /* Install YANG and YIN file */
    srctl_get_yang_path(module_name, revision_date, yang_dst, PATH_MAX);
    printf("Installing the YANG file to %s ...\n", yang_dst);
    snprintf(cmd, PATH_MAX, "cp %s %s", yang, yang_dst);
    ret = system(cmd);
    if (0 != ret) {
        goto fail;
    }

    srctl_get_yin_path(module_name, revision_date, yin_dst, PATH_MAX);
    printf("Installing the YIN file to %s ...\n", yin_dst);
    snprintf(cmd, PATH_MAX, "cp %s %s", (yin ? yin : tmp_yin), yin_dst);
    ret = system(cmd);
    if (0 != ret) {
        goto fail;
    }

    printf("Generating data files ...\n");
    ret = srctl_data_files_alter(module_name, revision_date, "touch");
    if (0 != ret) {
        goto fail;
    }

    printf("Notifying sysrepo about the change ...\n");
    ret = srctl_get_session(&connection, &session);
    if (SR_ERR_OK == ret) {
        ret = sr_module_install(session, module_name, revision_date, true);
    }
    if (SR_ERR_OK == ret) {
        printf("Install operation completed successfully.\n");
    } else {
        srctl_report_error(session, ret);
        goto fail;
    }

    sr_disconnect(connection);
    free(tmp_yin);
    ly_ctx_destroy(ly_ctx, NULL);

    return EXIT_SUCCESS;

fail:
    printf("Install operation cancelled.\n");
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    if (NULL != module_name) {
        srctl_data_files_alter(module_name, revision_date, "rm -f");
    }
    if ('\0' != yang_dst[0]) {
        snprintf(cmd, PATH_MAX, "rm -f %s", yang_dst);
        system(cmd);
    }
    if ('\0' != yin_dst[0]) {
        snprintf(cmd, PATH_MAX, "rm -f %s", yin_dst);
        system(cmd);
    }
    ly_ctx_destroy(ly_ctx, NULL);
    free(tmp_yin);
    return EXIT_FAILURE;
}

static int
srctl_uninstall(const char *module, const char *revision)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    char yang_dst[PATH_MAX] = { 0, }, yin_dst[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    int ret = SR_ERR_OK;

    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --uninstall operation.\n");
        exit(EXIT_FAILURE);
    }
    printf("Uninstalling the module '%s'.\n", module);

    /* request uninstall in sysrepo */
    ret = srctl_get_session(&connection, &session);
    if (SR_ERR_OK == ret) {
        ret = sr_module_install(session, module, revision, false);
    }
    if (SR_ERR_OK == ret) {
        printf("Operation completed successfully.\n");
        ret = EXIT_SUCCESS;
    } else {
        srctl_report_error(session, ret);
        ret = EXIT_FAILURE;
    }
    sr_disconnect(connection);

    /* delete YANG and YIN file */
    srctl_get_yang_path(module, revision, yang_dst, PATH_MAX);
    printf("Deleting the YANG file %s ...\n", yang_dst);
    snprintf(cmd, PATH_MAX, "rm %s", yang_dst);
    system(cmd);

    srctl_get_yin_path(module, revision, yin_dst, PATH_MAX);
    printf("Deleting the YIN file %s ...\n", yin_dst);
    snprintf(cmd, PATH_MAX, "rm %s", yin_dst);
    system(cmd);

    /* delete data files */
    printf("Deleting data files ...\n");
    srctl_data_files_alter(module, revision, "rm");

    return EXIT_SUCCESS;
}

static int
srctl_change(const char *module, const char *revision, const char *owner, const char *permissions)
{
    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --change operation.\n");
        exit(EXIT_FAILURE);
    }
    printf("Changing the module '%s'.\n", module);

    // TODO
    printf("This operation is not yet implemented.\n");

    return EXIT_SUCCESS;
}

static int
srctl_feature_change(const char *module, const char *feature_name, bool enable)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --%s operation.\n",
                enable ? "feature-enable" : "feature-disable");
        exit(EXIT_FAILURE);
    }
    printf("%s feature '%s' in the module '%s'.\n", enable ? "Enabling" : "Disabling", feature_name, module);

    rc = srctl_get_session(&connection, &session);

    if (SR_ERR_OK == rc) {
        rc = sr_feature_enable(session, module, feature_name, enable);
    }

    if (SR_ERR_OK == rc) {
        printf("Operation completed successfully.\n");
        rc = EXIT_SUCCESS;
    } else {
        srctl_report_error(session, rc);
        rc = EXIT_FAILURE;
    }
    sr_disconnect(connection);

    return rc;
}

static int
srctl_print_version()
{
    printf("sysrepoctl - sysrepo control tool, version %s\n\n", SR_VERSION);

    return EXIT_SUCCESS;
}

static int
srctl_print_help()
{
    srctl_print_version();

    printf("Usage:\n");
    printf("  sysrepoctl [operation-option] [other-options]\n\n");
    printf("Available operation-options:\n");
    printf("  -h, --help             Prints usage help.\n");
    printf("  -v, --version          Prints version.\n");
    printf("  -l, --list             Lists YANG modules installed in sysrepo.\n");
    printf("  -i, --install          Installs specified schema into sysrepo (at least --yang must be specified).\n");
    printf("  -u, --uninstall        Uninstalls specified schema from sysrepo (at least --module must be specified).\n");
    printf("  -c, --change           Changes specified module in sysrepo (at least --module must be specified).\n");
    printf("  -e, --feature-enable   Enables a feature within a module in sysrepo (at least --module must be specified).\n");
    printf("  -d, --feature-disable  Disables a feature within a module in sysrepo (at least --module must be specified).\n");
    printf("\n");
    printf("Available other-options:\n");
    printf("  -g, --yang             Path to the file with schema in YANG format (--install operation).\n");
    printf("  -n, --yin              Path to the file with schema in YIN format (--install operation).\n");
    printf("  -m, --module           Name of the module to be operated on (--uninstall, --change, --feature-enable, --feature-disable operations).\n");
    printf("  -r, --revision         Revision of the module to be operated on (--uninstall, --change operations).\n");
    printf("  -o, --owner            Owner user and/or group of the data module (--install, --change operations).\n");
    printf("  -p, --permissions      Access permissions of the data module (--install, --change operations).\n");
    printf("\n");
    printf("Examples:\n");
    printf("  1) Install a new module by specifying YANG file, ownership and access permissions:\n");
    printf("     sysrepoctl --install --yang=/home/user/ietf-interfaces.yang --owner=admin:admin --permissions=644\n\n");
    printf("  2) Change the ownership and permissions of an existing YANG module:\n");
    printf("     sysrepoctl --change --module=ietf-interfaces --owner=admin:admin --permissions=644\n\n");
    printf("  3) Enable a feature within a YANG module:\n");
    printf("     sysrepoctl --feature-enable=if-mib --module=ietf-interfaces\n\n");

    return 0;
}

/**
 * @brief Main routine of the sysrepo control tool.
 */
int
main(int argc, char* argv[])
{
    int c = 0, operation = 0, rc = 0;
    char *feature_name = NULL;
    char *yang = NULL, *yin = NULL, *module = NULL, *revision = NULL;
    char *owner = NULL, *permissions = NULL;

    struct option longopts[] = {
       { "help",            no_argument,       NULL, 'h' },
       { "version",         no_argument,       NULL, 'v' },
       { "list",            no_argument,       NULL, 'l' },
       { "install",         no_argument,       NULL, 'i' },
       { "uninstall",       no_argument,       NULL, 'u' },
       { "change",          no_argument,       NULL, 'c' },
       { "feature-enable",  required_argument, NULL, 'e' },
       { "feature-disable", required_argument, NULL, 'd' },

       { "yang",            required_argument, NULL, 'g' },
       { "yin",             required_argument, NULL, 'n' },
       { "module",          required_argument, NULL, 'm' },
       { "revision",        required_argument, NULL, 'r' },

       { "owner",           required_argument, NULL, 'o' },
       { "permissions",     required_argument, NULL, 'p' },
       { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "hvliuce:d:g:n:m:r:o:p:W;", longopts, NULL)) != -1) {
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
            rc = srctl_install(yang, yin, owner, permissions);
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
        default:
            rc = srctl_print_help();
    }

    return rc;
}
