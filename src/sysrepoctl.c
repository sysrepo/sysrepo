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

#include "sr_common.h"
#include "client_library.h"

static int
srctl_list_modules()
{
    printf("Sysrepo schema directory: %s\n", SR_SCHEMA_SEARCH_DIR);
    printf("Sysrepo data directory:   %s\n", SR_DATA_SEARCH_DIR);

    // TODO

    return EXIT_SUCCESS;
}

static int
srctl_install(const char *yang, const char *yin, const char *owner, const char *permissions)
{
    if (NULL == yang) {
        fprintf(stderr, "Error: YANG file must be specified for --install operation.\n");
        exit(EXIT_FAILURE);
    }
    printf("Installing a new module from YANG file '%s'.\n", yang);

    // TODO

    return EXIT_SUCCESS;
}

static int
srctl_uninstall(const char *module, const char *revision)
{
    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --uninstall operation.\n");
        exit(EXIT_FAILURE);
    }
    printf("Uninstalling the module '%s'.\n", module);

    // TODO

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

    return EXIT_SUCCESS;
}

static int
srctl_feature_change(const char *module, const char *feature_name, bool enable)
{
    if (NULL == module) {
        fprintf(stderr, "Error: Module must be specified for --%s operation.\n",
                enable ? "feature-enable" : "feature-disable");
        exit(EXIT_FAILURE);
    }
    printf("%s feature '%s' in the module '%s'.\n", enable ? "Enabling" : "Disabling", feature_name, module);

    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_connect("sysrepoctl", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK == rc) {
        rc = sr_session_start(connection, SR_DS_STARTUP, &session);
    }
    if (SR_ERR_OK == rc) {
        rc = sr_feature_enable(session, module, feature_name, enable);
    }
    if (SR_ERR_OK == rc) {
        printf("Operation completed successfully.\n");
        rc = EXIT_SUCCESS;
    } else {
        if (NULL == session) {
            fprintf(stderr, "Error: %s\n", sr_strerror(rc));
        } else {
            const sr_error_info_t *error = NULL;
            sr_get_last_error(session, &error);
            fprintf(stderr, "Error: %s\n", error->message);
        }
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
