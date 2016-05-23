/*
 * @file sysrepocfg.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo configuration tool (sysrepocfg) implementation.
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
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "client_library.h"

#define EXPECTED_MAX_INPUT_FILE_SIZE  4096
#define DEFAULT_TEXT_EDITOR           "vi"

/**
 * @brief Operation to be performed.
 */
typedef enum srcfg_operation_e {
    SRCFG_OP_EDIT,   /**< Edit current configuration */
    SRCFG_OP_IMPORT, /**< Import configuration from file or stdin */
    SRCFG_OP_EXPORT  /**< Export configuration to file or stdout */
} srcfg_operation_t;

/**
 * @brief Datastore to be operated on.
 */
typedef enum srcfg_datastore_e {
    SRCFG_STORE_RUNNING,   /**< Work with the running datastore */
    SRCFG_STORE_STARTUP    /**< Work with the startup datastore */
} srcfg_datastore_t;

static char *srcfg_schema_search_dir = SR_SCHEMA_SEARCH_DIR;
static char *srcfg_data_search_dir = SR_DATA_SEARCH_DIR;
static bool srcfg_custom_repository = false;
static const char * const srcfg_default_text_editor = DEFAULT_TEXT_EDITOR;

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
srcfg_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    return;
}

/**
 * @brief Reads complete content of a file referenced by the descriptor 'fd' into the memory.
 * Caller is responsible for deallocation of the memory block returned through the output argument 'out'.
 * Returns SR_ERR_OK in case of success, SR_ERR_INTERNAL otherwise.
 */
static int
srcfg_read_file_content(int fd, char **out)
{
    size_t size = EXPECTED_MAX_INPUT_FILE_SIZE;
    unsigned cur = 0;
    ssize_t n = 0;
    char *buffer = malloc(size);
    if (NULL == buffer) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return SR_ERR_INTERNAL;
    }

    do {
        if (size == cur + 1) {
            size <<= 1;
            char *new_buffer = realloc(buffer, size);
            if (NULL == new_buffer) {
                free(buffer);
                fprintf(stderr, "Error: Memory allocation failed.\n");
                return SR_ERR_INTERNAL;
            }
            buffer = new_buffer;
        }
        n = read(fd, buffer + cur, size - cur - 1);
        if (0 > n) {
            free(buffer);
            fprintf(stderr, "Error: Read operation failed: %s.\n", strerror(errno));
            return SR_ERR_INTERNAL;
        }
        cur += n;
    } while (0 < n);

    buffer[cur] = '\0';
    *out = buffer;
    return SR_ERR_OK;
}
/**
 * @brief Initializes libyang ctx with all schemas installed for specified module in sysrepo.
 */
static int
srcfg_ly_init(struct ly_ctx **ly_ctx, const char *module_name)
{
    DIR *dp = NULL;
    struct dirent *ep = NULL;
    char *delim = NULL;
    char schema_filename[PATH_MAX] = { 0, };

    *ly_ctx = ly_ctx_new(srcfg_schema_search_dir);
    if (NULL == *ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
        return SR_ERR_INTERNAL;
    }
    ly_set_log_clb(srcfg_ly_log_cb, 0);

    /* iterate over all files in the directory with schemas */
    dp = opendir(srcfg_schema_search_dir);
    if (NULL == dp) {
        fprintf(stderr, "Error: Failed to open the schema directory: %s.\n", strerror(errno));
        return SR_ERR_INTERNAL;
    }
    while (NULL != (ep = readdir(dp))) {
        /* test file extension */
        LYS_INFORMAT fmt = LYS_IN_UNKNOWN;
        if (sr_str_ends_with(ep->d_name, SR_SCHEMA_YIN_FILE_EXT)) {
            fmt = LYS_IN_YIN;
        } else if (sr_str_ends_with(ep->d_name, SR_SCHEMA_YANG_FILE_EXT)) {
            fmt = LYS_IN_YANG;
        }
        if (fmt != LYS_IN_UNKNOWN) {
            /* strip extension and revision */
            strcpy(schema_filename, ep->d_name);
            delim = strrchr(schema_filename, '.');
            assert(delim);
            *delim = '\0';
            delim = strrchr(schema_filename, '@');
            if (delim) {
                *delim = '\0';
            }
            /* TODO install all revisions and dependencies of the specified module, but not more */
#if 0 /* XXX install all schemas until we can resolve all dependencies */
            if (strcmp(schema_filename, module_name) == 0) {
#endif
                /* construct full file path */
                snprintf(schema_filename, PATH_MAX, "%s%s", srcfg_schema_search_dir, ep->d_name);
                /* load the schema into the context */
                SR_LOG_DBG("Loading module schema '%s'...\n", schema_filename);
                lys_parse_path(*ly_ctx, schema_filename, fmt);
#if 0
            }
#endif
        }
    }
    closedir(dp);

    return SR_ERR_OK;
}

/**
 * @brief Import content of the specified datastore for the given module from a file
 * referenced by the descriptor 'fd_in'
 */
static int
srcfg_import_datastore(struct ly_ctx *ly_ctx, int fd_in, const char *module_name, srcfg_datastore_t datastore,
                       LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *data_tree = NULL;
    char data_filename[PATH_MAX] = { 0, };
    int fd_out = -1;
    char *input_data = NULL;
    int locked = 0, ret = 0;

    /* load input data into the memory */
    ret = srcfg_read_file_content(fd_in, &input_data);
    if (SR_ERR_OK != ret) {
        fprintf(stderr, "Error: Unable to read the input data.\n");
        goto cleanup;
    }

    /* try to parse the input data */
    data_tree = lyd_parse_mem(ly_ctx, input_data, format, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == data_tree && LY_SUCCESS != ly_errno) {
        fprintf(stderr, "Error: Unable to parse the input data: %s.\n", ly_errmsg());
        goto cleanup;
    }

    /* validate input data */
    if (NULL != data_tree) {
        ret = lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG | LYD_WD_IMPL_TAG);
        if (0 != ret) {
            fprintf(stderr, "Error: input data are not valid: %s.\n", ly_errmsg());
            goto cleanup;
        }
    }

    /* try to open the data file */
    snprintf(data_filename, PATH_MAX, "%s%s%s", srcfg_data_search_dir, module_name,
             datastore == SRCFG_STORE_RUNNING ? SR_RUNNING_FILE_EXT : SR_STARTUP_FILE_EXT);

    fd_out = open(data_filename, O_WRONLY | O_TRUNC);
    if (-1 == fd_out) {
        fprintf(stderr, "Error: Unable to open the data file '%s': %s.\n", data_filename, strerror(errno));
        goto cleanup;
    }

    /* lock data file */
    locked = (sr_lock_fd(fd_out, true, true) == SR_ERR_OK);
    if (!locked) {
        fprintf(stderr, "Error: Unable to lock the data file '%s'.\n", data_filename);
        goto cleanup;
    }

    /* re-write data file content (approach suitable for startup datastore only) */
    lyd_wd_cleanup(&data_tree, 0);
    ret = lyd_print_fd(fd_out, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to save the data: %s.\n", ly_errmsg());
        goto cleanup;
    }

    rc = SR_ERR_OK;

cleanup:
    if (locked) {
        sr_unlock_fd(fd_out);
    }
    if (-1 != fd_out) {
        close(fd_out);
    }
    if (input_data) {
        free(input_data);
    }
    return rc;
}

/**
 * @brief Performs the --import operation.
 */
static int
srcfg_import_operation(const char *module_name, srcfg_datastore_t datastore, const char *filepath,
                       LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_in = STDIN_FILENO;

    if (datastore == SRCFG_STORE_RUNNING) {
        fprintf(stderr, "Error: Running datastore is not yet supported for the import operation.\n");
        goto fail;
    }

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
    if (SR_ERR_OK != ret) {
        fprintf(stderr, "Error: Failed to initialize libyang context.\n");
        goto fail;
    }

    if (filepath) {
        /* try to open the input file */
        fd_in = open(filepath, O_RDONLY);
        if (-1 == fd_in) {
            fprintf(stderr, "Error: Unable to open the input file '%s': %s.\n", filepath, strerror(errno));
            goto fail;
        }
    } else {
        /* read configuration from stdin */
        printf("Please enter the new configuration:\n");
    }

    /* import datastore data */
    ret = srcfg_import_datastore(ly_ctx, fd_in, module_name, datastore, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    printf("The new configuration was successfully applied.\n");
    goto cleanup;

fail:
    printf("Errors were encountered during importing. Cancelling the operation.\n");

cleanup:
    if (STDIN_FILENO != fd_in && -1 != fd_in) {
        close(fd_in);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Export content of the specified datastore for the given module into a file
 * referenced by the descriptor 'fd_out'
 */
static int
srcfg_export_datastore(struct ly_ctx *ly_ctx, int fd_out, const char *module_name, srcfg_datastore_t datastore,
                       LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *data_tree = NULL;
    char data_filename[PATH_MAX] = { 0, };
    int fd_in = -1;
    int locked = 0, ret = 0;

    /* try to open the data file */
    snprintf(data_filename, PATH_MAX, "%s%s%s", srcfg_data_search_dir, module_name,
             datastore == SRCFG_STORE_RUNNING ? SR_RUNNING_FILE_EXT : SR_STARTUP_FILE_EXT);

    fd_in = open(data_filename, O_RDONLY);
    if (-1 == fd_in) {
        fprintf(stderr, "Error: Unable to open the data file '%s': %s.\n", data_filename, strerror(errno));
        goto cleanup;
    }

    /* lock data file */
    locked = (sr_lock_fd(fd_in, false, true) == SR_ERR_OK);
    if (!locked) {
        fprintf(stderr, "Error: Unable to lock the data file '%s'.\n", data_filename);
        goto cleanup;
    }

    /* parse data file */
    data_tree = lyd_parse_fd(ly_ctx, fd_in, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == data_tree && LY_SUCCESS != ly_errno) {
        fprintf(stderr, "Error: Unable to parse the data file '%s': %s.\n", data_filename, ly_errmsg());
        goto cleanup;
    }

    /* dump data */
    lyd_wd_cleanup(&data_tree, 0);
    ret = lyd_print_fd(fd_out, data_tree, format, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (0 != ret) {
        fprintf(stderr, "Error: Unable to print the data: %s.\n", ly_errmsg());
        goto cleanup;
    }

    rc = SR_ERR_OK;

cleanup:
    if (locked) {
        sr_unlock_fd(fd_in);
    }
    if (-1 != fd_in) {
        close(fd_in);
    }
    return rc;
}

/**
 * @brief Performs the --export operation.
 */
static int
srcfg_export_operation(const char *module_name, srcfg_datastore_t datastore, const char *filepath,
                       LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_out = STDOUT_FILENO;

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
    if (SR_ERR_OK != ret) {
        fprintf(stderr, "Error: Failed to initialize libyang context.\n");
        goto fail;
    }

    /* try to open/create the output file if needed */
    if (filepath) {
        fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (-1 == fd_out) {
            fprintf(stderr, "Error: Unable to open the output file '%s': %s.\n", filepath, strerror(errno));
            goto fail;
        }
    }

    /* export datastore data */
    ret = srcfg_export_datastore(ly_ctx, fd_out, module_name, datastore, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    if (filepath) { /* do not clutter the output sent to stdout */
        printf("The configuration was successfully exported.\n");
    }
    goto cleanup;

fail:
    printf("Errors were encountered during exporting. Cancelling the operation.\n");

cleanup:
    if (STDOUT_FILENO != fd_out && -1 != fd_out) {
        close(fd_out);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Asks user a question and returns true (non-zero value) if the answer was positive, false otherwise.
 */
static int
srcfg_prompt(const char *question, const char *positive, const char *negative)
{
    char input[PATH_MAX] = { 0, };
    printf("%s [%s/%s]\n", question, positive, negative);

    for (;;) {
        scanf("%s", input);
        sr_str_trim(input);
        if (0 == strcasecmp(positive, input)) {
            return 1;
        }
        if (0 == strcasecmp(negative, input)) {
            return 0;
        }
        printf("Please enter [%s] or [%s].\n", positive, negative);
    }
}

/**
 * @brief Performs the program's main operation: lets user to edit specified module and datastore
 * using the preferred editor. New configuration is validated before it is saved.
 */
static int
srcfg_edit_operation(const char *module_name, srcfg_datastore_t datastore, LYD_FORMAT format,
                     const char *editor)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    char tmpfile_path[PATH_MAX] = { 0, }, cmd[PATH_MAX] = { 0, };
    char *dest = NULL;
    int fd_tmp = -1;
    pid_t child_pid = -1;
    int child_status = 0, first_attempt = 1;

    /* find default editor if none specified */
    if (NULL == editor) {
        editor = getenv("VISUAL");
        if (NULL == editor) {
            editor = getenv("EDITOR");
        }
        if (NULL == editor) {
            editor = srcfg_default_text_editor;
        }
    }

    if (datastore == SRCFG_STORE_RUNNING) {
        fprintf(stderr, "Error: Running datastore is not yet supported for editing.\n");
        goto fail;
    }

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
    if (SR_ERR_OK != ret) {
        fprintf(stderr, "Error: Failed to initialize libyang context.\n");
        goto fail;
    }

    /* create temporary file for datastore editing */
    snprintf(tmpfile_path, PATH_MAX, "/tmp/srcfg.%s%s.XXXXXX", module_name,
             datastore == SRCFG_STORE_RUNNING ? SR_RUNNING_FILE_EXT : SR_STARTUP_FILE_EXT);
    fd_tmp = mkstemp(tmpfile_path);
    if (-1 == fd_tmp)
    {
        fprintf(stderr, "Error: Failed to create temporary file for datastore editing.\n");
        goto fail;
    }

    /* export datastore content into a temporary file */
    ret = srcfg_export_datastore(ly_ctx, fd_tmp, module_name, datastore, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }
    close(fd_tmp);

edit:
    if (!first_attempt) {
        if (!srcfg_prompt("Unable to apply the changes. "
                          "Would you like to continue editing the configuration?", "y", "n")) {
            goto save;
        }
    }
    first_attempt = 0;

    /* Open the temporary file inside the preferred text editor */
    child_pid = fork();
    if (0 <= child_pid) { /* fork succeeded */
        if (0 == child_pid) { /* child process */
            /* Open text editor */
            return execlp(editor, editor, tmpfile_path, (char *)NULL);
         } else { /* parent process */
             /* wait for the child to exit */
             ret = waitpid(child_pid, &child_status, 0);
             if (child_pid != ret) {
                 fprintf(stderr, "Error: Unable to wait for the editor to exit.\n");
                 goto save;
             }
             /* Check return status from the child */
             if (!WIFEXITED(child_status) || 0 != WEXITSTATUS(child_status)) {
                 fprintf(stderr, "Error: Text editor didn't terminate properly.\n");
                 goto save;
             }
         }
    }
    else /* fork failed */
    {
        fprintf(stderr, "Error: Failed to fork a new process for the text editor.\n");
        goto fail;
    }

    /* re-open temporary file */
    fd_tmp = open(tmpfile_path, O_RDONLY);
    if (-1 == fd_tmp) {
        fprintf(stderr, "Error: Unable to re-open the configuration after it was edited using the text editor.\n");
        goto save;
    }

    /* import temporary file content into the datastore */
    ret = srcfg_import_datastore(ly_ctx, fd_tmp, module_name, datastore, format);
    if (SR_ERR_OK != ret) {
        goto edit;
    }

    rc = SR_ERR_OK;
    printf("The new configuration was successfully applied.\n");
    goto cleanup;

save:
    if (srcfg_prompt("Failed to commit the new configuration. "
                     "Would you like to save your changes to a file?", "y", "n")) {
        /* copy whatever is in the temporary file right now */
        snprintf(cmd, PATH_MAX, "cp %s ", tmpfile_path);
        dest = cmd + strlen(cmd);
        do {
            printf("Enter a file path: ");
            scanf("%s", dest);
            sr_str_trim(dest);
            ret = system(cmd);
            if (0 != ret) {
                fprintf(stderr, "Error: Unable to save the configuration to '%s'.\n", dest);
                if (!srcfg_prompt("Retry?", "y", "n")) {
                    printf("Your changes were discarded.\n");
                    goto fail;
                }
            }
        } while (0 != ret);
        printf("Your changes have been saved to '%s'. "
               "You may try to apply them again using the import operation.\n", dest);
        goto cleanup;
    } else {
        printf("Your changes were discarded.\n");
    }

fail:
    printf("Errors were encountered during editing. Cancelling the operation.\n");

cleanup:
    if (-1 != fd_tmp) {
        close(fd_tmp);
    }
    if ('\0' != tmpfile_path[0]) {
        unlink(tmpfile_path);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Performs the --version operation.
 */
static void
srcfg_print_version()
{
    printf("sysrepocfg - sysrepo configuration tool, version %s\n\n", SR_VERSION);
}

/**
 * @brief Performs the --help operation.
 */
static void
srcfg_print_help()
{
    srcfg_print_version();

    printf("Usage:\n");
    printf("  sysrepocfg [options] <module_name>\n\n");
    printf("Available options:\n");
    printf("  -h, --help       Print usage help and exit.\n");
    printf("  -v, --version    Print version and exit.\n");
    printf("  -d, --datastore  Datastore to be operated on\n");
    printf("                   (either \"running\" or \"startup\", \"running\" is default).\n");
    printf("  -f, --format     Data format to be used for configuration editing/importing/exporting\n");
    printf("                   (\"xml\" or \"json\", \"xml\" is default).\n");
    printf("  -e, --editor     Text editor to be used for editing datastore data\n");
    printf("                   (default editor is defined by $VISUAL or $EDITOR env. variables).\n");
    printf("  -i, --import     Read and replace entire configuration from a supplied file\n");
    printf("                   or from stdin if the argument is empty.\n");
    printf("  -x, --export     Export data of specified module and datastore to a file at the defined path\n");
    printf("                   or to stdout if the argument is empty.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  1) Edit *ietf-interfaces* module's *running config* in *xml format* in *default editor*:\n");
    printf("     sysrepocf ietf-interfaces\n\n");
    printf("  2) Edit *ietf-interfaces* module's *running config* in *xml format* in *vim*:\n");
    printf("     sysrepocfg --editor=vim ietf-interfaces\n\n");
    printf("  3) Edit *ietf-interfaces* module's *startup config* in *json format* in *default editor*:\n");
    printf("     sysrepocfg --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  4) Export *ietf-interfaces* module's *startup config* in *json format* into */tmp/backup.json* file:\n");
    printf("     sysrepocfg --export=/tmp/backup.json --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  5) Import *ietf-interfaces* module's *running config* content from */tmp/backup.json* file in *json format*:\n");
    printf("     sysrepocfg --import=/tmp/backup.json --format=json ietf-interfaces\n\n");

}

/**
 * @brief Main routine of the sysrepo configuration tool.
 */
int
main(int argc, char* argv[])
{
    int c = 0;
    srcfg_operation_t operation = SRCFG_OP_EDIT;
    char *module_name = NULL, *datastore_name = "running";
    char *format_name = "xml", *editor = NULL;
    char *filepath = NULL;
    srcfg_datastore_t datastore = SRCFG_STORE_RUNNING;
    LYD_FORMAT format = LYD_XML;
    char local_schema_search_dir[PATH_MAX] = { 0, }, local_data_search_dir[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    struct option longopts[] = {
       { "help",            no_argument,       NULL, 'h' },
       { "version",         no_argument,       NULL, 'v' },
       { "datastore",       required_argument, NULL, 'd' },
       { "format",          required_argument, NULL, 'f' },
       { "editor",          required_argument, NULL, 'e' },
       { "import",          optional_argument, NULL, 'i' },
       { "export",          optional_argument, NULL, 'x' },
       { 0, 0, 0, 0 }
    };

    /* read mandatory <module_name> argument */
    if (1 < argc && '-' != argv[argc-1][0]) {
        module_name = argv[argc-1];
        --argc;
    }

    /* parse options */
    while ((c = getopt_long(argc, argv, ":hvd:f:e:i:x:0:", longopts, NULL)) != -1) {
        switch (c) {
            case 'h':
                srcfg_print_help();
                goto terminate;
                break;
            case 'v':
                srcfg_print_version();
                goto terminate;
                break;
            case 'd':
                datastore_name = optarg;
                break;
            case 'f':
                format_name = optarg;
                break;
            case 'e':
                editor = optarg;
                break;
            case 'i':
                operation = SRCFG_OP_IMPORT;
                filepath = optarg;
                break;
            case 'x':
                operation = SRCFG_OP_EXPORT;
                filepath = optarg;
                break;
            case '0':
                /* 'hidden' option - custom repository location */
                strncpy(local_schema_search_dir, optarg, PATH_MAX - 6);
                strncpy(local_data_search_dir, optarg, PATH_MAX - 6);
                strcat(local_schema_search_dir, "/yang/");
                strcat(local_data_search_dir, "/data/");
                srcfg_schema_search_dir = local_schema_search_dir;
                srcfg_data_search_dir = local_data_search_dir;
                srcfg_custom_repository = true;
                break;
            case ':':
                /* missing option argument */
                switch (optopt) {
                    case 'i':
                        operation = SRCFG_OP_IMPORT;
                        break;
                    case 'x':
                        operation = SRCFG_OP_EXPORT;
                        break;
                    default:
                        fprintf(stderr, "%s: option `-%c' requires an argument\n", argv[0], optopt);
                        rc = SR_ERR_INVAL_ARG;
                        goto terminate;
                }
                break;
            case '?':
            default:
                /* invalid option */
                fprintf(stderr, "%s: option `-%c' is invalid. Exiting.\n", argv[0], optopt);
                rc = SR_ERR_INVAL_ARG;
                goto terminate;
        }
    }

   /* check argument values */
    if (NULL == module_name) {
        fprintf(stderr, "Error: Module name was not specified.\n");
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    }
    if (strcasecmp("xml", format_name) == 0) {
        format = LYD_XML;
    } else if (strcasecmp("json", format_name) == 0) {
        format = LYD_JSON;
    } else {
        fprintf(stderr, "Error: Unsupported data format (xml and json are supported).\n");
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    }
    if (strcasecmp("startup", datastore_name) == 0) {
        datastore = SRCFG_STORE_STARTUP;
    } else if (strcasecmp("running", datastore_name) == 0) {
        datastore = SRCFG_STORE_RUNNING;
    } else {
        fprintf(stderr, "Error: Invalid datastore specified (select either \"running\" or \"startup\").\n");
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    }

    /* call selected operation */
    switch (operation) {
        case SRCFG_OP_EDIT:
            rc = srcfg_edit_operation(module_name, datastore, format, editor);
            break;
        case SRCFG_OP_IMPORT:
            rc = srcfg_import_operation(module_name, datastore, filepath, format);
            break;
        case SRCFG_OP_EXPORT:
            rc = srcfg_export_operation(module_name, datastore, filepath, format);
            break;
    }

terminate:
    return (SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE;
}
