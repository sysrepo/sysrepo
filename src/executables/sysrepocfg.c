/**
 * @file sysrepocfg.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepocfg tool
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#define _GNU_SOURCE /* asprintf */
#define _DEFAULT_SOURCE /* mkstemps */
#define _XOPEN_SOURCE 500 /* mkstemp */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "sysrepo.h"
#include "bin_common.h"

static void
version_print(void)
{
    printf(
        "sysrepocfg - sysrepo configuration manipulation tool, compiled with libsysrepo v%s (SO v%s)\n"
        "\n",
        SR_VERSION, SR_SOVERSION
    );
}

static void
help_print(void)
{
    printf(
        "Usage:\n"
        "  sysrepocfg <operation-option> [other-options]\n"
        "\n"
        "Available operation-options:\n"
        "  -h, --help                   Prints usage help.\n"
        "  -V, --version                Prints only information about sysrepo version.\n"
        "  -I, --import[=<file-path>]   Import the configuration from a file or STDIN.\n"
        "  -X, --export[=<file-path>]   Export configuration to a file or STDOUT.\n"
        "  -E, --edit[=<file-path>/<editor>]\n"
        "                               Edit configuration data by merging (applying) a configuration (edit) file or\n"
        "                               by editing the current datastore content using a text editor.\n"
        "  -R, --rpc[=<file-path>/<editor>]\n"
        "                               Send a RPC/action in a file or using a text editor. Output is printed to STDOUT.\n"
        "  -N, --notification[=<file-path>/<editor>]\n"
        "                               Send a notification in a file or using a text editor.\n"
        "  -C, --copy-from <file-path>/<source-datastore>\n"
        "                               Perform a copy-config from a file or a datastore.\n"
        "  -W, --new-data <file-path>   Set the configuration from a file as the initial one for a new module only scheduled\n"
        "                               to be installed. Is useful for modules with mandatory top-level nodes.\n"
        "\n"
        "       When both a <file-path> and <editor>/<target-datastore> can be specified, it is always first checked\n"
        "       that the file exists. If not, then it is interpreted as the other parameter.\n"
        "       If no <file-path> and no <editor> is set, use text editor in $VISUAL or $EDITOR environment variables.\n"
        "\n"
        "Available other-options:\n"
        "  -d, --datastore <datastore>  Datastore to be operated on, \"running\" by default (\"running\", \"startup\",\n"
        "                               \"candidate\", or \"operational\") (import, export, edit, copy-from op).\n"
        "  -m, --module <module-name>   Module to be operated on, otherwise it is operated on full datastore\n"
        "                               (import, export, edit, copy-from, mandatory for new-data op).\n"
        "  -x, --xpath <xpath>          XPath to select (export op).\n"
        "  -f, --format <format>        Data format to be used, by default based on file extension or \"xml\" if not applicable\n"
        "                               (\"xml\", \"json\", or \"lyb\") (import, export, edit, rpc, notification, copy-from, new-data op).\n"
        "  -l, --lock                   Lock the specified datastore for the whole operation (edit op).\n"
        "  -n, --not-strict             Silently ignore any unknown data (import, edit, copy-from op).\n"
        "  -p, --depth <number>         Limit the depth of returned subtrees, 0 so unlimited by default (export op).\n"
        "  -t, --timeout <seconds>      Set the timeout for the operation, otherwise the default one is used.\n"
        "  -w, --wait                   Wait for all the callbacks to be called on a data change including DONE or ABORT.\n"
        "  -e, --defaults <wd-mode>     Print the default values, which are hidden by default (\"report-all\",\n"
        "                               \"report-all-tagged\", \"trim\", \"explicit\", \"implicit-tagged\") (export, edit, rpc op).\n"
        "  -v, --verbosity <level>      Change verbosity to a level (none, error, warning, info, debug) or number (0, 1, 2, 3, 4).\n"
        "\n"
    );
}

static void
error_print(int sr_error, const char *format, ...)
{
    va_list ap;
    char msg[2048];

    if (!sr_error) {
        sprintf(msg, "sysrepocfg error: %s\n", format);
    } else {
        sprintf(msg, "sysrepocfg error: %s (%s)\n", format, sr_strerror(sr_error));
    }

    va_start(ap, format);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}

static void
error_ly_print(const struct ly_ctx *ctx)
{
    struct ly_err_item *e;

    for (e = ly_err_first(ctx); e; e = e->next) {
        error_print(0, "libyang: %s", e->msg);
    }

    ly_err_clean((struct ly_ctx *)ctx, NULL);
}

static int
step_edit_input(const char *editor, const char *path)
{
    int ret;
    pid_t pid, wait_pid;

    /* learn what editor to use */
    if (!editor) {
        editor = getenv("VISUAL");
    }
    if (!editor) {
        editor = getenv("EDITOR");
    }
    if (!editor) {
        error_print(0, "Editor not specified nor read from the environment");
        return EXIT_FAILURE;
    }

    if ((pid = fork()) == -1) {
        error_print(0, "Fork failed (%s)", strerror(errno));
        return EXIT_FAILURE;
    } else if (pid == 0) {
        /* child */
        execlp(editor, editor, path, (char *)NULL);

        error_print(0, "Exec failed (%s)", strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        /* parent */
        wait_pid = wait(&ret);
        if (wait_pid != pid) {
            error_print(0, "Child process other than the editor exited, weird");
            return EXIT_FAILURE;
        }
        if (!WIFEXITED(ret)) {
            error_print(0, "Editor exited in a non-standard way");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int
step_read_file(FILE *file, char **mem)
{
    size_t mem_size, mem_used;

    mem_size = 512;
    mem_used = 0;
    *mem = malloc(mem_size);

    do {
        if (mem_used == mem_size) {
            mem_size >>= 1;
            *mem = realloc(*mem, mem_size);
        }

        mem_used += fread(*mem + mem_used, 1, mem_size - mem_used, file);
    } while (mem_used == mem_size);

    (*mem)[mem_used] = '\0';

    if (ferror(file)) {
        free(*mem);
        error_print(0, "Error reading from file (%s)", strerror(errno));
        return EXIT_FAILURE;
    } else if (!feof(file)) {
        free(*mem);
        error_print(0, "Unknown file problem");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

enum data_type {
    DATA_CONFIG,
    DATA_EDIT,
    DATA_RPC,
    DATA_NOTIF
};

static int
step_load_data(sr_session_ctx_t *sess, const char *file_path, LYD_FORMAT format, enum data_type data_type,
        int not_strict, struct lyd_node **data)
{
    const struct ly_ctx *ly_ctx;
    struct ly_in *in;
    char *ptr;
    int parse_flags;
    LY_ERR lyrc;

    ly_ctx = sr_get_context(sr_session_get_connection(sess));

    /* learn format */
    if (format == LYD_UNKNOWN) {
        if (!file_path) {
            error_print(0, "When reading data from STDIN, format must be specified");
            return EXIT_FAILURE;
        }

        ptr = strrchr(file_path, '.');
        if (ptr && !strcmp(ptr, ".xml")) {
            format = LYD_XML;
        } else if (ptr && !strcmp(ptr, ".json")) {
            format = LYD_JSON;
        } else if (ptr && !strcmp(ptr, ".lyb")) {
            format = LYD_LYB;
        } else {
            error_print(0, "Failed to detect format of \"%s\"", file_path);
            return EXIT_FAILURE;
        }
    }

    /* get input */
    if (file_path) {
        ly_in_new_filepath(file_path, 0, &in);
    } else {
        /* we need to load the data into memory first */
        if (step_read_file(stdin, &ptr)) {
            return EXIT_FAILURE;
        }
        ly_in_new_memory(ptr, &in);
    }

    /* parse data */
    switch (data_type) {
    case DATA_CONFIG:
        parse_flags = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY | (not_strict ? 0 : LYD_PARSE_STRICT);
        lyrc = lyd_parse_data(ly_ctx, in, format, parse_flags, 0, data);
        break;
    case DATA_EDIT:
        parse_flags = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY | LYD_PARSE_OPAQ;
        lyrc = lyd_parse_data(ly_ctx, in, format, parse_flags, 0, data);
        break;
    case DATA_RPC:
        lyrc = lyd_parse_rpc(ly_ctx, in, format, data, NULL);
        break;
    case DATA_NOTIF:
        lyrc = lyd_parse_notif(ly_ctx, in, format, data, NULL);
        break;
    }
    ly_in_free(in, 1);

    if (lyrc) {
        error_ly_print(ly_ctx);
        error_print(0, "Data parsing failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
step_create_input_file(LYD_FORMAT format, char *tmp_file)
{
    int fd;

    if (format == LYD_LYB) {
        error_print(0, "LYB binary format cannot be opened in a text editor");
        return EXIT_FAILURE;
    } else if (format == LYD_UNKNOWN) {
        format = LYD_XML;
    }

#ifdef SR_HAVE_MKSTEMPS
    int suffix;

    /* create temporary file, suffix is used only so that the text editor
     * can automatically use syntax highlighting */
    if (format == LYD_JSON) {
        sprintf(tmp_file, "/tmp/srtmpXXXXXX.json");
        suffix = 5;
    } else {
        sprintf(tmp_file, "/tmp/srtmpXXXXXX.xml");
        suffix = 4;
    }
    fd = mkstemps(tmp_file, suffix);
#else
    sprintf(tmp_file, "/tmp/srtmpXXXXXX");
    fd = mkstemp(tmp_file);
#endif
    if (fd == -1) {
        error_print(0, "Failed to open temporary file (%s)", strerror(errno));
        return EXIT_FAILURE;
    }
    close(fd);

    return EXIT_SUCCESS;
}

static int
op_import(sr_session_ctx_t *sess, const char *file_path, const char *module_name, LYD_FORMAT format, int not_strict,
        int timeout_s, int wait)
{
    struct lyd_node *data;
    int r;

    if (step_load_data(sess, file_path, format, DATA_CONFIG, not_strict, &data)) {
        return EXIT_FAILURE;
    }

    /* replace config (always spends data) */
    r = sr_replace_config(sess, module_name, data, timeout_s * 1000, wait);
    if (r) {
        error_print(r, "Replace config failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
op_export(sr_session_ctx_t *sess, const char *file_path, const char *module_name, const char *xpath, LYD_FORMAT format,
        uint32_t max_depth, int wd_opt, int timeout_s)
{
    struct lyd_node *data;
    FILE *file = NULL;
    char *str;
    int r;

    if (format == LYD_UNKNOWN) {
        format = LYD_XML;
    }

    if (file_path) {
        file = fopen(file_path, "w");
        if (!file) {
            error_print(0, "Failed to open \"%s\" for writing (%s)", file_path, strerror(errno));
            return EXIT_FAILURE;
        }
    }

    /* get subtrees */
    if (module_name) {
        asprintf(&str, "/%s:*", module_name);
        r = sr_get_data(sess, str, max_depth, timeout_s * 1000, 0, &data);
        free(str);
    } else if (xpath) {
        r = sr_get_data(sess, xpath, max_depth, timeout_s * 1000, 0, &data);
    } else {
        r = sr_get_data(sess, "/*", max_depth, timeout_s * 1000, 0, &data);
    }
    if (r != SR_ERR_OK) {
        error_print(r, "Getting data failed");
        if (file) {
            fclose(file);
        }
        return EXIT_FAILURE;
    }

    /* print exported data */
    lyd_print_file(file ? file : stdout, data, format, LYD_PRINT_WITHSIBLINGS | wd_opt);
    lyd_free_all(data);

    /* cleanup */
    if (file) {
        fclose(file);
    }
    return EXIT_SUCCESS;
}

static int
op_edit(sr_session_ctx_t *sess, const char *file_path, const char *editor, const char *module_name, LYD_FORMAT format,
        int not_strict, int lock, int wd_opt, int timeout_s, int wait)
{
    char tmp_file[22];
    int r, rc = EXIT_FAILURE;
    struct lyd_node *data;

    if (file_path) {
        /* just apply an edit from a file */
        if (step_load_data(sess, file_path, format, DATA_EDIT, 0, &data)) {
            return EXIT_FAILURE;
        }

        r = sr_edit_batch(sess, data, "merge");
        lyd_free_all(data);
        if (r != SR_ERR_OK) {
            error_print(r, "Failed to prepare edit");
            return EXIT_FAILURE;
        }

        r = sr_apply_changes(sess, timeout_s * 1000, wait);
        if (r != SR_ERR_OK) {
            error_print(r, "Failed to merge edit data");
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* create temporary file */
    if (step_create_input_file(format, tmp_file)) {
        return EXIT_FAILURE;
    }

    /* lock if requested */
    if (lock && ((r = sr_lock(sess, module_name)) != SR_ERR_OK)) {
        error_print(r, "Lock failed");
        return EXIT_FAILURE;
    }

    /* use export operation to get data to edit */
    if (op_export(sess, tmp_file, module_name, NULL, format, 0, wd_opt, timeout_s)) {
        goto cleanup_unlock;
    }

    /* edit */
    if (step_edit_input(editor, tmp_file)) {
        goto cleanup_unlock;
    }

    /* use import operation to store edited data */
    if (op_import(sess, tmp_file, module_name, format, not_strict, timeout_s, wait)) {
        goto cleanup_unlock;
    }

    /* success */
    rc = EXIT_SUCCESS;

cleanup_unlock:
    if (lock && ((r = sr_unlock(sess, module_name)) != SR_ERR_OK)) {
        error_print(r, "Unlock failed");
    }
    return rc;
}

static int
op_rpc(sr_session_ctx_t *sess, const char *file_path, const char *editor, LYD_FORMAT format, int wd_opt, int timeout_s)
{
    char tmp_file[22];
    int r;
    struct lyd_node *input, *output, *node;

    if (!file_path) {
        /* create temp file */
        if (step_create_input_file(format, tmp_file)) {
            return EXIT_FAILURE;
        }

        /* load rpc/action into the file */
        if (step_edit_input(editor, tmp_file)) {
            return EXIT_FAILURE;
        }

        file_path = tmp_file;
    }

    /* load the file */
    if (step_load_data(sess, file_path, format, DATA_RPC, 0, &input)) {
        return EXIT_FAILURE;
    }

    /* send rpc/action */
    r = sr_rpc_send_tree(sess, input, timeout_s * 1000, &output);
    lyd_free_all(input);
    if (r) {
        error_print(r, "Sending RPC/action failed");
        return EXIT_FAILURE;
    }

    /* print output if any */
    LY_LIST_FOR(lyd_child(output), node) {
        if (!(node->flags & LYD_DEFAULT)) {
            break;
        }
    }
    if (node) {
        lyd_print_file(stdout, output, format, wd_opt);
    }
    lyd_free_all(output);

    return EXIT_SUCCESS;
}

static int
op_notif(sr_session_ctx_t *sess, const char *file_path, const char *editor, LYD_FORMAT format)
{
    char tmp_file[22];
    int r;
    struct lyd_node *notif;

    if (!file_path) {
        /* create temp file */
        if (step_create_input_file(format, tmp_file)) {
            return EXIT_FAILURE;
        }

        /* load notif into the file */
        if (step_edit_input(editor, tmp_file)) {
            return EXIT_FAILURE;
        }

        file_path = tmp_file;
    }

    /* load the file */
    if (step_load_data(sess, file_path, format, DATA_NOTIF, 0, &notif)) {
        return EXIT_FAILURE;
    }

    /* send notification */
    r = sr_event_notif_send_tree(sess, notif);
    lyd_free_all(notif);
    if (r) {
        error_print(r, "Sending notification failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
op_copy(sr_session_ctx_t *sess, const char *file_path, sr_datastore_t source_ds, const char *module_name,
        LYD_FORMAT format, int not_strict, int timeout_s, int wait)
{
    int r;
    struct lyd_node *data;

    if (file_path) {
        /* load the file */
        if (step_load_data(sess, file_path, format, DATA_CONFIG, not_strict, &data)) {
            return EXIT_FAILURE;
        }

        /* replace data */
        r = sr_replace_config(sess, module_name, data, timeout_s * 1000, wait);
        if (r) {
            error_print(r, "Replace config failed");
            return EXIT_FAILURE;
        }
    } else {
        /* copy config */
        r = sr_copy_config(sess, module_name, source_ds, timeout_s * 1000, wait);
        if (r) {
            error_print(r, "Copy config failed");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int
op_new_data(sr_conn_ctx_t *conn, const char *file_path, const char *module_name, LYD_FORMAT format)
{
    int r;

    /* set the initial data */
    r = sr_install_module_data(conn, module_name, NULL, file_path, format);
    if (r) {
        error_print(r, "Install module data failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
arg_is_file(const char *optarg)
{
    return !access(optarg, F_OK);
}

static int
arg_get_ds(const char *optarg, sr_datastore_t *ds)
{
    if (!strcmp(optarg, "running")) {
        *ds = SR_DS_RUNNING;
    } else if (!strcmp(optarg, "startup")) {
        *ds = SR_DS_STARTUP;
    } else if (!strcmp(optarg, "candidate")) {
        *ds = SR_DS_CANDIDATE;
    } else if (!strcmp(optarg, "operational")) {
        *ds = SR_DS_OPERATIONAL;
    } else {
        error_print(0, "Unknown datastore \"%s\"", optarg);
        return -1;
    }

    return 0;
}

int
main(int argc, char** argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    sr_datastore_t ds = SR_DS_RUNNING, source_ds;
    LYD_FORMAT format = LYD_UNKNOWN;
    const char *module_name = NULL, *editor = NULL, *file_path = NULL, *xpath = NULL, *op_str;
    char *ptr;
    sr_log_level_t log_level = SR_LL_ERR;
    int r, rc = EXIT_FAILURE, opt, operation = 0, lock = 0, not_strict = 0, timeout = 0, wait = 0, wd_opt = 0;
    uint32_t max_depth = 0;
    struct option options[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"version",         no_argument,       NULL, 'V'},
        {"import",          optional_argument, NULL, 'I'},
        {"export",          optional_argument, NULL, 'X'},
        {"edit",            optional_argument, NULL, 'E'},
        {"rpc",             optional_argument, NULL, 'R'},
        {"notification",    optional_argument, NULL, 'N'},
        {"copy-from",       required_argument, NULL, 'C'},
        {"new-data",        required_argument, NULL, 'W'},
        {"datastore",       required_argument, NULL, 'd'},
        {"module",          required_argument, NULL, 'm'},
        {"xpath",           required_argument, NULL, 'x'},
        {"format",          required_argument, NULL, 'f'},
        {"lock",            no_argument,       NULL, 'l'},
        {"not-strict",      no_argument,       NULL, 'n'},
        {"depth",           required_argument, NULL, 'p'},
        {"timeout",         required_argument, NULL, 't'},
        {"wait",            no_argument,       NULL, 'w'},
        {"defaults",        required_argument, NULL, 'e'},
        {"verbosity",       required_argument, NULL, 'v'},
        {NULL,              0,                 NULL, 0},
    };

    if (argc == 1) {
        help_print();
        goto cleanup;
    }

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hVI::X::E::R::N::C:W:d:m:x:f:lnp:t:we:v:", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            version_print();
            help_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'V':
            version_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'I':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                file_path = optarg;
            }
            operation = opt;
            break;
        case 'X':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                file_path = optarg;
            }
            operation = opt;
            break;
        case 'E':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                if (arg_is_file(optarg)) {
                    file_path = optarg;
                } else {
                    editor = optarg;
                }
            }
            operation = opt;
            break;
        case 'R':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                if (arg_is_file(optarg)) {
                    file_path = optarg;
                } else {
                    editor = optarg;
                }
            }
            operation = opt;
            break;
        case 'N':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                if (arg_is_file(optarg)) {
                    file_path = optarg;
                } else {
                    editor = optarg;
                }
            }
            operation = opt;
            break;
        case 'C':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (arg_is_file(optarg)) {
                file_path = optarg;
            } else {
                if (arg_get_ds(optarg, &source_ds)) {
                    goto cleanup;
                }
            }
            operation = opt;
            break;
        case 'W':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            file_path = optarg;
            operation = opt;
            break;
        case 'd':
            if (arg_get_ds(optarg, &ds)) {
                goto cleanup;
            }
            break;
        case 'm':
            if (module_name) {
                error_print(0, "Module already specified");
                goto cleanup;
            } else if (xpath) {
                error_print(0, "Only one of options --module and --xpath can be set");
                goto cleanup;
            }
            module_name = optarg;
            break;
        case 'x':
            if (xpath) {
                error_print(0, "XPath already specified");
                goto cleanup;
            } else if (module_name) {
                error_print(0, "Only one of options --module and --xpath can be set");
                goto cleanup;
            }
            xpath = optarg;
            break;
        case 'f':
            if (!strcmp(optarg, "xml")) {
                format = LYD_XML;
            } else if (!strcmp(optarg, "json")) {
                format = LYD_JSON;
            } else if (!strcmp(optarg, "lyb")) {
                format = LYD_LYB;
            } else {
                error_print(0, "Unknown format \"%s\"", optarg);
                goto cleanup;
            }
            break;
        case 'l':
            lock = 1;
            break;
        case 'n':
            not_strict = 1;
            break;
        case 'p':
            max_depth = strtoul(optarg, &ptr, 10);
            if (ptr[0]) {
                error_print(0, "Invalid depth \"%s\"", optarg);
                goto cleanup;
            }
            break;
        case 't':
            timeout = strtoul(optarg, &ptr, 10);
            if (ptr[0]) {
                error_print(0, "Invalid timeout \"%s\"", optarg);
                goto cleanup;
            }
            break;
        case 'w':
            wait = 1;
            break;
        case 'e':
            if (!strcmp(optarg, "report-all")) {
                wd_opt = LYD_PRINT_WD_ALL;
            } else if (!strcmp(optarg, "report-all-tagged")) {
                wd_opt = LYD_PRINT_WD_ALL_TAG;
            } else if (!strcmp(optarg, "trim")) {
                wd_opt = LYD_PRINT_WD_TRIM;
            } else if (!strcmp(optarg, "explicit")) {
                wd_opt = LYD_PRINT_WD_EXPLICIT;
            } else if (!strcmp(optarg, "implicit-tagged")) {
                wd_opt = LYD_PRINT_WD_IMPL_TAG;
            } else {
                error_print(0, "Invalid defaults mode \"%s\"", optarg);
                goto cleanup;
            }
            break;
        case 'v':
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

    /* check if operation on the datastore is supported */
    if (ds == SR_DS_OPERATIONAL) {
        switch (operation) {
        case 'I':
            op_str = "Import";
            break;
        case 'E':
            op_str = "Edit";
            break;
        case 'C':
            op_str = "Copy-config";
            break;
        default:
            op_str = NULL;
            break;
        }

        if (op_str) {
            error_print(0, "%s operation on operational DS not supported, changes would be lost after session is terminated", op_str);
            goto cleanup;
        }
    }

    /* set logging */
    sr_log_stderr(log_level);

    /* create connection */
    if ((r = sr_connect(0, &conn)) != SR_ERR_OK) {
        error_print(r, "Failed to connect");
        goto cleanup;
    }

    /* create session */
    if ((r = sr_session_start(conn, ds, &sess)) != SR_ERR_OK) {
        error_print(r, "Failed to start a session");
        goto cleanup;
    }

    /* perform the operation */
    switch (operation) {
    case 'I':
        rc = op_import(sess, file_path, module_name, format, not_strict, timeout, wait);
        break;
    case 'X':
        rc = op_export(sess, file_path, module_name, xpath, format, max_depth, wd_opt, timeout);
        break;
    case 'E':
        rc = op_edit(sess, file_path, editor, module_name, format, lock, not_strict, wd_opt, timeout, wait);
        break;
    case 'R':
        rc = op_rpc(sess, file_path, editor, format, wd_opt, timeout);
        break;
    case 'N':
        rc = op_notif(sess, file_path, editor, format);
        break;
    case 'C':
        rc = op_copy(sess, file_path, source_ds, module_name, format, not_strict, timeout, wait);
        break;
    case 'W':
        if (!module_name) {
            error_print(0, "Module must be specified when setting its initial data");
            break;
        } else if (!format) {
            error_print(0, "Format of the file must be specified when setting initial data");
            break;
        }
        rc = op_new_data(conn, file_path, module_name, format);
        break;
    case 0:
        error_print(0, "No operation specified");
        break;
    default:
        error_print(0, "Internal");
        break;
    }

cleanup:
    sr_session_stop(sess);
    sr_disconnect(conn);
    return rc;
}
