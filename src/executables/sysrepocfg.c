/**
 * @file sysrepocfg.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepocfg tool
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "sysrepo.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <libyang/libyang.h>

static void
help_print(void)
{
    printf(
        "sysrepocfg - sysrepo configuration tool\n"
        "\n"
        "Usage:\n"
        "  sysrepocfg [operation-option] [other-options]\n"
        "\n"
        "Available operation-options:\n"
        "  -h, --help                   Prints usage help.\n"
        "  -v, --verbosity              Change verbosity to a level (none, error, warning, info, debug) or number (0, 1, 2, 3, 4).\n"
        "\n"
        "  -i, --import [<file-path>]   Import the configuration from a file or STDIN.\n"
        "  -o, --export [<file-path>]   Export configuration to a file or STDOUT.\n"
        "  -e, --edit [<editor>]        Edit configuration data using <editor> or read from $VISUAL or $EDITOR env variables.\n"
        "\n"
        "Available other-options:\n"
        "  -d, --datastore <datastore>  Datastore to be operated on, \"running\" by default (\"running\", \"startup\",\n"
        "                               or \"operational\") (edit, import, export op).\n"
        "  -m, --module <module-name>   Module to be operated on, otherwise it is operated on full datastore\n"
        "                               (edit, import, export op).\n"
        "  -x, --xpath <xpath>          XPath to select (export op).\n"
        "  -f, --format <format>        Data format to be used, by default based on file extension or \"xml\" if not applicable\n"
        "                               (\"xml\", \"json\", or \"lyb\") (edit, import, export op).\n"
        "  -l, --lock                   Lock the specified datastore for the whole operation (edit op).\n"
        "  -p, --permanent              Make all changes in the \"running\" datastore permanent by performing a copy-config\n"
        "                               from \"running\" to \"startup\" (edit op).\n"
        "  -n, --not-strict             Silently ignore any unknown data (edit, import op).\n"
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
error_ly_print(struct ly_ctx *ctx)
{
    struct ly_err_item *e;

    for (e = ly_err_first(ctx); e; e = e->next) {
        error_print(0, "libyang: %s", e->msg);
    }

    ly_err_clean(ctx, NULL);
}

static int
edit_input(const char *editor, const char *path)
{
    int ret;
    pid_t pid, wait_pid;

    if ((pid = vfork()) == -1) {
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
read_file(FILE *file, char **mem)
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

    if (ferror(file)) {
        free(*mem);
        error_print(0, "Error reading from file");
        return EXIT_FAILURE;
    } else if (!feof(file)) {
        free(*mem);
        error_print(0, "Unknown file problem");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
op_import(sr_session_ctx_t *sess, const char *file_path, const char *module_name, LYD_FORMAT format, int not_strict)
{
    struct ly_ctx *ly_ctx;
    struct lyd_node *data;
    int r, flags;
    char *ptr;

    ly_ctx = (struct ly_ctx *)sr_get_context(sr_session_get_connection(sess));

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

    /* parse import data */
    flags = LYD_OPT_CONFIG | (not_strict ? 0 : LYD_OPT_STRICT);
    if (file_path) {
        data = lyd_parse_path(ly_ctx, file_path, format, flags);
    } else {
        /* we need to load the data into memory first */
        if (read_file(stdin, &ptr)) {
            return EXIT_FAILURE;
        }
        data = lyd_parse_mem(ly_ctx, ptr, format, flags);
        free(ptr);
    }
    if (ly_errno) {
        error_ly_print(ly_ctx);
        error_print(0, "Data parsing failed");
        return EXIT_FAILURE;
    }

    /* replace config (always spends data) */
    r = sr_replace_config(sess, module_name, data, sr_session_get_ds(sess));
    if (r) {
        error_print(r, "Replace config failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
op_export(sr_session_ctx_t *sess, const char *file_path, const char *module_name, const char *xpath, LYD_FORMAT format)
{
    struct ly_set *set;
    FILE *file = NULL;
    char *str;
    int r;
    uint32_t i;

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
        r = sr_get_subtrees(sess, str, &set);
        free(str);
    } else if (xpath) {
        r = sr_get_subtrees(sess, xpath, &set);
    } else {
        r = sr_get_subtrees(sess, "/*", &set);
    }
    if (r != SR_ERR_OK) {
        error_print(r, "Getting data failed");
        if (file) {
            fclose(file);
        }
        return EXIT_FAILURE;
    }

    /* print exported data */
    for (i = 0; i < set->number; ++i) {
        lyd_print_file(file ? file : stdout, set->set.d[i], format, LYP_FORMAT);
        lyd_free_withsiblings(set->set.d[i]);
    }
    ly_set_free(set);

    /* cleanup */
    if (file) {
        fclose(file);
    }
    return EXIT_SUCCESS;
}

static int
op_edit(sr_session_ctx_t *sess, const char *editor, const char *module_name, LYD_FORMAT format, int lock, int permanent,
        int not_strict)
{
    char tmp_file[22];
    int suffix, fd, r, rc = EXIT_FAILURE;

    if (format == LYD_LYB) {
        error_print(0, "LYB binary format cannot be opened in a text editor");
        return EXIT_FAILURE;
    } else if (format == LYD_UNKNOWN) {
        format = LYD_XML;
    }

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

    /* create temporary file */
    if (format == LYD_JSON) {
        sprintf(tmp_file, "/tmp/srtmpXXXXXX.json");
        suffix = 5;
    } else {
        sprintf(tmp_file, "/tmp/srtmpXXXXXX.xml");
        suffix = 4;
    }
    fd = mkstemps(tmp_file, suffix);
    if (fd == -1) {
        error_print(0, "Failed to open temporary file (%s)", strerror(errno));
        return EXIT_FAILURE;
    }
    close(fd);

    /* lock if requested */
    if (lock && ((r = sr_lock(sess, module_name)) != SR_ERR_OK)) {
        error_print(r, "Lock failed");
        return EXIT_FAILURE;
    }

    /* use export operation to get data to edit */
    if (op_export(sess, tmp_file, module_name, NULL, format)) {
        goto cleanup_unlock;
    }

    /* edit */
    if (edit_input(editor, tmp_file)) {
        goto cleanup_unlock;
    }

    /* use import operation to store edited data */
    if (op_import(sess, tmp_file, module_name, format, not_strict)) {
        goto cleanup_unlock;
    }

    /* perform copy-config */
    if (permanent && (sr_session_get_ds(sess) == SR_DS_RUNNING)) {
        if ((r = sr_copy_config(sess, module_name, SR_DS_RUNNING, SR_DS_STARTUP)) != SR_ERR_OK) {
            error_print(r, "Copy-config failed");
            goto cleanup_unlock;
        }
    }

    /* success */
    rc = EXIT_SUCCESS;

cleanup_unlock:
    if (lock && ((r = sr_unlock(sess, module_name)) != SR_ERR_OK)) {
        error_print(r, "Unlock failed");
    }
    return rc;
}

int
main(int argc, char** argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    sr_datastore_t ds = SR_DS_RUNNING;
    LYD_FORMAT format = LYD_UNKNOWN;
    const char *module_name = NULL, *editor = NULL, *file_path = NULL, *xpath = NULL;
    sr_log_level_t log_level = 0;
    int r, rc = EXIT_FAILURE, opt, operation = 0, lock = 0, permanent = 0, not_strict = 0;
    struct option options[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"verbosity",       required_argument, NULL, 'v'},
        {"import",          optional_argument, NULL, 'i'},
        {"export",          optional_argument, NULL, 'o'},
        {"edit",            optional_argument, NULL, 'e'},
        {"datastore",       required_argument, NULL, 'd'},
        {"module",          required_argument, NULL, 'm'},
        {"xpath",           required_argument, NULL, 'x'},
        {"format",          required_argument, NULL, 'f'},
        {"lock",            no_argument,       NULL, 'l'},
        {"permanent",       no_argument,       NULL, 'p'},
        {"not-strict",      no_argument,       NULL, 'n'},
    };

    if (argc == 1) {
        help_print();
        goto cleanup;
    }

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hv:i::o::e::d:m:x:f:lpn", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            help_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
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
            sr_log_stderr(log_level);
            break;
        case 'i':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                file_path = optarg;
            }
            operation = 'i';
            break;
        case 'o':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                file_path = optarg;
            }
            operation = 'o';
            break;
        case 'e':
            if (operation) {
                error_print(0, "Operation already specified");
                goto cleanup;
            }
            if (optarg) {
                editor = optarg;
            }
            operation = 'e';
            break;
        case 'd':
            if (!strcmp(optarg, "running")) {
                ds = SR_DS_RUNNING;
            } else if (!strcmp(optarg, "startup")) {
                ds = SR_DS_STARTUP;
            } else if (!strcmp(optarg, "operational")) {
                ds = SR_DS_OPERATIONAL;
            } else {
                error_print(0, "Unknown datastore \"%s\"", optarg);
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
        case 'p':
            permanent = 1;
            break;
        case 'n':
            not_strict = 1;
            break;
        default:
            error_print(0, "Invalid option or missing argument: -%c", optopt);
            goto cleanup;
        }
    }

    /* check for additional argument */
    if (optind < argc) {
        error_print(0, "Redundant parameters");
        goto cleanup;
    }

    /* create connection */
    if ((r = sr_connect("sysrepocfg", 0, &conn)) != SR_ERR_OK) {
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
    case 'i':
        rc = op_import(sess, file_path, module_name, format, not_strict);
        break;
    case 'o':
        rc = op_export(sess, file_path, module_name, xpath, format);
        break;
    case 'e':
        rc = op_edit(sess, editor, module_name, format, lock, permanent, not_strict);
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
