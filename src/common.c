
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>

#include "common.h"

static void
sr_log_vprintf(sr_log_level_t ll, const char *format, va_list args)
{
    char msg[2048];

    if (vsnprintf(msg, 2048, format, args) == -1) {
        return;
    }

    switch (ll) {
    case SR_LL_ERR:
        fprintf(stderr, "SRERR: %s\n", msg);
        break;
    case SR_LL_WRN:
        fprintf(stderr, "SRWRN: %s\n", msg);
        break;
    case SR_LL_INF:
        fprintf(stderr, "SRINF: %s\n", msg);
        break;
    case SR_LL_DBG:
        fprintf(stderr, "SRDBG: %s\n", msg);
        break;
    case SR_LL_NONE:
        break;
    }
}

void
sr_log(sr_log_level_t ll, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    sr_log_vprintf(ll, format, ap);
    va_end(ap);
}

void *
sr_realloc(void *ptr, size_t size)
{
    void *new_mem;

    new_mem = realloc(ptr, size);
    if (!new_mem) {
        free(ptr);
    }

    return new_mem;
}

const char *
sr_get_repo_path(void)
{
    char *value;

    value = getenv(SR_REPO_PATH_ENV);
    if (value) {
        return value;
    }

    return SR_REPO_PATH;
}

int
sr_mkpath(char *file_path, mode_t mode, uint32_t start_idx)
{
    char *p;

    assert(file_path[start_idx] == '/');

    for (p = strchr(file_path + start_idx + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                SR_LOG_FUNC_ERRNO("mkdir");
                return SR_ERR_IO;
            }
        }
        *p = '/';
    }

    if (mkdir(file_path, mode) == -1) {
        if (errno != EEXIST) {
            SR_LOG_FUNC_ERRNO("mkdir");
            return SR_ERR_IO;
        }
    }

    return SR_ERR_OK;;
}

char *
sr_val_sr2ly_str(struct ly_ctx *ctx, const sr_val_t *value, char *buf)
{
    struct lys_node_leaf *sleaf;

    if (!value) {
        return NULL;
    }

    switch (value->type) {
    case SR_STRING_T:
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_ANYDATA_T:
    case SR_ANYXML_T:
        return (value->data.string_val);
    case SR_LEAF_EMPTY_T:
        return NULL;
    case SR_BOOL_T:
        return value->data.bool_val ? "true" : "false";
    case SR_DECIMAL64_T:
        /* get fraction-digits */
        sleaf = (struct lys_node_leaf *)ly_ctx_get_node(ctx, NULL, value->xpath, 0);
        if (!sleaf) {
            return NULL;
        }
        while (sleaf->type.base == LY_TYPE_LEAFREF) {
            sleaf = sleaf->type.info.lref.target;
        }
        sprintf(buf, "%.*f", sleaf->type.info.dec64.dig, value->data.decimal64_val);
        return buf;
    case SR_UINT8_T:
    case SR_UINT16_T:
    case SR_UINT32_T:
        sprintf(buf, "%u", value->data.uint32_val);
        return buf;
    case SR_UINT64_T:
        sprintf(buf, "%"PRIu64, value->data.uint64_val);
        return buf;
    case SR_INT8_T:
    case SR_INT16_T:
    case SR_INT32_T:
        sprintf(buf, "%d", value->data.int32_val);
        return buf;
    case SR_INT64_T:
        sprintf(buf, "%"PRId64, value->data.int64_val);
        return buf;
    default:
        return NULL;
    }
}

char *
sr_get_first_ns(const char *expr)
{
    int i;

    if (expr[0] != '/') {
        return NULL;
    }
    if (expr[1] == '/') {
        expr += 2;
    } else {
        ++expr;
    }

    if (!isalpha(expr[0]) && (expr[0] != '_')) {
        return NULL;
    }
    for (i = 1; expr[i] && (isalnum(expr[i]) || (expr[i] == '_') || (expr[i] == '-') || (expr[i] == '.')); ++i);
    if (expr[i] != ':') {
        return NULL;
    }

    return strndup(expr, i);
}

const char *
sr_ds2str(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_RUNNING:
        return "running";
    case SR_DS_STARTUP:
        return "startup";
    case SR_DS_COUNT:
        return NULL;
    }

    return NULL;
}

int
sr_msleep(uint32_t msec)
{
    struct timespec ts;
    int ret;

    memset(&ts, 0, sizeof ts);
    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        ret = nanosleep(&ts, &ts);
    } while ((ret == -1) && (errno = EINTR));

    if (ret == -1) {
        SR_LOG_FUNC_ERRNO("nanosleep");
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

uint32_t
sr_file_get_size(int fd)
{
    off_t size;

    size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        SR_LOG_FUNC_ERRNO("lseek");
        return 0;
    }
    if (lseek(fd, 0, SEEK_SET) == -1) {
        SR_LOG_FUNC_ERRNO("lseek");
        return 0;
    }

    return (uint32_t)size;
}

const char *
sr_ly_leaf_value_str(const struct lyd_node *leaf)
{
    assert(leaf->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
    return ((struct lyd_node_leaf_list *)leaf)->value_str;
}

int
sr_shared_rwlock_init(pthread_rwlock_t *rwlock)
{
    pthread_rwlockattr_t lock_attr;
    int ret;

    /* init attr */
    if ((ret = pthread_rwlockattr_init(&lock_attr))) {
        SR_LOG_ERR("Initializing pthread rwlockattr failed (%s).", strerror(ret));
        return SR_ERR_INIT_FAILED;
    }
    if ((ret = pthread_rwlockattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED))) {
        SR_LOG_ERR("Changing pthread rwlockattr failed (%s).", strerror(ret));
        pthread_rwlockattr_destroy(&lock_attr);
        return SR_ERR_INIT_FAILED;
    }

    if ((ret = pthread_rwlock_init(rwlock, &lock_attr))) {
        SR_LOG_ERR("Initializing pthread rwlock failed (%s).", strerror(ret));
        pthread_rwlockattr_destroy(&lock_attr);
        return SR_ERR_INIT_FAILED;
    }

    pthread_rwlockattr_destroy(&lock_attr);
    return SR_ERR_OK;
}

const char *
sr_ev2str(sr_notif_event_t ev)
{
    switch (ev) {
    case SR_EV_NONE:
        return "none";
    case SR_EV_UPDATE:
        return "update";
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
        return "abort";
    case SR_EV_ENABLED:
        return "enabled";
    }

    return NULL;
}

int
sr_val_ly2sr(const struct lyd_node *node, sr_val_t *sr_val)
{
    char *ptr;
    const struct lyd_node_leaf_list *leaf;
    int ret;

    sr_val->xpath = lyd_path(node);
    SR_CHECK_MEM_GOTO(!sr_val->xpath, ret, error);

    sr_val->dflt = node->dflt;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (const struct lyd_node_leaf_list *)node;
        switch (leaf->value_type) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.binary_val, ret, error);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.bits_val, ret, error);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            sr_val->data.bool_val = leaf->value.bln ? true : false;
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(leaf->value_str, &ptr);
            if (ptr[0]) {
                SR_LOG_ERR("Value \"%s\" is not a valid decimal64 number.", leaf->value_str);
                ret = SR_ERR_VALIDATION_FAILED;
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            sr_val->data.string_val = NULL;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.enum_val, ret, error);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.identityref_val, ret, error);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.instanceid_val, ret, error);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = leaf->value.int8;
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = leaf->value.int16;
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = leaf->value.int32;
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = leaf->value.int64;
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.string_val, ret, error);
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = leaf->value.uint8;
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = leaf->value.uint16;
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = leaf->value.uint32;
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = leaf->value.uint64;
            break;
        default:
            SR_LOG_ERRINT;
            return SR_ERR_INTERNAL;
        }
        break;
    case LYS_CONTAINER:
        if (((struct lys_node_container *)node->schema)->presence) {
            sr_val->type = SR_CONTAINER_PRESENCE_T;
        } else {
            sr_val->type = SR_CONTAINER_T;
        }
        break;
    case LYS_LIST:
        sr_val->type = SR_LIST_T;
        break;
    case LYS_NOTIF:
        sr_val->type = SR_NOTIFICATION_T;
        break;
    case LYS_ANYXML:
        sr_val->type = SR_ANYXML_T;
        /* TODO sr_val->data.anyxml_val = */
        break;
    case LYS_ANYDATA:
        sr_val->type = SR_ANYDATA_T;
        /* TODO sr_val->data.anydata_val = */
        break;
    default:
        SR_LOG_ERRINT;
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;

error:
    free(sr_val->xpath);
    return ret;
}

void
sr_ly_split(struct lyd_node *sibling)
{
    struct lyd_node *first, *last;

    if (!sibling || !sibling->prev->next) {
        return;
    }

    /* only works with top-level nodes */
    assert(!sibling->parent);

    /* find first and last node */
    for (first = sibling->prev; first->prev->next; first = first->prev);
    last = first->prev;

    /* correct left sibling list */
    first->prev = sibling->prev;
    sibling->prev->next = NULL;

    /* correct right sibling list */
    sibling->prev = last;
}

void
sr_ly_link(struct lyd_node *first, struct lyd_node *sibling)
{
    struct lyd_node *last;

    if (!first || !sibling) {
        return;
    }

    assert(!first->prev->next && !sibling->prev->next);

    /* remember the last node */
    last = sibling->prev;

    /* link sibling lists together */
    sibling->prev = first->prev;
    first->prev->next = sibling;
    first->prev = last;
}
