/**
 * @file sr_utils.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo utility functions.
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

#include "sr_constants.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
//! @cond doxygen_suppress
#define __USE_XOPEN
//! @endcond
#include <time.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "sr_utils.h"

#include "data_manager.h"

/** maximum number of buffer reallocation attempts */
#define MAX_BUF_REALLOC_ATEMPTS   10

/**
 * @brief used for sr_buff_to_uint32 and sr_uint32_to_buff conversions
 */
typedef union {
   uint32_t value;
   uint8_t data[sizeof(uint32_t)];
} uint32_value_t;

uint32_t
sr_buff_to_uint32(uint8_t *buff)
{
    uint32_value_t val = { 0, };

    if (NULL == buff) {
        return 0;
    }
    memcpy(val.data, buff, sizeof(uint32_t));
    return ntohl(val.value);
}

void
sr_uint32_to_buff(uint32_t number, uint8_t *buff)
{
    uint32_value_t val = { 0, };

    if (NULL != buff) {
        val.value = htonl(number);
        memcpy(buff, val.data, sizeof(uint32_t));
    }
}

bool
sr_str_ends_with(const char *str, const char *suffix)
{
    if (NULL == str || NULL == suffix) {
        return false;
    }

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len){
        return false;
    }
    return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

bool
sr_str_begins_with(const char *str, const char *prefix)
{
    if (NULL == str || NULL == prefix) {
        return false;
    }

    while (*prefix && *str) {
        if (*prefix++ != *str++) {
            return false;
        }
    }

    return *prefix == '\0';
}

int
sr_str_join(const char *str1, const char *str2, char **result)
{
    CHECK_NULL_ARG3(str1, str2, result);
    char *res = NULL;
    size_t l1 = strlen(str1);
    size_t l2 = strlen(str2);
    res = calloc(l1 + l2 + 1, sizeof(*res));
    CHECK_NULL_NOMEM_RETURN(res);
    strcpy(res, str1);
    strcpy(res + l1, str2);
    *result = res;
    return SR_ERR_OK;
}

int
sr_path_join(const char *path1, const char *path2, char **result)
{
    CHECK_NULL_ARG3(path1, path2, result);
    char *res = NULL;
    size_t l1 = strlen(path1);
    size_t l2 = strlen(path2);
    res = calloc(l1 + l2 + 2, sizeof(*res));
    CHECK_NULL_NOMEM_RETURN(res);
    strcpy(res, path1);
    res[l1] = '/';
    strcpy(res + l1 + 1, path2);
    *result = res;
    return SR_ERR_OK;
}

void
sr_str_trim(char *str) {
    if (NULL == str) {
        return;
    }

    char *ptr = str;
    size_t len = strlen(str);
    if (0 == len) {
        return;
    }

    while(isspace(ptr[len - 1])) ptr[--len] = 0;
    while(*ptr && isspace(*ptr)) ++ptr, --len;

    memmove(str, ptr, len + 1);
}

uint32_t
sr_str_hash(const char *str)
{
    uint32_t hash = 5381;
    char c;

    if (NULL == str) {
        return 0;
    }

    while ('\0' != (c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

int
sr_vasprintf(char **strp, const char *fmt, va_list ap)
{
    int ret = 0;
    va_list ap1;
    size_t size;
    char *buffer;

    /* get the size of the resulting string */
    va_copy(ap1, ap);
    size = vsnprintf(NULL, 0, fmt, ap1) + 1;
    va_end(ap1);

    /* allocate memory for the string */
    buffer = calloc(size, sizeof *buffer);
    CHECK_NULL_NOMEM_RETURN(buffer);

    /* print */
    ret = vsnprintf(buffer, size, fmt, ap);
    if (ret >= 0) {
        *strp = buffer;
        return SR_ERR_OK;
    } else {
        free(buffer);
        return SR_ERR_INTERNAL;
    }
}

int
sr_asprintf(char **strp, const char *fmt, ...)
{
    int rc = SR_ERR_OK;
    va_list ap;

    va_start(ap, fmt);
    rc = sr_vasprintf(strp, fmt, ap);
    va_end(ap);

    return rc;
}

int
sr_copy_first_ns(const char *xpath, char **namespace)
{
    CHECK_NULL_ARG2(xpath, namespace);

    char *colon_pos = strchr(xpath, ':');
    if (xpath[0] != '/' || NULL == colon_pos) {
        return SR_ERR_INVAL_ARG;
    }
    ++xpath;
    if (xpath[0] == '/') {
        ++xpath;
    }

    *namespace = strndup(xpath, colon_pos - xpath);
    CHECK_NULL_NOMEM_RETURN(*namespace);
    return SR_ERR_OK;
}

int
sr_copy_all_ns(const char *xpath, char ***namespaces_p, size_t *ns_count_p)
{
    CHECK_NULL_ARG3(xpath, namespaces_p, ns_count_p);

    int rc = SR_ERR_OK;
    char *xp, *sptr, *ptr, *cur_node, **tmp, **namespaces = NULL;
    size_t ns_count = 0;
    static const char qchars[] = "\"'";
    const char *qchar;
    char *q1, *q2, *qptr;

    if (xpath[0] != '/') {
        return SR_ERR_INVAL_ARG;
    }

    xp = strdup(xpath);

    // Blank quoted strings in the xpath, which may contain '/' characters
    for (qchar = qchars; *qchar; qchar++) {
        q1 = strchr(xp, *qchar);
        while (q1) {
            q2 = strchr(q1 + 1, *qchar);
            if (!q2) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }

            for (qptr = q1 + 1; qptr < q2; qptr++) {
                *qptr = ' ';
            }
            q1 = strchr(q2 + 1, *qchar);
        }
    }

    for (cur_node = strtok_r(xp, "/", &sptr); cur_node; cur_node = strtok_r(NULL, "/", &sptr)) {
        if (cur_node[strlen(cur_node) - 1] == ']') {
            ptr = strchr(cur_node, '[');
            if (!ptr) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            *ptr = '\0';
        }

        ptr = strchr(cur_node, ':');
        if (ptr) {
            tmp = realloc(namespaces, (ns_count + 1) * sizeof *namespaces);
            CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
            namespaces = tmp;
            ns_count++;

            namespaces[ns_count - 1] = strndup(cur_node, ptr - cur_node);
            CHECK_NULL_NOMEM_GOTO(namespaces[ns_count - 1], rc, cleanup);
        }
    }

cleanup:
    free(xp);
    if (SR_ERR_OK == rc) {
        *namespaces_p = namespaces;
        *ns_count_p = ns_count;
    } else {
        for (size_t i = 0; i < ns_count; ++i) {
            free(namespaces[i]);
        }
        free(namespaces);
    }
    return rc;
}

int
sr_cmp_first_ns(const char *xpath, const char *ns)
{
    size_t cmp_len = 0;

    if (NULL == xpath || xpath[0] != '/') {
        xpath = "";
    }
    else {
        char *colon_pos = strchr(xpath, ':');
        if (NULL != colon_pos) {
            cmp_len = colon_pos - xpath -1;
            xpath++; /* skip leading slash */
        }
    }

    if (NULL == ns) {
        ns = "";
    }

    return strncmp(xpath, ns, cmp_len);

}

int
sr_get_lock_data_file_name(const char *data_search_dir, const char *module_name,
        const sr_datastore_t ds, char **file_name)
{
    CHECK_NULL_ARG3(data_search_dir, module_name, file_name);
    char *tmp = NULL;
    int rc = sr_get_data_file_name(data_search_dir, module_name, ds, &tmp);
    if (SR_ERR_OK == rc){
        rc = sr_str_join(tmp, SR_LOCK_FILE_EXT, file_name);
        free(tmp);
    }
    return rc;
}

int
sr_get_persist_data_file_name(const char *data_search_dir, const char *module_name, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, SR_PERSIST_FILE_EXT, file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

int
sr_get_persist_data_file_name_buf(const char *data_search_dir, const char *module_name, char *buff, size_t buff_len)
{
    CHECK_NULL_ARG3(data_search_dir, module_name, buff);

    strncpy(buff, data_search_dir, buff_len - 1);
    strncat(buff, module_name, buff_len - strlen(buff) - 1);
    strncat(buff, SR_PERSIST_FILE_EXT, buff_len - strlen(buff) - 1);

    return SR_ERR_OK;
}

int
sr_get_data_file_name(const char *data_search_dir, const char *module_name, const sr_datastore_t ds, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        char *suffix = NULL;
        switch (ds) {
        case SR_DS_CANDIDATE:
            suffix = SR_CANDIDATE_FILE_EXT;
            break;
        case SR_DS_RUNNING:
            suffix = SR_RUNNING_FILE_EXT;
            break;
        case SR_DS_STARTUP:
            /* fall through */
        default:
            suffix = SR_STARTUP_FILE_EXT;
        }
        rc = sr_str_join(tmp, suffix, file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

int
sr_get_schema_file_name(const char *schema_search_dir, const char *module_name,
        const char *rev_date, bool yang_format, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL, *tmp2 = NULL;
    int rc = sr_str_join(schema_search_dir, module_name, &tmp);
    if (NULL != rev_date && 0 != strcmp(rev_date, "")) {
        if (SR_ERR_OK != rc) {
            return rc;
        }
        rc = sr_str_join(tmp, "@", &tmp2);
        if (SR_ERR_OK != rc) {
            free(tmp);
            return rc;
        }
        free(tmp);
        tmp = NULL;
        rc = sr_str_join(tmp2, rev_date, &tmp);
        free(tmp2);
    }
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, yang_format ? SR_SCHEMA_YANG_FILE_EXT : SR_SCHEMA_YIN_FILE_EXT, file_name);
        free(tmp);
        return rc;
    }
    free(tmp);
    return SR_ERR_NOMEM;
}

static int
sr_lock_fd_internal(int fd, bool lock, bool write, bool wait)
{
    int ret = -1;
    struct flock fl = { 0, };

    if (lock) {
        /* lock */
        fl.l_type = write ? F_WRLCK : F_RDLCK;
    } else {
        /* unlock */
        fl.l_type = F_UNLCK;
    }
    fl.l_whence = SEEK_SET; /* from the beginning */
    fl.l_start = 0;         /* with offset 0*/
    fl.l_len = 0;           /* to EOF */
#ifdef HAVE_LINUX_OFD_LOCK
    fl.l_pid = 0;
#else
    fl.l_pid = getpid();
#endif

    /* set the lock, waiting if requested and necessary */
#ifdef HAVE_LINUX_OFD_LOCK
    ret = fcntl(fd, wait ? F_OFD_SETLKW : F_OFD_SETLK, &fl);
#else
    ret = fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl);
#endif

    if (-1 == ret) {
        SR_LOG_WRN("Unable to acquire the lock on fd %d: %s", fd, sr_strerror_safe(errno));
        if (!wait && (EAGAIN == errno || EACCES == errno)) {
            /* already locked by someone else */
            return SR_ERR_LOCKED;
        } else {
            return SR_ERR_INTERNAL;
        }
    }

    return SR_ERR_OK;
}

int
sr_lock_fd(int fd, bool write, bool wait)
{
    return sr_lock_fd_internal(fd, true, write, wait);
}

int
sr_unlock_fd(int fd)
{
    return sr_lock_fd_internal(fd, false, false, false);
}

int
sr_fd_set_nonblock(int fd)
{
    int flags = 0, rc = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (-1 == flags) {
        SR_LOG_WRN("Socket fcntl error (skipped): %s", sr_strerror_safe(errno));
        flags = 0;
    }
    rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (-1 == rc) {
        SR_LOG_ERR("Socket fcntl error: %s", sr_strerror_safe(errno));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

/*
 * An attempt for portable sr_get_peer_eid implementation
 */
#if !defined(HAVE_GETPEEREID)

#if defined(SO_PEERCRED)

#if !defined(SCM_CREDENTIALS)
/* struct ucred is ifdefined behind __USE_GNU, but __USE_GNU is not defined */
struct ucred {
    pid_t pid;    /* process ID of the sending process */
    uid_t uid;    /* user ID of the sending process */
    gid_t gid;    /* group ID of the sending process */
};
#endif /* !defined(SCM_CREDENTIALS) */

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    struct ucred cred = { 0, };
    socklen_t len = sizeof(cred);

    CHECK_NULL_ARG2(uid, gid);

    if (-1 == getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len)) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", sr_strerror_safe(errno));
        return SR_ERR_INTERNAL;
    }
    *uid = cred.uid;
    *gid = cred.gid;

    return SR_ERR_OK;
}

#elif defined(HAVE_GETPEERUCRED)

#if defined(HAVE_UCRED_H)
#include <ucred.h>
#endif /* defined(HAVE_UCRED_H) */

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    ucred_t *ucred = NULL;

    CHECK_NULL_ARG2(uid, gid);

    if (-1 == getpeerucred(fd, &ucred)) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", sr_strerror_safe(errno));
        return SR_ERR_INTERNAL;
    }
    if (-1 == (*uid = ucred_geteuid(ucred))) {
        ucred_free(ucred);
        return SR_ERR_INTERNAL;
    }
    if (-1 == (*gid = ucred_getegid(ucred))) {
        ucred_free(ucred);
        return SR_ERR_INTERNAL;
    }

    ucred_free(ucred);
    return SR_ERR_OK;
}

#endif /* defined(SO_PEERCRED) */

#elif defined(HAVE_GETPEEREID)

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    int ret = 0;

    CHECK_NULL_ARG2(uid, gid);

    ret = getpeereid(fd, uid, gid);
    if (-1 == ret) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", sr_strerror_safe(errno));
        return SR_ERR_INTERNAL;
    } else {
        return SR_ERR_OK;
    }
}

#endif /* !defined(HAVE_GETPEEREID) */

int
sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree, LYD_FORMAT format)
{
    CHECK_NULL_ARG2(file_name, data_tree);
    int ret = 0;
    int rc = SR_ERR_OK;

    FILE *f = fopen(file_name, "w");
    if (NULL == f){
        SR_LOG_ERR("Failed to open file %s", file_name);
        return SR_ERR_IO;
    }
    ret = lockf(fileno(f), F_LOCK, 0);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup, "Failed to lock the file %s", file_name);

    ret = lyd_print_file(f, data_tree, format, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Failed to write output into %s", file_name);

cleanup:
    fclose(f);
    return rc;
}

int
sr_ly_set_contains(const struct ly_set *set, void *node, bool sorted)
{
    if (NULL == set || NULL == node) {
        return -1;
    }

    if (sorted) {
        int lo = 0, hi = set->number-1, mid = 0;
        while (lo <= hi) {
            mid = lo + ((hi-lo) >> 1);
            if (set->set.g[mid] == node) {
                return mid;
            } else if (set->set.g[mid] < node) {
                lo = mid+1;
            } else {
                hi = mid-1;
            }
        }
        return -1;
    } else {
        return ly_set_contains(set, node);
    }
}

/**
 * @brief Comparison function for ly_set.
 */
static int
sr_ly_set_cmp(const void *item1, const void *item2)
{
    return (*(int **)item1) - (*(int **)item2);
}

int
sr_ly_set_sort(struct ly_set *set)
{
    CHECK_NULL_ARG(set);

    if (set->number <= 16) {
        /* for smaller sets use insertion sort */
        for (int i = 1; i < set->number; ++i) {
            void *key = set->set.g[i];
            int j = i-1;
            while (j >= 0 && set->set.g[j] > key) {
                set->set.g[j+1] = set->set.g[j];
                --j;
            }
            set->set.g[j+1] = key;
        }
    } else {
        qsort(set->set.g, set->number, sizeof(void *), sr_ly_set_cmp);
    }

    return SR_ERR_OK;
}

bool
sr_lys_data_node(struct lys_node *node)
{
    if (NULL == node) {
        return false;
    }

    return node->nodetype & (LYS_CONTAINER | LYS_LEAF | LYS_LEAFLIST | LYS_LIST |
                             LYS_ANYXML | LYS_NOTIF | LYS_RPC | LYS_ACTION | LYS_ANYDATA);
}

struct lys_node *
sr_lys_node_get_data_parent(struct lys_node *node, bool augment)
{
    node = node ? node->parent : NULL;

    while (node && !sr_lys_data_node(node) &&
            (!augment || LYS_AUGMENT != node->nodetype)) {
        if (LYS_AUGMENT == node->nodetype) {
            node = ((struct lys_node_augment *)node)->target;
        } else {
            node = node->parent;
        }
    }

    return node;
}

struct lyd_node *
sr_lyd_parse_fd(struct ly_ctx *ctx, int fd, LYD_FORMAT format, int options)
{
    struct lyd_node *node;
    ssize_t ret;
    char c;

    node = lyd_parse_fd(ctx, fd, format, options);
    if (!node) {
        /* we will attempt to load the file in different format and then convert it based on the first character */
        ret = read(fd, &c, 1);
        if (ret < 1) {
            return NULL;
        } else {
            lseek(fd, 0, SEEK_SET);
        }

        switch (c) {
        case '<':
            /* XML */
            if (format == LYD_XML) {
                return NULL;
            }

            SR_LOG_WRN("Attempting data file conversion from \"xml\" to \"%s\".", SR_FILE_FORMAT_EXT);
            node = lyd_parse_fd(ctx, fd, LYD_XML, options);
            break;
        case '{':
            /* JSON */
            if (format == LYD_JSON) {
                return NULL;
            }

            SR_LOG_WRN("Attempting data file conversion from \"json\" to \"%s\".", SR_FILE_FORMAT_EXT);
            node = lyd_parse_fd(ctx, fd, LYD_JSON, options);
            break;
        case 'l':
            /* LYB */
            if (format == LYD_LYB) {
                return NULL;
            }

            SR_LOG_WRN("Attempting data file conversion from \"lyb\" to \"%s\".", SR_FILE_FORMAT_EXT);
            node = lyd_parse_fd(ctx, fd, LYD_LYB, options);
            break;
        default:
            return NULL;
        }

        if (!node) {
            return NULL;
        }

        /* now store it in the new format */
        if ((ftruncate(fd, 0) == -1) || (lseek(fd, 0, SEEK_SET) == -1)) {
            SR_LOG_ERR("Preparing conversion data fd failed (%s).", strerror(errno));
        } else if (lyd_print_fd(fd, node, format, LYP_WITHSIBLINGS | LYP_FORMAT)) {
            SR_LOG_ERR_MSG("Storing the converted data file failed.");
        }
    }

    return node;
}

struct lyd_node*
sr_dup_datatree(struct lyd_node *root) {
    struct lyd_node *dup = NULL, *s = NULL, *n = NULL;

    struct lyd_node *next = NULL;
    /* loop through top-level nodes*/
    while (NULL != root) {
        next = root->next;

        n = lyd_dup(root, 1);
        /*set output node*/
        if (NULL == dup){
            dup = n;
        }

        if (NULL == s){
            s = n;
        }
        else if (0 != lyd_insert_after(s, n)){
            SR_LOG_ERR_MSG("Memory allocation failed");
            lyd_free_withsiblings(dup);
            return NULL;
        }
        /* last appended sibling*/
        s = n;

        root = next;
    }
    return dup;
}

struct lyd_node*
sr_dup_datatree_to_ctx(struct lyd_node *root, struct ly_ctx *ctx) {
    struct lyd_node *dup = NULL;

    while (NULL != root) {
        /* dup the first one, rest should be done by one merge */
        if (NULL == dup){
            dup = lyd_dup_to_ctx(root, 1, ctx);
        } else {
            lyd_merge_to_ctx(&dup, root, LYD_OPT_EXPLICIT, ctx);
            break;
        }

        root = root->next;
    }
    return dup;
}

int
sr_lyd_unlink(dm_data_info_t *data_info, struct lyd_node *node)
{
    CHECK_NULL_ARG2(data_info, node);
    if (node == data_info->node){
        data_info->node = node->next;
    }
    if (0 != lyd_unlink(node)){
        SR_LOG_ERR_MSG("Node unlink failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

int
sr_lyd_insert_before(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node)
{
    CHECK_NULL_ARG3(data_info, sibling, node);

    int rc = lyd_insert_before(sibling, node);
    if (data_info->node == sibling) {
        data_info->node = node;
    }

    return rc;
}

int
sr_lyd_insert_after(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node)
{
    CHECK_NULL_ARG2(data_info, node);

    if (NULL == sibling && NULL == data_info->node && NULL == node->schema->parent) {
        /* adding top-level-node to empty tree */
        data_info->node = node;
        return SR_ERR_OK;
    }
    CHECK_NULL_ARG(sibling);

    int rc = lyd_insert_after(sibling, node);
    if (data_info->node == node) {
        data_info->node = sibling;
    }

    return rc;
}

static sr_type_t
sr_ly_data_type_to_sr(LY_DATA_TYPE type)
{
    switch(type){
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_LEAF_REF
            //LY_DERIVED
            //LY_TYPE_UNION
        }
}

static sr_type_t
sr_libyang_leaf_get_type_sch(const struct lys_node_leaf *leaf)
{
    if (NULL == leaf || !((LYS_LEAF | LYS_LEAFLIST) & leaf->nodetype)) {
        return SR_UNKNOWN_T;
    }

    switch(leaf->type.base){
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_LEAFREF:
            return sr_libyang_leaf_get_type_sch(leaf->type.info.lref.target);
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_DERIVED
        }
}

sr_type_t
sr_libyang_leaf_get_type(const struct lyd_node_leaf_list *leaf)
{
    switch(leaf->value_type) {
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_LEAFREF:
            /* if the target leafref was disconnected there is a problem in case the leaf is actually a union */
            if ((struct lyd_node_leaf_list *)leaf->value.leafref) {
                return sr_libyang_leaf_get_type((struct lyd_node_leaf_list *)leaf->value.leafref);
            } else {
                return sr_libyang_leaf_get_type_sch(((struct lys_node_leaf *)leaf->schema)->type.info.lref.target);
            }
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_DERIVED
        }
}

int
sr_check_value_conform_to_schema(const struct lys_node *node, const sr_val_t *value)
{
    CHECK_NULL_ARG2(node, value);

    struct lys_node_leaf *leafref = NULL;
    sr_list_t *union_list = NULL;
    sr_type_t type = SR_UNKNOWN_T;
    int rc = SR_ERR_OK;
    if (LYS_CONTAINER & node->nodetype) {
        struct lys_node_container *cont = (struct lys_node_container *) node;
        type = cont->presence != NULL ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
    } else if (LYS_LIST & node->nodetype) {
        type = SR_LIST_T;
    } else if ((LYS_LEAF | LYS_LEAFLIST) & node->nodetype) {
        struct lys_node_leaf *l = (struct lys_node_leaf *) node;
        struct lys_type *actual_type = &l->type;
        switch(actual_type->base){
        case LY_TYPE_BINARY:
            type = SR_BINARY_T;
            break;
        case LY_TYPE_BITS:
            type = SR_BITS_T;
            break;
        case LY_TYPE_BOOL:
            type = SR_BOOL_T;
            break;
        case LY_TYPE_DEC64:
            type = SR_DECIMAL64_T;
            break;
        case LY_TYPE_EMPTY:
            type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            type = SR_ENUM_T;
            break;
        case LY_TYPE_IDENT:
            type = SR_IDENTITYREF_T;
            break;
        case LY_TYPE_INST:
            type = SR_INSTANCEID_T;
            break;
        case LY_TYPE_LEAFREF:
            leafref = actual_type->info.lref.target;
            if (NULL != leafref && ((LYS_LEAF | LYS_LEAFLIST) & leafref->nodetype)) {
                return sr_check_value_conform_to_schema((const struct lys_node *)leafref, value);
            }
            break;
        case LY_TYPE_STRING:
            type = SR_STRING_T;
            break;
        case LY_TYPE_UNION:
            /* find the type in typedefs */
            rc = sr_list_init(&union_list);
            CHECK_RC_MSG_RETURN(rc, "List init failed");

            rc = sr_list_add(union_list, actual_type);
            CHECK_RC_MSG_GOTO(rc, matching_done, "List add failed");

            while (union_list->count > 0) {
                actual_type = (struct lys_type *) union_list->data[0];
                while (0 == actual_type->info.uni.count) {
                   actual_type = &actual_type->der->type;
                }
                for (int i = 0; i < actual_type->info.uni.count; i++) {
                    type = sr_ly_data_type_to_sr(actual_type->info.uni.types[i].base);
                    if (LY_TYPE_LEAFREF == actual_type->info.uni.types[i].base) {
                        leafref = actual_type->info.uni.types[i].info.lref.target;
                        if (SR_ERR_OK == sr_check_value_conform_to_schema((const struct lys_node *)leafref, value)) {
                            sr_list_cleanup(union_list);
                            return SR_ERR_OK;
                        }
                    } else if (LY_TYPE_UNION == actual_type->info.uni.types[i].base) {
                        rc = sr_list_add(union_list, &actual_type->info.uni.types[i]);
                        CHECK_RC_MSG_GOTO(rc, matching_done, "List add failed");
                    } else if (value->type == type) {
                        goto matching_done;
                    }
                }
                sr_list_rm_at(union_list, 0);
            }
            break;
        case LY_TYPE_INT8:
            type = SR_INT8_T;
            break;
        case LY_TYPE_UINT8:
            type = SR_UINT8_T;
            break;
        case LY_TYPE_INT16:
            type = SR_INT16_T;
            break;
        case LY_TYPE_UINT16:
            type = SR_UINT16_T;
            break;
        case LY_TYPE_INT32:
            type = SR_INT32_T;
            break;
        case LY_TYPE_UINT32:
            type = SR_UINT32_T;
            break;
        case LY_TYPE_INT64:
            type = SR_INT64_T;
            break;
        case LY_TYPE_UINT64:
            type = SR_UINT64_T;
            break;
        default:
            type = SR_UNKNOWN_T;
            //LY_DERIVED
        }
    } else if (LYS_ANYXML == node->nodetype) {  /* cannot use bitwise or, since LYS_ANYXML is sub-type of LYS_ANYDATA */
        type = SR_ANYXML_T;
    } else if (LYS_ANYDATA & node->nodetype) {
        type = SR_ANYDATA_T;
    }
matching_done:
    if (type != value->type) {
        SR_LOG_ERR("Value doesn't conform to schema expected %d instead of %d", type, value->type);
    }
    sr_list_cleanup(union_list);
    return type == value->type ? SR_ERR_OK : SR_ERR_INVAL_ARG;
}

static int
sr_libyang_val_str_to_sr_val(const char *val_str, sr_type_t type, sr_val_t *value)
{
    CHECK_NULL_ARG2(val_str, value);
    int ret = 0;

    switch (type) {
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_STRING_T:
    case SR_ANYXML_T:
    case SR_ANYDATA_T:
        sr_mem_edit_string(value->_sr_mem, &value->data.string_val, val_str);
        CHECK_NULL_NOMEM_RETURN(value->data.string_val);
        return SR_ERR_OK;
    case SR_BOOL_T:
        value->data.bool_val = 0 == strcmp("true", val_str);
        return SR_ERR_OK;
    case SR_UINT8_T:
        ret = sscanf(val_str, "%"SCNu8, &value->data.uint8_val);
        break;
    case SR_UINT16_T:
        ret = sscanf(val_str, "%"SCNu16, &value->data.uint16_val);
        break;
    case SR_UINT32_T:
        ret = sscanf(val_str, "%"SCNu32, &value->data.uint32_val);
        break;
    case SR_UINT64_T:
        ret = sscanf(val_str, "%"SCNu64, &value->data.uint64_val);
        break;
    case SR_INT8_T:
        ret = sscanf(val_str, "%"SCNd8, &value->data.int8_val);
        break;
    case SR_INT16_T:
        ret = sscanf(val_str, "%"SCNd16, &value->data.int16_val);
        break;
    case SR_INT32_T:
        ret = sscanf(val_str, "%"SCNd32, &value->data.int32_val);
        break;
    case SR_INT64_T:
        ret = sscanf(val_str, "%"SCNd64, &value->data.int64_val);
        break;
    case SR_DECIMAL64_T:
        ret = sscanf(val_str, "%lf", &value->data.decimal64_val);
        break;
    default:
        SR_LOG_ERR_MSG("Unknown type to convert");
        return SR_ERR_INVAL_ARG;
    }

    return ret == 1 ? SR_ERR_OK : SR_ERR_INTERNAL;
}

/**
 * @brief Get pointer to the first type-info matching the given type in the DFS order,
 *        starting from base_info as the root node.
 */
static struct lys_type *
sr_libyang_get_actual_leaf_type(struct lys_type *base_info, LY_DATA_TYPE type)
{
    struct lys_type *actual_info = NULL;

    if (base_info->base == type) {
        return base_info;
    }
    if (LY_TYPE_LEAFREF == base_info->base) {
        if (NULL != base_info->info.lref.target) {
            return sr_libyang_get_actual_leaf_type(&base_info->info.lref.target->type, type);
        }
    }
    if (LY_TYPE_UNION == base_info->base) {
        while (0 == base_info->info.uni.count) {
            base_info = &base_info->der->type;
        }
        for (int i = 0; i < base_info->info.uni.count; ++i) {
            actual_info = sr_libyang_get_actual_leaf_type(&base_info->info.uni.types[i], type);
            if (NULL != actual_info) {
                return actual_info;
            }
        }
    }
    return NULL;
}

int
sr_libyang_leaf_copy_value(const struct lyd_node_leaf_list *leaf, sr_val_t *value)
{
    CHECK_NULL_ARG2(leaf, value);
    int rc = SR_ERR_OK;
    struct lys_type *actual_type = NULL;
    LY_DATA_TYPE type = leaf->value_type;
    const char *node_name = "(unknown)";
    if (NULL != leaf->schema && NULL != leaf->schema->name) {
        node_name = leaf->schema->name;
    }

    switch (type) {
    case LY_TYPE_BINARY:
        if (NULL == leaf->value.binary) {
            SR_LOG_ERR("Binary data in leaf '%s' is NULL", node_name);
            return SR_ERR_INTERNAL;
        }
        sr_mem_edit_string(value->_sr_mem, &value->data.binary_val, leaf->value.binary);
        if (NULL == value->data.binary_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'binary'", node_name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_BITS:
        if (NULL != leaf->value_str) {
            sr_mem_edit_string(value->_sr_mem, &value->data.bits_val, leaf->value_str);
            if (NULL == value->data.bits_val) {
                SR_LOG_ERR_MSG("Bits duplication failed");
                return SR_ERR_NOMEM;
            }
        }
        return rc;
    case LY_TYPE_BOOL:
        value->data.bool_val = leaf->value.bln;
        return SR_ERR_OK;
    case LY_TYPE_DEC64:
        CHECK_NULL_ARG(leaf->schema);
        value->data.decimal64_val = (double) leaf->value.dec64;
        actual_type = sr_libyang_get_actual_leaf_type(&((struct lys_node_leaf *)leaf->schema)->type, LY_TYPE_DEC64);
        if (NULL == actual_type) {
            SR_LOG_ERR("Missing schema information for node '%s'", node_name);
            return SR_ERR_INTERNAL;
        }
        for (size_t i = 0; i < actual_type->info.dec64.dig; i++) {
            /* shift decimal point*/
            value->data.decimal64_val *= 0.1;
        }
        return SR_ERR_OK;
    case LY_TYPE_EMPTY:
        return SR_ERR_OK;
    case LY_TYPE_ENUM:
        if (NULL == leaf->value.enm || NULL == leaf->value.enm->name) {
            SR_LOG_ERR("Missing schema information for node '%s'", node_name);
            return SR_ERR_INTERNAL;
        }
        sr_mem_edit_string(value->_sr_mem, &value->data.enum_val, leaf->value.enm->name);
        if (NULL == value->data.enum_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'enum'", node_name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_IDENT:
        if (NULL == leaf->value_str) {
            SR_LOG_ERR("Identity ref or schema in leaf '%s' is NULL", node_name);
            return SR_ERR_INTERNAL;
        }

        sr_mem_edit_string(value->_sr_mem, &value->data.identityref_val, leaf->value_str);
        if (NULL == value->data.identityref_val) {
            SR_LOG_ERR_MSG("Identityref duplication failed");
            return SR_ERR_NOMEM;
        }

        return SR_ERR_OK;
    case LY_TYPE_INST:
        return sr_libyang_val_str_to_sr_val(leaf->value_str, value->type, value);
    case LY_TYPE_LEAFREF:
        return sr_libyang_val_str_to_sr_val(leaf->value_str, value->type, value);
    case LY_TYPE_STRING:
        if (NULL != leaf->value.string) {
            sr_mem_edit_string(value->_sr_mem, &value->data.string_val, leaf->value.string);
            if (NULL == value->data.string_val) {
                SR_LOG_ERR_MSG("String duplication failed");
                return SR_ERR_NOMEM;
            }
        }
        return SR_ERR_OK;
    case LY_TYPE_UNION:
        /* Copy of selected union type should be called instead */
        SR_LOG_ERR("Can not copy value of union '%s'", node_name);
        return SR_ERR_INTERNAL;
    case LY_TYPE_INT8:
        value->data.int8_val = leaf->value.int8;
        return SR_ERR_OK;
    case LY_TYPE_UINT8:
        value->data.uint8_val = leaf->value.uint8;
        return SR_ERR_OK;
    case LY_TYPE_INT16:
        value->data.int16_val = leaf->value.int16;
        return SR_ERR_OK;
    case LY_TYPE_UINT16:
        value->data.uint16_val = leaf->value.uint16;
        return SR_ERR_OK;
    case LY_TYPE_INT32:
        value->data.int32_val = leaf->value.int32;
        return SR_ERR_OK;
    case LY_TYPE_UINT32:
        value->data.uint32_val = leaf->value.uint32;
        return SR_ERR_OK;
    case LY_TYPE_INT64:
        value->data.int64_val = leaf->value.int64;
        return SR_ERR_OK;
    case LY_TYPE_UINT64:
        value->data.uint64_val = leaf->value.uint64;
        return SR_ERR_OK;
    default:
        SR_LOG_ERR("Copy value failed for leaf '%s'", node_name);
        return SR_ERR_INTERNAL;
    }
}

int
sr_libyang_anydata_copy_value(const struct lyd_node_anydata *node, sr_val_t *value)
{
    CHECK_NULL_ARG2(node, value);
    char *str_val = NULL;
    bool free_str = false;
    const char *node_name = "(unknown)";
    if (NULL != node->schema && NULL != node->schema->name) {
        node_name = node->schema->name;
    }

    switch (node->value_type) {
    case LYD_ANYDATA_CONSTSTRING:
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_JSON:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_SXML:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_LYBD:
    case LYD_ANYDATA_LYB:
        str_val = (char *)node->value.str;
        break;
    case LYD_ANYDATA_XML:
        lyxml_print_mem(&str_val, node->value.xml, LYXML_PRINT_FORMAT);
        free_str = true;
        break;
    case LYD_ANYDATA_DATATREE:
        lyd_print_mem(&str_val, node->value.tree, LYD_JSON, LYP_FORMAT | LYP_WITHSIBLINGS);
        free_str = true;
        break;
    }

    if ((NULL != node->schema) && (NULL != str_val)) {
        switch (node->schema->nodetype) {
            case LYS_ANYXML:
                sr_mem_edit_string(value->_sr_mem, &value->data.anyxml_val, node->value.str);
                if (NULL == value->data.anyxml_val) {
                    SR_LOG_ERR_MSG("String duplication failed");
                    if (free_str) {
                        free(str_val);
                    }
                    return SR_ERR_NOMEM;
                }
                break;
            case LYS_ANYDATA:
                sr_mem_edit_string(value->_sr_mem, &value->data.anydata_val, node->value.str);
                if (NULL == value->data.anydata_val) {
                    SR_LOG_ERR_MSG("String duplication failed");
                    if (free_str) {
                        free(str_val);
                    }
                    return SR_ERR_NOMEM;
                }
                break;
            default:
                SR_LOG_ERR("Copy value failed for anydata node '%s'", node_name);
                if (free_str) {
                    free(str_val);
                }
                return SR_ERR_INTERNAL;
        }
    }

    if (free_str) {
        free(str_val);
    }
    return SR_ERR_OK;
}

/** max dec64 format string length */
#define MAX_FMT_LEN 7

static int
sr_dec64_to_str(double val, const struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG2(schema_node, out);
    size_t fraction_digits = 0;
    if (LYS_LEAF == schema_node->nodetype || LYS_LEAFLIST == schema_node->nodetype) {
        struct lys_node_leaflist *l = (struct lys_node_leaflist *) schema_node;
        struct lys_type *actual_type = sr_libyang_get_actual_leaf_type(&l->type, LY_TYPE_DEC64);
        if (NULL == actual_type) {
            SR_LOG_ERR("Missing schema information for node '%s'", schema_node->name);
            return SR_ERR_INTERNAL;
        }
        fraction_digits = actual_type->info.dec64.dig;
    } else {
        SR_LOG_ERR_MSG("Node must be either leaf or leaflist");
        return SR_ERR_INVAL_ARG;
    }
    /* format string for double string conversion "%.XXf", where XX is corresponding number of fraction digits 1-18 */
    char format_string [MAX_FMT_LEN] = {0,};
    snprintf(format_string, MAX_FMT_LEN, "%%.%zuf", fraction_digits);

    return sr_asprintf(out, format_string, val);
}

int
sr_val_to_str_with_schema(const sr_val_t *value, const struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG3(value, schema_node, out);
    int rc = SR_ERR_OK;
    rc = sr_check_value_conform_to_schema(schema_node, value);
    CHECK_RC_LOG_RETURN(rc, "Value doesn't conform to schema node %s", schema_node->name);

    switch (value->type) {
    case SR_BINARY_T:
        if (NULL != value->data.binary_val) {
            *out = strdup(value->data.binary_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        }
        break;
    case SR_BITS_T:
        if (NULL != value->data.bits_val) {
            *out = strdup(value->data.bits_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        }
        break;
    case SR_BOOL_T:
        *out = value->data.bool_val ? strdup("true") : strdup("false");
        CHECK_NULL_NOMEM_RETURN(*out);
        break;
    case SR_DECIMAL64_T:
        return sr_dec64_to_str(value->data.decimal64_val, schema_node, out);
    case SR_ENUM_T:
        if (NULL != value->data.enum_val) {
            *out = strdup(value->data.enum_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        }
        break;
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        *out = strdup("");
        CHECK_NULL_NOMEM_RETURN(*out);
        break;
    case SR_IDENTITYREF_T:
        if (NULL != value->data.identityref_val) {
            *out = strdup(value->data.identityref_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        }
        break;
    case SR_INSTANCEID_T:
        if (NULL != value->data.instanceid_val) {
            *out = strdup(value->data.instanceid_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        }
        break;
    case SR_INT8_T:
        rc = sr_asprintf(out, "%"PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        rc = sr_asprintf(out, "%"PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        rc = sr_asprintf(out, "%"PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        rc = sr_asprintf(out, "%"PRId64, value->data.int64_val);
        break;
    case SR_STRING_T:
        if (NULL != value->data.string_val){
            *out = strdup(value->data.string_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        } else {
            *out = NULL;
            return SR_ERR_OK;
        }
        break;
    case SR_UINT8_T:
        rc = sr_asprintf(out, "%"PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        rc = sr_asprintf(out, "%"PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        rc = sr_asprintf(out, "%"PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        rc = sr_asprintf(out, "%"PRIu64, value->data.uint64_val);
        break;
    case SR_ANYXML_T:
        if (NULL != value->data.anyxml_val){
            *out = strdup(value->data.anyxml_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        } else {
            *out = NULL;
            return SR_ERR_OK;
        }
        break;
    case SR_ANYDATA_T:
        if (NULL != value->data.anydata_val){
            *out = strdup(value->data.anydata_val);
            CHECK_NULL_NOMEM_RETURN(*out);
        } else {
            *out = NULL;
            return SR_ERR_OK;
        }
        break;
    default:
        SR_LOG_ERR_MSG("Conversion of value_t to string failed");
        *out = NULL;
    }
    return rc;
}

bool
sr_is_key_node(const struct lys_node *node)
{
    if (NULL == node) {
        return false;
    }

    const struct lys_node *parent = NULL;
    for (parent = lys_parent(node); parent && (parent->nodetype == LYS_USES); parent = lys_parent(parent));
    if (NULL == parent || LYS_LIST != parent->nodetype) {
        return false;
    }

    struct lys_node_list *list  = (struct lys_node_list *) parent;
    for (uint8_t i = 0;  i < list->keys_size; i++) {
        if (node == (struct lys_node *)list->keys[i]) {
            return true;
        }
    }
    return false;
}

char *
sr_api_variant_to_str(sr_api_variant_t api_variant)
{
    switch (api_variant) {
        case SR_API_VALUES:
            return "values";
        case SR_API_TREES:
            return "trees";
        default:
            return "values";
    }
}

sr_api_variant_t
sr_api_variant_from_str(const char *api_variant_str)
{
    if (0 == strcmp("trees", api_variant_str)) {
        return SR_API_TREES;
    }

    /* SR_API_VALUES is default */
    return SR_API_VALUES;
}

/**
 * @brief Copy and convert content of a libyang node and its descendands into a sysrepo tree.
 *
 * @param [in] top_parent Top-level parent node.
 * @param [in] node libyang node.
 * @param [in] depth Depth of the node relative to the root node.
 * @param [in] slice_offset Number of child nodes of the chunk root to skip.
 * @param [in] slice_width Maximum number of child nodes of the chunk root to include.
 * @param [in] child_limit Limit on the number of copied children imposed on each node starting from 3rd level.
 * @param [in] depth_limit Maximum number of tree levels to copy.
 * @param [out] sr_tree Returned sysrepo tree.
 */
static int
sr_copy_node_to_tree_internal(const struct lyd_node *top_parent, const struct lyd_node *node, size_t depth,
         size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit,
         sr_tree_pruning_cb pruning_cb, void *pruning_ctx, sr_node_t *sr_tree)
{
    int rc = SR_ERR_OK;
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lys_node_container *cont = NULL;
    struct lyd_node_anydata *sch_any = NULL;
    const struct lyd_node *child = NULL;
    size_t idx = 0;
    bool prune = false;
    sr_node_t *sr_subtree = NULL;

    CHECK_NULL_ARG2(node, sr_tree);

    /* copy node name */
    rc = sr_node_set_name(sr_tree, node->schema->name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set sysrepo node name");

    /* copy value and type */
    switch (node->schema->nodetype) {
        case LYS_LEAF:
        case LYS_LEAFLIST:
            data_leaf = (struct lyd_node_leaf_list *)node;
            sr_tree->type = sr_libyang_leaf_get_type(data_leaf);
            rc = sr_libyang_leaf_copy_value(data_leaf, (sr_val_t *)sr_tree);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Error returned from sr_libyang_leaf_copy_value: %s.", sr_strerror(rc));
            break;
        case LYS_CONTAINER:
            cont = (struct lys_node_container *)node->schema;
            sr_tree->type = cont->presence != NULL ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
            break;
        case LYS_LIST:
            sr_tree->type = SR_LIST_T;
            break;
        case LYS_NOTIF:
            sr_tree->type = SR_NOTIFICATION_T;
            break;
        case LYS_ANYXML:
        case LYS_ANYDATA:
            sch_any = (struct lyd_node_anydata *) node;
            sr_tree->type = (LYS_ANYXML == node->schema->nodetype) ? SR_ANYXML_T : SR_ANYDATA_T;
            rc = sr_libyang_anydata_copy_value(sch_any, (sr_val_t *)sr_tree);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Error returned from sr_libyang_anydata_copy_value: %s.", sr_strerror(rc));
            break;
        default:
            SR_LOG_ERR("Detected unsupported node data type (schema name: %s).", sr_tree->name);
            rc = SR_ERR_UNSUPPORTED;
            goto cleanup;
    }

    /* dflt flag */
    sr_tree->dflt = node->dflt;

    /* set module_name */
    if (NULL == top_parent || lyd_node_module(top_parent) != lyd_node_module(node)) {
        rc = sr_node_set_module(sr_tree, lyd_node_module(node)->name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set module of a sysrepo node.");
    }

    /* copy children */
    if ((LYS_CONTAINER | LYS_LIST) & node->schema->nodetype) {
        child = node->child;
        idx = 0;
        while (child) {
            if ((0 < depth || slice_offset <= idx) /* slice_offset */ &&
                (0 < depth || slice_width > idx - slice_offset) /* slice width */ &&
                (0 == depth || child_limit > idx) /* child_limit */ &&
                (depth_limit > depth + 1) /* depth limit */) {
                prune = false;
                if (NULL != pruning_cb) {
                    rc = pruning_cb(pruning_ctx, child, &prune);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Tree pruning has failed.");
                }
                if (true == prune) {
                    child = child->next;
                    continue;
                }
                rc = sr_node_add_child(sr_tree, NULL, NULL, &sr_subtree);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                rc = sr_copy_node_to_tree_internal(top_parent ? top_parent : node, child, depth + 1, slice_offset, slice_width,
                        child_limit, depth_limit, pruning_cb, pruning_ctx, sr_subtree);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
            child = child->next;
            ++idx;
        }
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_tree_content(sr_tree);
    }
    return rc;
}

int
sr_copy_node_to_tree(const struct lyd_node *node, sr_tree_pruning_cb pruning_cb, void *pruning_ctx, sr_node_t *sr_tree)
{
    return sr_copy_node_to_tree_internal(NULL, node, 0, 0, SIZE_MAX, SIZE_MAX, SIZE_MAX, pruning_cb, pruning_ctx, sr_tree);
}

int
sr_copy_node_to_tree_chunk(const struct lyd_node *node, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_tree_pruning_cb pruning_cb, void *pruning_ctx, sr_node_t *sr_tree)
{
    return sr_copy_node_to_tree_internal(NULL, node, 0, slice_offset, slice_width, child_limit, depth_limit,
            pruning_cb, pruning_ctx, sr_tree);
}

int
sr_nodes_to_trees(struct ly_set *nodes, sr_mem_ctx_t *sr_mem, sr_tree_pruning_cb pruning_cb, void *pruning_ctx,
        sr_node_t **sr_trees, size_t *count)
{
    return sr_nodes_to_tree_chunks(nodes, 0, SIZE_MAX, SIZE_MAX, SIZE_MAX, sr_mem, pruning_cb, pruning_ctx,
            sr_trees, count, NULL);
}

int
sr_nodes_to_tree_chunks(struct ly_set *nodes, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_mem_ctx_t *sr_mem, sr_tree_pruning_cb pruning_cb, void *pruning_ctx,
        sr_node_t **sr_trees, size_t *count, char ***chunk_ids_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL;
    size_t tree_cnt = 0;
    sr_mem_snapshot_t snapshot = { 0, };
    sr_bitset_t *pruned = NULL;
    bool prune = false;
    size_t i = 0, j = 0;
    char **chunk_ids = NULL;
    char *chunk_id = NULL;

    CHECK_NULL_ARG3(nodes, sr_trees, count);

    if (0 == nodes->number) {
        *sr_trees = NULL;
        *count = 0;
        return rc;
    }

    if (sr_mem) {
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    /* find out which trees should be completely pruned away and which should not */
    if (NULL != pruning_cb) {
        rc = sr_bitset_init(nodes->number, &pruned);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize bitset.");
        for (i = 0; i < nodes->number; ++i) {
            rc = pruning_cb(pruning_ctx, nodes->set.d[i], &prune);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Tree pruning has failed.");
            rc = sr_bitset_set(pruned, i, prune);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enable bit in a bitset.");
            tree_cnt += !prune;
        }
    } else {
        tree_cnt = nodes->number;
    }

    if (0 == tree_cnt) {
        goto cleanup;
    }

    if (NULL != chunk_ids_p) {
        chunk_ids = sr_calloc(sr_mem, tree_cnt, sizeof(char *));
        CHECK_NULL_NOMEM_GOTO(chunk_ids, rc, cleanup);
        for (i = j = 0; i < nodes->number; ++i) {
            prune = false;
            if (NULL != pruned) {
                rc = sr_bitset_get(pruned, i, &prune);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get value of a bit in a bitset.");
            }
            if (prune) {
                continue;
            }
            chunk_id = lyd_path(nodes->set.d[i]);
            if (NULL == chunk_id) {
                SR_LOG_ERR_MSG("Failed to get ID of a subtree chunk.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            rc = sr_mem_edit_string(sr_mem, chunk_ids+j, chunk_id);
            free(chunk_id);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Failed to store ID of a subtree chunk.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            ++j;
        }
    }

    trees = sr_calloc(sr_mem, tree_cnt, sizeof *trees);
    CHECK_NULL_NOMEM_GOTO(trees, rc, cleanup);
    if (sr_mem) {
        ATOMIC_INC(&sr_mem->obj_count);
    }

    for (i = j = 0; i < nodes->number && 0 == rc; ++i) {
        prune = false;
        if (NULL != pruned) {
            rc = sr_bitset_get(pruned, i, &prune);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get value of a bit in a bitset.");
        }
        if (prune) {
            continue;
        }
        trees[j]._sr_mem = sr_mem;
        rc = sr_copy_node_to_tree_internal(NULL, nodes->set.d[i], 0, slice_offset, slice_width, child_limit,
                depth_limit, pruning_cb, pruning_ctx, trees + j);
        ++j;
    }

cleanup:
    sr_bitset_cleanup(pruned);
    if (SR_ERR_OK == rc) {
        *sr_trees = trees;
        *count = tree_cnt;
        if (NULL != chunk_ids_p) {
            *chunk_ids_p = chunk_ids;
        }
    } else {
        if (sr_mem) {
            sr_mem_restore(&snapshot);
        } else {
            for (size_t i = 0; NULL != chunk_ids && i < tree_cnt; ++i) {
                free(chunk_ids[i]);
            }
            free(chunk_ids);
            sr_free_trees(trees, tree_cnt);
        }
    }
    return rc;
}

static int
sr_subtree_to_dt(struct ly_ctx *ly_ctx, const sr_node_t *sr_tree, bool output, struct lyd_node *parent,
        const char *xpath, struct lyd_node **data_tree)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    struct ly_set *nodeset = NULL;
    const struct lys_module *module = NULL;
    const struct lys_node *sch_node = NULL;
    sr_node_t *sr_subtree = NULL;
    char *string_val = NULL, *relative_xpath = NULL;

    CHECK_NULL_ARG3(ly_ctx, sr_tree, data_tree);

    if (NULL == parent && NULL == xpath) {
        return SR_ERR_INVAL_ARG;
    }

    if (NULL != parent) {
        /* get module */
        if (NULL != sr_tree->module_name) {
            module = ly_ctx_get_module(ly_ctx, sr_tree->module_name, NULL, 1);
        } else {
            module = lyd_node_module(parent);
        }
    } else {
        char *ns = NULL;
        ret = sr_copy_first_ns(xpath, &ns);
        CHECK_RC_MSG_RETURN(ret, "Copy first ns failed");
        module = ly_ctx_get_module(ly_ctx, ns, NULL, 1);
        free(ns);
    }
    if (NULL == module) {
        SR_LOG_ERR("Failed to obtain module schema for node: %s.", sr_tree->name);
        return SR_ERR_INTERNAL;
    }

    switch (sr_tree->type) {
        case SR_LIST_T:
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
            /* create the inner node in the tree */
            if (NULL == parent) {
                node = lyd_new_path(*data_tree, ly_ctx, xpath, NULL, 0, output ? LYD_PATH_OPT_OUTPUT : 0);
                if (NULL == *data_tree) {
                    *data_tree = node;
                }
                if (NULL == node) {
                    SR_LOG_ERR("Failed to create tree root node with xpath: %s.", xpath);
                    return SR_ERR_INTERNAL;
                }
                node = NULL;
                nodeset = lyd_find_path(*data_tree, xpath);
                if (NULL != nodeset && 1 == nodeset->number) {
                    node = nodeset->set.d[0];
                }
                ly_set_free(nodeset);
                if (NULL == node) {
                    SR_LOG_ERR("Failed to obtain newly created tree root node with xpath: %s.", xpath);
                    return SR_ERR_INTERNAL;
                }
            } else {
                node = lyd_new(parent, module, sr_tree->name);
            }
            /* process children */
            sr_subtree = sr_tree->first_child;
            while  (sr_subtree) {
                ret = sr_subtree_to_dt(ly_ctx, sr_subtree, output, node, NULL, data_tree);
                sr_subtree = sr_subtree->next;
            }
            return ret;

        case SR_UNKNOWN_T:
            SR_LOG_ERR("Detected unsupported node data type (schema name: %s).", sr_tree->name);
            return SR_ERR_UNSUPPORTED;

        default: /* leaf */
            if (sr_tree->dflt) {
                /* skip default value */
                return SR_ERR_OK;
            }
            /* get node schema */
            if (NULL == parent) {
                ret = sr_find_schema_node(module, NULL, xpath, output, &nodeset);
                if (SR_ERR_OK != ret) {
                    SR_LOG_ERR("Failed to evaluate path '%s'.", xpath);
                    return ret;
                }
            } else {
                relative_xpath = calloc(strlen(module->name) + strlen(sr_tree->name) + 2, sizeof(*relative_xpath));
                CHECK_NULL_NOMEM_RETURN(relative_xpath);
                sprintf(relative_xpath, "%s:%s", module->name, sr_tree->name);
                ret = sr_find_schema_node(NULL, parent->schema, relative_xpath, output, &nodeset);
                if (SR_ERR_OK != ret) {
                    SR_LOG_ERR("Failed to evaluate path '%s'.", relative_xpath);
                    free(relative_xpath);
                    return ret;
                }
                free(relative_xpath);
            }
            if (nodeset->number != 1) {
                SR_LOG_ERR("Unable to get the schema node for a sysrepo node ('%s')", sr_tree->name);
                ly_set_free(nodeset);
                return SR_ERR_INTERNAL;
            }
            sch_node = nodeset->set.s[0];
            ly_set_free(nodeset);

            /* copy argument value to string */
            ret = sr_val_to_str_with_schema((sr_val_t *)sr_tree, sch_node, &string_val);
            if (SR_ERR_OK != ret) {
                SR_LOG_ERR("Unable to convert value to string for sysrepo node: %s.", sr_tree->name);
                return ret;
            }
            /* create the leaf in the tree */
            if (NULL == parent) {
                node = lyd_new_path(*data_tree, ly_ctx, xpath, string_val, 0, output ? LYD_PATH_OPT_OUTPUT : 0);
                free(string_val);
                if (NULL == *data_tree) {
                    *data_tree = node;
                }
                if (NULL == node) {
                    SR_LOG_ERR("Failed to create tree root node (leaf) ('%s'): %s", xpath, ly_errmsg(ly_ctx));
                    return SR_ERR_INTERNAL;
                }
            } else {
                node = lyd_new_leaf(parent, module, sr_tree->name, string_val);
                free(string_val);
                if (NULL == node) {
                    SR_LOG_ERR("Unable to add leaf node (named '%s'): %s", sr_tree->name, ly_errmsg(ly_ctx));
                    return SR_ERR_INTERNAL;
                }
            }
            return SR_ERR_OK;
    }
}

int
sr_tree_to_dt(struct ly_ctx *ly_ctx, const sr_node_t *sr_tree, const char *root_xpath, bool output, struct lyd_node **data_tree)
{
    int rc = 0;
    char *xpath = NULL;

    CHECK_NULL_ARG2(ly_ctx, data_tree);

    if (NULL == sr_tree) {
        return SR_ERR_OK;
    }
    if (NULL == root_xpath && NULL == sr_tree->module_name) {
        return SR_ERR_INVAL_ARG;
    }

    if (NULL == root_xpath) {
        xpath = calloc(strlen(sr_tree->name) + strlen(sr_tree->module_name) + 3, sizeof(*xpath));
        CHECK_NULL_NOMEM_RETURN(xpath);
        sprintf(xpath, "/%s:%s", sr_tree->module_name, sr_tree->name);
    }

    rc = sr_subtree_to_dt(ly_ctx, sr_tree, output, NULL, NULL == root_xpath ? xpath : root_xpath, data_tree);
    free(xpath);
    return rc;
}

const char *
sr_ds_to_str(sr_datastore_t ds)
{
    const char *const sr_dslist[] = {
        "startup",    /* SR_DS_STARTUP */
        "running",    /* SR_DS_RUNNING */
        "candidate",  /* SR_DS_CANDIDATE */
    };

    if (ds >= (sizeof(sr_dslist) / (sizeof *sr_dslist))) {
        return "Unknown datastore";
    } else {
        return sr_dslist[ds];
    }
}

void
sr_free_val_content(sr_val_t *value)
{
    if (NULL == value){
        return;
    }
    if (NULL != value->_sr_mem) {
        /* do nothing */
        return;
    }
    free(value->xpath);
    if (SR_BINARY_T == value->type){
        free(value->data.binary_val);
    }
    else if (SR_STRING_T == value->type){
        free(value->data.string_val);
    }
    else if (SR_IDENTITYREF_T == value->type){
        free(value->data.identityref_val);
    }
    else if (SR_ENUM_T == value->type){
        free(value->data.enum_val);
    }
    else if (SR_BINARY_T == value->type){
        free(value->data.binary_val);
    }
    else if (SR_BITS_T == value->type){
        free(value->data.bits_val);
    }
    else if (SR_INSTANCEID_T == value->type){
        free(value->data.instanceid_val);
    }
    else if (SR_ANYXML_T == value->type){
        free(value->data.anyxml_val);
    }
    else if (SR_ANYDATA_T == value->type){
        free(value->data.anydata_val);
    }
    value->xpath = NULL;
    value->data.int64_val = 0;
}

void
sr_free_values_arr(sr_val_t **values, size_t count)
{
    if (NULL != values) {
        for (size_t i = 0; i < count; i++) {
            sr_free_val(values[i]);
        }
        free(values);
    }
}

void
sr_free_values_arr_range(sr_val_t **values, size_t from, size_t to)
{
    if (NULL != values) {
        for (size_t i = from; i < to; i++) {
            sr_free_val(values[i]);
        }
        free(values);
    }
}

void
sr_free_tree_content(sr_node_t *tree)
{
    if (NULL != tree) {
        if (NULL != tree->_sr_mem) {
            /* do nothing */
            return;
        }

        if (SR_TREE_ITERATOR_T == tree->type) {
            assert(0 == tree->data.int32_val);
        } else {
            sr_node_t *sr_subtree = tree->first_child, *next = NULL;
            while (sr_subtree) {
                next = sr_subtree->next;
                sr_free_tree(sr_subtree);
                sr_subtree = next;
            }
        }
        free(tree->module_name);
        sr_free_val_content((sr_val_t *)tree);
    }
}

void
sr_free_node(sr_node_t *node)
{
    if (NULL != node) {
        if (NULL != node->_sr_mem) {
            /* do nothing */
            return;
        }

        if (SR_TREE_ITERATOR_T == node->type) {
            assert(0 == node->data.int32_val);
        }

        free(node->module_name);
        sr_free_val_content((sr_val_t *)node);
        free(node);
    }
}

int
sr_add_error(sr_error_info_t **sr_errors, size_t *sr_error_cnt, const char *xpath,
        const char *msg_fmt, ...)
{
    CHECK_NULL_ARG3(sr_errors, sr_error_cnt, msg_fmt);
    int rc = SR_ERR_OK;
    char *message = NULL;
    char *xpath_dup = NULL;
    sr_error_info_t *tmp_errors = NULL;

    va_list va;
    va_start(va, msg_fmt);

    /* copy xpath */
    if (NULL != xpath) {
        xpath_dup = strdup(xpath);
        CHECK_NULL_NOMEM_GOTO(xpath_dup, rc, cleanup);
    }

    /* construct error message */
    rc = sr_vasprintf(&message, msg_fmt, va);
    CHECK_RC_MSG_GOTO(rc, cleanup, "::sr_vasprintf has failed.");

    /* add error into the array */
    tmp_errors = realloc(*sr_errors, (*sr_error_cnt+1) * sizeof(**sr_errors));
    CHECK_NULL_NOMEM_GOTO(tmp_errors, rc, cleanup);
    *sr_errors = tmp_errors;
    (*sr_errors)[*sr_error_cnt].message = message;
    (*sr_errors)[*sr_error_cnt].xpath = xpath_dup;
    (*sr_error_cnt) += 1;

cleanup:
    if (SR_ERR_OK != rc) {
        free(xpath_dup);
        free(message);
    }
    va_end(va);
    return rc;
}

void
sr_free_errors(sr_error_info_t *errors, size_t error_cnt)
{
    if (NULL != errors) {
        for (size_t i = 0; i < error_cnt; i++) {
            free((void*)errors[i].xpath);
            free((void*)errors[i].message);
        }
        free(errors);
    }
}

void
sr_free_schema(sr_schema_t *schema)
{
    if (NULL != schema) {
        if (schema->_sr_mem) {
            /* do nothing, object counter will be decreased by ::sr_free_schemas */
            return;
        }
        free((void*)schema->module_name);
        free((void*)schema->prefix);
        free((void*)schema->ns);
        free((void*)schema->revision.revision);
        free((void*)schema->revision.file_path_yin);
        free((void*)schema->revision.file_path_yang);
        for (size_t s = 0; s < schema->submodule_count; s++){
            free((void*)schema->submodules[s].submodule_name);
            free((void*)schema->submodules[s].revision.revision);
            free((void*)schema->submodules[s].revision.file_path_yin);
            free((void*)schema->submodules[s].revision.file_path_yang);
        }
        free(schema->submodules);
        for (size_t f = 0; f < schema->enabled_feature_cnt; f++) {
            free(schema->enabled_features[f]);
        }
        free(schema->enabled_features);
    }
}

void
sr_free_changes(sr_change_t *changes, size_t count)
{
    if (NULL != changes) {
        for (size_t i = 0; i < count; i++) {
            sr_free_val(changes[i].old_value);
            sr_free_val(changes[i].new_value);
        }
        free(changes);
    }
}

/**
 * @brief Signal handler used to deliver initialization result from daemon
 * child to daemon parent process, so that the parent can exit with appropriate exit code.
 */
static void
sr_daemon_child_status_handler(int signum)
{
    switch(signum) {
        case SIGUSR1:
            /* child process has initialized successfully */
            exit(EXIT_SUCCESS);
            break;
        case SIGALRM:
            /* child process has not initialized within SR_CHILD_INIT_TIMEOUT seconds */
            fprintf(stderr, "Sysrepo daemon did not initialize within the timeout period, "
                    "check syslog for more info.\n");
            exit(EXIT_FAILURE);
            break;
        case SIGCHLD:
            /* child process has terminated */
            fprintf(stderr, "Failure by initialization of sysrepo daemon, check syslog for more info.\n");
            exit(EXIT_FAILURE);
            break;
    }
}

/**
 * @brief Maintains only single instance of a daemon by opening and locking the PID file.
 */
static void
sr_daemon_check_single_instance(const char *pid_file, int *pid_file_fd)
{
    char str[NAME_MAX] = { 0 };
    int ret = 0;

    CHECK_NULL_ARG_VOID2(pid_file, pid_file_fd);

    /* open PID file */
    *pid_file_fd = open(pid_file, O_RDWR | O_CREAT, 0640);
    if (*pid_file_fd < 0) {
        SR_LOG_ERR("Unable to open sysrepo PID file '%s': %s.", pid_file, sr_strerror_safe(errno));
        exit(EXIT_FAILURE);
    }

    /* acquire lock on the PID file */
    if (lockf(*pid_file_fd, F_TLOCK, 0) < 0) {
        if (EACCES == errno || EAGAIN == errno) {
            SR_LOG_ERR_MSG("Another instance of sysrepo daemon is running, unable to start.");
        } else {
            SR_LOG_ERR("Unable to lock sysrepo PID file '%s': %s.", pid_file, sr_strerror_safe(errno));
        }
        exit(EXIT_FAILURE);
    }

    /* write PID into the PID file */
    snprintf(str, NAME_MAX, "%d\n", getpid());
    ret = write(*pid_file_fd, str, strlen(str));
    if (-1 == ret) {
        SR_LOG_ERR("Unable to write into sysrepo PID file '%s': %s.", pid_file, sr_strerror_safe(errno));
        exit(EXIT_FAILURE);
    }

    /* do not close nor unlock the PID file, keep it open while the daemon is alive */
}

/**
 * @brief Ignores certain signals that sysrepo daemon should not care of.
 */
static void
sr_daemon_ignore_signals()
{
    signal(SIGCHLD, SIG_DFL);  /* do not ignore, use default handler to keep e.g. waitpid() working */
    signal(SIGUSR1, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);  /* keyboard stop */
    signal(SIGTTIN, SIG_IGN);  /* background read from tty */
    signal(SIGTTOU, SIG_IGN);  /* background write to tty */
    signal(SIGHUP, SIG_IGN);   /* hangup */
    signal(SIGPIPE, SIG_IGN);  /* broken pipe */
}

/**
 * @brief Daemonize the process - fork() and instruct the child to behave as a proper daemon.
 */
pid_t
sr_daemonize(bool debug_mode, int log_level, const char *pid_file, int *pid_file_fd)
{
    pid_t pid = 0, sid = 0;
    int fd = -1;

    /* set file creation mask */
    umask(S_IWGRP | S_IWOTH);

    /* set log levels */
    if (debug_mode) {
        sr_log_stderr(SR_DAEMON_LOG_LEVEL);
        sr_log_syslog(SR_LL_NONE);
    } else {
        sr_log_stderr(SR_DAEMON_LOG_LEVEL);
        sr_log_syslog(SR_DAEMON_LOG_LEVEL);
    }
    if ((-1 != log_level) && (log_level >= SR_LL_NONE) && (log_level <= SR_LL_DBG)) {
        if (debug_mode) {
            sr_log_stderr(log_level);
        } else {
            sr_log_syslog(log_level);
        }
    }

    if (debug_mode) {
        /* do not fork in debug mode */
        sr_daemon_check_single_instance(pid_file, pid_file_fd);
        sr_daemon_ignore_signals();
        return 0;
    }

    /* register handlers for signals that we expect to receive from child process */
    signal(SIGCHLD, sr_daemon_child_status_handler);
    signal(SIGUSR1, sr_daemon_child_status_handler);
    signal(SIGALRM, sr_daemon_child_status_handler);

    /* fork off the parent process. */
    pid = fork();
    if (pid < 0) {
        SR_LOG_ERR("Unable to fork sysrepo plugin daemon: %s.", sr_strerror_safe(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* this is the parent process, wait for a signal from child */
        alarm(SR_DAEMON_INIT_TIMEOUT);
        pause();
        exit(EXIT_FAILURE); /* this should not be executed */
    }

    /* at this point we are executing as the child process */
    sr_daemon_check_single_instance(pid_file, pid_file_fd);

    /* ignore certain signals */
    sr_daemon_ignore_signals();

    /* create a new session containing a single (new) process group */
    sid = setsid();
    if (sid < 0) {
        SR_LOG_ERR("Unable to create new session: %s.", sr_strerror_safe(errno));
        exit(EXIT_FAILURE);
    }

    /* change the current working directory. */
    if ((chdir(SR_DEAMON_WORK_DIR)) < 0) {
        SR_LOG_ERR("Unable to change directory to '%s': %s.", SR_DEAMON_WORK_DIR, sr_strerror_safe(errno));
        exit(EXIT_FAILURE);
    }

    /* turn off stderr logging */
    sr_log_stderr(SR_LL_NONE);

    /* redirect standard files to /dev/null */
    fd = open("/dev/null", O_RDWR, 0);
    if (-1 != fd) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    return getppid(); /* return PID of the parent */
}

void
sr_daemonize_signal_success(pid_t parent_pid)
{
    kill(parent_pid, SIGUSR1);
}

int
sr_set_data_file_permissions(const char *target_file, bool target_is_dir, const char *data_serach_dir,
        const char *module_name, bool strict)
{
    char *data_file_name = NULL;
    struct stat data_file_stat = { 0, };
    mode_t mode = 0;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG3(target_file, data_serach_dir, module_name);

    /* skip privilege setting for internal 'module name' */
    if (0 == strcmp(module_name, SR_GLOBAL_SUBSCRIPTIONS_SUBDIR)) {
        return SR_ERR_OK;
    }

    /* retrieve module's data filename */
    rc = sr_get_data_file_name(data_serach_dir, module_name, SR_DS_STARTUP, &data_file_name);
    CHECK_RC_LOG_RETURN(rc, "Unable to get data file name for module %s.", module_name);

    /* lookup for permissions of the data file */
    ret = stat(data_file_name, &data_file_stat);
    free(data_file_name);

    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_UNKNOWN_MODEL, "Unable to stat data file for '%s': %s.", module_name, sr_strerror_safe(errno));

    mode = data_file_stat.st_mode;
    /* for directory, set the execute permissions to be the same as write permissions */
    if (target_is_dir) {
        if (mode & S_IWUSR) {
            mode |= S_IXUSR;
        }
        if (mode & S_IWGRP) {
            mode |= S_IXGRP;
        }
        if (mode & S_IWOTH) {
            mode |= S_IXOTH;
        }
    }

    /* change the permissions */
    ret = chmod(target_file, mode);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_UNAUTHORIZED, "Unable to execute chmod on '%s': %s.", target_file, sr_strerror_safe(errno));

    /* change the owner (if possible) */
    ret = chown(target_file, data_file_stat.st_uid, data_file_stat.st_gid);
    if (0 != ret) {
        if (strict) {
            SR_LOG_ERR("Unable to execute chown on '%s': %s.", target_file, sr_strerror_safe(errno));
            return SR_ERR_INTERNAL;
        } else {
            /* non-privileged process may not be able to set chown - print warning, since
             * this may prevent some users otherwise allowed to access the data to connect to our socket.
             * Correct permissions can be set up at any time using sysrepoctl. */
            SR_LOG_WRN("Unable to execute chown on '%s': %s.", target_file, sr_strerror_safe(errno));
        }
    }

    return rc;
}

int
sr_clock_get_time(clockid_t clock_id, struct timespec *ts)
{
    CHECK_NULL_ARG(ts);
    return clock_gettime(clock_id, ts);
}

static bool
sr_has_parent(const struct lys_node *node, LYS_NODE type)
{
    for (node = node->parent; node; node = node->parent) {
        if (node->nodetype == type) {
            return true;
        }
    }

    return false;
}

static bool
sr_find_schema_node_valid_identifier(const char *identifier, size_t id_len)
{
    if (0 == id_len) {
        id_len = strlen(identifier);
    }

    if (0 == id_len) {
        return false;
    } else if (!isalpha(identifier[0]) && (identifier[0] != '_')) {
        return false;
    }

    --id_len;

    for (size_t i = 1; i < id_len; ++i) {
        if (!isalnum(identifier[0]) && (identifier[0] != '_') && (identifier[0] != '-') && (identifier[0] != '.')) {
            return false;
        }
    }

    return true;
}

static int
sr_find_schema_node_predicate(const struct lys_node *node, char *predicate, const struct lys_module *prev_mod)
{
    char *ptr = NULL, *pred_end = NULL, *identifier = NULL, *mod_name = NULL;
    size_t id_len = 0, mod_name_len = 0;
    uint16_t i = 0;
    struct lys_node_leaf *key = NULL;
    const struct lys_module *key_mod;

    if (!(node->nodetype & (LYS_LIST | LYS_LEAFLIST))) {
        return -1;
    }

    for (; !pred_end || (pred_end[1] == '['); predicate = pred_end + 2) {
        pred_end = strchr(predicate, ']');
        if (NULL == pred_end) {
            return SR_ERR_INVAL_ARG;
        }

        identifier = predicate;
        while (isspace(identifier[0])) {
            ++identifier;
        }

        id_len = 0;
        while (!isspace(identifier[id_len]) && (identifier[id_len] != '=') && (identifier[id_len] != ']')) {
            ++id_len;
        }

        /* check the identifier */
        if (node->nodetype == LYS_LEAFLIST) {
            if ((identifier[0] != '.') || (id_len != 1)) {
                return SR_ERR_INVAL_ARG;
            }
            break;
        } else {
            if (isdigit(identifier[0])) {
                /* position */
                for (i = 1; i < id_len; ++i) {
                    if (!isdigit(identifier[i])) {
                        return SR_ERR_INVAL_ARG;
                    }
                }
            } else {
                /* prefix */
                mod_name = NULL;
                ptr = strchr(identifier, ':');
                if (ptr != NULL && (ptr - identifier < id_len)) {
                    mod_name = identifier;
                    mod_name_len = ptr - identifier;
                    identifier = ptr + 1;
                    id_len -= mod_name_len + 1;

                    if (!sr_find_schema_node_valid_identifier(mod_name, mod_name_len)) {
                        return SR_ERR_INVAL_ARG;
                    }
                }

                if (!sr_find_schema_node_valid_identifier(identifier, id_len)) {
                    return SR_ERR_INVAL_ARG;
                }

                for (i = 0; i < ((struct lys_node_list *)node)->keys_size; ++i) {
                    key = ((struct lys_node_list *)node)->keys[i];
                    key_mod = lys_node_module((struct lys_node *)key);
                    if (0 == strncmp(key->name, identifier, id_len) && !key->name[id_len]) {
                        if ((mod_name == NULL && key_mod == prev_mod) ||
                                (mod_name != NULL && 0 == strncmp(key_mod->name, mod_name, mod_name_len) && !key_mod->name[mod_name_len])) {
                            break;
                        }
                    }
                }
                if (i == ((struct lys_node_list *)node)->keys_size) {
                    return -1;
                }
            }
        }
    }

    return SR_ERR_OK;
}

int
sr_find_schema_node(const struct lys_module *module, const struct lys_node *start, const char *data_path, bool output,
                    struct ly_set **ret)
{
    int rc = SR_ERR_OK, tmp_rc = SR_ERR_OK;
    const struct lys_node *node = NULL, *next = NULL, *elem = NULL;
    char *path = NULL, *name = NULL, *mod_name = NULL, *path_end = NULL, *predicate = NULL;
    const struct lys_module *prev_mod = NULL;
    bool all_desc = false, last_iter = false;

    assert(module || start);
    if (ret) {
        *ret = NULL;
    }

    path = strdup(data_path);
    path_end = path + strlen(path);

    for (name = path; name[0]; ++name) {
        switch (name[0]) {
        case '/':
            /* replace every '/' with 0 (but be careful with "//") */
            name[0] = '\0';
            if (name[1] == '\0') {
                rc = SR_ERR_INVAL_ARG;
                goto error;
            }
            ++name;
            break;
        case '\'':
            /* skip quoted values */
            do {
                ++name;
            } while (name[0] && (name[0] != '\''));
            if (!name[0]) {
                rc = SR_ERR_INVAL_ARG;
                goto error;
            }
            break;
        case '\"':
            /* skip quoted values */
            do {
                ++name;
            } while (name[0] && ((name[0] != '\"') || (name[-1] == '\\')));
            if (!name[0]) {
                rc = SR_ERR_INVAL_ARG;
                goto error;
            }
            break;
        default:
            break;
        }
    }
    if (path[0] == '\0') {
        /* absolute path */
        if (NULL == module) {
            module = lys_node_module(start);
        }
        start = NULL;

        name = path + 1;
    } else {
        /* relative path */
        if (NULL == start) {
            rc = SR_ERR_INTERNAL;
            goto error;
        }
        module = NULL;

        name = path;
        prev_mod = lys_node_module(start);
    }

    /* main loop */
    while (1) {
        if ((predicate = strchr(name, '['))) {
            predicate[0] = '\0';
            ++predicate;
        }
        mod_name = strchr(name, ':');
        if (mod_name) {
            mod_name[0] = '\0';
            mod_name = name;
            name = mod_name + strlen(mod_name) + 1;

            if (mod_name[0] == '/') {
                all_desc = 1;
                ++mod_name;
            }
        } else if (name[0] == '/') {
            all_desc = 1;
            ++name;
        }
        if (all_desc && (0 != strcmp(name, ".")) && (0 != strcmp(name, "*"))) {
            /* we do not support "node//node" */
            rc = SR_ERR_UNSUPPORTED;
            goto error;
        } else if (!all_desc && (0 == strcmp(name, "."))) {
            /* we do not support "node/." */
            rc = SR_ERR_UNSUPPORTED;
            goto error;
        }
        if ((0 != strcmp(name, ".") && 0 != strcmp(name, "*") && !sr_find_schema_node_valid_identifier(name, 0))
                || (mod_name && !sr_find_schema_node_valid_identifier(mod_name, 0))) {
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }

        /* last iteration, we are getting results */
        if ((predicate ? predicate : name) + strlen(predicate ? predicate : name) == path_end && ret) {
            last_iter = true;
            *ret = ly_set_new();
            if (0 == strcmp(name, ".")) {
                /* handle "." */
                ly_set_add(*ret, (void *)start, LY_SET_OPT_USEASLIST);
                name[0] = '*';
            }
        }

        node = NULL;
        while ((node = lys_getnext(node, start, module, 0))) {
            /* check input/output */
            if (output && sr_has_parent(node, LYS_INPUT)) {
                continue;
            } else if (!output && sr_has_parent(node, LYS_OUTPUT)) {
                continue;
            }

            /* check module */
            if (mod_name) {
                if (strcmp(mod_name, lys_node_module(node)->name)) {
                    continue;
                }
            } else if (lys_node_module(node) != prev_mod && name[0] != '*') {
                continue;
            }

            /* check name */
            if (name[0] != '*') {
                if (0 == strcmp(node->name, name)) {
                    if (predicate) {
                        tmp_rc = sr_find_schema_node_predicate(node, predicate, lys_node_module(node));
                        if (tmp_rc == -1) {
                            continue;
                        } else if (tmp_rc != SR_ERR_OK) {
                            rc = tmp_rc;
                            goto error;
                        }
                    }
                    if (last_iter && ret) {
                        if (all_desc) {
                            LY_TREE_DFS_BEGIN(node, next, elem) {
                                ly_set_add(*ret, (void *)elem, LY_SET_OPT_USEASLIST);
                                LY_TREE_DFS_END(node, next, elem);
                            }
                        } else {
                            ly_set_add(*ret, (void *)node, LY_SET_OPT_USEASLIST);
                        }
                    }
                    break;
                }
            } else {
                if (last_iter && ret) {
                    if (all_desc) {
                        LY_TREE_DFS_BEGIN(node, next, elem) {
                            ly_set_add(*ret, (void *)elem, LY_SET_OPT_USEASLIST);
                            LY_TREE_DFS_END(node, next, elem);
                        }
                    } else {
                        ly_set_add(*ret, (void *)node, LY_SET_OPT_USEASLIST);
                    }
                }
            }
        }
        if (NULL == node && name[0] != '*') {
            rc = SR_ERR_BAD_ELEMENT;
            goto error;
        }

        if (last_iter) {
            /* finished */
            break;
        }

        /* next iteration */
        start = node;
        prev_mod = lys_node_module(start);
        if (predicate) {
            name = predicate + strlen(predicate) + 1;
        } else {
            name += strlen(name) + 1;
        }
    }

    free(path);
    return rc;

error:
    if (ret) {
        ly_set_free(*ret);
    }
    free(path);
    return rc;
}

int
sr_mkdir_recursive(const char *path, mode_t mode)
{
    CHECK_NULL_ARG(path);

    const size_t len = strlen(path);
    char path_dup[PATH_MAX] = { 0, };
    char *p = NULL;

    errno = 0;

    /* Duplicate string so its mutable */
    if (len > sizeof(path_dup)-1) {
        errno = ENAMETOOLONG;
        return SR_ERR_INVAL_ARG;
    }
    strcpy(path_dup, path);

    /* Iterate the string */
    for (p = path_dup + 1; *p; p++) {
        if (*p == '/') {
            /* Temporarily truncate */
            *p = '\0';
            if (mkdir(path_dup, mode) != 0) {
                if (errno != EEXIST)
                    return SR_ERR_IO;
            }
            *p = '/';
        }
    }

    if (mkdir(path_dup, mode) != 0) {
        if (errno != EEXIST)
            return SR_ERR_IO;
    }

    return 0;
}

bool
sr_lys_module_has_data(const struct lys_module *module)
{
    struct lys_node *iter = NULL;

    if (!module) {
        return false;
    }

    /* submodules don't have data tree, the data nodes are placed in the main module altogether */
    if (module->type) {
        return false;
    }

    /* iterate through top-level nodes */
    LY_TREE_FOR(module->data, iter) {
        if (((LYS_CONFIG_R & iter->flags) /* operational data */ ||
             ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST | LYS_CHOICE | LYS_RPC | LYS_NOTIF | LYS_ACTION | LYS_USES) & iter->nodetype))) {
            /* data-carrying */
            return true;
        }
    }
    return false;
}

int
sr_print(sr_print_ctx_t *print_ctx, const char *format, ...)
{
    int rc = SR_ERR_OK, count = 0, len = 0;
    char *str = NULL, *aux = NULL;
    size_t new_size;
    va_list va;

    CHECK_NULL_ARG2(print_ctx, format);

    va_start(va, format);

    switch (print_ctx->type) {
        case SR_PRINT_FD:
            count = vdprintf(print_ctx->method.fd, format, va);
            CHECK_NOT_MINUS1_MSG_GOTO(count, rc, SR_ERR_INTERNAL, cleanup, "vdprintf failed");
            break;
        case SR_PRINT_STREAM:
            count = vfprintf(print_ctx->method.stream, format, va);
            CHECK_NOT_MINUS1_MSG_GOTO(count, rc, SR_ERR_INTERNAL, cleanup, "vfprintf failed");
            break;
        case SR_PRINT_MEM:
            /* print string to a temporary memory buffer */
            len = vsnprintf(NULL, 0, format, va);
            str = calloc(len+1, sizeof *str);
            CHECK_NULL_NOMEM_GOTO(str, rc, cleanup);
            va_end(va); /**< restart va_list */
            va_start(va, format);
            count = vsnprintf(str, len+1, format, va);
            CHECK_NOT_MINUS1_MSG_GOTO(count, rc, SR_ERR_INTERNAL, cleanup, "vsnprintf failed");
            /* append the string to already printed data */
            if (print_ctx->method.mem.len + count + 1 > print_ctx->method.mem.size) {
                new_size = MAX(2 * print_ctx->method.mem.size, print_ctx->method.mem.len + count + 1);
                aux = realloc(print_ctx->method.mem.buf, new_size * sizeof *aux);
                CHECK_NULL_NOMEM_GOTO(aux, rc, cleanup);
                print_ctx->method.mem.buf = aux;
                print_ctx->method.mem.size = new_size;
            }
            strcpy(print_ctx->method.mem.buf + print_ctx->method.mem.len, str);
            print_ctx->method.mem.len += count;
            break;
    }

cleanup:
    free(str);
    va_end(va);
    return rc;
}

int
sr_create_uri_for_module(const struct lys_module *module, char **uri)
{
    CHECK_NULL_ARG4(module, uri, module->name, module->ns);

    int rc = SR_ERR_OK;
    char *buffer = NULL;
    sr_list_t *features = NULL;

    rc = sr_list_init(&features);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    size_t len = strlen(module->ns)+strlen("?module=")+strlen(module->name)+1;

    if (0 < module->rev_size) {
        len += strlen("&amp;revision=")+strlen(module->rev[0].date);
    }

    if (0 < module->features_size) {
        for (uint8_t i = 0; i < module->features_size; i++) {
            if (module->features[i].flags & LYS_FENABLED) {
                len += strlen(module->features[i].name);
                rc = sr_list_add(features, (void *) module->features[i].name);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add feature into list");
            }
        }
        if (features->count > 0) {
            len += strlen("&amp;features=");
            len += features->count -1; /*commas among feature names*/
        }
    }
    buffer = calloc(len, sizeof(*buffer));
    CHECK_NULL_NOMEM_GOTO(buffer, rc, cleanup);

    snprintf(buffer, len, "%s?module=%s", module->ns, module->name);
    size_t ptr = strlen(buffer);
    if (0 < module->rev_size) {
        snprintf(buffer + ptr, len-ptr, "&amp;revision=%s", module->rev[0].date);
    }

    if (features->count > 0) {
        ptr = strlen(buffer);
        snprintf(buffer + ptr, len-ptr, "&amp;features=");
        ptr += strlen("&amp;features=");

        for (size_t i = 0; i < features->count; i++) {
            snprintf(buffer+ptr, len-ptr, "%s,", (char *)features->data[i]);
            ptr += strlen((char *)features->data[i])+1;
        }
        /* overwrite last comma by terminating NULL byte*/
        buffer[len-1] = 0;
    }

cleanup:
    sr_list_cleanup(features);
    if (SR_ERR_OK == rc ) {
        *uri = buffer;
    } else {
        free(buffer);
    }
    return rc;
}

int sr_get_user_name(uid_t uid, char **username_p)
{
    int rc = SR_ERR_OK, ret = 0;
    size_t max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    size_t pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    struct passwd pw = {0}, *pw_p = NULL;
    char *tmp_buf = NULL, *pw_buf = NULL;
    char *username = NULL;

    /* allocate buffer for members of passwd structure */
    if (-1 == pw_bufsize) {
        pw_bufsize = 256;
    }
    pw_buf = malloc(pw_bufsize);
    CHECK_NULL_NOMEM_GOTO(pw_buf, rc, cleanup);

    /* get password file entry */
    while (max_attempts && ERANGE == (ret = getpwuid_r(uid, &pw, pw_buf, pw_bufsize, &pw_p))) {
        tmp_buf = realloc(pw_buf, pw_bufsize << 1);
        CHECK_NULL_NOMEM_GOTO(tmp_buf, rc, cleanup);
        pw_buf = tmp_buf;
        pw_bufsize <<= 1;
        --max_attempts;
    }
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup, "Failed to get the password file record for UID '%d': %s. ",
                        uid, sr_strerror_safe(ret));
    if (NULL == pw_p || NULL == pw_p->pw_name) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* copy username */
    if (NULL != username_p) {
        username = strdup(pw_p->pw_name);
        CHECK_NULL_NOMEM_GOTO(username, rc, cleanup);
    }

cleanup:
    free(pw_buf);
    if (SR_ERR_OK == rc && NULL != username_p) {
        *username_p = username;
    }
    return rc;
}

int sr_get_user_id(const char *username, uid_t *uid_p, gid_t *gid_p)
{
    int rc = SR_ERR_OK, ret = 0;
    size_t max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    size_t pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    struct passwd pw = {0}, *pw_p = NULL;
    char *tmp_buf = NULL, *pw_buf = NULL;

    CHECK_NULL_ARG(username);

    /* allocate buffer for members of passwd structure */
    if (-1 == pw_bufsize) {
        pw_bufsize = 256;
    }
    pw_buf = malloc(pw_bufsize);
    CHECK_NULL_NOMEM_GOTO(pw_buf, rc, cleanup);

    /* get password file entry */
    while (max_attempts && ERANGE == (ret = getpwnam_r(username, &pw, pw_buf, pw_bufsize, &pw_p))) {
        tmp_buf = realloc(pw_buf, pw_bufsize << 1);
        CHECK_NULL_NOMEM_GOTO(tmp_buf, rc, cleanup);
        pw_buf = tmp_buf;
        pw_bufsize <<= 1;
        --max_attempts;
    }
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup, "Failed to get the password file record for user '%s': %s. ",
                        username, sr_strerror_safe(ret));
    if (NULL == pw_p) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

cleanup:
    if (SR_ERR_OK == rc) {
        if (NULL != uid_p) {
            *uid_p = pw_p->pw_uid;
        }
        if (NULL != gid_p) {
            *gid_p = pw_p->pw_gid;
        }
    }
    free(pw_buf);
    return rc;
}

int sr_get_group_name(gid_t gid, char **groupname_p)
{
    int rc = SR_ERR_OK, ret = 0;
    size_t max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    size_t gr_bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    struct group gr = {0}, *gr_p = NULL;
    char *tmp_buf = NULL, *gr_buf = NULL;
    char *groupname = NULL;

    CHECK_NULL_ARG(groupname_p);

    /* allocate buffer for members of group structure */
    if (-1 == gr_bufsize) {
        gr_bufsize = 256;
    }
    gr_buf = malloc(gr_bufsize);
    CHECK_NULL_NOMEM_GOTO(gr_buf, rc, cleanup);

    /* get password file entry */
    while (max_attempts && ERANGE == (ret = getgrgid_r(gid, &gr, gr_buf, gr_bufsize, &gr_p))) {
        tmp_buf = realloc(gr_buf, gr_bufsize << 1);
        CHECK_NULL_NOMEM_GOTO(tmp_buf, rc, cleanup);
        gr_buf = tmp_buf;
        gr_bufsize <<= 1;
        --max_attempts;
    }
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup, "Failed to get the group file record for GID '%d': %s. ",
                        gid, sr_strerror_safe(ret));
    if (NULL == gr_p || NULL == gr_p->gr_name) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* copy groupname */
    groupname = strdup(gr_p->gr_name);
    CHECK_NULL_NOMEM_GOTO(groupname, rc, cleanup);

cleanup:
    free(gr_buf);
    if (SR_ERR_OK == rc) {
        *groupname_p = groupname;
    }
    return rc;
}

int sr_get_group_id(const char *groupname, gid_t *gid_p)
{
    int rc = SR_ERR_OK, ret = 0;
    size_t max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    size_t gr_bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    struct group gr = {0}, *gr_p = NULL;
    char *tmp_buf = NULL, *gr_buf = NULL;

    CHECK_NULL_ARG(groupname);

    /* allocate buffer for members of group structure */
    if (-1 == gr_bufsize) {
        gr_bufsize = 256;
    }
    gr_buf = malloc(gr_bufsize);
    CHECK_NULL_NOMEM_GOTO(gr_buf, rc, cleanup);

    /* get password file entry */
    while (max_attempts && ERANGE == (ret = getgrnam_r(groupname, &gr, gr_buf, gr_bufsize, &gr_p))) {
        tmp_buf = realloc(gr_buf, gr_bufsize << 1);
        CHECK_NULL_NOMEM_GOTO(tmp_buf, rc, cleanup);
        gr_buf = tmp_buf;
        gr_bufsize <<= 1;
        --max_attempts;
    }
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup, "Failed to get the group file record for group '%s': %s. ",
                        groupname, sr_strerror_safe(ret));
    if (NULL == gr_p) {
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

cleanup:
    if (SR_ERR_OK == rc) {
        if (NULL != gid_p) {
            *gid_p = gr_p->gr_gid;
        }
    }
    free(gr_buf);
    return rc;
}

int
sr_get_user_groups(const char *username, char ***groups_p, size_t *group_cnt_p)
{
    int rc = SR_ERR_OK, ret = 0;
    size_t max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    size_t group_cnt = 0;
    int group_id_cnt = 16;
    gid_t gid = 0;
#ifdef __APPLE__
    int *group_ids = NULL, *tmp_group_ids = NULL;
    int user_gid = 0;
#else
    gid_t *group_ids = NULL, *tmp_group_ids = NULL;
    gid_t user_gid = 0;
#endif
    char **groups = NULL;
    CHECK_NULL_ARG3(username, groups_p, group_cnt_p);

    /* get the user's primary group */
    rc = sr_get_user_id(username, NULL, &gid);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_NOT_FOUND == rc) {
            rc = SR_ERR_OK;
        }
        goto cleanup;
    }
#ifdef __APPLE__
    user_gid = (int)gid;
#else
    user_gid = gid;
#endif

    /* get secondary groups */
    group_ids = calloc(group_id_cnt, sizeof *group_ids);
    CHECK_NULL_NOMEM_GOTO(group_ids, rc, cleanup);

    max_attempts = MAX_BUF_REALLOC_ATEMPTS;
    while (max_attempts && (ret = getgrouplist(username, user_gid, group_ids, &group_id_cnt)) < 0) {
        tmp_group_ids = realloc(group_ids, group_id_cnt * (sizeof *tmp_group_ids));
        CHECK_NULL_NOMEM_GOTO(tmp_group_ids, rc, cleanup);
        group_ids = tmp_group_ids;
        --max_attempts;
    }
    CHECK_NOT_MINUS1_LOG_GOTO(ret, rc, SR_ERR_IO, cleanup,
                              "Failed to get the list of secondary groups for user '%s'.", username);
    if (0 == group_id_cnt) {
        goto cleanup;
    }

    /* get names of the groups */
    groups = calloc(group_id_cnt, sizeof(char *));
    CHECK_NULL_NOMEM_GOTO(groups, rc, cleanup);

    for (size_t i = 0; i < group_id_cnt; ++i) {
        rc = sr_get_group_name((gid_t)group_ids[i], groups+group_cnt);
        if (SR_ERR_OK == rc) {
            ++group_cnt;
        } else if (SR_ERR_NOT_FOUND != rc) {
            goto cleanup;
        }
        rc = SR_ERR_OK;
    }

cleanup:
    free(group_ids);
    if (SR_ERR_OK == rc) {
        *groups_p = groups;
        *group_cnt_p = group_cnt;
    } else {
        if (NULL != groups) {
            for (size_t i = 0; i < group_cnt; ++i) {
                free(groups[i]);
            }
            free(groups);
        }
    }
    return rc;
}

void
sr_free_list_of_strings(sr_list_t *list)
{
    if (NULL != list) {
        for (size_t i = 0; i < list->count; i++) {
            free((char *) list->data[i]);
        }
        sr_list_cleanup(list);
    }
}

int
sr_time_to_str(time_t time, char *buff, size_t buff_size)
{
    CHECK_NULL_ARG(buff);

    strftime(buff, buff_size - 1, "%Y-%m-%dT%H:%M:%S%z", localtime(&time));
    /* time buff ends in '+hhmm' but should be '+hh:mm' */
    memmove(buff + strlen(buff) - 1, buff + strlen(buff) - 2, 3);
    buff[strlen(buff) - 3] = ':';

    return SR_ERR_OK;
}

int
sr_str_to_time(char *time_str, time_t *time)
{
    struct tm tm = { 0, };
    char *time_str_copy = NULL, *colon = NULL, *ret = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(time_str, time);

    time_str_copy = strdup(time_str);
    CHECK_NULL_NOMEM_RETURN(time_str_copy);

    /* time str ends in '+hh:mm' but should be '+hhmm' */
    colon = strrchr(time_str_copy, ':');
    if (NULL == colon) {
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    memmove(colon, colon + 1, 2);
    *(colon + 2) = '\0';

    ret = strptime(time_str_copy, "%Y-%m-%dT%H:%M:%S%z", &tm);
    if (NULL == ret || '\0' != *ret) {
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    /* need to learn on its own whether it is DST */
    tm.tm_isdst = -1;

    *time = mktime(&tm);

cleanup:
    free(time_str_copy);
    return rc;
}

int sr_features_clone(const struct lys_module *module_src, const struct lys_module *module_tgt)
{
    int i, j;

    uint8_t fsize_src, fsize_tgt;
    struct lys_feature *f_src, *f_tgt;

    if (module_src->inc_size != module_tgt->inc_size) {
        SR_LOG_ERR("Features cannot be cloned %s.", module_src->name);
        return EXIT_FAILURE;
    }

    for (i = -1; i < module_src->inc_size; i++) {
        if (i == -1) {
            fsize_src = module_src->features_size;
            fsize_tgt = module_tgt->features_size;
            f_src = module_src->features;
            f_tgt = module_tgt->features;
        } else {
            fsize_src = module_src->inc[i].submodule->features_size;
            fsize_tgt = module_tgt->inc[i].submodule->features_size;
            f_src = module_src->inc[i].submodule->features;
            f_tgt = module_tgt->inc[i].submodule->features;
        }

        if (fsize_src != fsize_tgt) {
            SR_LOG_ERR("Features cannot be cloned %s.", module_src->name);
            return EXIT_FAILURE;
        }

        for (j = 0; j < fsize_src; j++) {
            if (!strcmp(f_src[j].name, f_tgt[j].name)) {
                f_tgt[j].flags |= f_src[j].flags & LYS_FENABLED;
            }
            else {
                SR_LOG_ERR("Features cannot be cloned %s.", module_src->name);
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}
