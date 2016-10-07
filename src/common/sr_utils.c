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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "sr_utils.h"

#include "data_manager.h"

/* used for sr_buff_to_uint32 and sr_uint32_to_buff conversions */
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

int
sr_str_ends_with(const char *str, const char *suffix)
{
    CHECK_NULL_ARG2(str, suffix);

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len >  str_len){
        return 0;
    }
    return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
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

int
sr_copy_first_ns(const char *xpath, char **namespace)
{
    CHECK_NULL_ARG2(xpath, namespace);

    char *colon_pos = strchr(xpath, ':');
    if (xpath[0] != '/' || NULL == colon_pos) {
        return SR_ERR_INVAL_ARG;
    }
    *namespace = strndup(xpath + 1, (colon_pos - xpath -1));
    CHECK_NULL_NOMEM_RETURN(*namespace);
    return SR_ERR_OK;
}

int
sr_copy_first_ns_from_expr(const char *expr, char*** namespaces_p, size_t *namespace_cnt_p)
{
    int rc = SR_ERR_OK;
    const char *ns = NULL, *cur = NULL;
    bool ignore = false, copied = false;
    char **namespaces = NULL, **tmp = NULL;
    size_t namespace_cnt = 0, namespace_size = 0, new_size = 0;

    CHECK_NULL_ARG3(expr, namespaces_p, namespace_cnt_p);

    cur = ns = expr;
    while ('\0' != *cur) {
        if (isspace(*cur) || NULL != strchr("[<>=+@$&|", *cur)) {
            /* restart */
            ignore = false;
            ns = cur+1;
        } else if ('\'' == *cur || '"' == *cur) {
            if (!ignore) {
                /* restart */
                ns = cur+1;
            }
        } else if ('/' == *cur) {
            if (ns < cur) {
                ignore = true;
            } else {
                /* restart */
                ns = cur+1;
            }
        } else if (']' == *cur) {
            ignore = true;
        } else if (':' == *cur) {
            if (!ignore && ns < cur) {
                copied = false;
                for (size_t i = 0; i < namespace_cnt; ++i) {
                    if (0 == strncmp(namespaces[i], ns, cur - ns)) {
                        copied = true;
                        break;
                    }
                }
                if (false == copied) {
                    if (namespace_cnt == namespace_size) {
                        /* realloc */
                        if (0 == namespace_size) {
                            new_size = 2;
                        } else {
                            new_size = namespace_size * 2;
                        }
                        tmp = (char **)realloc(namespaces, (sizeof *namespaces) * new_size);
                        CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
                        namespaces = tmp;
                        for (size_t i = namespace_size; i < new_size; ++i) {
                            namespaces[i] = NULL;
                        }
                        namespace_size = new_size;
                    }
                    assert(namespace_cnt < namespace_size);
                    namespaces[namespace_cnt] = strndup(ns, cur - ns);
                    CHECK_NULL_NOMEM_GOTO(namespaces[namespace_cnt], rc, cleanup);
                    ++namespace_cnt;
                }
            }
            ignore = true;
        }
        ++cur;
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *namespaces_p = namespaces;
        *namespace_cnt_p = namespace_cnt;
    } else {
        for (size_t i = 0; i < namespace_cnt; ++i) {
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
    fl.l_pid = getpid();

    /* set the lock, waiting if requested and necessary */
    ret = fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl);

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

#if !defined(__USE_GNU)
/* struct ucred is ifdefined behind __USE_GNU, but __USE_GNU is not defined */
struct ucred {
    pid_t pid;    /* process ID of the sending process */
    uid_t uid;    /* user ID of the sending process */
    gid_t gid;    /* group ID of the sending process */
};
#endif /* !defined(__USE_GNU) */

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
sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree)
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

    ret = lyd_print_file(f, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Failed to write output into %s", file_name);

cleanup:
    fclose(f);
    return rc;
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

    switch(leaf->value_type){
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
            return sr_libyang_leaf_get_type_sch(((struct lys_node_leaf *)leaf->schema)->type.info.lref.target);
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
    }
matching_done:
    if (type != value->type) {
        SR_LOG_ERR("Value doesn't conform to schema expected %d instead of %d", type, value->type);
    }
    sr_list_cleanup(union_list);
    return type == value->type ? SR_ERR_OK : SR_ERR_INVAL_ARG;
}

/**
 * Functions copies the bits into string
 * @param [in] leaf - data tree node from the bits will be copied
 * @param [out] value - destination value where a space separated set bit field will be copied to
 * @return Error code (SR_ERR_OK on success)
 */
static int
sr_libyang_leaf_copy_bits(const struct lyd_node_leaf_list *leaf, sr_val_t *value)
{
    CHECK_NULL_ARG3(leaf, value, leaf->schema);

    struct lys_node_leaf *sch = (struct lys_node_leaf *) leaf->schema;
    char *bits_str = NULL;
    int bits_count = sch->type.info.bits.count;
    struct lys_type_bit **bits = leaf->value.bit;

    size_t length = 1; /* terminating NULL byte*/
    for (int i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            length += strlen(bits[i]->name);
            length++; /*space after bit*/
        }
    }
    bits_str = sr_calloc(value->_sr_mem, length, sizeof(*bits_str));
    if (NULL == bits_str) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    size_t offset = 0;
    for (int i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            strcpy(bits_str + offset, bits[i]->name);
            offset += strlen(bits[i]->name);
            bits_str[offset] = ' ';
            offset++;
        }
    }
    if (0 != offset) {
        bits_str[offset - 1] = '\0';
    }

    value->data.bits_val = bits_str;
    return SR_ERR_OK;
}

int
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
        ret = scanf(val_str, "%g", &value->data.decimal64_val);
        break;
    default:
        SR_LOG_ERR_MSG("Unknown type to convert");
        return SR_ERR_INVAL_ARG;
    }

    return ret == 1 ? SR_ERR_OK : SR_ERR_INTERNAL;
}

int
sr_libyang_leaf_copy_value(const struct lyd_node_leaf_list *leaf, sr_val_t *value)
{
    CHECK_NULL_ARG2(leaf, value);
    int rc = SR_ERR_OK;
    struct lys_node_leaf *leaf_schema = NULL;
    const struct lyd_node_leaf_list *leafref = NULL;
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
        if (NULL == leaf->value.bit) {
            SR_LOG_ERR("Missing schema information for node '%s'", node_name);
        }
        rc = sr_libyang_leaf_copy_bits(leaf, value);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'bits'", node_name);
        }
        return rc;
    case LY_TYPE_BOOL:
        value->data.bool_val = leaf->value.bln;
        return SR_ERR_OK;
    case LY_TYPE_DEC64:
        CHECK_NULL_ARG(leaf->schema);
        value->data.decimal64_val = (double) leaf->value.dec64;
        leaf_schema = (struct lys_node_leaf *) leaf->schema;
        for (size_t i = 0; i < leaf_schema->type.info.dec64.dig; i++) {
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
        if (NULL == leaf->value.ident->name) {
            SR_LOG_ERR("Identity ref in leaf '%s' is NULL", node_name);
            return SR_ERR_INTERNAL;
        }
        sr_mem_edit_string(value->_sr_mem, &value->data.identityref_val, leaf->value.ident->name);
        if (NULL == value->data.identityref_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'identityref'", node_name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_INST:
        /* NOT IMPLEMENTED yet*/
        if (NULL != leaf->schema && NULL != leaf->schema->name) {
            SR_LOG_ERR("Copy value failed for leaf '%s'", node_name);
        }
        return SR_ERR_INTERNAL;
    case LY_TYPE_LEAFREF:
        leafref = (const struct lyd_node_leaf_list *) leaf->value.leafref;
        if (NULL != leafref) {
            return sr_libyang_leaf_copy_value(leafref, value);
        } else {
            return sr_libyang_val_str_to_sr_val(leaf->value_str, value->type, value);
        }
        return SR_ERR_OK;
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


static int
sr_dec64_to_str(double val, const struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG2(schema_node, out);
    size_t fraction_digits = 0;
    if (LYS_LEAF == schema_node->nodetype || LYS_LEAFLIST == schema_node->nodetype) {
        struct lys_node_leaflist *l = (struct lys_node_leaflist *) schema_node;
        fraction_digits = l->type.info.dec64.dig;
    } else {
        SR_LOG_ERR_MSG("Node must be either leaf or leaflist");
        return SR_ERR_INVAL_ARG;
    }
    /* format string for double string conversion "%.XXf", where XX is corresponding number of fraction digits 1-18 */
#define MAX_FMT_LEN 6 /**< max dec64 format string length */
    char format_string [MAX_FMT_LEN] = {0,};
    snprintf(format_string, MAX_FMT_LEN, "%%.%zuf", fraction_digits);

    size_t len = snprintf(NULL, 0, format_string, val);
    *out = calloc(len + 1, sizeof(**out));
    CHECK_NULL_NOMEM_RETURN(*out);
    snprintf(*out, len + 1, format_string, val);
    return SR_ERR_OK;
}

int
sr_val_to_str(const sr_val_t *value, const struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG3(value, schema_node, out);
    size_t len = 0;
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
        len = snprintf(NULL, 0, "%"PRId8, value->data.int8_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        len = snprintf(NULL, 0, "%"PRId16, value->data.int16_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        len = snprintf(NULL, 0, "%"PRId32, value->data.int32_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        len = snprintf(NULL, 0, "%"PRId64, value->data.int64_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRId64, value->data.int64_val);
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
        len = snprintf(NULL, 0, "%"PRIu8, value->data.uint8_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        len = snprintf(NULL, 0, "%"PRIu16, value->data.uint16_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        len = snprintf(NULL, 0, "%"PRIu32, value->data.uint32_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        len = snprintf(NULL, 0, "%"PRIu64, value->data.uint64_val);
        *out = calloc(len + 1, sizeof(**out));
        CHECK_NULL_NOMEM_RETURN(*out);
        snprintf(*out, len + 1, "%"PRIu64, value->data.uint64_val);
        break;
    default:
        SR_LOG_ERR_MSG("Conversion of value_t to string failed");
        *out = NULL;
    }
    return SR_ERR_OK;
}

bool
sr_is_key_node(const struct lys_node *node)
{
    if (NULL == node || NULL == node->parent || LYS_LIST != node->parent->nodetype) {
        return false;
    }
    struct lys_node_list *list  = (struct lys_node_list *) node->parent;
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
 * @param [in] parent Parent node.
 * @param [in] node libyang node.
 * @param [in] depth Depth of the node relative to the root node.
 * @param [in] slice_offset Number of child nodes of the chunk root to skip.
 * @param [in] slice_width Maximum number of child nodes of the chunk root to include.
 * @param [in] child_limit Limit on the number of copied children imposed on each node starting from 3rd level.
 * @param [in] depth_limit Maximum number of tree levels to copy.
 * @param [out] sr_tree Returned sysrepo tree.
 */
static int
sr_copy_node_to_tree_internal(const struct lyd_node *parent, const struct lyd_node *node, size_t depth,
         size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, sr_node_t *sr_tree)
{
    int rc = SR_ERR_OK;
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lys_node_container *cont = NULL;
    const struct lyd_node *child = NULL;
    size_t idx = 0;
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
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Error returned from sr_libyang_leaf_copy_value: %s.", sr_strerror(rc));
                goto cleanup;
            }
            break;
        case LYS_CONTAINER:
            cont = (struct lys_node_container *)node->schema;
            sr_tree->type = cont->presence != NULL ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
            break;
        case LYS_LIST:
            sr_tree->type = SR_LIST_T;
            break;
        default:
            SR_LOG_ERR("Detected unsupported node data type (schema name: %s).", sr_tree->name);
            rc = SR_ERR_UNSUPPORTED;
            goto cleanup;
    }

    /* dflt flag */
    sr_tree->dflt = node->dflt;

    /* set module_name */
    if (NULL == parent || lyd_node_module(parent) != lyd_node_module(node)) {
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
                rc = sr_node_add_child(sr_tree, NULL, NULL, &sr_subtree);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                rc = sr_copy_node_to_tree_internal(node, child, depth + 1, slice_offset, slice_width,
                        child_limit, depth_limit, sr_subtree);
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
sr_copy_node_to_tree(const struct lyd_node *node, sr_node_t *sr_tree)
{
    return sr_copy_node_to_tree_internal(NULL, node, 0, 0, SIZE_MAX, SIZE_MAX, SIZE_MAX, sr_tree);
}

int
sr_copy_node_to_tree_chunk(const struct lyd_node *node, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_node_t *sr_tree)
{
    return sr_copy_node_to_tree_internal(NULL, node, 0, slice_offset, slice_width, child_limit, depth_limit, sr_tree);
}

int
sr_nodes_to_trees(struct ly_set *nodes, sr_mem_ctx_t *sr_mem, sr_node_t **sr_trees, size_t *count)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    size_t i = 0;

    CHECK_NULL_ARG3(nodes, sr_trees, count);

    if (0 == nodes->number) {
        *sr_trees = NULL;
        *count = 0;
        return rc;
    }

    if (sr_mem) {
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    trees = sr_calloc(sr_mem, nodes->number, sizeof *trees);
    CHECK_NULL_NOMEM_RETURN(trees);
    if (sr_mem) {
        ++sr_mem->obj_count;
    }

    for (i = 0; i < nodes->number && 0 == rc; ++i) {
        trees[i]._sr_mem = sr_mem;
        rc = sr_copy_node_to_tree_internal(NULL, nodes->set.d[i], 0, 0, SIZE_MAX, SIZE_MAX, SIZE_MAX, trees + i);
    }

    if (SR_ERR_OK == rc) {
        *sr_trees = trees;
        *count = nodes->number;
    } else {
        if (sr_mem) {
            sr_mem_restore(&snapshot);
        } else {
            sr_free_trees(trees, i);
        }
    }
    return rc;
}

int
sr_nodes_to_tree_chunks(struct ly_set *nodes, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_mem_ctx_t *sr_mem, sr_node_t **sr_trees, size_t *count)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees = NULL;
    sr_mem_snapshot_t snapshot = { 0, };
    size_t i = 0;

    CHECK_NULL_ARG3(nodes, sr_trees, count);

    if (0 == nodes->number) {
        *sr_trees = NULL;
        *count = 0;
        return rc;
    }

    if (sr_mem) {
        sr_mem_snapshot(sr_mem, &snapshot);
    }

    trees = sr_calloc(sr_mem, nodes->number, sizeof *trees);
    CHECK_NULL_NOMEM_RETURN(trees);
    if (sr_mem) {
        ++sr_mem->obj_count;
    }

    for (i = 0; i < nodes->number && 0 == rc; ++i) {
        trees[i]._sr_mem = sr_mem;
        rc = sr_copy_node_to_tree_internal(NULL, nodes->set.d[i], 0, slice_offset, slice_width, child_limit,
                depth_limit, trees + i);
    }

    if (SR_ERR_OK == rc) {
        *sr_trees = trees;
        *count = nodes->number;
    } else {
        if (sr_mem) {
            sr_mem_restore(&snapshot);
        } else {
            sr_free_trees(trees, i);
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
    struct lys_node *start_node = NULL;

    CHECK_NULL_ARG3(ly_ctx, sr_tree, data_tree);

    if (NULL == parent && NULL == xpath) {
        return SR_ERR_INVAL_ARG;
    }

    if (NULL != parent) {
        /* get module */
        if (NULL != sr_tree->module_name) {
            module = ly_ctx_get_module(ly_ctx, sr_tree->module_name, NULL);
        } else {
            module = lyd_node_module(parent);
        }
        if (NULL == module) {
            SR_LOG_ERR("Failed to obtain module schema for node: %s.", sr_tree->name);
            return SR_ERR_INTERNAL;
        }
    } else {
        char *ns = NULL;
        ret = sr_copy_first_ns(xpath, &ns);
        CHECK_RC_MSG_RETURN(ret, "Copy first ns failed");
        module = ly_ctx_get_module(ly_ctx, ns, NULL);
        free(ns);
        if (NULL != module) {
            start_node = module->data;
            module = NULL;
        }
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
                nodeset = lyd_find_xpath(*data_tree, xpath);
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
                sch_node = sr_find_schema_node(start_node, xpath, output ? LYS_FIND_OUTPUT : 0);
            } else {
                relative_xpath = calloc(strlen(module->name) + strlen(sr_tree->name) + 2, sizeof(*relative_xpath));
                CHECK_NULL_NOMEM_RETURN(relative_xpath);
                strcat(relative_xpath, module->name);
                strcat(relative_xpath, ":");
                strcat(relative_xpath, sr_tree->name);
                sch_node = sr_find_schema_node(parent->schema, relative_xpath, output ? LYS_FIND_OUTPUT : 0);
                free(relative_xpath);
                relative_xpath = NULL;
            }
            if (NULL == sch_node) {
                SR_LOG_ERR("Unable to get the schema node for a sysrepo node ('%s'): %s", sr_tree->name, ly_errmsg());
                return SR_ERR_INTERNAL;
            }
            /* copy argument value to string */
            ret = sr_val_to_str((sr_val_t *)sr_tree, sch_node, &string_val);
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
                    SR_LOG_ERR("Failed to create tree root node (leaf) ('%s'): %s", xpath, ly_errmsg());
                    return SR_ERR_INTERNAL;
                }
            } else {
                node = lyd_new_leaf(parent, module, sr_tree->name, string_val);
                free(string_val);
                if (NULL == node) {
                    SR_LOG_ERR("Unable to add leaf node (named '%s'): %s", sr_tree->name, ly_errmsg());
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
        strcat(xpath, "/");
        strcat(xpath, sr_tree->module_name);
        strcat(xpath, ":");
        strcat(xpath, sr_tree->name);
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
    int length = 0;
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
    length = vsnprintf(NULL, 0, msg_fmt, va);
    message = calloc(length+1, sizeof *message);
    CHECK_NULL_NOMEM_GOTO(message, rc, cleanup);
    va_end(va); /**< restart va_list */
    va_start(va, msg_fmt);
    vsnprintf(message, length+1, msg_fmt, va);

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
    signal(SIGUSR1, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
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
sr_set_socket_dir_permissions(const char *socket_dir, const char *data_serach_dir, const char *module_name, bool strict)
{
    char *data_file_name = NULL;
    struct stat data_file_stat = { 0, };
    mode_t mode = 0;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG2(socket_dir, module_name);

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

    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to stat data file for '%s': %s.", module_name, sr_strerror_safe(errno));

    mode = data_file_stat.st_mode;
    /* set the execute permissions to be the same as write permissions */
    if (mode & S_IWUSR) {
        mode |= S_IXUSR;
    }
    if (mode & S_IWGRP) {
        mode |= S_IXGRP;
    }
    if (mode & S_IWOTH) {
        mode |= S_IXOTH;
    }

    /* change the permissions */
    ret = chmod(socket_dir, mode);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_UNAUTHORIZED, "Unable to execute chmod on '%s': %s.", socket_dir, sr_strerror_safe(errno));

    /* change the owner (if possible) */
    ret = chown(socket_dir, data_file_stat.st_uid, data_file_stat.st_gid);
    if (0 != ret) {
        if (strict) {
            SR_LOG_ERR("Unable to execute chown on '%s': %s.", socket_dir, sr_strerror_safe(errno));
            return SR_ERR_INTERNAL;
        } else {
            /* non-privileged process may not be able to set chown - print warning, since
             * this may prevent some users otherwise allowed to access the data to connect to our socket.
             * Correct permissions can be set up at any time using sysrepoctl. */
            SR_LOG_WRN("Unable to execute chown on '%s': %s.", socket_dir, sr_strerror_safe(errno));
        }
    }

    return rc;
}

int
sr_clock_get_time(clockid_t clock_id, struct timespec *ts)
{
    CHECK_NULL_ARG(ts);
#ifdef __APPLE__
    /* OS X */
    clock_serv_t cclock = {0};
    mach_timespec_t mts = {0};
    host_get_clock_service(mach_host_self(), clock_id, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
    return 0;
#else
    return clock_gettime(clock_id, ts);
#endif
}

struct lys_node *
sr_find_schema_node(const struct lys_node *node, const char *expr, int options)
{
    struct lys_node *result = NULL;
    struct ly_set *set = lys_find_xpath(node, expr, options);
    if (NULL != set && 1 == set->number) {
        result = set->set.s[0];
    }
    ly_set_free(set);
    return result;
}
