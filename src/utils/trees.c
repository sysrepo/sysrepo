/**
 * @file trees.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for simplified manipulation with Sysrepo trees.
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

#include "sr_common.h"
#include "client_library.h"
#include "sysrepo/trees.h"
#include "values_internal.h"
#include "trees_internal.h"

#include <stdarg.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief Allocate a new instance of a sysrepo node over an existing sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context.
 * @param [in] name Name of the node to create.
 * @param [in] module_name Name of the module that this node belongs to.
 * @param [out] node_p Returned newly allocate node.
 */
int
sr_new_node(sr_mem_ctx_t *sr_mem, const char *name, const char *module_name, sr_node_t **node_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *node = NULL;

    CHECK_NULL_ARG(node_p);

    node = (sr_node_t *)sr_calloc(sr_mem, 1, sizeof *node);
    CHECK_NULL_NOMEM_RETURN(node);
    node->_sr_mem = sr_mem;

    if (name) {
        rc = sr_node_set_name(node, name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set sysrepo node name.");
    }

    if (module_name) {
        rc = sr_node_set_module(node, module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set module name for a sysrepo node.");
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *node_p = node;
    } else if (NULL == sr_mem) {
        sr_free_tree(node);
    }
    return rc;
}

/**
 * @brief Create a new sysrepo tree over a possibly existing sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL, a new one will be created.
 * @param [in] root_name Name for the newly allocated tree root. Can be NULL.
 * @param [in] root_module_name Name of the module that defines scheme of the tree root.
 *                              Can be NULL.
 * @param [out] tree Returned newly allocated Sysrepo tree.
 */
static int
sr_new_tree_ctx(sr_mem_ctx_t *sr_mem, const char *name, const char *module_name, sr_node_t **node_p)
{
    int rc = SR_ERR_OK;
    bool new_ctx = false;

    CHECK_NULL_ARG(node_p);

    if (NULL == sr_mem) {
        rc = sr_mem_new(sizeof(sr_node_t) + (name ? strlen(name) + 1 : 0)
                                          + (module_name ? strlen(module_name) + 1 : 0),
                        &sr_mem);
        CHECK_RC_MSG_RETURN(rc, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    rc = sr_new_node(sr_mem, name, module_name, node_p);
    if (SR_ERR_OK != rc) {
        if (new_ctx) {
            sr_mem_free(sr_mem);
        }
    } else {
        if (sr_mem) {
            sr_mem->obj_count += 1;
        }
    }

    return rc;
}

int
sr_new_tree(const char *name, const char *module_name, sr_node_t **node_p)
{
    return sr_new_tree_ctx(NULL, name, module_name, node_p);
}


/**
 * @brief Create a new array of sysrepo trees.
 */
static int
sr_new_trees_ctx(sr_mem_ctx_t *sr_mem, size_t count, sr_node_t **trees_p)
{
    int rc = SR_ERR_OK;
    bool new_ctx = false;
    sr_node_t *trees = NULL;

    CHECK_NULL_ARG(trees_p);

    if (0 == count) {
        *trees_p = NULL;
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        rc = sr_mem_new((sizeof *trees) * count, &sr_mem);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    trees = (sr_node_t *)sr_calloc(sr_mem, count, sizeof *trees);
    CHECK_NULL_NOMEM_GOTO(trees, rc, cleanup);
    if (NULL != sr_mem) {
        for (size_t i = 0; i < count; ++i) {
            trees[i]._sr_mem = sr_mem;
        }
        sr_mem->obj_count += 1; /* 1 for the entire array */
    }

cleanup:
    if (SR_ERR_OK != rc) {
        if (new_ctx) {
            if (sr_mem) {
                sr_mem_free(sr_mem);
            } else {
                free(trees);
            }
        }
    } else {
        *trees_p = trees;
    }
    return SR_ERR_OK;
}

int
sr_new_trees(size_t count, sr_node_t **trees_p)
{
    return sr_new_trees_ctx(NULL, count, trees_p);
}

int
sr_node_set_name(sr_node_t *node, const char *name)
{
    CHECK_NULL_ARG2(node, name);
    return sr_mem_edit_string(node->_sr_mem, &node->name, name);
}

int
sr_node_set_module(sr_node_t *node, const char *module_name)
{
    CHECK_NULL_ARG2(node, module_name);
    return sr_mem_edit_string(node->_sr_mem, &node->module_name, module_name);
}

int
sr_node_set_string(sr_node_t *node, const char *string_val)
{
    return sr_val_set_string((sr_val_t *)node, string_val);
}

/**
 * @brief Insert child into the linked-list of children of a given parent node.
 */
void
sr_node_insert_child(sr_node_t *parent, sr_node_t *child)
{
    if (NULL == parent || NULL == child) {
        return;
    }
    if (NULL == parent->first_child) {
        parent->first_child = child;
    } else {
        parent->last_child->next = child;
    }
    if (SR_TREE_ITERATOR_T != child->type) {
        child->prev = parent->last_child;
        child->next = NULL;
        child->parent = parent;
    }
    parent->last_child = child;
}

int
sr_node_add_child(sr_node_t *parent, const char *child_name, const char *child_module_name,
        sr_node_t **child_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *child = NULL;

    CHECK_NULL_ARG2(parent, child_p);

    rc = sr_new_node(parent->_sr_mem, child_name, child_module_name, &child);

    if (SR_ERR_OK == rc) {
        sr_node_insert_child(parent, child);
        *child_p = child;
    }

    return rc;
}

/**
 * @brief Recursivelly duplicate sysrepo tree.
 */
static int
sr_dup_tree_recursive(sr_mem_ctx_t *sr_mem, sr_node_t *tree, size_t depth, sr_node_t **tree_dup_p, sr_node_t **iterator_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *tree_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG3(tree, tree_dup_p, iterator_p);

    if (0 == depth) {
        rc = sr_new_tree_ctx(sr_mem, tree->name, tree->module_name, &tree_dup);
    } else {
        rc = sr_new_node(sr_mem, tree->name, tree->module_name, &tree_dup);
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new sysrepo node.");

    rc = sr_dup_val_data((sr_val_t *)tree_dup, (sr_val_t *)tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node data.");

    if (SR_TREE_ITERATOR_T == tree_dup->type) {
        assert(NULL == *iterator_p);
        *iterator_p = tree_dup;
    } else {
        /* duplicate descendants */
        child = tree->first_child;
        while (child) {
            if (SR_TREE_ITERATOR_T == child->type && NULL != *iterator_p) {
                assert(NULL == child->next);
                sr_node_insert_child(tree_dup, *iterator_p);
            } else {
                rc = sr_dup_tree_recursive(tree_dup->_sr_mem, child, depth+1, &child_dup, iterator_p);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                sr_node_insert_child(tree_dup, child_dup);
            }
            child = child->next;
        }
    }

    *tree_dup_p = tree_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        if (NULL != sr_mem) {
            if (0 == depth) {
                sr_free_tree(tree_dup);
            }
        } else {
            sr_free_tree(tree_dup);
        }
    }

    return rc;
}

int
sr_dup_tree_ctx(sr_node_t *tree, sr_mem_ctx_t *sr_mem_dest, sr_node_t **tree_dup_p)
{
    sr_node_t *iterator = NULL;
    return sr_dup_tree_recursive(sr_mem_dest, tree, 0, tree_dup_p, &iterator);
}

int
sr_dup_tree(sr_node_t *tree, sr_node_t **tree_dup_p)
{
    return sr_dup_tree_ctx(tree, NULL, tree_dup_p);
}

int
sr_dup_trees_ctx(sr_node_t *trees, size_t count, sr_mem_ctx_t *sr_mem_dest, sr_node_t **trees_dup_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG2(trees, trees_dup_p);

    rc = sr_new_trees_ctx(sr_mem_dest, count, &trees_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new array of sysrepo nodes.");

    for (size_t i = 0; i < count; ++i) {
        sr_node_set_name(trees_dup + i, trees[i].name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node name.");
        sr_node_set_module(trees_dup + i, trees[i].module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate module of a sysrepo node.");
        rc = sr_dup_val_data((sr_val_t *)(trees_dup + i), (sr_val_t *)(trees + i));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");

        if (SR_TREE_ITERATOR_T != trees[i].type) {
            /* duplicate descendants */
            sr_node_t *iterator = NULL;
            child = trees[i].first_child;
            while (child) {
                rc = sr_dup_tree_recursive(trees_dup->_sr_mem, child, 1, &child_dup, &iterator);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                sr_node_insert_child(trees_dup + i, child_dup);
                child = child->next;
            }
        }
    }

    *trees_dup_p = trees_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_trees(trees_dup, count);
    }

    return rc;
}

int
sr_dup_trees(sr_node_t *trees, size_t count, sr_node_t **trees_dup_p)
{
    return sr_dup_trees_ctx(trees, count, NULL, trees_dup_p);
}

/**
 * @brief Construct string according to the format and the extra arguments, and then
 * print it in the given context.
 *
 * @param [in] print_ctx Print context to use for printing.
 * @param [in] format Format string followed by corresponding set of extra arguments.
 */
static int
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

/**
 * @brief Print single sysrepo tree node.
 *
 * @param [in] print_ctx Context for printing.
 * @param [in] node Sysrepo tree node to print.
 */
static int
sr_print_node(sr_print_ctx_t *print_ctx, sr_node_t *node)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(print_ctx, node);

    if (node->module_name && 0 < strlen(node->module_name)) {
        rc = sr_print(print_ctx, "%s:%s ", node->module_name, node->name);
    } else {
        rc = sr_print(print_ctx, "%s ", node->name);
    }
    CHECK_RC_MSG_RETURN(rc, "Failed to print name of a sysrepo tree node");

    switch (node->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        rc = sr_print(print_ctx, "(container)\n");
        break;
    case SR_LIST_T:
        rc = sr_print(print_ctx, "(list instance)\n");
        break;
    case SR_STRING_T:
        rc = sr_print(print_ctx, "= %s\n", node->data.string_val);
        break;
    case SR_BOOL_T:
        rc = sr_print(print_ctx, "= %s\n", node->data.bool_val ? "true" : "false");
        break;
    case SR_UINT8_T:
        rc = sr_print(print_ctx, "= %u\n", node->data.uint8_val);
        break;
    case SR_UINT16_T:
        rc = sr_print(print_ctx, "= %u\n", node->data.uint16_val);
        break;
    case SR_UINT32_T:
        rc = sr_print(print_ctx, "= %u\n", node->data.uint32_val);
        break;
    case SR_IDENTITYREF_T:
        rc = sr_print(print_ctx, "= %s\n", node->data.identityref_val);
        break;
    case SR_ENUM_T:
        rc = sr_print(print_ctx, "= %s\n", node->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        rc = sr_print(print_ctx, "(empty leaf)\n");
        break;
    default:
        rc = sr_print(print_ctx, "(unprintable)\n");
    }

    CHECK_RC_MSG_RETURN(rc, "Failed to print value of a sysrepo tree node");
    return rc;
}

/**
 * @brief Print sysrepo tree.
 *
 * @param [in] print_ctx Context for printing.
 * @param [in] tree Sysrepo tree to print.
 * @param [in] depth_limit Maximum number of tree levels to print.
 */
static int
sr_print_tree(sr_print_ctx_t *print_ctx, sr_node_t *tree, int depth_limit)
{
    int rc = SR_ERR_OK;
    sr_node_t *node = NULL, *pred = NULL, *parent = NULL;
    char *indent = NULL, *aux = NULL, *cur = NULL;
    int indent_len = 0, new_len = 0;
    int depth = 0;
    bool backtracking = false;

    CHECK_NULL_ARG(print_ctx);

    if (0 == depth_limit || NULL == tree) {
        return rc;
    }

    indent_len = 24;
    indent = calloc(indent_len, sizeof *indent);
    CHECK_NULL_NOMEM_GOTO(indent, rc, cleanup);

    parent = NULL;
    node = tree;
    backtracking = false;

    while (!backtracking || node != tree) {
        if (!backtracking) {
            /* print the indent */
            if (0 < depth) {
                if (indent_len < 4*(depth-1) + 1) {
                    new_len = MAX(2*indent_len, 4*(depth-1)+1);
                    aux = realloc(indent, new_len * sizeof *aux);
                    CHECK_NULL_NOMEM_GOTO(aux, rc, cleanup);
                    indent_len = new_len;
                }
                indent[4*(depth-1)] = '\0';
                cur = indent + 4*(depth-1);
                pred = parent;
                while (cur != indent) {
                    cur -= 4;
                    if (pred->next) {
                        memcpy(cur, " |  ", 4);
                    } else {
                        memcpy(cur, "    ", 4);
                    }
                    pred = pred->parent;
                }
                rc = sr_print(print_ctx, "%s |\n", indent);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to print indent for sysrepo tree node");
                if (depth >= depth_limit || SR_TREE_ITERATOR_T == node->type) {
                    rc = sr_print(print_ctx, "%s ...\n", indent);
                } else {
                    rc = sr_print(print_ctx, "%s -- ", indent);
                }
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to print indent for sysrepo tree node");
            }
            /* print the node */
            if (depth < depth_limit && SR_TREE_ITERATOR_T != node->type) {
                rc = sr_print_node(print_ctx, node);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to print sysrepo tree node");
            }
            /* next node */
            if (SR_TREE_ITERATOR_T == node->type) {
                node = parent;
                parent = node->parent;
                --depth;
                backtracking = true;
            } else if (depth < depth_limit && node->first_child) {
                parent = node;
                node = node->first_child;
                ++depth;
            } else if (depth < depth_limit && node->next) {
                node = node->next;
            } else {
                backtracking = true;
            }
        } else {
            /* backtracking */
            if (depth < depth_limit && node->next) {
                node = node->next;
                backtracking = false;
            } else {
                node = node->parent;
                parent = node->parent;
                --depth;
            }
        }
    }

cleanup:
    free(indent);
    return rc;
}

int
sr_print_tree_fd(int fd, sr_node_t *tree, int depth_limit)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_FD;
    print_ctx.method.fd = fd;

    return sr_print_tree(&print_ctx, tree, depth_limit);
}

int
sr_print_tree_stream(FILE *stream, sr_node_t *tree, int depth_limit)
{
    sr_print_ctx_t print_ctx = { 0, };

    print_ctx.type = SR_PRINT_STREAM;
    print_ctx.method.stream = stream;

    return sr_print_tree(&print_ctx, tree, depth_limit);
}

int
sr_print_tree_mem(char **mem_p, sr_node_t *tree, int depth_limit)
{
    int rc = SR_ERR_OK;
    sr_print_ctx_t print_ctx = { 0, };

    CHECK_NULL_ARG(mem_p);

    print_ctx.type = SR_PRINT_MEM;
    print_ctx.method.mem.buf = NULL;
    print_ctx.method.mem.len = 0;
    print_ctx.method.mem.size = 0;

    rc = sr_print_tree(&print_ctx, tree, depth_limit);
    if (SR_ERR_OK == rc) {
        *mem_p = print_ctx.method.mem.buf;
    } else {
        free(print_ctx.method.mem.buf);
    }
    return rc;
}
