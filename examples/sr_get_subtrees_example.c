/**
 * @file sr_get_subtrees_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Example usage of sr_get_subtrees function.
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

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "sysrepo.h"
#include "sysrepo/trees.h"

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    const char *xpath = NULL;
    sr_node_t *subtrees = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;

    /* turn on debug logging to stderr - to see what's happening behind the scenes */
    sr_log_stderr(SR_LL_DBG);

    /* connect to sysrepo */
    rc = sr_connect("app1", SR_CONN_DEFAULT, &conn);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* get all list instances as separate trees */
    xpath = "/ietf-interfaces:interfaces/interface";
    rc = sr_get_subtrees(sess, xpath, SR_GET_SUBTREE_DEFAULT, &subtrees, &count);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* print the content of every subtree */
    printf("\n\n");
    for (size_t i = 0; i < count; ++i) {
        printf("Subtree No. %lu =\n", i+1);
        sr_print_tree(subtrees+i, INT_MAX);
        printf("\n");
    }
    printf("\n\n");

cleanup:
    if (NULL != subtrees) {
        sr_free_trees(subtrees, count);
    }
    if (NULL != sess) {
        sr_session_stop(sess);
    }
    if (NULL != conn) {
        sr_disconnect(conn);
    }
    return rc;
}
