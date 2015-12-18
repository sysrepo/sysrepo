/**
 * @file sr_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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
#include "sr_common.h"

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


int sr_str_join(const char *str1, const char *str2, char **result)
{
    CHECK_NULL_ARG3(str1, str2, result);
    char *res = NULL;
    size_t l1 = strlen(str1);
    size_t l2 = strlen(str2);
    res = malloc(l1 + l2 + 1);
    if (res == NULL) {
        SR_LOG_ERR_MSG("Calloc in sr_str_join failed.");
        return SR_ERR_OK;
    }
    strcpy(res, str1);
    strcpy(res + l1, str2);
    *result = res;
    return SR_ERR_OK;
}

int
sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree)
{
    CHECK_NULL_ARG2(file_name, data_tree);

    FILE *f = fopen(file_name, "w");
    if (NULL == f){
        SR_LOG_ERR("Failed to open file %s", file_name);
        return SR_ERR_IO;
    }

    fprintf(f, "<module>");
    if( 0 != lyd_print(f, data_tree, LYD_XML)){
        SR_LOG_ERR("Failed to write output into %s", file_name);
        return SR_ERR_INTERNAL;
    }
    fprintf(f, "</module>");
    fclose(f);
    return SR_ERR_OK;
}

