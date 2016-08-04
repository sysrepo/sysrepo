/**
 * @file md_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Module Dependencies unit tests.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include "module_dependencies.h"
#include "sr_common.h"
#include "test_data.h"

#define TEST_MODULE_PREFIX     "md_test_module-"
#define TEST_SUBMODULE_PREFIX  "md_test_submodule-"
#define TEST_MODULE_EXT        ".yang"

typedef struct md_test_inserted_modules_s {
    bool A, B, C, D_rev1, D_rev2, E_rev1, E_rev2;
} md_test_inserted_modules_t;

static const char * const md_module_A_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "A" TEST_MODULE_EXT;
static const char * const md_module_A_body =
"  container base-container{\n"
"    description \"Trivial container which is augmented by other modules.\";\n"
"    leaf name {\n"
"      type string;\n"
"    }\n"
"  }\n"
"\n"
"  identity base-identity {\n"
"    description \"Base identity from which specific identities are derived.\";\n"
"  }";

static const char * const md_module_B_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "B" TEST_MODULE_EXT;
static const char * const md_module_B_body =
"  container inst-ids {\n"
"    leaf-list inst-id {\n"
"      type instance-identifier;\n"
"    }\n"
"  }";

static const char * const md_submodule_B_sub1_filepath = TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "Bs1" TEST_MODULE_EXT;
static const char * const md_submodule_B_sub1_body =
"  identity B-ext-identity {\n"
"    base A:base-identity;\n"
"  }";

static const char * const md_submodule_B_sub2_filepath = TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "Bs2" TEST_MODULE_EXT;
static const char * const md_submodule_B_sub2_body =
"  augment \"/A:base-container\" {\n"
"    leaf B-ext-leaf {\n"
"      type uint32;\n"
"    }\n"
"    leaf B-ext-inst-id {\n"
"      type instance-identifier;\n"
"    }\n"
"    leaf B-ext-op-data {\n"
"       type uint32;\n"
"       config false;\n"
"    }\n"
"  }";

static const char * const md_submodule_B_sub3_filepath = TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "Bs3" TEST_MODULE_EXT;
static const char * const md_submodule_B_sub3_body =
"  container op-data {\n"
"    config false;\n"
"    leaf-list list-with-op-data {\n"
"      type string;\n"
"    }\n"
"    container nested-op-data {\n"
"      leaf nested-leaf1 {\n"
"        type string;\n"
"      }\n"
"      leaf nested-leaf2 {\n"
"        type int8;\n"
"      }\n"
"    }\n"
"  }";

static const char * const md_module_C_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "C" TEST_MODULE_EXT;
static const char * const md_module_C_body =
"  augment \"/A:base-container\" {\n"
"    container C-ext-container {\n"
"      leaf C-ext-leaf {\n"
"        type identityref {\n"
"          base A:base-identity;\n"
"        }\n"
"      }\n"
"    }\n"
"  }\n"
"\n"
"  identity C-ext-identity1 {\n"
"    base A:base-identity;\n"
"  }\n"
"  identity C-ext-identity2 {\n"
"    base A:base-identity;\n"
"  }\n"
"\n"
"  leaf inst-id1 {\n"
"    type instance-identifier;\n"
"  }\n"
"  leaf inst-id2 {\n"
"    type instance-identifier;\n"
"  }\n"
"  container partly-op-data {\n"
"    config true;\n"
"    leaf-list list-with-config-data {\n"
"      type string;\n"
"    }\n"
"    container nested-op-data {\n"
"      config false;\n"
"      leaf nested-leaf1 {\n"
"        type string;\n"
"      }\n"
"      leaf nested-leaf2 {\n"
"        type int8;\n"
"      }\n"
"    }\n"
"  }";

static const char * const md_module_D_rev1_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "D@2016-06-10" TEST_MODULE_EXT;
static const char * const md_module_D_rev1_body =
"  revision \"2016-06-10\" {\n"
"    description \"First revision of D.\";\n"
"  }\n"
"\n"
"  augment \"/A:base-container/C:C-ext-container\" {\n"
"    uses Dcommon-grouping;\n"
"  }\n"
"\n"
"  identity D-extA-identity {\n"
"    base A:base-identity;\n"
"  }";

static const char * const md_module_D_rev2_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "D@2016-06-20" TEST_MODULE_EXT;
static const char * const md_module_D_rev2_body =
"  revision \"2016-06-20\" {\n"
"    description \"Second revision of D.\";\n"
"  }\n"
"\n"
"  revision \"2016-06-10\" {\n"
"    description \"First revision of D.\";\n"
"  }\n"
"\n"
"  augment \"/A:base-container/C:C-ext-container\" {\n"
"    uses Dcommon-grouping;\n"
"    leaf D-ext-op-data2 {\n"
"       type uint32;\n"
"       config false;\n"
"    }\n"
"    leaf D-ext-inst-id2 {\n"
"      type instance-identifier;\n"
"    }\n"
"  }\n"
"\n"
"  identity D-extB-identity {\n"
"    base B:B-ext-identity;\n"
"  }";

static const char * const md_submodule_D_common_filepath = TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "Dcommon" TEST_MODULE_EXT;
static const char * const md_submodule_D_common_body =
"  revision \"2016-06-10\" {\n"
"    description \"First and the only revision of Dcommon.\";\n"
"  }\n"
"\n"
"  grouping Dcommon-grouping {\n"
"    leaf D-ext-leaf {\n"
"      type identityref {\n"
"        base mod-C:C-ext-identity1;\n"
"      }\n"
"    }\n"
"    leaf D-ext-op-data {\n"
"       type uint32;\n"
"       config false;\n"
"    }\n"
"    leaf D-ext-inst-id {\n"
"      type instance-identifier;\n"
"    }\n"
"  }";

static const char * const md_module_E_rev1_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "E@2016-06-11" TEST_MODULE_EXT;
static const char * const md_module_E_rev1_body =
"  revision \"2016-06-11\" {\n"
"    description \"First revision of E.\";\n"
"  }\n"
"\n"
"  leaf id-ref {\n"
"    type identityref {\n"
"      base D:D-extA-identity;\n"
"    }\n"
"  }\n"
"\n"
"  list inst-id-list {\n"
"    key \"name\";\n"
"    leaf name {\n"
"      type string;\n"
"    }\n"
"    leaf inst-id {\n"
"      type instance-identifier;\n"
"    }\n"
"  }"
"  container partly-op-data {\n"
"    config true;\n"
"    leaf-list list-with-op-data {\n"
"      config false;\n"
"      type string;\n"
"    }\n"
"    container nested-op-data {\n"
"      config true;\n"
"      leaf nested-leaf1 {\n"
"        config false;\n"
"        type string;\n"
"      }\n"
"      leaf nested-leaf2 {\n"
"        config false;\n"
"        type int8;\n"
"      }\n"
"    }\n"
"  }";

static const char * const md_module_E_rev2_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "E@2016-06-21" TEST_MODULE_EXT;
static const char * const md_module_E_rev2_body =
"  revision \"2016-06-21\" {\n"
"    description \"Second revision of E.\";\n"
"  }\n"
"\n"
"  revision \"2016-06-11\" {\n"
"    description \"First revision of E.\";\n"
"  }\n"
"\n"
"  leaf id-ref {\n"
"    type identityref {\n"
"      base D:D-extB-identity;\n"
"    }\n"
"  }\n"
"\n"
"  list inst-id-list {\n"
"    key \"name\";\n"
"    leaf name {\n"
"      type string;\n"
"    }\n"
"    leaf inst-id {\n"
"      type instance-identifier;\n"
"    }\n"
"  }"
"  container partly-op-data {\n"
"    config true;\n"
"    leaf-list list-with-op-data {\n"
"      config false;\n"
"      type string;\n"
"    }\n"
"    container nested-op-data {\n"
"      config true;\n"
"      leaf nested-leaf1 {\n"
"        config false;\n"
"        type string;\n"
"      }\n"
"      leaf nested-leaf2 {\n"
"        config false;\n"
"        type int8;\n"
"      }\n"
"      leaf added-config-leaf {\n"
"        config true;\n"
"        type int8;\n"
"      }\n"
"    }\n"
"  }";


/**
 * @brief Always get a new instance of libyang context, while the old one is released.
 */
static struct ly_ctx *
md_get_new_ly_ctx()
{
    static struct ly_ctx *ly_ctx = NULL;
    if (NULL != ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    return ly_ctx;
}

/**
 * @brief Print out all the imports/includes of a (sub)module.
 */
static void
md_output_module_deps(FILE *fp, va_list args)
{
    const char *arg = NULL;
    char *arg_copy = NULL, *dep = NULL;
    char *rev = NULL;
    bool include = false;

    do {
        arg = va_arg(args, const char *);
        if (NULL == arg) {
            break;
        }
        arg_copy = strdup(arg);
        dep = arg_copy;
        include = false;
        if (4 < strlen(arg_copy)) {
            if (0 == strncmp("sub-", arg_copy, 4)) {
                dep = arg_copy + 4;
                include = true;
            } else if (0 == strncmp("mod-", arg_copy, 4)) {
                dep = arg_copy + 4;
                include = false;
            }
        }
        rev = strchr(dep, '@');
        if (NULL != rev) {
            *rev = '\0';
        }
        if (include) {
            fprintf(fp,
                    "  include " TEST_SUBMODULE_PREFIX "%s%s\n", dep,
                    rev ? " {" : ";");
        } else {
            fprintf(fp,
                    "  import " TEST_MODULE_PREFIX "%s {\n"
                    "    prefix %s;\n%s", dep, arg_copy,
                    rev ? "" : "  }\n");
        }
        if (NULL != rev) {
            fprintf(fp,
                    "    revision-date \"%s\";\n  }\n", rev + 1);
        }
        free(arg_copy);
    } while (true);
}

/**
 * @brief Construct a yang schema file for a module.
 */
static char *
md_create_module_yang_schema(const char *name, const char *destpath, const char *body, ...)
{
    va_list args;
    FILE *fp = NULL;

    fp = fopen(destpath, "w");
    assert_non_null(fp);
    fprintf(fp,
            "module " TEST_MODULE_PREFIX "%s {\n"
            "  namespace \"urn:ietf:params:xml:ns:yang:%s\";\n"
            "  prefix %s;\n", name, name, name);

    va_start(args, body);
    md_output_module_deps(fp, args);
    va_end(args);

    fprintf(fp,
            "  organization \"sysrepo.org\";\n"
            "  description \"module used by md_test referenced as '%s'\";\n"
            "  contact \"sysrepo-devel@sysrepo.org\";\n"
            "\n"
            "%s\n"
            "}", name, body);
    fclose(fp);
    return 0;
}

/**
 * @brief Construct a yang schema file for a submodule.
 */
static char *
md_create_submodule_yang_schema(const char *name, const char *belongsto, const char *destpath, const char *body, ...)
{
    va_list args;
    FILE *fp = NULL;

    fp = fopen(destpath, "w");
    assert_non_null(fp);
    fprintf(fp,
            "submodule " TEST_SUBMODULE_PREFIX "%s {\n"
            "  belongs-to " TEST_MODULE_PREFIX "%s {\n"
            "    prefix %s;\n"
            "  }\n", name, belongsto, belongsto);

    va_start(args, body);
    md_output_module_deps(fp, args);
    va_end(args);

    fprintf(fp,
            "  organization \"sysrepo.org\";\n"
            "  description \"submodule used by md_test referenced as '%s'\";\n"
            "  contact \"sysrepo-devel@sysrepo.org\";\n"
            "\n"
            "%s\n"
            "}", name, body);
    fclose(fp);
    return 0;
}

static int
md_tests_setup(void **state)
{
    md_create_module_yang_schema("A", md_module_A_filepath, md_module_A_body, NULL);
    md_create_module_yang_schema("B", md_module_B_filepath, md_module_B_body, "sub-Bs1", "sub-Bs2", "sub-Bs3", NULL);
    md_create_submodule_yang_schema("Bs1", "B", md_submodule_B_sub1_filepath, md_submodule_B_sub1_body,
            /* "sub-Bs2" TODO: uncomment once the second issue from libyang/#97 is fixed ,*/ "A", NULL);
    md_create_submodule_yang_schema("Bs2", "B", md_submodule_B_sub2_filepath, md_submodule_B_sub2_body,
            /* "sub-Bs3" TODO: uncomment once the second issue from libyang/#97 is fixed ,*/ "A", NULL);
    md_create_submodule_yang_schema("Bs3", "B", md_submodule_B_sub3_filepath, md_submodule_B_sub3_body, NULL);
    md_create_module_yang_schema("C", md_module_C_filepath, md_module_C_body, "A", NULL);
    md_create_module_yang_schema("D", md_module_D_rev1_filepath, md_module_D_rev1_body, "sub-Dcommon@2016-06-10", "A", "C", NULL);
    md_create_module_yang_schema("D", md_module_D_rev2_filepath, md_module_D_rev2_body, "sub-Dcommon@2016-06-10", "A", "B", "C", NULL);
    md_create_submodule_yang_schema("Dcommon", "D", md_submodule_D_common_filepath, md_submodule_D_common_body,
            "mod-C" /* "TODO: rename to just "C" once the second issue from libyang/#97 is fixed */, NULL);
    md_create_module_yang_schema("E", md_module_E_rev1_filepath, md_module_E_rev1_body, "D@2016-06-10", NULL);
    md_create_module_yang_schema("E", md_module_E_rev2_filepath, md_module_E_rev2_body, "D@2016-06-20", NULL);
    return 0;
}

static int
md_tests_teardown(void **state)
{
//    system("rm -f " TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "*");
//    system("rm -f " TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "*");
    return 0;
}

/**
 * @brief Test initialization and destruction of the Module Dependencies context.
 */
static void
md_test_init_and_destroy(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;

    /* initialize context */
    rc = md_init(md_get_new_ly_ctx(), NULL, TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(0, rc);
    assert_non_null(md_ctx->schema_search_dir);
    assert_int_equal(md_ctx->fd, -1);
    assert_non_null(md_ctx->ly_ctx);
    assert_non_null(md_ctx->data_tree);
    assert_non_null(md_ctx->modules);
    assert_non_null(md_ctx->modules_btree);

    /* destroy context */
    md_destroy(md_ctx);
}

/**
 * @brief Validate dependency between modules.
 */
static void
md_test_validate_dependency(const sr_llist_t *deps, const char *module_name, md_dep_type_t type, bool direct,
                            md_test_inserted_modules_t inserted)
{
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dep = NULL;
    bool found = false;

    if (0 == strcmp("A", module_name)) {
        type = inserted.A ? type : MD_DEP_NONE;
    } else if (0 == strcmp("B", module_name)) {
        type = inserted.B ? type : MD_DEP_NONE;
    } else if (0 == strcmp("C", module_name)) {
        type = inserted.C ? type : MD_DEP_NONE;
    } else if (0 == strcmp("D@2016-06-10", module_name)) {
        type = inserted.D_rev1 ? type : MD_DEP_NONE;
    } else if (0 == strcmp("D@2016-06-20", module_name)) {
        type = inserted.D_rev2 ? type : MD_DEP_NONE;
    } else if (0 == strcmp("E@2016-06-11", module_name)) {
        type = inserted.E_rev1 ? type : MD_DEP_NONE;
    } else if (0 == strcmp("E@2016-06-21", module_name)) {
        type = inserted.E_rev2 ? type : MD_DEP_NONE;
    }

    dep_node = deps->first;
    while (dep_node) {
        dep = (md_dep_t*)dep_node->data;
        if (0 == strcmp(md_get_module_fullname(dep->dest)
                            + (dep->dest->submodule ? strlen(TEST_SUBMODULE_PREFIX) : strlen(TEST_MODULE_PREFIX)),
                        module_name)) {
            assert_false(found);
            found = true;
            assert_int_equal(type, dep->type);
            assert_int_equal(direct, dep->direct);
        }
        dep_node = dep_node->next;
    }

    if (!found) {
        assert_int_equal(MD_DEP_NONE, type);
    }
}

/**
 * @brief Check size of a linked-list.
 */
static void
md_test_check_list_size(sr_llist_t *list, size_t expected)
{
    size_t size = 0;
    sr_llist_node_t *node = list->first;

    while (node) {
        ++size;
        node = node->next;
    }
    assert_int_equal(expected, size);
}

/**
 * @brief Validate subtree reference.
 */
static void
md_test_validate_subtree_ref(md_ctx_t *md_ctx, sr_llist_t *list, const char *xpath,
                             const char *orig_module_name)
{
    sr_llist_node_t *node = list->first;
    md_subtree_ref_t *subtree_ref = NULL;
    md_module_t *orig = NULL;
    char *orig_name_cpy = strdup(orig_module_name);
    char full_module_name[PATH_MAX] = { 0, };

    char *at = strchr(orig_name_cpy, '@');
    if (NULL != at) {
        *at = '\0';
        ++at;
    } else {
        at = "";
    }

    /* test if the module is inserted */
    snprintf(full_module_name, PATH_MAX, "%s%s", TEST_MODULE_PREFIX, orig_name_cpy);
    int rc = md_get_module_info(md_ctx, full_module_name, at, &orig);

    while (node) {
        subtree_ref = (md_subtree_ref_t *)node->data;
        if (0 == strcmp(subtree_ref->xpath, xpath)) {
            assert_string_equal(subtree_ref->orig->name, full_module_name);
            if (0 == strcmp(subtree_ref->orig->revision_date, at)) {
                assert_int_equal(SR_ERR_OK, rc);
                free(orig_name_cpy);
                return;
            }
        }
        node = node->next;
    }
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    free(orig_name_cpy);
}

/**
 * @brief Validate Module Dependencies context.
 */
static void
md_test_validate_context(md_ctx_t *md_ctx, md_test_inserted_modules_t inserted)
{
    int rc = 0;
    md_module_t *module = NULL;

    /* validate module A */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "A", NULL, &module);
    if (inserted.A) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "A", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "A", md_get_module_fullname(module));
        assert_string_equal("A", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:A", module->ns);
        assert_string_equal(md_module_A_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, inserted.B + inserted.D_rev1 + 2*inserted.D_rev2);
        md_test_validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "B:B-ext-inst-id", "B");
        md_test_validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:Dcommon-grouping"
                                     "/D-ext-inst-id", "D@2016-06-10");
        md_test_validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:Dcommon-grouping"
                                     "/D-ext-inst-id", "D@2016-06-20");
        md_test_validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-inst-id2", "D@2016-06-20");
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, inserted.B + inserted.D_rev1 + 2*inserted.D_rev2);
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "B:B-ext-op-data", "B");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:Dcommon-grouping"
                                     "/D-ext-op-data", "D@2016-06-10");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:Dcommon-grouping"
                                     "/D-ext-op-data", "D@2016-06-20");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-op-data2", "D@2016-06-20");
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_EXTENSION, false, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_IMPORT, false, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module B */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "B", NULL, &module);
    if (inserted.B) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "B", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "B", md_get_module_fullname(module));
        assert_string_equal("B", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:B", module->ns);
        assert_string_equal(md_module_B_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 1);
        md_test_validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "B:inst-ids/inst-id", "B");
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 1);
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "B:op-data", "B");
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_IMPORT, false, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate submodule Bs1 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs1", NULL, &module);
    if (inserted.B) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs1", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs1", md_get_module_fullname(module));
        assert_string_equal("", module->prefix);
        assert_string_equal("", module->ns);
        assert_string_equal(md_submodule_B_sub1_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_check_list_size(module->deps, 0);
        md_test_check_list_size(module->inv_deps, 1);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_INCLUDE, true, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate submodule Bs2 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs2", NULL, &module);
    if (inserted.B) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs2", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs2", md_get_module_fullname(module));
        assert_string_equal("", module->prefix);
        assert_string_equal("", module->ns);
        assert_string_equal(md_submodule_B_sub2_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_check_list_size(module->deps, 0);
        md_test_check_list_size(module->inv_deps, 1);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_INCLUDE, true, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate submodule Bs3 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs3", NULL, &module);
    if (inserted.B) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs3", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Bs3", md_get_module_fullname(module));
        assert_string_equal("", module->prefix);
        assert_string_equal("", module->ns);
        assert_string_equal(md_submodule_B_sub3_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_check_list_size(module->deps, 0);
        md_test_check_list_size(module->inv_deps, 1);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_INCLUDE, true, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module C */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "C", NULL, &module);
    if (inserted.C) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "C", module->name);
        assert_string_equal("", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "C", md_get_module_fullname(module));
        assert_string_equal("C", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:C", module->ns);
        assert_string_equal(md_module_C_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 2);
        md_test_validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "C:inst-id1", "C");
        md_test_validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "C:inst-id2", "C");
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 1);
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "C:partly-op-data/nested-op-data", "C");
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_IMPORT, false, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module D-rev1 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10", &module);
    if (inserted.D_rev1) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "D", module->name);
        assert_string_equal("2016-06-10", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "D@2016-06-10", md_get_module_fullname(module));
        assert_string_equal("D", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:D", module->ns);
        assert_string_equal(md_module_D_rev1_filepath, module->filepath);
        if (inserted.D_rev2) {
            assert_false(module->latest_revision);
        } else {
            assert_true(module->latest_revision);
        }
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module D-rev2 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20", &module);
    if (inserted.D_rev2) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "D", module->name);
        assert_string_equal("2016-06-20", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "D@2016-06-20", md_get_module_fullname(module));
        assert_string_equal("D", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:D", module->ns);
        assert_string_equal(md_module_D_rev2_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_EXTENSION, false, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_EXTENSION, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_IMPORT, true, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate submodule Dcommon */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Dcommon", NULL, &module);
    if (inserted.D_rev1 || inserted.D_rev2) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Dcommon", module->name);
        assert_string_equal("2016-06-10", module->revision_date);
        assert_string_equal(TEST_SUBMODULE_PREFIX "Dcommon@2016-06-10", md_get_module_fullname(module));
        assert_string_equal("", module->prefix);
        assert_string_equal("", module->ns);
        assert_string_equal(md_submodule_D_common_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_check_list_size(module->deps, 0);
        md_test_check_list_size(module->inv_deps, inserted.D_rev1 + inserted.D_rev2);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_INCLUDE, true, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_INCLUDE, true, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module E-rev1 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-11", &module);
    if (inserted.E_rev1) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "E", module->name);
        assert_string_equal("2016-06-11", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "E@2016-06-11", md_get_module_fullname(module));
        assert_string_equal("E", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:E", module->ns);
        assert_string_equal(md_module_E_rev1_filepath, module->filepath);
        if (inserted.E_rev2) {
            assert_false(module->latest_revision);
        } else {
            assert_true(module->latest_revision);
        }
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 1);
        md_test_validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "E:inst-id-list/inst-id", "E@2016-06-11");
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 2);
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/list-with-op-data", "E@2016-06-11");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/nested-op-data", "E@2016-06-11");
        /* outsiide references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
    } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }

    /* validate module E-rev2 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-21", &module);
    if (inserted.E_rev2) {
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(module);
        assert_string_equal(TEST_MODULE_PREFIX "E", module->name);
        assert_string_equal("2016-06-21", module->revision_date);
        assert_string_equal(TEST_MODULE_PREFIX "E@2016-06-21", md_get_module_fullname(module));
        assert_string_equal("E", module->prefix);
        assert_string_equal("urn:ietf:params:xml:ns:yang:E", module->ns);
        assert_string_equal(md_module_E_rev2_filepath, module->filepath);
        assert_true(module->latest_revision);
        /* inst_ids */
        md_test_check_list_size(module->inst_ids, 1);
        md_test_validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "E:inst-id-list/inst-id", "E@2016-06-21");
        /* op_data_subtrees */
        md_test_check_list_size(module->op_data_subtrees, 3);
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/list-with-op-data", "E@2016-06-21");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/nested-op-data/nested-leaf1", "E@2016-06-21");
        md_test_validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/nested-op-data/nested-leaf2", "E@2016-06-21");
        /* outside references */
        assert_non_null(module->ly_data);
        assert_non_null(module->ll_node);
        /* dependencies */
        md_test_validate_dependency(module->deps, "A", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->deps, "B", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "C", MD_DEP_IMPORT, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "D@2016-06-20", MD_DEP_IMPORT, true, inserted);
        md_test_validate_dependency(module->deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "A", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "B", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs1", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs2", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Bs3", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "C", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "D@2016-06-20", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "Dcommon@2016-06-10", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-11", MD_DEP_NONE, false, inserted);
        md_test_validate_dependency(module->inv_deps, "E@2016-06-21", MD_DEP_NONE, false, inserted);
     } else {
        assert_int_equal(SR_ERR_NOT_FOUND, rc);
        assert_null(module);
    }
}

/*
 * @brief Test md_insert_module().
 */
static void
md_test_insert_module(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    md_test_inserted_modules_t inserted;
    memset(&inserted, 0, sizeof inserted);

    /* initialize context */
    rc = md_init(md_get_new_ly_ctx(), NULL, TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    md_test_validate_context(md_ctx, inserted);

    /* insert module A */
    rc = md_insert_module(md_ctx, md_module_A_filepath);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.A = true;
    md_test_validate_context(md_ctx, inserted);

    /* insert module B */
    rc = md_insert_module(md_ctx, md_module_B_filepath);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.B = true;
    md_test_validate_context(md_ctx, inserted);

    /* insert module C */
    rc = md_insert_module(md_ctx, md_module_C_filepath);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.C = true;
    md_test_validate_context(md_ctx, inserted);

    /* insert module E-rev1 (D-rev1 should get inserted automatically) */
    rc = md_insert_module(md_ctx, md_module_E_rev1_filepath);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev1 = inserted.E_rev1 = true;
    md_test_validate_context(md_ctx, inserted);

    /* insert module E-rev2 (D-rev2 should get inserted automatically) */
    rc = md_insert_module(md_ctx, md_module_E_rev2_filepath);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev2 = inserted.E_rev2 = true;
    md_test_validate_context(md_ctx, inserted);

    /* flush changes into the internal data file */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* destroy context */
    md_destroy(md_ctx);

    /* reload dependencies from the file and re-test */
    rc = md_init(md_get_new_ly_ctx(), NULL, TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    md_test_validate_context(md_ctx, inserted);

    /* no write-lock this time */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* destroy context for the final time */
    md_destroy(md_ctx);
}

/*
 * @brief Test md_remove_module().
 */
static void
md_test_remove_module(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    md_test_inserted_modules_t inserted;
    memset(&inserted, 1, sizeof inserted);

    /* initialize context */
    rc = md_init(md_get_new_ly_ctx(), NULL, TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    md_test_validate_context(md_ctx, inserted);

    /* there is no module named F */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "F", NULL);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* initialy only the module E can be removed (both rev1, rev2) */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "A", NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "B", NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "C", NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* remove module E-rev2 */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-21");
    assert_int_equal(SR_ERR_OK, rc);
    inserted.E_rev2 = false;
    md_test_validate_context(md_ctx, inserted);

    /* remove module D-rev2 */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20");
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev2 = false;
    md_test_validate_context(md_ctx, inserted);

    /* now there are no modules dependent on B, remove it */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "B", ""); /*< try "" instead of NULL */
    assert_int_equal(SR_ERR_OK, rc);
    inserted.B = false;
    md_test_validate_context(md_ctx, inserted);

    /* still can't remove A, C, D-rev1 */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "A", NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "C", NULL);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10");
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* B is not present anymore */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "B", NULL);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* remove module E-rev1 */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-11");
    assert_int_equal(SR_ERR_OK, rc);
    inserted.E_rev1 = false;
    md_test_validate_context(md_ctx, inserted);

    /* remove module D-rev1 */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10");
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev1 = false;
    md_test_validate_context(md_ctx, inserted);

    /* remove module C */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "C", NULL);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.C = false;
    md_test_validate_context(md_ctx, inserted);

    /* finally remove module A */
    rc = md_remove_module(md_ctx, TEST_MODULE_PREFIX "A", NULL);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.A = false;
    md_test_validate_context(md_ctx, inserted);

    /* flush changes into the internal data file */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* destroy context */
    md_destroy(md_ctx);

    /* reload dependencies from the file and re-test */
    rc = md_init(md_get_new_ly_ctx(), NULL, TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    md_test_validate_context(md_ctx, inserted);

    /* no write-lock this time */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* destroy context for the final time */
    md_destroy(md_ctx);
}

int main(){
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(md_test_init_and_destroy),
            cmocka_unit_test(md_test_insert_module),
            cmocka_unit_test(md_test_remove_module),
    };

    return cmocka_run_group_tests(tests, md_tests_setup, md_tests_teardown);
}

