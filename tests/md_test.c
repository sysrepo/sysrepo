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
#include "system_helper.h"

#define TEST_MODULE_PREFIX     "md_test_module-"
#define TEST_SUBMODULE_PREFIX  "md_test_submodule-"
#define TEST_MODULE_EXT        ".yang"

typedef struct md_test_inserted_modules_s {
    bool A, B, C, D_rev1, D_rev2, E, F, V;
} md_test_inserted_modules_t;

md_test_inserted_modules_t inserted;
md_test_inserted_modules_t implemented; /**< inserted AND implemented */

typedef struct md_test_dep_s {
    md_dep_type_t type;
    bool direct;
    sr_list_t *orig_modules;
} md_test_dep_t;

static const char * const md_module_A_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "A" TEST_MODULE_EXT;
static const char * const md_module_A_body =
"  container base-container{\n"
"    description \"Trivial container which is augmented by other modules.\";\n"
"    leaf name {\n"
"      type string;\n"
"    }\n"
"    leaf num {\n"
"      type int16;\n"
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
"  }\n"
"\n"
"  leaf tax-enabled {\n"
"    when \"/A:base-container/A:name = 'tax authority'\";\n"
"    type boolean;\n"
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
"    leaf avoid-data-loop {\n"
"      type leafref {\n"
"        path \"/A:base-container/B:B-ext-leaf\";\n"
"      }\n"
"    }\n"
"  }\n"
"\n"
"  leaf B-data-deps-on-A {\n"
"    type leafref {\n"
"      path \"/A:base-container/B:B-ext-leaf\";\n"
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
"  }\n"
"\n"
"  container conditional-data {\n"
"    leaf limit {\n"
"      type int16;\n"
"    }\n"
"    leaf tax {\n"
"      when \"/A:base-container/A:num > ../limit\";\n"
"      type int16;\n"
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
"  }\n"
"\n"
"  leaf vat {\n"
"    must \". <= /C:conditional-data/C:tax\";\n"
"    type uint16;\n"
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
"    leaf A-data-deps-on-B {\n"
"      type leafref {\n"
"        path \"/B:inst-ids/B:inst-id\";\n"
"      }\n"
"    }\n"
"  }\n"
"\n"
"  identity D-extB-identity {\n"
"    base B:B-ext-identity;\n"
"  }\n"
"\n"
"  leaf vat {\n"
"    must \". <= /C:conditional-data/C:tax\";\n"
"    must \"/B:tax-enabled = 'true'\";\n"
"    type uint16;\n"
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

static const char * const md_module_E_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "E" TEST_MODULE_EXT;
static const char * const md_module_E_body =
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
"  }\n"
"\n"
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
"  }\n"
"\n"
"  leaf E-data-deps-on-C {\n"
"    type leafref {\n"
"      path \"/C:inst-id1\";\n"
"    }\n"
"  }";

static const char * const md_module_F_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "F" TEST_MODULE_EXT;
static const char * const md_module_F_body =
"  revision \"2016-06-21\" {\n"
"    description \"First revision of F.\";\n"
"  }\n"
"\n"
"  container data {\n"
"    config true;\n"
"    leaf-list list-with-data {\n"
"      type string;\n"
"    }\n"
"  }";

static const char * const md_module_X_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "X" TEST_MODULE_EXT;
static const char * const md_module_X_body =
"  grouping config-data {\n"
"    leaf config-data1 {\n"
"      type uint8;\n"
"    }\n"
"    leaf config-data2 {\n"
"      type uint8;\n"
"    }\n"
"  }\n"
"  \n"
"  grouping state-data {\n"
"    leaf state-data1 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"    leaf state-data2 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"  }\n"
"  \n"
"  grouping mixed-data {\n"
"    leaf state-data {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"    leaf config-data {\n"
"      type uint8;\n"
"    }\n"
"  }\n"
"  \n"
"  grouping nested-state-data1 {\n"
"    uses state-data;\n"
"    leaf state-data3 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"    leaf state-data4 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"  }\n"
"  \n"
"  grouping nested-state-data2 {\n"
"    uses mixed-data;\n"
"    leaf state-data2 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"    leaf state-data3 {\n"
"      config false;\n"
"      type uint8;\n"
"    }\n"
"  }\n"
"  \n"
"  container container-1 {\n"
"    uses config-data;\n"
"    container sensors {\n"
"      config false;\n"
"      leaf temperature {\n"
"        type uint8;\n"
"      }\n"
"      leaf humidity {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-2 {\n"
"    uses state-data;\n"
"    container sensors {\n"
"      config false;\n"
"      leaf temperature {\n"
"        type uint8;\n"
"      }\n"
"      leaf humidity {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-3 {\n"
"    uses state-data;\n"
"    container configuration {\n"
"      leaf config1 {\n"
"        type uint8;\n"
"      }\n"
"      leaf config2 {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-4 {\n"
"    uses mixed-data;\n"
"    container sensors {\n"
"      config false;\n"
"      leaf temperature {\n"
"        type uint8;\n"
"      }\n"
"      leaf humidity {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-5 {\n"
"    uses nested-state-data1;\n"
"    container sensors {\n"
"      config false;\n"
"      leaf temperature {\n"
"        type uint8;\n"
"      }\n"
"      leaf humidity {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-6 {\n"
"    uses nested-state-data2;\n"
"    container sensors {\n"
"      config false;\n"
"      leaf temperature {\n"
"        type uint8;\n"
"      }\n"
"      leaf humidity {\n"
"        type uint8;\n"
"      }\n"
"    }\n"
"  }\n"
"  \n"
"  container container-7 {\n"
"    uses config-data;\n"
"    uses mixed-data;\n"
"  }\n"
"  \n"
"  container container-8 {\n"
"    grouping nested-mixed-data {\n"
"      leaf cfg-property {\n"
"        type string;\n"
"      }\n"
"      container sensors {\n"
"        config false;\n"
"        leaf temperature {\n"
"         type int8;\n"
"        }\n"
"        leaf humidity {\n"
"         type int8;\n"
"        }\n"
"      }\n"
"    }\n"
"  \n"
"    container nested-container1 {\n"
"      uses nested-mixed-data;\n"
"    }\n"
"  \n"
"    container nested-container2 {\n"
"      uses nested-mixed-data;\n"
"    }\n"
"  }";


static const char * const md_module_V_filepath = TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "V" TEST_MODULE_EXT;
static const char * const md_module_V_body =
"  deviation \"/A:base-container/A:num\" {\n"
"    deviate replace {\n"
"      type uint8;\n"
"    }\n"
"  }";



static md_test_dep_t *
md_test_dep(md_dep_type_t type, int is_direct, ...)
{
    md_test_dep_t *dep = NULL;
    size_t orig_cnt = 0;
    const char *orig = NULL;
    va_list va;

    dep = calloc(1, sizeof *dep);
    assert_non_null_bt(dep);
    assert_int_equal_bt(SR_ERR_OK, sr_list_init(&dep->orig_modules));

    dep->type = type;
    dep->direct = is_direct;

    if (MD_DEP_DATA == type) {
        va_start(va, is_direct);
        orig_cnt = va_arg(va, int);

        for (int i = 0; i < orig_cnt; ++i) {
            orig = va_arg(va, const char *);
            assert_non_null_bt((void *)orig);
            assert_int_equal_bt(SR_ERR_OK, sr_list_add(dep->orig_modules, (void *)orig));
        }

        va_end(va);
    }

    return dep;
}

/**
 * @brief Print out all the imports/includes of a (sub)module.
 */
static void
output_module_deps(FILE *fp, va_list args)
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
create_module_yang_schema(const char *name, const char *destpath, const char *body, ...)
{
    va_list args;
    FILE *fp = NULL;

    fp = fopen(destpath, "w");
    assert_non_null_bt(fp);
    fprintf(fp,
            "module " TEST_MODULE_PREFIX "%s {\n"
            "  namespace \"urn:ietf:params:xml:ns:yang:%s\";\n"
            "  prefix %s;\n", name, name, name);

    va_start(args, body);
    output_module_deps(fp, args);
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
create_submodule_yang_schema(const char *name, const char *belongsto, const char *destpath, const char *body, ...)
{
    va_list args;
    FILE *fp = NULL;

    fp = fopen(destpath, "w");
    assert_non_null_bt(fp);
    fprintf(fp,
            "submodule " TEST_SUBMODULE_PREFIX "%s {\n"
            "  belongs-to " TEST_MODULE_PREFIX "%s {\n"
            "    prefix %s;\n"
            "  }\n", name, belongsto, belongsto);

    va_start(args, body);
    output_module_deps(fp, args);
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
    create_module_yang_schema("A", md_module_A_filepath, md_module_A_body, NULL);
    create_module_yang_schema("B", md_module_B_filepath, md_module_B_body, "sub-Bs1", "sub-Bs2", "sub-Bs3", NULL);
    create_submodule_yang_schema("Bs1", "B", md_submodule_B_sub1_filepath, md_submodule_B_sub1_body,
            /* "sub-Bs2" TODO: uncomment once the second issue from libyang/#97 is fixed ,*/ "A", NULL);
    create_submodule_yang_schema("Bs2", "B", md_submodule_B_sub2_filepath, md_submodule_B_sub2_body,
            /* "sub-Bs3" TODO: uncomment once the second issue from libyang/#97 is fixed ,*/ "A", NULL);
    create_submodule_yang_schema("Bs3", "B", md_submodule_B_sub3_filepath, md_submodule_B_sub3_body, NULL);
    create_module_yang_schema("C", md_module_C_filepath, md_module_C_body, "A", NULL);
    create_module_yang_schema("D", md_module_D_rev1_filepath, md_module_D_rev1_body, "sub-Dcommon@2016-06-10", "A", "C", NULL);
    create_module_yang_schema("D", md_module_D_rev2_filepath, md_module_D_rev2_body, "sub-Dcommon@2016-06-10", "A", "B", "C", NULL);
    create_submodule_yang_schema("Dcommon", "D", md_submodule_D_common_filepath, md_submodule_D_common_body,
            "mod-C" /* "TODO: rename to just "C" once the second issue from libyang/#97 is fixed */, NULL);
    create_module_yang_schema("E", md_module_E_filepath, md_module_E_body, "D@2016-06-10", "C", NULL);
    create_module_yang_schema("F", md_module_F_filepath, md_module_F_body, "D@2016-06-20", NULL);
    create_module_yang_schema("X", md_module_X_filepath, md_module_X_body, NULL);
    create_module_yang_schema("V", md_module_V_filepath, md_module_V_body, "A", NULL);
    return 0;
}

static int
md_tests_teardown(void **state)
{
    system("rm -f " TEST_SCHEMA_SEARCH_DIR TEST_MODULE_PREFIX "*");
    system("rm -f " TEST_SCHEMA_SEARCH_DIR TEST_SUBMODULE_PREFIX "*");
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
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", false, &md_ctx);
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

/*
 * presence_type flag: 0 - inserted modules, 1 - implemented modules
 */
static bool
present_module(const char *module_name, int presence_type)
{
    md_test_inserted_modules_t *presence;

    if (presence_type) {
        presence = &implemented;
    } else {
        presence = &inserted;
    }

    if (0 == strcmp("A", module_name)) {
        return presence->A;
    } else if (0 == strcmp("B", module_name)   ||
               0 == strcmp("Bs1", module_name) ||
               0 == strcmp("Bs2", module_name) ||
               0 == strcmp("Bs3", module_name)){
        return presence->B;
    } else if (0 == strcmp("C", module_name)) {
        return presence->C;
    } else if (0 == strcmp("D@2016-06-10", module_name)) {
        return presence->D_rev1;
    } else if (0 == strcmp("D@2016-06-20", module_name)) {
        return presence->D_rev2;
    } else if (0 == strcmp("Dcommon@2016-06-10", module_name)) {
        return presence->D_rev1 || presence->D_rev2;
    } else if (0 == strcmp("E@2016-06-11", module_name)) {
        return presence->E;
    } else if (0 == strcmp("F@2016-06-21", module_name)) {
        return presence->F;
    } else if (0 == strcmp("V", module_name)) {
        return presence->V;
    }
    return false;
}

static bool
dependency_edge(md_test_dep_t *dep, const char *dest_module)
{
    int presence_type = 0;

    if (MD_DEP_NONE == dep->type) {
        return false;
    } else if (dep->type == MD_DEP_EXTENSION || dep->type == MD_DEP_DATA) {
        presence_type = 1;
    }

    if (!present_module(dest_module, presence_type)) {
        return false;
    }

    if (MD_DEP_DATA == dep->type && 0 < dep->orig_modules->count) {
        for (int i = 0; i < dep->orig_modules->count; ++i) {
            if (present_module((const char *)(dep->orig_modules->data[i]), presence_type)) {
                return true;
            }
        }
        return false;
    }

    return true;
}

/**
 * @brief Check size of a linked-list.
 */
static void
check_list_size(sr_llist_t *list, size_t expected)
{
    size_t size = 0;
    sr_llist_node_t *node = list->first;

    while (node) {
        ++size;
        node = node->next;
    }
    assert_int_equal_bt(expected, size);
}

static void
compare_orig_modules(sr_llist_t *orig_modules, sr_list_t *expected)
{
    md_module_t *orig_module = NULL;
    sr_llist_node_t *node = NULL;
    bool found = false;
    size_t expected_cnt = 0;

    for (int i = 0; i < expected->count; ++i) {
        if (present_module(expected->data[i], 1)) {
            ++expected_cnt;
            found = false;
            node = orig_modules->first;
            while (node) {
                orig_module = (md_module_t *)node->data;
                if (0 == strcmp(md_get_module_fullname(orig_module)
                                       + (orig_module->submodule ? strlen(TEST_SUBMODULE_PREFIX) : strlen(TEST_MODULE_PREFIX)),
                                expected->data[i])) {
                    assert_false_bt(found);
                    found = true;
                }
                node = node->next;
            }
            assert_true_bt(found);
        }
    }
    check_list_size(orig_modules, expected_cnt);
}

/**
 * @brief Validate dependency between modules.
 */
static void
validate_dependency(const sr_llist_t *deps, const char *module_name, int count, ... /* md_test_dep_t */ )
{
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dep = NULL;
    md_test_dep_t *test_dep = NULL;
    bool found = false, in = false;
    int in_cnt = 0;
    va_list va;

    va_start(va, count);

    for (int i = 0; i < count; ++i) {
        test_dep = va_arg(va, md_test_dep_t *);
        in = dependency_edge(test_dep, module_name);
        in_cnt += in;
        /* try to find the expected dependency */
        found = false;
        dep_node = deps->first;
        while (dep_node) {
            dep = (md_dep_t*)dep_node->data;
            if (0 == strcmp(md_get_module_fullname(dep->dest)
                                + (dep->dest->submodule ? strlen(TEST_SUBMODULE_PREFIX) : strlen(TEST_MODULE_PREFIX)),
                            module_name) && dep->type == test_dep->type) {
                assert_true_bt(in);
                assert_false_bt(found);
                found = true;
                assert_int_equal(test_dep->direct, dep->direct);
                if (MD_DEP_DATA == test_dep->type) {
                    compare_orig_modules(dep->orig_modules, test_dep->orig_modules);
               }
            }
            dep_node = dep_node->next;
        }
        if (!found) {
            assert_false_bt(in);
        }
        /* release the expected dependency */
        sr_list_cleanup(test_dep->orig_modules);
        free(test_dep);
    }

    va_end(va);

    /* check total count */
    dep_node = deps->first;
    while (dep_node) {
        dep = (md_dep_t*)dep_node->data;
        if (0 == strcmp(md_get_module_fullname(dep->dest)
                            + (dep->dest->submodule ? strlen(TEST_SUBMODULE_PREFIX) : strlen(TEST_MODULE_PREFIX)),
                        module_name)) {
            --in_cnt;
        }
        dep_node = dep_node->next;
    }
    assert_int_equal_bt(0, in_cnt);
}

/**
 * @brief Validate subtree reference.
 */
static void
validate_subtree_ref(md_ctx_t *md_ctx, sr_llist_t *list, const char *xpath,
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
    int rc = md_get_module_info(md_ctx, full_module_name, at, NULL, &orig);

    while (node) {
        subtree_ref = (md_subtree_ref_t *)node->data;
        if (0 == strcmp(subtree_ref->xpath, xpath) && orig == subtree_ref->orig) {
            assert_true_bt(orig->implemented);
            assert_string_equal_bt(subtree_ref->orig->name, full_module_name);
            if (0 == strcmp(subtree_ref->orig->revision_date, at)) {
                assert_int_equal_bt(SR_ERR_OK, rc);
                free(orig_name_cpy);
                return;
            }
        }
        node = node->next;
    }
    if (SR_ERR_OK == rc) {
        assert_false_bt(orig->implemented);
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
    }
    free(orig_name_cpy);
}

/**
 * @brief Validate Module Dependencies context.
 */
static void
validate_context(md_ctx_t *md_ctx)
{
    int rc = 0;
    md_module_t *module = NULL;

    /* validate module A */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "A", NULL, NULL, &module);
    if (inserted.A) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "A", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "A", md_get_module_fullname(module));
        assert_string_equal_bt("A", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:A", module->ns);
        assert_string_equal_bt(md_module_A_filepath, module->filepath);
        assert_true(module->latest_revision);
        if (implemented.A) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, implemented.B + implemented.D_rev1 + 2*implemented.D_rev2);
        validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "B:B-ext-inst-id", "B");
        validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-inst-id", "D@2016-06-10");
        validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-inst-id", "D@2016-06-20");
        validate_subtree_ref(md_ctx, module->inst_ids,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-inst-id2", "D@2016-06-20");
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, implemented.B + implemented.D_rev1 + implemented.D_rev2);
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "B:B-ext-op-data", "B");
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-op-data", "D@2016-06-10");
#if 0 /* FIXME: record all originators of a state data subtree */
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-op-data", "D@2016-06-20");
#endif
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                                     "/" TEST_MODULE_PREFIX "A:base-container"
                                     "/" TEST_MODULE_PREFIX "C:C-ext-container"
                                     "/" TEST_MODULE_PREFIX "D:D-ext-op-data2", "D@2016-06-20");
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        validate_dependency(module->deps, "A", 0);
        validate_dependency(module->deps, "B", 2, md_test_dep(MD_DEP_EXTENSION, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        validate_dependency(module->deps, "C", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->deps, "D@2016-06-20", 1, md_test_dep(MD_DEP_EXTENSION, false));
        validate_dependency(module->deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        validate_dependency(module->inv_deps, "A", 0);
        validate_dependency(module->inv_deps, "B", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "B"));
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        validate_dependency(module->inv_deps, "C", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "C"), md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->inv_deps, "D@2016-06-10", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, false, 0), md_test_dep(MD_DEP_EXTENSION, false));
        validate_dependency(module->inv_deps, "D@2016-06-20", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, false, 0));
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->inv_deps, "E@2016-06-11", 3, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, false, 0), md_test_dep(MD_DEP_IMPORT, false));
        } else {
            validate_dependency(module->inv_deps, "E@2016-06-11", 2, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, false, 0));
        }
        validate_dependency(module->inv_deps, "F@2016-06-21", 1, md_test_dep(MD_DEP_IMPORT, false));
        if (implemented.V) {
            validate_dependency(module->deps, "V", 1, md_test_dep(MD_DEP_EXTENSION, true));
        }
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module B */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "B", NULL, NULL, &module);
    if (inserted.B) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "B", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "B", md_get_module_fullname(module));
        assert_string_equal_bt("B", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:B", module->ns);
        assert_string_equal_bt(md_module_B_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.B) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 1);
        validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "B:inst-ids/inst-id", "B");
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 1);
        validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "B:op-data", "B");
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        validate_dependency(module->deps, "A", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "B"));
        validate_dependency(module->deps, "B", 0);
        validate_dependency(module->deps, "Bs1", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->deps, "Bs2", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->deps, "Bs3", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->deps, "C", 0);
        validate_dependency(module->deps, "D@2016-06-10", 0);
        validate_dependency(module->deps, "D@2016-06-20", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        validate_dependency(module->inv_deps, "A", 2, md_test_dep(MD_DEP_EXTENSION, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        validate_dependency(module->inv_deps, "B", 0);
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        if (implemented.D_rev2) {
            validate_dependency(module->inv_deps, "C", 1, md_test_dep(MD_DEP_DATA, false, 0));
        } else {
            validate_dependency(module->inv_deps, "C", 1, md_test_dep(MD_DEP_EXTENSION, false));
        }
        if (implemented.D_rev2) {
            validate_dependency(module->inv_deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_DATA, false, 0));
        } else {
            validate_dependency(module->inv_deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_EXTENSION, false));
        }
        validate_dependency(module->inv_deps, "D@2016-06-20", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        if (implemented.D_rev2) {
            validate_dependency(module->inv_deps, "E", 1, md_test_dep(MD_DEP_DATA, false, 0));
            validate_dependency(module->inv_deps, "F", 2, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, false, 0));
        } else {
            validate_dependency(module->inv_deps, "E", 0);
            validate_dependency(module->inv_deps, "F", 1, md_test_dep(MD_DEP_IMPORT, false));
        }
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate submodule Bs1 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs1", NULL, NULL, &module);
    if (inserted.B) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs1", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs1", md_get_module_fullname(module));
        assert_string_equal_bt("", module->prefix);
        assert_string_equal_bt("", module->ns);
        assert_string_equal_bt(md_submodule_B_sub1_filepath, module->filepath);
        assert_true(module->latest_revision);
        if (implemented.B) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_false_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        check_list_size(module->deps, 0);
        check_list_size(module->inv_deps, 1);
        validate_dependency(module->inv_deps, "B", 1, md_test_dep(MD_DEP_INCLUDE, true));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate submodule Bs2 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs2", NULL, NULL, &module);
    if (inserted.B) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs2", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs2", md_get_module_fullname(module));
        assert_string_equal_bt("", module->prefix);
        assert_string_equal_bt("", module->ns);
        assert_string_equal_bt(md_submodule_B_sub2_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.B) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_false_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        check_list_size(module->deps, 0);
        check_list_size(module->inv_deps, 1);
        validate_dependency(module->inv_deps, "B", 1, md_test_dep(MD_DEP_INCLUDE, true));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate submodule Bs3 */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Bs3", NULL, NULL, &module);
    if (inserted.B) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs3", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Bs3", md_get_module_fullname(module));
        assert_string_equal_bt("", module->prefix);
        assert_string_equal_bt("", module->ns);
        assert_string_equal_bt(md_submodule_B_sub3_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.B) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_false_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        check_list_size(module->deps, 0);
        check_list_size(module->inv_deps, 1);
        validate_dependency(module->inv_deps, "B", 1, md_test_dep(MD_DEP_INCLUDE, true));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module C */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "C", NULL, NULL, &module);
    if (inserted.C) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "C", module->name);
        assert_string_equal_bt("", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "C", md_get_module_fullname(module));
        assert_string_equal_bt("C", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:C", module->ns);
        assert_string_equal_bt(md_module_C_filepath, module->filepath);
        assert_true(module->latest_revision);
        if (implemented.C) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 2);
        validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "C:inst-id1", "C");
        validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "C:inst-id2", "C");
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 1);
        validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "C:partly-op-data/nested-op-data", "C");
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        validate_dependency(module->deps, "A", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "C"), md_test_dep(MD_DEP_EXTENSION, true));
        if (implemented.D_rev2) {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_DATA, false, 0));
        } else {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_EXTENSION, false));
        }
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        validate_dependency(module->deps, "C", 0);
        validate_dependency(module->deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->deps, "D@2016-06-20", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        validate_dependency(module->inv_deps, "A", 1, md_test_dep(MD_DEP_EXTENSION, true));
        validate_dependency(module->inv_deps, "B", 0);
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        validate_dependency(module->inv_deps, "C", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->inv_deps, "D@2016-06-10", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-10"), md_test_dep(MD_DEP_IMPORT, true));
        } else {
            validate_dependency(module->inv_deps, "D@2016-06-10", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-10"));
        }
        validate_dependency(module->inv_deps, "D@2016-06-20", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->inv_deps, "E", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "E@2016-06-11"));
        validate_dependency(module->inv_deps, "F", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "F@2016-06-21"));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module D-rev1 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10", NULL, &module);
    if (inserted.D_rev1) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "D", module->name);
        assert_string_equal_bt("2016-06-10", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "D@2016-06-10", md_get_module_fullname(module));
        assert_string_equal_bt("D", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:D", module->ns);
        assert_string_equal_bt(md_module_D_rev1_filepath, module->filepath);
        if (inserted.D_rev2) {
            assert_false_bt(module->latest_revision);
        } else {
            assert_true_bt(module->latest_revision);
        }
        if (implemented.D_rev1) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        if (implemented.D_rev1) {
            validate_dependency(module->deps, "A", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, false, 0), md_test_dep(MD_DEP_IMPORT, true));
        } else {
            validate_dependency(module->deps, "A", 1, md_test_dep(MD_DEP_IMPORT, true));
        }
        if (implemented.D_rev2) {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_DATA, false, 0));
        } else if (implemented.D_rev1) {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_EXTENSION, false));
        } else {
            validate_dependency(module->deps, "B", 0);
        }
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->deps, "C", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-10"), md_test_dep(MD_DEP_EXTENSION, true));
        } else {
            validate_dependency(module->deps, "C", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-10"));
        }
        validate_dependency(module->deps, "D@2016-06-10", 0);
        validate_dependency(module->deps, "D@2016-06-20", 0);
        validate_dependency(module->deps, "Dcommon@2016-06-10", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->inv_deps, "A", 1, md_test_dep(MD_DEP_EXTENSION, true));
        }
        validate_dependency(module->inv_deps, "B", 0);
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->inv_deps, "C", 1, md_test_dep(MD_DEP_EXTENSION, true));
        }
        validate_dependency(module->inv_deps, "D@2016-06-10", 0);
        validate_dependency(module->inv_deps, "D@2016-06-20", 0);
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->inv_deps, "E", 1, md_test_dep(MD_DEP_IMPORT, true));
        validate_dependency(module->inv_deps, "F", 0);
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module D-rev2 */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20", NULL, &module);
    if (inserted.D_rev2) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "D", module->name);
        assert_string_equal_bt("2016-06-20", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "D@2016-06-20", md_get_module_fullname(module));
        assert_string_equal_bt("D", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:D", module->ns);
        assert_string_equal_bt(md_module_D_rev2_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.D_rev2) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        if (implemented.D_rev2) {
            validate_dependency(module->deps, "A", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, false, 0));
            validate_dependency(module->deps, "B", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        } else {
            validate_dependency(module->deps, "A", 1, md_test_dep(MD_DEP_IMPORT, true));
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_IMPORT, true));
        }
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        if (implemented.D_rev2) {
            validate_dependency(module->deps, "C", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1, "D@2016-06-20"));
        } else {
            validate_dependency(module->deps, "C", 1, md_test_dep(MD_DEP_IMPORT, true));
        }
        validate_dependency(module->deps, "D@2016-06-10", 0);
        validate_dependency(module->deps, "D@2016-06-20", 0);
        validate_dependency(module->deps, "Dcommon@2016-06-10", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        if (implemented.D_rev2) {
            validate_dependency(module->inv_deps, "A", 1, md_test_dep(MD_DEP_EXTENSION, false));
            validate_dependency(module->inv_deps, "B", 1, md_test_dep(MD_DEP_EXTENSION, true));
        } else {
            validate_dependency(module->inv_deps, "A", 0);
            validate_dependency(module->inv_deps, "B", 0);
        }
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        if (implemented.D_rev2) {
            validate_dependency(module->inv_deps, "C", 1, md_test_dep(MD_DEP_EXTENSION, true));
        } else {
            validate_dependency(module->inv_deps, "C", 0);
        }
        validate_dependency(module->inv_deps, "D@2016-06-10", 0);
        validate_dependency(module->inv_deps, "D@2016-06-20", 0);
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->inv_deps, "E", 0);
        validate_dependency(module->inv_deps, "F", 1, md_test_dep(MD_DEP_IMPORT, true));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate submodule Dcommon */
    rc = md_get_module_info(md_ctx, TEST_SUBMODULE_PREFIX "Dcommon", NULL, NULL, &module);
    if (inserted.D_rev1 || inserted.D_rev2) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Dcommon", module->name);
        assert_string_equal_bt("2016-06-10", module->revision_date);
        assert_string_equal_bt(TEST_SUBMODULE_PREFIX "Dcommon@2016-06-10", md_get_module_fullname(module));
        assert_string_equal_bt("", module->prefix);
        assert_string_equal_bt("", module->ns);
        assert_string_equal_bt(md_submodule_D_common_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.D_rev1 || implemented.D_rev2) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_false_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 0);
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 0);
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        check_list_size(module->deps, 0);
        check_list_size(module->inv_deps, inserted.D_rev1 + inserted.D_rev2);
        validate_dependency(module->inv_deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_INCLUDE, true));
        validate_dependency(module->inv_deps, "D@2016-06-20", 1, md_test_dep(MD_DEP_INCLUDE, true));
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module E */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-11", NULL, &module);
    if (inserted.E) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "E", module->name);
        assert_string_equal_bt("2016-06-11", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "E@2016-06-11", md_get_module_fullname(module));
        assert_string_equal_bt("E", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:E", module->ns);
        assert_string_equal_bt(md_module_E_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.E) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* inst_ids */
        check_list_size(module->inst_ids, 1);
        validate_subtree_ref(md_ctx, module->inst_ids, "/" TEST_MODULE_PREFIX "E:inst-id-list/inst-id", "E@2016-06-11");
        /* op_data_subtrees */
        check_list_size(module->op_data_subtrees, 2);
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/list-with-op-data", "E@2016-06-11");
        validate_subtree_ref(md_ctx, module->op_data_subtrees,
                "/" TEST_MODULE_PREFIX "E:partly-op-data/nested-op-data", "E@2016-06-11");
        /* outside references */
        assert_non_null_bt(module->ly_data);
        assert_non_null_bt(module->ll_node);
        /* dependencies */
        if (implemented.D_rev1) {
            validate_dependency(module->deps, "A", 3, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, false, 0), md_test_dep(MD_DEP_IMPORT, false));
        } else {
            validate_dependency(module->deps, "A", 2, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, false, 0));
        }
        if (implemented.D_rev2) {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_DATA, false, 0));
        } else if (implemented.D_rev1) {
            validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_EXTENSION, false));
        } else {
            validate_dependency(module->deps, "B", 0);
        }
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        if (implemented.D_rev1) {
            validate_dependency(module->deps, "C", 3, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1,  "E@2016-06-11"), md_test_dep(MD_DEP_IMPORT, true));
        } else {
            validate_dependency(module->deps, "C", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_DATA, true, 1,  "E@2016-06-11"));
        }
        if (implemented.D_rev1) {
            validate_dependency(module->deps, "D@2016-06-10", 2, md_test_dep(MD_DEP_IMPORT, true), md_test_dep(MD_DEP_IMPORT, true));
        } else {
            validate_dependency(module->deps, "D@2016-06-10", 1, md_test_dep(MD_DEP_IMPORT, true));
        }
        validate_dependency(module->deps, "D@2016-06-20", 0);
        validate_dependency(module->deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        validate_dependency(module->inv_deps, "A", 0);
        validate_dependency(module->inv_deps, "B", 0);
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        validate_dependency(module->inv_deps, "C", 0);
        validate_dependency(module->inv_deps, "D@2016-06-10", 0);
        validate_dependency(module->inv_deps, "D@2016-06-20", 0);
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->inv_deps, "E", 0);
        validate_dependency(module->inv_deps, "F", 0);
    } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
    }

    /* validate module F */
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "F", "2016-06-21", NULL, &module);
    if (inserted.F) {
        assert_int_equal_bt(SR_ERR_OK, rc);
        assert_non_null_bt(module);
        assert_string_equal_bt(TEST_MODULE_PREFIX "F", module->name);
        assert_string_equal_bt("2016-06-21", module->revision_date);
        assert_string_equal_bt(TEST_MODULE_PREFIX "F@2016-06-21", md_get_module_fullname(module));
        assert_string_equal_bt("F", module->prefix);
        assert_string_equal_bt("urn:ietf:params:xml:ns:yang:F", module->ns);
        assert_string_equal_bt(md_module_F_filepath, module->filepath);
        assert_true_bt(module->latest_revision);
        if (implemented.F) {
            assert_true_bt(module->implemented);
        } else {
            assert_false_bt(module->implemented);
        }
        assert_true_bt(module->has_data);
        /* dependencies */
        validate_dependency(module->deps, "A", 1, md_test_dep(MD_DEP_IMPORT, false));
        validate_dependency(module->deps, "B", 1, md_test_dep(MD_DEP_IMPORT, false));
        validate_dependency(module->deps, "Bs1", 0);
        validate_dependency(module->deps, "Bs2", 0);
        validate_dependency(module->deps, "Bs3", 0);
        validate_dependency(module->deps, "C", 2, md_test_dep(MD_DEP_IMPORT, false), md_test_dep(MD_DEP_DATA, true, 1, "F"));
        validate_dependency(module->deps, "D@2016-06-10", 0);
        validate_dependency(module->deps, "D@2016-06-20", 1, md_test_dep(MD_DEP_IMPORT, true));
        validate_dependency(module->deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->deps, "E", 0);
        validate_dependency(module->deps, "F", 0);
        validate_dependency(module->inv_deps, "A", 0);
        validate_dependency(module->inv_deps, "B", 0);
        validate_dependency(module->inv_deps, "Bs1", 0);
        validate_dependency(module->inv_deps, "Bs2", 0);
        validate_dependency(module->inv_deps, "Bs3", 0);
        validate_dependency(module->inv_deps, "C", 0);
        validate_dependency(module->inv_deps, "D@2016-06-10", 0);
        validate_dependency(module->inv_deps, "D@2016-06-20", 0);
        validate_dependency(module->inv_deps, "Dcommon@2016-06-10", 0);
        validate_dependency(module->inv_deps, "E", 0);
        validate_dependency(module->inv_deps, "F", 0);
     } else {
        assert_int_equal_bt(SR_ERR_NOT_FOUND, rc);
        assert_null_bt(module);
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
    md_module_key_t *module_key = NULL;
    sr_list_t *implicitly_inserted = NULL;
    memset(&inserted, 0, sizeof inserted);
    memset(&implemented, 0, sizeof implemented);

    /* initialize context */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    /* insert module A */
    rc = md_insert_module(md_ctx, md_module_A_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.A = implemented.A = true;
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* try to insert module A again */
    rc = md_insert_module(md_ctx, md_module_A_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);

    /* insert module B */
    rc = md_insert_module(md_ctx, md_module_B_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.B = implemented.B = true;
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* insert module C */
    rc = md_insert_module(md_ctx, md_module_C_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.C = implemented.C = true;
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* insert module E (D-rev1 should get inserted automatically) */
    rc = md_insert_module(md_ctx, md_module_E_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev1 = inserted.E = true;
    implemented.E = true;
    assert_int_equal(1, implicitly_inserted->count);
    module_key = (md_module_key_t *)implicitly_inserted->data[0];
    assert_string_equal(TEST_MODULE_PREFIX "D", module_key->name);
    assert_string_equal("2016-06-10", module_key->revision_date);
    assert_string_equal(md_module_D_rev1_filepath, module_key->filepath);
    md_free_module_key_list(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* D-rev1 is actually only imported, not implemented */
    rc = md_insert_module(md_ctx, md_module_D_rev1_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    implemented.D_rev1 = true;
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* D-rev1 is now really implemented, D-rev2 cannot be also implemented and installed */
    rc = md_insert_module(md_ctx, md_module_D_rev2_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);
    assert_null(implicitly_inserted);

    /* insert module F (D-rev2 should get inserted automatically, but only as import) */
    rc = md_insert_module(md_ctx, md_module_F_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.D_rev2 = inserted.F = true;
    implemented.F = true;
    assert_int_equal(1, implicitly_inserted->count);
    module_key = (md_module_key_t *)implicitly_inserted->data[0];
    assert_string_equal(TEST_MODULE_PREFIX "D", module_key->name);
    assert_string_equal("2016-06-20", module_key->revision_date);
    assert_string_equal(md_module_D_rev2_filepath, module_key->filepath);
    md_free_module_key_list(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* insert module V */
    rc = md_insert_module(md_ctx, md_module_V_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.V = implemented.V = true;
    assert_int_equal(0, implicitly_inserted->count);
    sr_list_cleanup(implicitly_inserted);
    implicitly_inserted = NULL;
    validate_context(md_ctx);

    /* flush changes into the internal data file */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* destroy context */
    md_destroy(md_ctx);

    /* reload dependencies from the file and re-test */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    /* no write-lock this time */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* destroy context for the final time */
    md_destroy(md_ctx);
}

/*
 * @brief Test md_insert_module().
 */

static const char * const md_test_insert_module_2_mod1 = TEST_SOURCE_DIR "/yang/augm_by_incl_m1" TEST_MODULE_EXT;

static void
md_test_insert_module_2(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    rc = md_init(TEST_SOURCE_DIR "/yang", TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    rc = md_insert_module(md_ctx, md_test_insert_module_2_mod1, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, implicitly_inserted->count);
    md_free_module_key_list(implicitly_inserted);
    validate_context(md_ctx);

    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    md_destroy(md_ctx);
}

/*
 * @brief Test md_insert_module().
 */

static const char * const md_test_insert_module_3_mod1 = TEST_SOURCE_DIR "/yang/mws-main-module" TEST_MODULE_EXT;

static void
md_test_insert_module_3(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    rc = md_init(TEST_SOURCE_DIR "/yang", TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    rc = md_insert_module(md_ctx, md_test_insert_module_3_mod1, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, implicitly_inserted->count);
    md_free_module_key_list(implicitly_inserted);
    validate_context(md_ctx);

    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    md_destroy(md_ctx);
}

/*
 * @brief Test md_insert_module_4().
 */

static const char * const md_test_insert_module_4_mod1 = TEST_SOURCE_DIR "/yang/augm_empty_container_m1" TEST_MODULE_EXT;

static void
md_test_insert_module_4(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    rc = md_init(TEST_SOURCE_DIR "/yang", TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    rc = md_insert_module(md_ctx, md_test_insert_module_4_mod1, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_inserted->count);
    md_free_module_key_list(implicitly_inserted);
    validate_context(md_ctx);

    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    md_destroy(md_ctx);
}

static const char * const md_test_insert_module_5_mod1 = TEST_SOURCE_DIR "/yang/augm_container_if_feature_m1" TEST_MODULE_EXT;

static void
md_test_insert_module_5(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    rc = md_init(TEST_SOURCE_DIR "/yang", TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    rc = md_insert_module(md_ctx, md_test_insert_module_5_mod1, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_inserted->count);
    md_free_module_key_list(implicitly_inserted);
    validate_context(md_ctx);

    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    md_destroy(md_ctx);
}

static const char * const md_test_insert_module_double_aug_mod = TEST_SOURCE_DIR "/yang/mwa-aug2" TEST_MODULE_EXT;

static void
md_test_insert_module_double_aug(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    rc = md_init(TEST_SOURCE_DIR "/yang", TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    rc = md_insert_module(md_ctx, md_test_insert_module_double_aug_mod, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, implicitly_inserted->count);
    md_free_module_key_list(implicitly_inserted);
    validate_context(md_ctx);

    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    md_destroy(md_ctx);
}

static int
_md_test_remove_modules(md_ctx_t *md_ctx, const char *name, const char *revision, sr_list_t **implicitly_removed)
{
    return md_remove_modules(md_ctx, &name, &revision, 1, implicitly_removed);
}

/*
 * @brief Test md_remove_modules().
 */
static void
md_test_remove_modules(void **state)
{
    int rc;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_removed = NULL;
    md_module_key_t *module_key = NULL;
    memset(&inserted, 1, sizeof inserted);
    memset(&implemented, 1, sizeof implemented);
    implemented.D_rev2 = false;

    /* initialize context */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", true, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    /* there is no module named G */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "G", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(implicitly_removed);


    /* initialy only the module E can be removed */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "A", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "B", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "C", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10", &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20", &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);

    /* remove module F (D-rev2 should get removed automatically) */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "F", "2016-06-21", &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    inserted.F = implemented.F = false;
    inserted.D_rev2 = false;
    assert_int_equal(1, implicitly_removed->count);
    module_key = (md_module_key_t *)implicitly_removed->data[0];
    assert_string_equal(TEST_MODULE_PREFIX "D", module_key->name);
    assert_string_equal("2016-06-20", module_key->revision_date);
    assert_string_equal(md_module_D_rev2_filepath, module_key->filepath);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;
    validate_context(md_ctx);

    /* D-rev2 is already removed */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-20", &implicitly_removed);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(implicitly_removed);

    /* now there are no modules dependent on B, remove it */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "B", "", &implicitly_removed); /*< try "" instead of NULL */
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.B = implemented.B =false;
    validate_context(md_ctx);

    /* still can't remove A, C, D-rev1 */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "A", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "C", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10", &implicitly_removed);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
    assert_null(implicitly_removed);

    /* B is not present anymore */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "B", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_null(implicitly_removed);

    /* remove module E */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "E", "2016-06-11", &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.E = implemented.E = false;
    validate_context(md_ctx);

    /* remove module D-rev1 */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "D", "2016-06-10", &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.D_rev1 = implemented.D_rev1 = false;
    validate_context(md_ctx);

    /* remove module C */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "C", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.C = implemented.C = false;
    validate_context(md_ctx);

    /* Remove the deviation */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "V", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.V = implemented.V = false;
    validate_context(md_ctx);

    /* finally remove module A */
    rc = _md_test_remove_modules(md_ctx, TEST_MODULE_PREFIX "A", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    inserted.A = implemented.A = false;
    validate_context(md_ctx);

    /* remove all augm modules */
    rc = _md_test_remove_modules(md_ctx, "augm_by_incl_m1", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, implicitly_removed->count);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;

    rc = _md_test_remove_modules(md_ctx, "augm_by_incl_m4", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    sr_list_cleanup(implicitly_removed);
    implicitly_removed = NULL;
    validate_context(md_ctx);

    rc = _md_test_remove_modules(md_ctx, "mws-main-module", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, implicitly_removed->count);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;
    validate_context(md_ctx);

    rc = _md_test_remove_modules(md_ctx, "augm_empty_container_m1", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;
  
    rc = _md_test_remove_modules(md_ctx, "augm_container_if_feature_m1", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, implicitly_removed->count);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;
  
    rc = _md_test_remove_modules(md_ctx, "mwa-aug2", NULL, &implicitly_removed);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, implicitly_removed->count);
    md_free_module_key_list(implicitly_removed);
    implicitly_removed = NULL;

    /* flush changes into the internal data file */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* destroy context */
    md_destroy(md_ctx);

    /* reload dependencies from the file and re-test */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    validate_context(md_ctx);

    /* no write-lock this time */
    rc = md_flush(md_ctx);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* destroy context for the final time */
    md_destroy(md_ctx);
}

/*
 * @brief Test how YANG groupings and uses are handled.
 */
static void
md_test_grouping_and_uses(void **state)
{
    int rc;
    md_module_t *module = NULL;
    md_ctx_t *md_ctx = NULL;
    sr_list_t *implicitly_inserted = NULL;

    /* initialize context */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* insert module X */
    rc = md_insert_module(md_ctx, md_module_X_filepath, &implicitly_inserted);
    assert_int_equal(SR_ERR_OK, rc);
    rc = md_get_module_info(md_ctx, TEST_MODULE_PREFIX "X", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);

    /* validate op_data_subtrees */
    check_list_size(module->op_data_subtrees, 14);
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-1/sensors", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-2", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-3/state-data1", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-3/state-data2", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-4/state-data", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-4/sensors", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-5", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-6/state-data", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-6/state-data2", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-6/state-data3", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-6/sensors", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-7/state-data", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-8/nested-container1/sensors", "X");
    validate_subtree_ref(md_ctx, module->op_data_subtrees, "/" TEST_MODULE_PREFIX "X:container-8/nested-container2/sensors", "X");

    /* destroy context */
    md_destroy(md_ctx);
    sr_list_cleanup(implicitly_inserted);
}

/*
 * @brief Test "has-data" flag.
 */
static void
md_test_has_data(void **state)
{
    int rc;
    md_module_t *module = NULL;
    md_ctx_t *md_ctx = NULL;

    /* initialize context, load module dependency file */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal",
                 TEST_DATA_SEARCH_DIR "internal", false, &md_ctx);
    assert_int_equal(SR_ERR_OK, rc);

    /* test modules installed by default */
    rc = md_get_module_info(md_ctx, "example-module", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "iana-if-type", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(module->has_data);
    rc = md_get_module_info(md_ctx, "ietf-interfaces", "2014-05-08", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    check_list_size(module->op_data_subtrees, 1); /* Bug #569 */
    rc = md_get_module_info(md_ctx, "ietf-ip", "2014-06-16", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(module->has_data);
    rc = md_get_module_info(md_ctx, "module-a", "2016-02-02", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "module-a", "2016-02-10", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "module-b", "2016-02-05", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "small-module", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "state-module", "2016-07-01", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "sub-a-one", "2016-02-02", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(module->has_data);
    rc = md_get_module_info(md_ctx, "sub-a-one", "2016-02-10", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(module->has_data);
    rc = md_get_module_info(md_ctx, "sub-a-two", "2016-02-02", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(module->has_data);
    rc = md_get_module_info(md_ctx, "test-module", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    rc = md_get_module_info(md_ctx, "top-level-mandatory", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);
    /*If top-level node is an USES node, it's data-carrying*/
    rc = md_get_module_info(md_ctx, "servers", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(module->has_data);

    /* destroy context */
    md_destroy(md_ctx);
}

int main(){
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(md_test_init_and_destroy),
            cmocka_unit_test(md_test_insert_module),
            cmocka_unit_test(md_test_insert_module_2),
            cmocka_unit_test(md_test_insert_module_3),
            cmocka_unit_test(md_test_insert_module_4),
            cmocka_unit_test(md_test_insert_module_5),
            cmocka_unit_test(md_test_insert_module_double_aug),
            cmocka_unit_test(md_test_remove_modules),
            cmocka_unit_test(md_test_grouping_and_uses),
            cmocka_unit_test(md_test_has_data),
    };

    return cmocka_run_group_tests(tests, md_tests_setup, md_tests_teardown);
}

