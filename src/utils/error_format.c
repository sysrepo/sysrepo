/**
 * @file error_format.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Functions for simplified manipulation with callback errors.
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "error_format.h"

#include <stdint.h>

#include "../sysrepo.h"
#include "common_types.h"
#include "config.h"
#include "log.h"

/**
 * @brief Set NETCONF callback error or add another if a NETCONF error has already been set.
 *
 * @param[in] session Implicit session provided in a callback.
 * @param[in] error_type NETCONF error type.
 * @param[in] error_tag NETCONF error tag.
 * @param[in] error_app_tag Optional NETCONF error app tag.
 * @param[in] error_path Optional NETCONF error path.
 * @param[in] error_message NETCONF error message.
 * @return err_info, NULl on success.
 */
static sr_error_info_t *
_sr_session_set_netconf_error(sr_session_ctx_t *session, const char *error_type, const char *error_tag,
        const char *error_app_tag, const char *error_path, const char *error_message)
{
    sr_error_info_t *err_info = NULL;
    uint32_t size, *val;

    if (!session || !session->ev || !error_type || !error_tag || !error_message) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid arguments for function \"%s\".", __func__);
        return err_info;
    }

    /* check error type */
    if (strcmp(error_type, "transport") && strcmp(error_type, "rpc") && strcmp(error_type, "protocol") &&
            strcmp(error_type, "application")) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid error type \"%s\".", error_type);
        return err_info;
    }

    /* check error tag */
    if (strcmp(error_tag, "in-use") && strcmp(error_tag, "invalid-value") && strcmp(error_tag, "too-big") &&
            strcmp(error_tag, "missing-attribute") && strcmp(error_tag, "bad-attribute") &&
            strcmp(error_tag, "unknown-attribute") && strcmp(error_tag, "missing-element") &&
            strcmp(error_tag, "bad-element") && strcmp(error_tag, "unknown-element") &&
            strcmp(error_tag, "unknown-namespace") && strcmp(error_tag, "access-denied") &&
            strcmp(error_tag, "lock-denied") && strcmp(error_tag, "resource-denied") &&
            strcmp(error_tag, "rollback-failed") && strcmp(error_tag, "data-exists") &&
            strcmp(error_tag, "data-missing") && strcmp(error_tag, "operation-not-supported") &&
            strcmp(error_tag, "operation-failed") && strcmp(error_tag, "malformed-message")) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid error tag \"%s\".", error_tag);
        return err_info;
    }

    if (session->ev_error.format && !strcmp(session->ev_error.format, "NETCONF")) {
        /* another NETCONF error */
        if (sr_ev_data_get(session->ev_error.data, 0, &size, (void **)&val) || (size != sizeof *val)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid NETCONF error format, unable to add another.");
            return err_info;
        }
        ++(*val);
    } else {
        /* generic error message */
        sr_session_set_error_message(session, "NETCONF error occurred.");

        /* error format */
        sr_session_set_error_format(session, "NETCONF");

        /* number of NETCONF errors */
        size = 1;
        sr_session_push_error_data(session, sizeof size, &size);
    }

    /* error-type */
    sr_session_push_error_data(session, strlen(error_type) + 1, error_type);

    /* error-tag */
    sr_session_push_error_data(session, strlen(error_tag) + 1, error_tag);

    /* error-app-tag */
    if (!error_app_tag) {
        error_app_tag = "";
    }
    sr_session_push_error_data(session, strlen(error_app_tag) + 1, error_app_tag);

    /* error-message */
    sr_session_push_error_data(session, strlen(error_message) + 1, error_message);

    /* error-path */
    if (!error_path) {
        error_path = "";
    }
    sr_session_push_error_data(session, strlen(error_path) + 1, error_path);

    return NULL;
}

API int
sr_session_set_netconf_error(sr_session_ctx_t *session, const char *error_type, const char *error_tag,
        const char *error_app_tag, const char *error_path, const char *error_message, uint32_t error_info_count, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list vargs;
    const char *arg;
    uint32_t i;
    int rc = SR_ERR_OK;

    /* set all parameters except error info */
    err_info = _sr_session_set_netconf_error(session, error_type, error_tag, error_app_tag, error_path, error_message);
    if (err_info) {
        goto cleanup;
    }

    /* error-info count */
    sr_session_push_error_data(session, sizeof error_info_count, &error_info_count);

    /* error-info */
    va_start(vargs, error_info_count);
    for (i = 0; i < error_info_count; ++i) {
        /* element */
        arg = va_arg(vargs, const char *);
        sr_session_push_error_data(session, strlen(arg) + 1, arg);

        /* value */
        arg = va_arg(vargs, const char *);
        sr_session_push_error_data(session, strlen(arg) + 1, arg);
    }
    va_end(vargs);

cleanup:
    if (err_info) {
        /* do not modify session errors */
        rc = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);
    }
    return rc;
}

API int
sr_session_set_netconf_error2(sr_session_ctx_t *session, const char *error_type, const char *error_tag,
        const char *error_app_tag, const char *error_path, const char *error_message, uint32_t error_info_count,
        const char **error_info_elems, const char **error_info_values)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int rc = SR_ERR_OK;

    /* set all parameters except error info */
    err_info = _sr_session_set_netconf_error(session, error_type, error_tag, error_app_tag, error_path, error_message);
    if (err_info) {
        goto cleanup;
    }

    /* error-info count */
    sr_session_push_error_data(session, sizeof error_info_count, &error_info_count);

    /* error-info */
    for (i = 0; i < error_info_count; ++i) {
        /* element */
        sr_session_push_error_data(session, strlen(error_info_elems[i]) + 1, error_info_elems[i]);

        /* value */
        sr_session_push_error_data(session, strlen(error_info_values[i]) + 1, error_info_values[i]);
    }

cleanup:
    if (err_info) {
        /* do not modify session errors */
        rc = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);
    }
    return rc;
}

API int
sr_err_get_netconf_error(const sr_error_info_err_t *err, const char **error_type, const char **error_tag,
        const char **error_app_tag, const char **error_path, const char **error_message,
        const char ***error_info_elements, const char ***error_info_values, uint32_t *error_info_count)
{
    return sr_err_get_netconf_error_idx(err, 0, error_type, error_tag, error_app_tag, error_path, error_message,
            error_info_elements, error_info_values, error_info_count);
}

API int
sr_err_get_netconf_error_idx(const sr_error_info_err_t *err, uint32_t idx, const char **error_type, const char **error_tag,
        const char **error_app_tag, const char **error_path, const char **error_message,
        const char ***error_info_elements, const char ***error_info_values, uint32_t *error_info_count)
{
    sr_error_info_t *err_info = NULL;
    uint32_t err_idx = 0, err_count, size, val, i;
    const char *arg, *arg2;
    const void *ptr;
    int rc = SR_ERR_OK;

    if (!err || strcmp(err->error_format, "NETCONF") || !error_type || !error_tag || !error_app_tag || !error_path ||
            !error_message || !error_info_elements || !error_info_values || !error_info_count) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid arguments for function \"%s\".", __func__);
        sr_errinfo_free(&err_info);
        return SR_ERR_INVAL_ARG;
    }

    /* error count */
    if (sr_get_error_data(err, err_idx++, NULL, &ptr)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF error count.");
        goto cleanup;
    }
    memcpy(&val, ptr, sizeof val);
    err_count = val;
    if (idx >= err_count) {
        return SR_ERR_NOT_FOUND;
    }

    /* skip previous errors */
    for (i = 0; i < idx; ++i) {
        /* read error-info-count */
        err_idx += 5;
        if (sr_get_error_data(err, err_idx++, &size, &ptr) || (size != sizeof val)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-info\" count.");
            goto cleanup;
        }
        memcpy(&val, ptr, sizeof val);

        /* skip error-info */
        err_idx += val * 2;
    }

    *error_info_elements = NULL;
    *error_info_values = NULL;
    *error_info_count = 0;

    /* error-type */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)error_type)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-type\".");
        goto cleanup;
    }

    /* error-tag */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)error_tag)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-tag\".");
        goto cleanup;
    }

    /* error-app-tag */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)error_app_tag)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-app-tag\".");
        goto cleanup;
    }
    if (!(*error_app_tag)[0]) {
        *error_app_tag = NULL;
    }

    /* error-message */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)error_message)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-message\".");
        goto cleanup;
    }

    /* error-path */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)error_path)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-path\".");
        goto cleanup;
    }
    if (!(*error_path)[0]) {
        *error_path = NULL;
    }

    /* error-info count */
    if (sr_get_error_data(err, err_idx++, NULL, &ptr)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-info\" count.");
        goto cleanup;
    }
    memcpy(&val, ptr, sizeof val);

    /* alloc */
    *error_info_elements = sr_realloc(*error_info_elements, val * sizeof **error_info_elements);
    *error_info_values = sr_realloc(*error_info_values, val * sizeof **error_info_values);
    SR_CHECK_MEM_GOTO(!*error_info_elements || !*error_info_values, err_info, cleanup);
    *error_info_count = val;

    for (i = 0; i < val; ++i) {
        /* error-info element */
        if (sr_get_error_data(err, err_idx++, NULL, (const void **)&arg)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-info\" element.");
            goto cleanup;
        }

        /* error-info value */
        if (sr_get_error_data(err, err_idx++, NULL, (const void **)&arg2)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing NETCONF \"error-info\" value.");
            goto cleanup;
        }

        /* store new error info */
        (*error_info_elements)[i] = arg;
        (*error_info_values)[i] = arg2;
    }

cleanup:
    if (err_info) {
        /* do not modify session errors */
        rc = err_info->err[0].err_code;
        sr_errinfo_free(&err_info);

        free(*error_info_elements);
        free(*error_info_values);
    }
    return rc;
}
