
#ifndef _LOG_H
#define _LOG_H

#include "common.h"

extern sr_error_info_t sr_errinfo_mem;

#define SR_ERRINFO_INT(err_info) sr_errinfo_new(err_info, SR_ERR_INTERNAL, NULL, "Internal error (%s:%d).", __FILE__, __LINE__)
#define SR_ERRINFO_RWLOCK(err_info, wr, func, ret) sr_errinfo_new(err_info, (ret == ETIMEDOUT) ? SR_ERR_TIME_OUT : SR_ERR_INTERNAL, \
        NULL, "%s locking a rwlock failed (%s: %s).", wr ? "Write" : "Read", func, strerror(ret))
#define SR_ERRINFO_SYSERRNO(err_info, func) sr_errinfo_new(err_info, SR_ERR_SYS, NULL, "%s() failed (%s).", func, strerror(errno))
#define SR_ERRINFO_VALID(err_info) sr_errinfo_new(err_info, SR_ERR_VALIDATION_FAILED, NULL, "Validation failed.")

#define SR_LOG_WRN(format, ...) sr_log(SR_LL_WRN, format, ##__VA_ARGS__)
#define SR_LOG_INF(format, ...) sr_log(SR_LL_INF, format, ##__VA_ARGS__)
#define SR_LOG_DBG(format, ...) sr_log(SR_LL_DBG, format, ##__VA_ARGS__)

#define SR_LOG_WRNMSG(format) sr_log(SR_LL_WRN, format)
#define SR_LOG_INFMSG(format) sr_log(SR_LL_INF, format)
#define SR_LOG_DBGMSG(format) sr_log(SR_LL_DBG, format)

#define SR_CHECK_MEM_GOTO(cond, err_info, go) if (cond) { sr_errinfo_free(&(err_info)); err_info = &sr_errinfo_mem; goto go; }
#define SR_CHECK_MEM_RET(cond, err_info) if (cond) { sr_errinfo_free(&(err_info)); return &sr_errinfo_mem; }
#define SR_CHECK_INT_GOTO(cond, err_info, go) if (cond) { SR_ERRINFO_INT(&(err_info)); goto go; }
#define SR_CHECK_INT_RET(cond, err_info) if (cond) { SR_ERRINFO_INT(&(err_info)); return err_info; }

#define SR_CHECK_ARG_APIRET(cond, session, err_info) if (cond) { sr_errinfo_new(&(err_info), SR_ERR_INVAL_ARG, NULL, \
        "Invalid arguments for function \"%s\".", __func__); return sr_api_ret(session, err_info); }

sr_error_t sr_api_ret(sr_session_ctx_t *session, sr_error_info_t *err_info);

void sr_log_msg(sr_log_level_t ll, const char *msg, const char *path);

void sr_errinfo_new(sr_error_info_t **err_info, sr_error_t err_code, const char *xpath, const char *format, ...);

void sr_errinfo_new_ly(sr_error_info_t **err_info, struct ly_ctx *ly_ctx);

void sr_errinfo_free(sr_error_info_t **err_info);

void sr_errinfo_merge(sr_error_info_t **err_info, sr_error_info_t *err_info2);

void sr_log(sr_log_level_t ll, const char *format, ...);

#endif
