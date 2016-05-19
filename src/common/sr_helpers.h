/**
 * @file sr_helpers.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo helper macros.
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

#ifndef SR_HELPERS_H_
#define SR_HELPERS_H_

#define CHECK_NULL_ARG__INTERNAL(ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __func__); \
        return SR_ERR_INVAL_ARG; \
    } \

#define CHECK_NULL_ARG_VOID__INTERNAL(ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __func__); \
        return; \
    } \

#define CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __func__); \
        RC = SR_ERR_INVAL_ARG; \
    } \


/**
 * Function argument checkers - return from function with SR_ERR_INVAL_ARG error.
 */

#define CHECK_NULL_ARG(ARG) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG) \
    } while(0)

#define CHECK_NULL_ARG2(ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
    } while(0)

#define CHECK_NULL_ARG3(ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
    } while(0)

#define CHECK_NULL_ARG4(ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
        CHECK_NULL_ARG__INTERNAL(ARG4) \
    } while(0)

#define CHECK_NULL_ARG5(ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
        CHECK_NULL_ARG__INTERNAL(ARG4) \
        CHECK_NULL_ARG__INTERNAL(ARG5) \
    } while(0)


/**
 * Function argument checkers - return from void function.
 */

#define CHECK_NULL_ARG_VOID(ARG) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG) \
    } while(0)

#define CHECK_NULL_ARG_VOID2(ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
    } while(0)

#define CHECK_NULL_ARG_VOID3(ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
    } while(0)

#define CHECK_NULL_ARG_VOID4(ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG4) \
    } while(0)

#define CHECK_NULL_ARG_VOID5(ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG4) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG5) \
    } while(0)


/**
 * Function argument checkers - do not return from function, set error code.
 */

#define CHECK_NULL_ARG_NORET(RC, ARG) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG) \
    } while(0)

#define CHECK_NULL_ARG_NORET2(RC, ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
    } while(0)

#define CHECK_NULL_ARG_NORET3(RC, ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
    } while(0)

#define CHECK_NULL_ARG_NORET4(RC, ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG4) \
    } while(0)

#define CHECK_NULL_ARG_NORET5(RC, ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG4) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG5) \
    } while(0)


/**
 * Memory allocation checkers.
 */

#define CHECK_NULL_NOMEM_RETURN(ARG) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __func__); \
            return SR_ERR_NOMEM; \
        } \
    } while(0)

#define CHECK_NULL_NOMEM_ERROR(ARG, ERROR) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __func__); \
            ERROR = SR_ERR_NOMEM; \
        } \
    } while(0)

#define CHECK_NULL_NOMEM_GOTO(ARG, ERROR, LABEL) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __func__); \
            ERROR = SR_ERR_NOMEM; \
            goto LABEL; \
        } \
    } while(0)


/**
 * Return code checkers.
 */

#define CHECK_RC_MSG_RETURN(RC, MSG) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR_MSG(MSG); \
            return RC; \
        } \
    } while(0)

#define CHECK_RC_LOG_RETURN(RC, MSG, ...) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            return RC; \
        } \
    } while(0)

#define CHECK_RC_MSG_GOTO(RC, LABEL, MSG) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR_MSG(MSG); \
            goto LABEL; \
        } \
    } while(0)

#define CHECK_RC_LOG_GOTO(RC, LABEL, MSG, ...) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            goto LABEL; \
        } \
    } while(0)


/**
 * Non-zero value checkers.
 */
#define CHECK_ZERO_MSG_RETURN(RET, ERROR, MSG) \
    do { \
        if (0 != RET) { \
            SR_LOG_ERR_MSG(MSG); \
            return ERROR; \
        } \
    } while(0)

#define CHECK_ZERO_LOG_RETURN(RET, ERROR, MSG, ...) \
    do { \
        if (0 != RET) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            return ERROR; \
        } \
    } while(0)

#define CHECK_ZERO_MSG_GOTO(RET, RC, ERROR, LABEL, MSG) \
    do { \
        if (0 != RET) { \
            SR_LOG_ERR_MSG(MSG); \
            RC = ERROR; \
            goto LABEL; \
        } \
    } while(0)

#define CHECK_ZERO_LOG_GOTO(RET, RC, ERROR, LABEL, MSG, ...) \
    do { \
        if (0 != RET) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            RC = ERROR; \
            goto LABEL; \
        } \
    } while(0)

/**
 * Non-minus value checkers.
 */
#define CHECK_NOT_MINUS1_MSG_RETURN(RET, ERROR, MSG) \
    do { \
        if (-1 == RET) { \
            SR_LOG_ERR_MSG(MSG); \
            return ERROR; \
        } \
    } while(0)

#define CHECK_NOT_MINUS1_LOG_RETURN(RET, ERROR, MSG, ...) \
    do { \
        if (-1 == RET) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            return ERROR; \
        } \
    } while(0)

#define CHECK_NOT_MINUS1_MSG_GOTO(RET, RC, ERROR, LABEL, MSG) \
    do { \
        if (-1 == RET) { \
            SR_LOG_ERR_MSG(MSG); \
            RC = ERROR; \
            goto LABEL; \
        } \
    } while(0)

#define CHECK_NOT_MINUS1_LOG_GOTO(RET, RC, ERROR, LABEL, MSG, ...) \
    do { \
        if (-1 == RET) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            RC = ERROR; \
            goto LABEL; \
        } \
    } while(0)

/**
 * NULL value checker - returns given error code.
 */

#define CHECK_NULL_RETURN(ARG, RC) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s in %s", #ARG, __func__); \
        return RC; \
    } \

#endif /* SR_HELPERS_H_ */
