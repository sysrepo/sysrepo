/**
 * @file Internal.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo class header implementation for internal C++ classes
 *
 * @copyright
 * Copyright 2016 - 2019 Deutsche Telekom AG.
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

#include <cassert>
#include <iostream>

#include "Sysrepo.hpp"
#include "Internal.hpp"

#include "sysrepo.h"

namespace sysrepo {

Deleter::Deleter(sr_val_t *val) {
    v._val = val;
    _t = Free_Type::VAL;
}
Deleter::Deleter(sr_val_t *vals, size_t cnt) {
    v._val = vals;
    c._cnt = cnt;
    _t = Free_Type::VALS;
}
Deleter::Deleter(sr_val_t **vals, size_t *cnt) {
    v.p_vals = vals;
    c.p_cnt = cnt;
    _t = Free_Type::VALS_POINTER;
}
Deleter::Deleter(sr_session_ctx_t *sess) {
    v._sess = sess;
    _t = Free_Type::SESSION;
}
Deleter::~Deleter() {
    switch(_t) {
    case Free_Type::VAL:
        if (v._val) sr_free_val(v._val);
    v._val = nullptr;
    break;
    case Free_Type::VALS:
        if (v._val) sr_free_values(v._val, c._cnt);
    v._val = nullptr;
    break;
    case Free_Type::VALS_POINTER:
        if (*v.p_vals) sr_free_values(*v.p_vals, *c.p_cnt);
    *v.p_vals = nullptr;
    break;
    case Free_Type::SESSION:
        if (!v._sess) break;
        int ret = sr_session_stop(v._sess);
        if (ret != SR_ERR_OK) {
            //this exception can't be catched
            //throw_exception(ret);
        }
    v._sess = nullptr;
    break;
    }
}

/** @short Notify the deleter that the underlying storage was reallocated */
void Deleter::update_vals_with_count(sr_val_t *val, size_t cnt)
{
    assert(_t == Free_Type::VALS);
    v._val = val;
    c._cnt = cnt;
}

}
