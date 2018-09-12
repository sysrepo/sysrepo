/**
 * @file Xpath.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo class header implementation for C header xpath_utils.h
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
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

#include "Sysrepo.hpp"
#include "Xpath.hpp"

extern "C" {
#include "sysrepo/xpath.h"
}

namespace sysrepo {

Xpath_Ctx::Xpath_Ctx() {
    sr_xpath_ctx_t *state = nullptr;
    state = (sr_xpath_ctx_t *) calloc(1, sizeof(*state));

    if (state == nullptr)
        throw_exception(SR_ERR_NOMEM);

    _state = state;
}
Xpath_Ctx::~Xpath_Ctx() {
    if (_state != nullptr)
        free(_state);
}

}
