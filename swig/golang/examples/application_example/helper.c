/**
 * @file helper.c
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief implementation of helper function for go program.
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

#include "helper.h"
#include "_cgo_export.h"
#include <sysrepo.h>

sr_val_t *get_val(sr_val_t *val, size_t i) {
	return &val[i];
}

int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    return Go_module_change_cb(session, (char *) module_name, event, NULL);
}
