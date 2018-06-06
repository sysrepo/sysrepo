/**
 * @file golang_application_example.go
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo go example.
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

package main

import (
	"fmt"
	"unsafe"
)

/*
#cgo LDFLAGS: -lsysrepo

#include <stdio.h>
#include <sysrepo.h>
#include <sysrepo/values.h>
#include "helper.h"
*/
import "C"

func print_value(value *C.sr_val_t) {
	fmt.Printf("%s ", C.GoString(value.xpath))

	switch value._type {
	case C.SR_CONTAINER_T:
	case C.SR_CONTAINER_PRESENCE_T:
		fmt.Printf("(container)\n")
		break
	case C.SR_LIST_T:
		fmt.Printf("(list instance)\n")
		break
	case C.SR_STRING_T:
		val := (**C.char)(unsafe.Pointer(&value.data))
		fmt.Printf("= %s\n", C.GoString(*val))
		break
	case C.SR_BOOL_T:
		bool_val := (*C.bool)(unsafe.Pointer(&value.data))
		if *bool_val == C.bool(true) {
			fmt.Printf("= true\n")
		} else {
			fmt.Printf("= false\n")
		}
		break
	case C.SR_ENUM_T:
		val := (**C.char)(unsafe.Pointer(&value.data))
		fmt.Printf("= %s\n", C.GoString(*val))
		break
	case C.SR_DECIMAL64_T:
		val := (*C.double)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_INT8_T:
		val := (*C.int8_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_INT16_T:
		val := (*C.int16_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_INT32_T:
		val := (*C.int32_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_INT64_T:
		val := (*C.int64_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_UINT8_T:
		val := (*C.uint8_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_UINT16_T:
		val := (*C.uint16_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_UINT32_T:
		val := (*C.uint32_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_UINT64_T:
		val := (*C.uint64_t)(unsafe.Pointer(&value.data))
		fmt.Printf("= %d\n", *val)
		break
	case C.SR_IDENTITYREF_T:
		val := (**C.char)(unsafe.Pointer(&value.data))
		fmt.Printf("= %s\n", C.GoString(*val))
		break
	case C.SR_BITS_T:
		val := (**C.char)(unsafe.Pointer(&value.data))
		fmt.Printf("= %s\n", C.GoString(*val))
		break
	case C.SR_BINARY_T:
		val := (**C.char)(unsafe.Pointer(&value.data))
		fmt.Printf("= %s\n", C.GoString(*val))
		break
	default:
		fmt.Printf("(unprintable)\n")
	}
}

func sysrepo_print_value(value *C.sr_val_t) {
	var mem *C.char = nil
	rc := C.sr_print_val_mem(&mem, value)
	if C.SR_ERR_OK != rc {
		fmt.Printf("Error by sr_print_val_mem: %d", C.sr_strerror(rc))
	} else {
		fmt.Printf("%s", C.GoString(mem))
	}
}

func print_current_config(session *C.sr_session_ctx_t, module_name *C.char) {
	var values *C.sr_val_t = nil
	var count C.size_t = 0
	var rc C.int = C.SR_ERR_OK
	xpath := C.CString("/" + C.GoString(module_name) + ":*//*")
	defer C.free(unsafe.Pointer(xpath))

	rc = C.sr_get_items(session, xpath, &values, &count)
	if C.SR_ERR_OK != rc {
		fmt.Printf("Error by sr_get_items: %d", C.sr_strerror(rc))
		return
	} else {
		defer C.sr_free_values(values, count)
	}

	var i C.size_t = 0
	for i = 0; i < count; i++ {
		val := C.get_val(values, i)
		sysrepo_print_value(val)
		// you can manually print the value, like in the function
		// func print_value(value *C.sr_val_t)
	}
}

//export Go_module_change_cb
func Go_module_change_cb(session *C.sr_session_ctx_t, module_name *C.char, event C.sr_notif_event_t, private_ctx *C.char) C.int {
	fmt.Printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n")

	print_current_config(session, module_name)

	return C.SR_ERR_OK
}

func main() {
	var connection *C.sr_conn_ctx_t = nil
	var session *C.sr_session_ctx_t = nil
	var subscription *C.sr_subscription_ctx_t = nil
	var rc C.int = C.SR_ERR_OK

	module_name := C.CString("ietf-interfaces")
	defer C.free(unsafe.Pointer(module_name))

	/* connect to sysrepo */
	rc = C.sr_connect(module_name, C.SR_CONN_DEFAULT, &connection)
	if C.SR_ERR_OK != rc {
		fmt.Printf("Error by sr_connect: %s\n", C.sr_strerror(rc))
		return
	} else {
		defer C.sr_disconnect(connection)
	}

	/* start session */
	rc = C.sr_session_start(connection, C.SR_DS_STARTUP, C.SR_SESS_DEFAULT, &session)
	if C.SR_ERR_OK != rc {
		fmt.Printf("Error by sr_session_start: %s\n", C.sr_strerror(rc))
		return
	} else {
		defer C.sr_session_stop(session)
	}

	/* read startup config */
	fmt.Printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n")
	print_current_config(session, module_name)

	/* subscribe for changes in running config */
	rc = C.sr_module_change_subscribe(session, module_name, C.sr_module_change_cb(C.module_change_cb), nil, 0, C.SR_SUBSCR_DEFAULT|C.SR_SUBSCR_APPLY_ONLY, &subscription)
	if C.SR_ERR_OK != rc {
		fmt.Printf("Error by sr_module_change_subscribe: %s\n", C.sr_strerror(rc))
		return
	} else {
		defer C.sr_unsubscribe(session, subscription)
	}

	fmt.Printf("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n")

	for {
	}

	fmt.Printf("Application exit requested, exiting.\n")

}
