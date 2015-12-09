/**
 * @file sr_app_read_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
 *
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

#include <stdio.h>
#include <stdlib.h>
#include "libsysrepo.h"

int main(int argc, char **argv){
  //init
  sr_settings_t settings;
  sr_init_default_settings(&settings);

  sr_ctx_p sr_ctx;
  sr_init(&settings, &sr_ctx);

  sr_session_ctx_p session;
  sr_session_start(sr_ctx, "username", &session);


  //get one particular leaf
  #define XPATH_TO_LEAF "/ModelName:container/list[key1='val1'][key2='val2']/leaf"
  sr_val_p my_value;
  sr_get_item(session, XPATH_TO_LEAF, &my_value);
  //process my_value
  if(SR_UINT_32 == SR_VAL_TYPE(my_value)){ // check is not neccessary if you are sure about the type
      uint32_t option = SR_VAL_DATA(my_option);
  }
  free(my_option);


  //bulk processing
  #define XPATH_TO_CONTAINER "/ModelName:container"
  sr_val_p *values, *sub_values;
  size_t values_cnt, sub_values_cnt;
  sr_get_items(session, XPATH_TO_CONTAINER, values, &values_cnt);

  for(size_t i = 0; i < values_cnt; i++){
      sr_val_p val = values[i];

      switch(SR_VAL_TYPE(val)){

          case SR_LIST:
              printf("%s is a list with keys: ", SR_VAL_NAME(val));
              for(size_t k=0; k < SR_VAL_KEY_COUNT(val); k++){
                  printf("%s = %s", SR_VAL_KEY_NAME(val, k),  SR_VAL_KEY_VALUE(val, k));
              }
              //SR_VAL_XPATH(value) can be used to call sr_get_items on this list (e.g. recursively)
              sr_get_items(session, SR_VAL_XPATH(val), sub_val, sub_val_cnt);
              break;

          case SR_CONTAINER:
               if(strcmp(SR_VAL_NAME(val), "my_presence_container") == 0){
                   puts("My presence container is present :)");
               }
               //possible to call sr_get_items in the same way as shown in list
               break;

          default:
               if(strcmp(SR_VAL_NAME(val), "my_leaf") == 0){
                   //proces my_leaf as shown in leaf example (use SR_VAL_DATA to access data)
               }
      }
      free(val);
  }

  //clean up
  sr_session_stop(session);
  sr_clean_up(sr_ctx);
}


