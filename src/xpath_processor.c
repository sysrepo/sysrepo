/**
 * @file xpath_processor.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief xpath addressing helpers
 *
 * @copyright
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
#include <string.h>
#include <ctype.h>
#include "xpath_processor.h"


char token_to_ch(token_t t){
    switch(t){
        case SLASH:
            return '/';
        case COLON:
            return ':';
        case LSQB:
            return '[';
        case RSQB:
            return ']';
        case APOSTROPH:
            return '\'';
        case KEY_NAME:
            return 'k';
        case KEY_VALUE:
            return 'v';
        case NAMESPACE:
            return 'n';
        case NODE:
            return 'i';
        case EQUAL:
            return '=';
        case ZERO:
            return '0';
        default:
            return '-';
    }
}

int node_key_count(location_id_p l, size_t node){
    size_t token_index = GET_NODE_TOKEN(l, node);
    int key_count = 0;
    while(GET_TOKEN(l,token_index)!=SLASH && GET_TOKEN(l,token_index)!=ZERO){
        if(GET_TOKEN(l,token_index)==KEY_VALUE){
            key_count++;
        }
        token_index++;
    }
    return key_count;
}


enum states{
    S_WAIT,
    S_NS,
    S_NODE,
    S_KEY_NAME,
    S_KEY,
};


#define BAD_ALLOC 1
#define BAD_LEX 2
/**
 * TODO more tokens than MAX_TOKENS
 */
int xpath_to_location_id(char *xpath, location_id_p *loc){
    token_t tokens[MAX_TOKENS];
    size_t positions[MAX_TOKENS] = {0, };
    size_t node_index[MAX_TOKENS] = {0,};
    int cnt = 0;
    int i=0;
    int node_count = 0;
    enum states state = S_WAIT;

/* Saves the token type and marks the position */
#define MARK_TOKEN(T) do{tokens[cnt]=T; positions[cnt]=i;  cnt++;}while(0)
    //TODO check token content
    while(xpath[i]!='\0'){
        switch(state){
            case S_WAIT:
                if('/' == xpath[i]){
                    MARK_TOKEN(SLASH);
                    state = S_NS;
                }
                break;
            case S_NS:
                if(':' == xpath[i]){
                    MARK_TOKEN(COLON);
                    state = S_NODE;
                }
                else if('/' == xpath[i]){
                    if(cnt>0 && tokens[cnt-1] == NAMESPACE){
                        tokens[cnt-1] = NODE;
                        node_index[node_count] = cnt-1;
                        node_count++;
                    }
                    MARK_TOKEN(SLASH);
                    state = S_NS;
                }
                else if('[' == xpath[i]) {
                    if (cnt > 0 && tokens[cnt - 1] == NAMESPACE) {
                        tokens[cnt - 1] = NODE;
                        node_index[node_count] = cnt - 1;
                        node_count++;
                    }
                    MARK_TOKEN(LSQB);
                    state=S_KEY_NAME;
                }
                break;
            case S_NODE:
                if('[' == xpath[i]){
                    if(cnt>0 && tokens[cnt-1] == NAMESPACE) {
                       tokens[cnt - 1] = NODE;
                       node_index[node_count] = cnt - 1;
                       node_count++;
                    }
                    MARK_TOKEN(LSQB);
                    state = S_KEY_NAME;
                }
                else if('/' == xpath[i]){
                    if(cnt>0 && tokens[cnt-1] == NAMESPACE){
                       tokens[cnt-1] = NODE;
                       node_index[node_count] = cnt - 1;
                       node_count++;
                    }
                    MARK_TOKEN(SLASH);
                    state = S_NS;
               }
               else if(cnt>0 &&tokens[cnt-1]==NODE){
                  if(!(isalpha(xpath[i]) || xpath[i]=='_' || xpath[i]=='-' || xpath[i]=='.')){
                     return BAD_LEX;
                  }
               }
               else{
                  if(!(isalpha(xpath[i]) || xpath[i]=='_')){
                      return BAD_LEX;
                  }
               }
               break;
            case S_KEY_NAME:
                if('=' == xpath[i]){
                    MARK_TOKEN(EQUAL);
                }
                else if(']' == xpath[i]){
                    if(cnt>0 && tokens[cnt-1] == KEY_NAME){
                        tokens[cnt-1] = KEY_VALUE;
                    }
                    MARK_TOKEN(LSQB);
                }
                else if ('\'' == xpath[i]){
                    MARK_TOKEN(APOSTROPH);
                    state = S_KEY;
                }
                break;
            case S_KEY:
                if(']' == xpath[i]){
                    MARK_TOKEN(RSQB);
                    state = S_NODE;
                }
                else if ('\'' == xpath[i]){
                    MARK_TOKEN(APOSTROPH);
                }
                break;
        }
        /*character right after a token*/
        if(cnt>0 && positions[cnt-1] == (i-1)){
            if(state == S_NS && tokens[cnt-1]!=NAMESPACE){
                MARK_TOKEN(NAMESPACE);
            }
            else if (state == S_NODE && tokens[cnt-1]!= NODE){
                tokens[cnt]=NODE;
                positions[cnt]=i;
                node_index[node_count] = cnt;
                node_count++;
                cnt++;
            }
            else if (state == S_KEY_NAME && tokens[cnt-1] != KEY_NAME){
                MARK_TOKEN(KEY_NAME);
            }
            else if(state == S_KEY && tokens[cnt-1] != KEY_VALUE){
                MARK_TOKEN(KEY_VALUE);
            }
        }
       i++;
    }
    if(cnt>0 && tokens[cnt-1] == NAMESPACE) {
        tokens[cnt - 1] = NODE;
        node_index[node_count] = cnt - 1;
        node_count++;
    }
    MARK_TOKEN(ZERO);

    /*Validate token order*/
#define BAD_TOKEN 4
    token_t curr = SLASH;
    token_t t = tokens[0];
    if(t!=SLASH)
        return BAD_TOKEN;
    for(int i=1; i<cnt; i++){
        t = tokens[i];
       switch(curr){
       case SLASH:
          if(t==NAMESPACE || t==NODE){
              curr=t;
          }
          else{
              return BAD_TOKEN;
          }
       break;
       case NODE:
          if(t==SLASH || t== LSQB || t==ZERO){
              curr=t;
          }
          else{
              return BAD_TOKEN;
          }
       break;
       case LSQB:
          if(t==APOSTROPH || t==KEY_NAME){
              curr=t;
          }
          else{
              return BAD_TOKEN;
          }
       break;
       case RSQB:
          if(t==LSQB || t==ZERO  || t==SLASH){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
       break;
       case APOSTROPH:
          if(t==KEY_VALUE || t==RSQB){
              curr = t;
          }else{
              return BAD_TOKEN;
          }
       break;
       case NAMESPACE:
          if(t==COLON){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
       break;
       case KEY_NAME:
          if(t==EQUAL){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
       break;
       case KEY_VALUE:
          if(t==APOSTROPH){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
          break;
       case COLON:
          if(t==NODE){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
          break;
       case EQUAL:
          if(t==APOSTROPH){
              curr=t;
          }else{
              return BAD_TOKEN;
          }
          break;
       case ZERO:
          break;
       default:
          return BAD_TOKEN;
       }
    }

    if(t!=ZERO){
        return BAD_TOKEN;
    }

    /*Allocate structure*/
    *loc = (location_id_p) malloc(sizeof(location_id_t));
    if(*loc == NULL){
        return BAD_ALLOC;
    }
    (*loc)->xpath = strdup(xpath);

    if((*loc)->xpath == NULL)
        return BAD_ALLOC;

    (*loc)->positions = malloc(cnt * sizeof(size_t));
    if((*loc)->positions == NULL)
        return BAD_ALLOC;

    (*loc)->tokens = malloc(cnt * sizeof(token_t));
    if((*loc)->tokens == NULL)
        return BAD_ALLOC;

    for(int j=0; j<cnt; j++){
       (*loc)->tokens[j] = tokens[j];
       (*loc)->positions[j] = positions[j];
    }
    (*loc)->cnt = cnt;

    (*loc)->node_index = malloc(node_count * sizeof(size_t));
    if((*loc)->node_index == NULL)
        return  BAD_ALLOC;

    (*loc)->node_count = node_count;

    for(int j=0; j<node_count; j++){
        (*loc)->node_index[j] = node_index[j];
    }

    return 0;
}

void free_location_id(location_id_p l){
   free(l->xpath);
   free(l->tokens);
   free(l->positions);
   free(l->node_index);
   free(l);
}

void print_location_id(location_id_p l){
   puts(l->xpath);
   for(int i=0; i < l->cnt; i++){
       printf("%c\t%d\n", token_to_ch(l->tokens[i]), (int) l->positions[i]);
   }
}
