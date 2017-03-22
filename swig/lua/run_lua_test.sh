#!/bin/sh
#
# author: Antonio Paunovic<antonio.paunovic@sartura.hr>
#
# Copyright 2017 Sartura d.o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#
# Brief: Sets the environment variable and execute lua test. This is needed
# to setup LUAPATH for ctest
#

if [ "$#" -ne 4 ] ; then
    echo "Usage: $0 PATH luapath lua_executable test" >&2
    exit 1
fi
PTH="$1"
LUA_EXE="$3"
TEST_FILE="$4"
export LUA_CPATH="$2/?.so"

$LUA_EXE $TEST_FILE
