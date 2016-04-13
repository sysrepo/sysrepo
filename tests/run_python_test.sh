#!/bin/sh
# 
# author: Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
# 
# Copyright 2016 Cisco Systems, Inc.
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
# Brief: Sets the environment variable and execute python test. This is needed
# to setup PYTHONPATH for ctest
#
 
if [ "$#" -ne 3 ] ; then
  echo "Usage: $0 PythonPath PythonExecutable Test" >&2
  exit 1
fi

PYTHON_EXE="$2"
TEST_FILE="$3"

export PYTHONPATH="$1"

$PYTHON_EXE $TEST_FILE
