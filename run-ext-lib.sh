#!/bin/bash
#
# Copyright 2016 The Fuzzemu Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################


test ${#@} -ne 2 || { echo $0 path_to_libarry_to_run; exit -1; } ;

test -f ${1} || { echo 'invalid file path to run'; exit -1; } ;
lib_path=$(realpath ${1})

./process-ext-lib.sh ${lib_path}

echo '==============='
echo 'Running Fuzzemu'
LD_LIBRARY_PATH="./third_party/unicorn/:./third_party/capstone/" ./build/fuzzemu ./build/fake.elf --use-pipe
