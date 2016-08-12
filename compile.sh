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

set -x
tp=third_party

njobs=`getconf _NPROCESSORS_ONLN`

# create the pipes for the emulator
mkfifo fuzzemu-pipe.{in,out}

# unicron

(pushd ${tp}/unicorn &&
	./make.sh &&
	popd)

# capstone
(pushd ${tp}/capstone &&
	./make.sh &&
	ln -s libcapstone.so libcapstone.so.3 &&
	popd)

# libaeabi-arm
(pushd ${tp}/libaeabi-cortexm0 &&
	make -j${njobs})
