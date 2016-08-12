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

function set_flags
{
	my_AR="arm-none-eabi-ar"
	FL_clang="-target arm-none-eabi -mcpu=cortex-m3 -mfloat-abi=soft -mthumb"
	my_CC="clang ${FL_clang}"
	my_OBJCOPY="arm-none-eabi-objcopy"
}

function re_archive_lib()
{
	### this function will replace libio-stlib (the one that external
	# parties should use, with our custom libio-board

	set_flags
	input_lib=${EXTERNANL_LIB} # this is the path to the library that was compiled
	test -f ${input_lib} || { echo "missing input lib: ${input_lib}"; exit -1; }

	# unpack the submited archive and add libio-board into it
	tmp=$(mktemp -d)
	cp ${input_lib} ${tmp}/
	lib_name=$(basename ${input_lib})
	pushd ${tmp}
	#${my_AR} t ${lib_name}
	${my_AR} x ${lib_name}
	rm ${lib_name}
	#rm libio-stdlib.a
	popd

	# create a thin ar archive
	test -d libs || mkdir libs
	target=libs/$(basename ${lib_name} .a)-thin.a
	test -f ${target} && mv ${target} ${target}.bkp.$(date +%s)
	rm -f ${target}
	${my_AR} rcT ${target} \
		${tmp}/*
}

out_dir=./build
out_elf=${out_dir}/fake.elf

function generate_fake_elf()
{
	# generate a elf with this lib for easy loading

	libflag=$(basename ${EXTERNANL_LIB} .a | sed -e "s/^lib/-l/")-thin

	mkdir -p ${out_dir}

	custom_ldflags="-Llibs ${libflag}"
	custom_ldflags="${custom_ldflags} -L./third_party/libaeabi-cortexm0/ -laeabi-cortexm0"
	custom_ldflags="${custom_ldflags} -nostdlib -lc"

	${my_CC} -static fake_app_main.c \
		${custom_ldflags} -static -o ${out_elf}

	# generate bin (not needed_)
	#--gap-fill 0 \
	${my_OBJCOPY} \
		-I elf32-littlearm -O binary \
		--remove-section .guarded_data \
		${out_elf} ${out_dir}/fake.bin
}

function generate_symbol_h()
{
	out_header=elf_symbols_gen.h
	nm ${1} | grep -v ' N $' | \
		cut -f1,3 -d ' ' | \
		grep -v '\$' | sort -n -k2 | \
		awk -F' ' '{print "#define symbol_" $2 "\t0x" $1}' > \
		${out_header}
	sync
}

EXTERNANL_LIB=$(realpath ${1})
#set -x
make clean
set_flags
re_archive_lib ${EXTERNANL_LIB}
generate_fake_elf ${EXTERNANL_LIB}
generate_symbol_h ${out_dir}/fake.elf

# compile the emulator
make
echo please run "'LD_LIBRARY_PATH=./third_party/unicorn/:./third_party/capstone ./build/fuzzemu ${out_elf}'"
