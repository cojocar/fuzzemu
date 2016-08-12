/*
 * Copyright 2016 The Fuzzemu Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STR(a) #a

//#define DEBUG_FUZZEMU
#ifdef DEBUG_FUZZEMU
#define Dprintf(format, ...) \
	fprintf(stderr, format, ##__VA_ARGS__)
#else
#define Dprintf(...)
#endif

#include <unicorn/unicorn.h>
#include <capstone.h>

#include "elf_symbols_gen.h"

static void dump_regs(uc_engine *uc);
uint32_t addr_base, addr_len;

static int fd_in = 0;
static int fd_out = 1;
static int use_pipe = 0;
static int flag_display_insn = 0;

/* capstone ahndle */
static csh cs_handle;

static void
hooked_uart_tx_char(char c)
{
	write(fd_out, &c, 1);
}

static unsigned
hooked_uart_rx_char(void)
{
	char x = 0;
	int ret;

	ret = read(fd_in, &x, 1);
	if (ret <= 0) {
		perror("read()");
		fprintf(stderr, "read error, exit!\n");
		exit(0);
	}
	return (unsigned)x;
}

static void
hooked_uart_init(void)
{
#define PIPE_NAME_IN "fuzzemu-pipe.in"
#define PIPE_NAME_OUT "fuzzemu-pipe.out"
	if (use_pipe) {
		fprintf(stderr, "using pipe: out:%s in:%s\n", PIPE_NAME_OUT, PIPE_NAME_IN);
		fprintf(stderr, "waiting for connection ...\n");
		fd_in = open(PIPE_NAME_IN, O_RDONLY);
		fd_out = open(PIPE_NAME_OUT, O_NOCTTY|O_SYNC|O_WRONLY);
		assert(fd_in >= 0 && fd_out >= 0);
		fprintf(stderr, "got connection. Resume execution\n");
	}
}

#if 0
enum insn_class
{
	ICLASS_BRANCH,
	ICLASS_UNKN,
};

static enum insn_class get_class_from_string(const char *mnemonic)
{
	return ICLASS_UNKN;
}
#endif

static uint32_t nop_cnt;

static void display_instrucion(uc_engine *uc, uint64_t address, uint32_t
		size, unsigned *should_skip_this)
{
	cs_insn *insn;
	size_t cnt;
	uint8_t insn_buf[size];
	uc_err err;
	size_t j;

	/* read code */
	err = uc_mem_read(uc, address, insn_buf, size);
	assert(!err && "failed mem read (insn)");

	/* disas code */
	cnt = cs_disasm(cs_handle, insn_buf, size, address, 0, &insn);
	if (cnt > 0) {
		for (j = 0; j < cnt; j++) {
			if (flag_display_insn)
				fprintf(stderr, "\t%"PRIx64":\t%s\t\t%s\n", insn[j].address,
						insn[j].mnemonic,
						insn[j].op_str);
			if (!strcmp("mov", insn[j].mnemonic) && !strcmp("r0, r0", insn[j].op_str)) {
				//fprintf(stderr, "NOP @0x%08x\n", insn[j].address);
				++nop_cnt;
				if (nop_cnt % 100000 == 0) {
					fprintf(stderr, "nops: %d\n", nop_cnt);
				}
			} else if (!strcmp("udf.w", insn[j].mnemonic)) {
				fprintf(stderr, "Got udf\n");
				*should_skip_this = 1;
			} else if (!strcmp("bx", insn[j].mnemonic)) {
				Dprintf("got bx\n");
				dump_regs(uc);
			} else if (!strcmp("strd", insn[j].mnemonic)) {
				Dprintf("got strd\n");
				dump_regs(uc);
			} else if (!strcmp("ldr", insn[j].mnemonic)) {
				Dprintf("got ldr\n");
				dump_regs(uc);
			} else if (!strcmp("mov", insn[j].mnemonic)) {
				Dprintf("got mov\n");
				dump_regs(uc);
			}
			if (cs_insn_group(cs_handle, &insn[j], CS_GRP_JUMP)) {
				/* fprintf(stderr, "\t\tjmp^^^\n"); */
			}
		}
	} else {
		fprintf(stderr,
				"XXX: failed to dissas @0x%08x %02hhx%02hhx (size=%u)\n",
				(uint32_t)address, insn_buf[0], insn_buf[1], size);
	}

	cs_free(insn, cnt);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint8_t bytes[2*size];
	uc_err err;
	uint32_t pc;


	Dprintf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

	err = uc_mem_read(uc, address, bytes, size);
	assert(!err && "failed mem read");

	if (bytes[0] == 0xff && bytes[1] == 0xf7) {
		Dprintf("quirk for insn 0xfff7\n");
		/* quirk: capstone reports 2 bytes insn size here */
		size = 4;
		err = uc_mem_read(uc, address, bytes, size);
		assert(!err && "failed mem read");
	} else if (bytes[0] == 0x00 && bytes[1] == 0xf0) {
		Dprintf("quirk for insn 0x00f0\n");
		/* quirk: capstone reports 2 bytes insn size here */
		size = 4;
		err = uc_mem_read(uc, address, bytes, size);
		assert(!err && "failed mem read");
	} else {
		/* cortex-m32 quirks for insn size */
		/* http://stackoverflow.com/questions/28860250/how-to-determine-if-a-word4-bytes-is-a-16-bit-instruction-or-32-bit-instructio
		 */
#define M 0xf8
#define A 0xf8
#define B 0xf0
#define C 0xe8
		uint8_t r = bytes[1] & M;
		if (r == A || r == B || r == C) {
			Dprintf("generic quirk for insn %02hhx%02hhx\n",
					bytes[0], bytes[1]);
			size = 4;
		}
	}

	uc_reg_read(uc, UC_ARM_REG_PC, &pc);
	Dprintf("pc@%08x[insn=%02x%02x]\n", pc, bytes[0], bytes[1]);

	/* stubs for the serial port */
	if (pc == (symbol_my_uart_init & -2)) {
		/* do nothin for symbol_my_uart_init */
		uint32_t lr;
		uc_reg_read(uc, UC_ARM_REG_LR, &lr);

		hooked_uart_init();

		Dprintf("my_uart_init ret@0x%08x\n", lr);
		uc_reg_write(uc, UC_ARM_REG_PC, &lr);
		return;
	} else if (pc == (symbol_my_uart_tx_char & -2)) {
		/* my uart tx char */
		/* void my_uart_tx_char(char c); */
		uint32_t lr, r0;
		uc_reg_read(uc, UC_ARM_REG_LR, &lr);
		uc_reg_read(uc, UC_ARM_REG_R0, &r0);

		hooked_uart_tx_char((char)r0);

		Dprintf("my_uart_tx_char ret@0x%08x\n", lr);
		uc_reg_write(uc, UC_ARM_REG_PC, &lr);
		return;
	} else if (pc == (symbol_my_uart_rx_char & -2)) {
		/* unsigned my_uart_rx_char(void); */
		uint32_t lr, r0;

		uc_reg_read(uc, UC_ARM_REG_LR, &lr);

		r0 = hooked_uart_rx_char();

		uc_reg_write(uc, UC_ARM_REG_R0, &r0);
		Dprintf("my_uart_rx_char ret@0x%08x\n", lr);
		uc_reg_write(uc, UC_ARM_REG_PC, &lr);
		return;
	} else if (pc == (symbol_my_signal & -2)) {
		uint32_t lr, r0;
		uc_reg_read(uc, UC_ARM_REG_LR, &lr);
		uc_reg_read(uc, UC_ARM_REG_R0, &r0);

		fprintf(stderr, "signal=0x%02x\n", r0);

		uc_reg_write(uc, UC_ARM_REG_PC, &lr);
		return;
	}

	unsigned should_skip_this = 0;
	/* disas instruction at pc */
	display_instrucion(uc, address, size, &should_skip_this);
	if (should_skip_this) {
		uint32_t new_pc = pc + size + 1;
		uc_reg_write(uc, UC_ARM_REG_PC, &new_pc);
	}
	/* actual instruction skip policy */
#if 0
	if (address == 0x80b4) {
		uint32_t new_pc = pc + size + 1;
		fprintf(stderr, "skip instruction\n");
		uc_reg_write(uc, UC_ARM_REG_PC, &new_pc);
	}
#endif
#if 0
	{
		uint32_t new_pc = 0x8396 + 1;
		static unsigned triggered = 0;
		if (!triggered) {
			fprintf(stderr, "Trigger udf\n");
			uc_reg_write(uc, UC_ARM_REG_PC, &new_pc);
			triggered = 1;
		}
	}
#endif
}

#if 0
static void hook_interrupt(uc_engine *uc, uint32_t intno, void *user_data)
{
	fprintf(stderr, "interrupt\n");
}
#endif

static void dump_regs(uc_engine *uc)
{
#define PRINT_REG(RN) do { \
	uint32_t reg_val_##RN; \
	uc_reg_read(uc, UC_ARM_REG_##RN, &reg_val_##RN); \
	Dprintf(STR(RN) ":0x%08x", reg_val_##RN); \
	} while (0)

	Dprintf(">>> ");
	PRINT_REG(PC); Dprintf(" "); PRINT_REG(LR); Dprintf(" "); PRINT_REG(SP);
	Dprintf("\n");

	Dprintf(">>> ");
	PRINT_REG(R0); Dprintf(" "); PRINT_REG(R1); Dprintf(" "); PRINT_REG(R2);
	Dprintf("\n");

	Dprintf(">>> ");
	PRINT_REG(R3); Dprintf(" "); PRINT_REG(R4); Dprintf(" "); PRINT_REG(R5);
	Dprintf("\n");
}

static int load_segment_in_unicorn(uc_engine *uc, void *elf_buf, Elf *e, size_t segm_num)
{
	GElf_Phdr phdr;
	uc_err err;

	if (gelf_getphdr(e, segm_num, &phdr) != &phdr)
		errx(EXIT_FAILURE, "getphdr() failed: %s.",
				elf_errmsg(-1));

	Dprintf("load segment: [0x%08x-0x%08x](type=%s, off=0x%08x)\n",
			(uint32_t)phdr.p_paddr, (uint32_t)phdr.p_filesz + (uint32_t)phdr.p_paddr,
			((phdr.p_type == PT_LOAD) ? "PT_LOAD" : "?"),
			(uint32_t)phdr.p_offset);
	err = uc_mem_write(uc, phdr.p_paddr, &((uint8_t*)elf_buf)[phdr.p_offset], phdr.p_filesz);
	assert(!err && "failed mem write");
	return err;
}

static void load_elf_in_unicorn(uc_engine *uc, const char *path_to_elf)
{

	uint32_t addr_min, addr_max;
	struct stat elf_stat;
	int fd, i;
	void *elf_buf;
	Elf *e;
	size_t n;
	GElf_Phdr phdr;
	uc_err err;

	/* map elf: get min address and max address
	 * alocate buffer
	 * copy things inplace
	 * min address p_paddr
	 * max address p_paddr+p_memsz
	 * min address p
	 * Map each segment [p_paddr; p_paddr+p_filesz] (assume the rest 0)
	 */

	/* get addr_min and addr_max to map */
	addr_max = 0;
	addr_min = UINT_MAX;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "ELF library initialization "
				"failed: %s", elf_errmsg(-1));

	if ((fd = open(path_to_elf, O_RDONLY, 0)) < 0)
		errx(EXIT_FAILURE, "open \"%s\" failed", path_to_elf);

	if (fstat(fd, &elf_stat) < 0) {
		perror("fstat()");
		goto failed_fstat;
	}

	elf_buf = malloc(elf_stat.st_size);
	assert(elf_buf != NULL);

	if (read(fd, elf_buf, elf_stat.st_size) != elf_stat.st_size) {
		perror("read()");
		goto failed_read;
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed: %s.",
				elf_errmsg(-1));

	if (elf_kind(e) != ELF_K_ELF)
		errx(EXIT_FAILURE, "\"%s\" is not an ELF object.",
				path_to_elf);

	if (elf_getphdrnum(e, &n) != 0)
		errx(EXIT_FAILURE, "elf_getphdrnum() failed: %s.",
				elf_errmsg(-1));

	for (i = 0; i < n; i++) {
		if (gelf_getphdr(e, i, &phdr) != &phdr)
			errx(EXIT_FAILURE, "getphdr() failed: %s.",
					elf_errmsg(-1));
		if (phdr.p_paddr < addr_min)
			addr_min = phdr.p_paddr;
		if (phdr.p_paddr+phdr.p_memsz > addr_max)
			addr_max = phdr.p_paddr+phdr.p_memsz;
	}

	addr_base = addr_min;
	addr_len = addr_max-addr_min;

#define ALIGN_SZ 1024
	addr_len = ((addr_len + ALIGN_SZ-1) /
		ALIGN_SZ) * ALIGN_SZ;
#undef ALIGN_SZ

	Dprintf("mapping elf from [0x%08x-0x%08x](len=0x%08x)\n", addr_min, addr_max, addr_len);
	err = uc_mem_map(uc, addr_base, addr_len, UC_PROT_ALL);
	if (err) {
		Dprintf("Failed on uc_mem_map() with error returned: %u (%s)\n",
				err, uc_strerror(err));
		goto failed_uc_map;
	}
	/* TODO: is this needed?  */
	void *zero_buf = calloc(addr_len, 1);
	uc_mem_write(uc, addr_base, zero_buf, addr_len);



	/* load segments */
	for (i = 0; i < n; i++) {
		load_segment_in_unicorn(uc, elf_buf, e, i);
	}

	free(zero_buf);


failed_uc_map:
	elf_end(e);
failed_read:
	free(elf_buf);
failed_fstat:
	close(fd);
}

int main(int argc, char **argv, char **envp)
{
	uc_err err;
	uc_hook trace_code;
	uc_engine *uc;
	uint32_t sp;
	int i;

	err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc);
	if (err) {
		Dprintf("Failed on uc_open() with error returned: %u (%s)\n",
				err, uc_strerror(err));
		return -1;
	}

	load_elf_in_unicorn(uc, argv[1]);

	/* TODO: use getopt */
	for (i = 2; i < argc; ++i) {
		if (!strcmp(argv[i], "--use-pipe"))
			use_pipe = 1;
		if (!strcmp(argv[i], "--dump"))
			flag_display_insn = 1;
	}


	/* initialize capstone engine */
	if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, &cs_handle) != CS_ERR_OK) {
		fprintf(stderr, "Failed to initialize capstone engine\n");
		return -1;
	}
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

	/* install hooks */
	uc_hook_add(uc, &trace_code, UC_HOOK_CODE, hook_code, NULL, addr_base, addr_len);

#define STACK_LEN (1024 * 100)

#ifndef symbol__stack
#define symbol__stack 0xA0000
#warning Using a default stack position
	/* TODO check if something else is mapped at that address */
#endif
	/* set stack */
	sp = symbol__stack;
	uc_reg_write(uc, UC_ARM_REG_SP, &sp);

	/* map stack */
	err = uc_mem_map(uc, symbol__stack-STACK_LEN, STACK_LEN, UC_PROT_ALL);
	if (err) {
		Dprintf("Stack: uc_mem_map(): %u: %s\n", err, uc_strerror(err));
	}

	/* start emulation */
	fprintf(stderr, "emulation started\n");
	err = uc_emu_start(uc, symbol_my_main|1, addr_base+addr_len, 0, 0);
	if (err) {
		Dprintf("Failed on uc_emu_start() with error returned: %u: %s\n", err, uc_strerror(err));
	}

	dump_regs(uc);
	uc_close(uc);

	return 0;
}
