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
unsigned my_uart_rx_char(void) __attribute__((noinline));
unsigned my_uart_rx_char(void)
{
	while (1)
		;
	return 0;
}

void my_uart_tx_char(char) __attribute__((noinline));
void my_uart_tx_char(char c)
{
	while (1)
		;
}

void my_uart_init(void) __attribute__((noinline));
void my_uart_init(void)
{
	while (1)
		;
}

void my_signal(unsigned) __attribute__((noinline));
void my_signal(unsigned s)
{
	while (1)
		;
}

extern int my_main(void);

#define PRINTF_BUFFER_LEN 4096
unsigned int printf_buffer_len = PRINTF_BUFFER_LEN;
char printf_buffer[PRINTF_BUFFER_LEN];

int
main(void)
{
	/* call this symbol with the assumption that the stack and the bss
	 * are setup
	 */
	my_main();
	while (1)
		;
	return 0;
}


void __attribute__((noreturn)) _exit(int e)
{
	while (1)
		;
}
