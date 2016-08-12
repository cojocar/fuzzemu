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
#include "io.h"

#define STACK_SIZE (10*1024)
char __stack[STACK_SIZE];

static void
puts(char *p)
{
	while (*p) {
		my_uart_tx_char(*p++);
	}
}

int
my_main(void)
{
	my_uart_init();
	puts("Hello World!\n");

	while (1) {
	    unsigned c = my_uart_rx_char();
	    switch (c) {
	    case 'q': puts("\nQuit!\n"); break;
	    case 's': puts("\nSending signal 1\n"); my_signal(1); break;
	    case 'S': puts("\nSending signal 2\n"); my_signal(2); break;
	    default : my_uart_tx_char((char)c); break;
	    };
	}
	return 0;
}
