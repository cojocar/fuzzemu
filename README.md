`fuzzemu` is an instruction emulator for the Cortex-M3 ARM architecture. Its
focus is on instruction emulation. It can be extended to model instruction skip
attacks. `fuzzemu` builds on [capstone](http://www.capstone-engine.org/) and
[unicorn](http://www.unicorn-engine.org/).

# Requirements

A working build environment is needed as well a arm-none-eabi\* toolchain.

# Building fuzzemu

1. Run the script `./setup.sh`. The script will pull in the required
   dependencies
2. Run the script `./compile.sh`. The script will compile the dependencies.

# Running fuzzemu

```sh
./run-ext-lib.sh input-lib.a
```

The above script will recompile the emulator and start the emulation of the input-lib.a

## API

The `input-lib` can use the following API to interact with the outside world:

```C
/* initialize the uart, this function should be called before printing */
void my_uart_init(void)                 __attribute__((noinline));
/* blocking receive of one character */
unsigned my_uart_rx_char(void)          __attribute__((noinline));
/* print one character */
void my_uart_tx_char(char c)            __attribute__((noinline));
/* a way to signal the emulator */
void my_signal(unsigned)                __attribute__((noinline));
/* the main function */
void my_main(void)                      __attribute__((noinline));
```

Check [example/hello-word/io.h](example/hello-word/io.h).

## Stack setup

The stack top is specified via `__stack` symbol in the input library. The stack
size is defined by `STACK_LEN` macro from [main.c](main.c). If the symbol
`__stack` is missing then a default value is used.

## Uart emulation

The uart is exposed through two named pipes: `fuzzemu-pipe.{in,out}`. The named
pipes are created by the `compile.sh` script.

## Example

Check [example/hello-world](example/hello-word) for a running example.

```sh
# compile the example
$ cd example/hello-world
$ CC="clang -O3 -target arm-none-eabi -mcpu=cortex-m3 -mfloat-abi=soft" make
$ cd -
$ ./run-ext-lib.sh example/hello-world/libhello-world-full.a
  RM      ./build
rm -f elf_symbols_gen.h
/tmp/tmp.WYg9vSRKgn ~/code/fuzzemu
~/code/fuzzemu
  CC      main.c
  LD      fuzzemu
please run 'LD_LIBRARY_PATH=./third_party/unicorn/:./third_party/capstone ./build/fuzzemu ./build/fake.elf'
===============
Running Fuzzemu
Using cortex-m3
emulation started
using pipe: out:fuzzemu-pipe.out in:fuzzemu-pipe.in
waiting for connection ...
```

Now `fuzzemu` waits for a connection on the two pipes.

Connect to the output pipe (new shell)
```sh
$ cat ~/code/fuzzemu/fuzzemu-pipe.out
```

Connect to the input pipe (new shell)

```sh
$ echo 'abcSasq' > ~/code/fuzzemu/fuzzemu-pipe.in
```

Now the emulator should resume execution.
```sh
got connection. Resume execution
signal=0x02
signal=0x01
read(): Invalid argument
read error, exit!
```

And output should appear at the out pipe.
```sh
Hello World!
abc
Sending signal 2
a
Sending signal 1

Quit!
```

# Disclaimer

Please note that although some of the authors are (or were) employed by Google,
this is not an official Google product.
