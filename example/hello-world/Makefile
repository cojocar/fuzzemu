
all: libhello-world-full.a

main.o: main.c

libhello-world-full.a: main.o
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	rm -rf libhello-world-full.a main.o
