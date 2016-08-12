obj ?= ./build

SOURCES = main.c

# Use V=1 for verbose output
ifeq ($(V),)
Q := @
else
Q :=
endif

CFLAGS += -Wall #-Werror
CFLAGS += -I./third_party/unicorn/include/
CFLAGS += -I./third_party/capstone/include/

LDFLAGS += -L./third_party/unicorn -lunicorn
LDFLAGS += -L./third_party/capstone -lcapstone
LDFLAGS += -lelf

OBJS = $(patsubst %.c,$(obj)/%.o,$(SOURCES))
DEPS = $(patsubst %.c,$(obj)/%.d,$(SOURCES))

all: $(obj)/fuzzemu

$(obj):
	@echo "  MKDIR   $(obj)"
	$(Q)mkdir -p $(obj)

$(obj)/%.d $(obj)/%.o: %.c | $(obj)
	@echo "  CC      $(notdir $<)"
	$(Q)$(CC) $(CFLAGS) -c -MMD -MF $(basename $@).d -o $(basename $@).o $<

$(obj)/fuzzemu: $(OBJS)
	@echo "  LD      $(notdir $@)"
	$(Q)$(CC) $< $(LDFLAGS) -o $@

.PHONY: clean
clean:
	@echo "  RM      $(obj)"
	$(Q)rm -rf $(obj)
	-rm -f elf_symbols_gen.h
