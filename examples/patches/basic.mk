CROSS_COMPILER ?= ""
ARCH_PICKLE_FILENAME ?= 
TARGET_TO_PATCH_FILENAME ?=

CC=$(CROSS_COMPILER)gcc
LD=$(CROSS_COMPILER)ld
STRIP=$(CROSS_COMPILER)strip

TARGET_RUNABLE := $(TARGET).runable
OBJ := $(TARGET).o
PYSCRIPT := $(TARGET).py

LDFLAGS := $(LDFLAGS)
CFLGAGS := $(CFLAGS)

%.o: %.c
	$(CC) -c $^ -o $@

$(TARGET): $(OBJ) $(PYSCRIPT)
	$(eval gcc_cmd := $(shell python ../../../compile_patch.py $(PYSCRIPT) $(CROSS_COMPILER) $(ARCH_PICKLE_FILENAME) $(TARGET_TO_PATCH_FILENAME) || echo failure))
	test "$(gcc_cmd)" != failure && $(gcc_cmd) $(LDFLAGS) $(OBJ) -o $(TARGET)

$(TARGET_RUNABLE): $(OBJ)
	$(CC) $(OBJ) -o $@

.PHONY: all clean rebuild

all: $(TARGET) $(TARGET_RUNABLE)

clean:
	rm -f $(OBJ) $(TARGET) $(TARGET_RUNABLE)

rebuild: clean all
