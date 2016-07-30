CROSS_COMPILER ?= 

CC=$(CROSS_COMPILER)gcc
LD=$(CROSS_COMPILER)ld
STRIP=$(CROSS_COMPILER)strip
OBJDUMP=$(CROSS_COMPILER)objdump

OBJ := $(TARGET).o
TARGET_ASM := $(TARGET).asm

%.o: %.c
	$(CC) -c $^ -o $@

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)
	
$(TARGET_ASM): $(TARGET)
	$(OBJDUMP) -d $(TARGET) > $(TARGET_ASM)

all: $(TARGET) $(TARGET_ASM)

clean:
	rm -f $(OBJ) $(TARGET) $(TARGET_ASM)

rebuild: clean all
