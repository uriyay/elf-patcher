CC=gcc
LD=ld
STRIP=strip
OBJDUMP=objdump

OBJ := main.o
TARGET := main
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
