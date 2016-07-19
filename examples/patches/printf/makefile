CC=gcc
LD=ld
STRIP=strip

OBJ := printf.o
TARGET := printf
LDSCRIPT := printf.lds

%.o: %.c
	$(CC) -c $^ -o $@

%.lds: %.py
	python ../../../generate_lds.py $^ $@

$(TARGET): $(OBJ) $(LDSCRIPT)
	$(LD) -T $(TARGET).lds $(OBJ) -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) $(LDSCRIPT)

rebuild: clean all
