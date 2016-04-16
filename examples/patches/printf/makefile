CC=gcc
LD=ld
STRIP=strip

OBJ := printf.o
TARGET := printf

%.o: %.c
	$(CC) -c $^ -o $@

$(TARGET): $(OBJ)
	$(LD) -T $(TARGET).lds $(OBJ) -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all
