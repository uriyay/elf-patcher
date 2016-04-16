CC=gcc
LD=ld
STRIP=strip

OBJ := run_sh.o
TARGET := run_sh

LDFLAGS := 

%.o: %.c
	$(CC) -c $^ -o $@

$(TARGET): $(OBJ)
	$(CC) -T $(TARGET).lds $(LDFLAGS) $(OBJ) -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all
