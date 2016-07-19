CC=gcc
LD=ld
STRIP=strip

OBJ := run_sh.o
TARGET := run_sh
LDSCRIPT := run_sh.lds

LDFLAGS := 

%.o: %.c
	$(CC) -c $^ -o $@

%.lds: %.py
	python ../../../generate_lds.py $^ $@.tmp
	echo INCLUDE default.lds > $@
	cat $@.tmp >> $@
	rm $@.tmp

$(TARGET): $(OBJ) $(LDSCRIPT)
	$(CC) -T $(TARGET).lds $(LDFLAGS) $(OBJ) -o $(TARGET)

all: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) $(LDSCRIPT)

rebuild: clean all
