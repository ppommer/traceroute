CC=gcc
TARGET=libraw.a
LDFLAGS=
CFLAGS+=-Iinclude -ggdb -Wall -Wextra -pedantic -fdiagnostics-color=auto -O2 -fPIC -fno-strict-aliasing

OBJECTS=src/raw.o src/hexdump.o src/checksum.o src/crc.o

.PHONY: all clean fresh

all: $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $(TARGET) $(OBJECTS)

clean:
	-rm -rf $(OBJECTS)
	-rm -f $(TARGET)

fresh: clean
	$(MAKE) all
