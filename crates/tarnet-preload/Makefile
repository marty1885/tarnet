CC ?= gcc
CFLAGS = -Wall -Wextra -fPIC -shared -O2 -D_GNU_SOURCE
LDFLAGS = -ldl -lpthread

TARGET = libtarnet_preload.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/preload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
