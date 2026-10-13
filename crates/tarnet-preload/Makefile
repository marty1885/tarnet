CC ?= gcc
CFLAGS = -Wall -Wextra -fPIC -O2
LDFLAGS = -lpthread

ifeq ($(shell uname -s),Darwin)
TARGET = libtarnet_preload.dylib
CFLAGS += -dynamiclib
else
TARGET = libtarnet_preload.so
CFLAGS += -shared -D_GNU_SOURCE
LDFLAGS += -ldl
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): src/preload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
