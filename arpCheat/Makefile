#
#
#

.PHONY: all clean depend

CFLAGS := -Wall -g -shared -fPIC -std=gnu99 -D_GNU_SOURCE
LDFLAGS := -lpthread
CC := gcc

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))


TARGET := arpCheat

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

explain:
	@echo "The information represents in the program:"
	@echo "Final executable name: $(TARGET)"
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"

clean:
	rm -f $(TARGET) $(OBJS)

