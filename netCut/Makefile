#
#
#

.PHONY: all clean depend

CFLAGS := -Wall -g -shared -fPIC -std=gnu99 -D_GNU_SOURCE
INCLUDE := -I./
LDFLAGS := -lpthread
CC := g++

SRCS := $(wildcard *.c)
DEPS := $(patsubst %.c,%.d,$(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))


TARGET := net_cut

all: $(TARGET)

$(TARGET): $(OBJS) $(DEPS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.d:%.c
	$(CC) -M $(INCLUDE) $(CFLAGS) $< > $@

%.o:%.c
	$(CC) -c $(INCLUDE) $(CFLAGS) $< -o $@

explain:
	@echo "The information represents in the program:"
	@echo "Final executable name: $(TARGET)"
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"

depend:$(DEPS)
	@echo "Dependencies are now up-to-date"

clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
