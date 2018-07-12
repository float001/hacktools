#
#
#

.PHONY: all clean depend

CFLAGS := -Wall -g -O0 -D_GNU_SOURCE
INCLUDE := -I./
LDFLAGS := -lpthread
CC := g++

SRCS := $(wildcard *.cpp)
OBJS := $(patsubst %.cpp,%.o,$(SRCS))


TARGET := net_cut

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o:%.cpp
	$(CC) -c $(INCLUDE) $(CFLAGS) $< -o $@

explain:
	@echo "The information represents in the program:"
	@echo "Final executable name: $(TARGET)"
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"

clean:
	rm -f $(TARGET) $(OBJS)

