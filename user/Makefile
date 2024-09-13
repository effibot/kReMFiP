PWD = $(shel pwd)
MISC = ../src/utils/misc.c
# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O0 -Wextra -Werror -Wno-implicit-fallthrough -Wno-unused-parameter

# Search for all .c files in the current directory
SRCS = $(wildcard *.c)
SRCS += $(MISC)



# Output executable name6
TARGET = user_test

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

# Clean up the build files
clean:
	rm -f $(OBJS) $(TARGET)
