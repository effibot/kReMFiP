PWD = $(shel pwd)
MISC_DIR = ../src/utils
KREMFIP_DIR = ../src/include
MISC = $(MISC_DIR)/misc.c
KREMFIP = $(KREMFIP_DIR)/kremfip_lib.c
# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O0 -Wextra -Werror -Wno-implicit-fallthrough -Wno-unused-parameter

# Search for all .c files in the current directory
SRCS = $(wildcard *.c)
SRCS += $(MISC) $(KREMFIP)

# Include directory
INCLUDES = -I$(MISC_DIR) -I$(KREMFIP_DIR)


# Output executable name6
TARGET = user_test

all:
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRCS)

# Clean up the build files
clean:
	rm -f $(OBJS) $(TARGET)
