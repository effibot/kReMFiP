MISC_DIR = ../src/utils
KREMFIP_DIR = ../src/user
MISC = $(MISC_DIR)/misc.c
KREMFIP = $(KREMFIP_DIR)/kremfip_lib.c
CLI_DIR = CLI
# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O0 -Wextra -Werror -Wno-implicit-fallthrough -Wno-unused-parameter

# Search for all .c files in the current directory
#SRCS = $(wildcard *.c)
#SRCS += $(MISC) $(KREMFIP)
CLIS = $(wildcard $(CLI_DIR)/*.c)

# Include directory
INCLUDES = -I$(MISC_DIR) -I$(KREMFIP_DIR)

# Output executable name
#MAIN_TARGET = user_test
CLI_TARGET = $(patsubst $(CLI_DIR)/%.c,$(CLI_DIR)/%,$(CLIS))

.PHONY: clean cli #all

#all:
#	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN_TARGET) $(SRCS)

cli: $(CLIS)
	for cli in $(CLIS); do \
		$(CC) $(CFLAGS) $(INCLUDES) -o $${cli%.c} $${cli} $(MISC) $(KREMFIP); \
	done


# Clean up the build files
clean:
	rm -f $(CLI_TARGET)
