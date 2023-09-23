# Makefile for Packet Sniffer

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Source files
SRC = debug_utils.c socket_utils.c main.c

# Object files
OBJ = $(SRC:.c=.o)

# Target executable
TARGET = sniffer

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
