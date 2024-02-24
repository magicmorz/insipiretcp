# Makefile for Packet Sniffer

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Source files
SRC = general_utils.c protocol_support.c debug_utils.c \
 socket_utils.c cli_utils.c main.c \
 capture/pcapng/epb.c capture/pcapng/idb.c capture/pcapng/shb.c capture/pcapng/pcapng.c \
 file/file_pcapng/file_pcapng_utils.c

# Object files
OBJ_DIR = build
OBJ = $(addprefix $(OBJ_DIR)/,$(SRC:.c=.o))

# Target executable
TARGET_DIR = .
TARGET = $(TARGET_DIR)/sniffer

.PHONY: all clean

all: $(OBJ_DIR) $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/capture/pcapng
	mkdir -p $(OBJ_DIR)/file/file_pcapng

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
