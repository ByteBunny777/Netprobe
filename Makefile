CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?= -pthread

SRC_DIR := src
TEST_DIR := tests
BUILD_DIR := build

SRCS := $(SRC_DIR)/portlist.c $(SRC_DIR)/scanner.c $(SRC_DIR)/output.c $(SRC_DIR)/main.c
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGET := netprobe

.PHONY: all clean test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

test: $(BUILD_DIR)/portlist.o
	$(CC) $(CFLAGS) $(TEST_DIR)/test_portlist.c $(SRC_DIR)/portlist.c -o $(BUILD_DIR)/test_portlist
	./$(BUILD_DIR)/test_portlist

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
