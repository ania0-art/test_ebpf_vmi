# Makefile for Map Destruction Test Programs
#
# Builds all test programs and places binaries in ../build/
#

CC = gcc
CFLAGS = -Wall -Wextra -O2
BUILD_DIR = ../build

# Source files
SRCS = test_map_destroy_simple.c \
       test_map_destroy_pinned.c \
       test_map_destroy_multi.c \
       test_map_destroy_stress.c

# Target binaries (in build directory)
TARGETS = $(BUILD_DIR)/test_map_destroy_simple \
          $(BUILD_DIR)/test_map_destroy_pinned \
          $(BUILD_DIR)/test_map_destroy_multi \
          $(BUILD_DIR)/test_map_destroy_stress

.PHONY: all clean

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/test_map_destroy_simple: test_map_destroy_simple.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(BUILD_DIR)/test_map_destroy_pinned: test_map_destroy_pinned.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(BUILD_DIR)/test_map_destroy_multi: test_map_destroy_multi.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(BUILD_DIR)/test_map_destroy_stress: test_map_destroy_stress.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

clean:
	rm -f $(TARGETS)
	@echo "Cleaned build artifacts"

help:
	@echo "Map Destruction Test Programs Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build all test programs (default)"
	@echo "  clean   - Remove built binaries"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Output directory: $(BUILD_DIR)"
	@echo ""
	@echo "Test programs:"
	@echo "  1. test_map_destroy_simple  - Simple map destruction (no pin)"
	@echo "  2. test_map_destroy_pinned  - Map destruction with pin/unpin"
	@echo "  3. test_map_destroy_multi   - Multiple map destruction"
	@echo "  4. test_map_destroy_stress  - Stress test (100 maps)"
	@echo ""
	@echo "Usage:"
	@echo "  make                        # Build all"
	@echo "  sudo $(BUILD_DIR)/test_map_destroy_simple"
	@echo "  sudo $(BUILD_DIR)/test_map_destroy_pinned"
	@echo "  sudo $(BUILD_DIR)/test_map_destroy_multi"
	@echo "  sudo $(BUILD_DIR)/test_map_destroy_stress"
