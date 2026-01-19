# Makefile for BPF_PROG_GET_FD_BY_ID tests

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGETS = test_main test_cross_process

.PHONY: all clean run

all: $(TARGETS)

test_main: test_main.c
	$(CC) $(CFLAGS) -o $@ $<

test_cross_process: test_cross_process.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -f /tmp/bpf_test_prog_id
	rm -f /sys/fs/bpf/test_pinned_prog

# 运行所有测试
run: all
	@echo "=== Running basic tests ==="
	sudo ./test_main
	@echo ""
	@echo "=== Running cross-process test ==="
	sudo ./test_cross_process

