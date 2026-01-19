CC = gcc
CFLAGS = -Wall -O2
TARGETS = test_cgroup_attach test_cross_process test_sockmap_attach \
		test_resolution_failure run_all_tests

all: $(TARGETS)

test_cgroup_attach: test_cgroup_attach.c
	$(CC) $(CFLAGS) -o $@ $<

test_cross_process: test_cross_process.c
	$(CC) $(CFLAGS) -o $@ $<

test_sockmap_attach: test_sockmap_attach.c
	$(CC) $(CFLAGS) -o $@ $<

test_resolution_failure: test_resolution_failure.c
	$(CC) $(CFLAGS) -o $@ $<

run_all_tests: run_all_tests.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

test: all
	@echo "Running all tests (requires root)..."
	sudo ./run_all_tests

.PHONY: all clean test
