//
// test_map_destroy_stress.c - Stress test for Map destruction tracking
//
// Expected behavior:
// 1. Create and destroy 100 maps rapidly
// 2. Verify all destruction events are tracked
// 3. Verify no duplicate destruction logs
// 4. Verify no log spam (TRACE level works correctly)
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif

#define NUM_MAPS 100

int main(void)
{
    union bpf_attr attr;
    int map_fd;
    int i;
    struct timespec start, end;
    double elapsed;

    printf("=== Test: Map Destruction Stress Test (%d maps) ===\n\n", NUM_MAPS);

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Rapidly create and destroy maps
    printf("[Step 1] Creating and destroying %d maps...\n", NUM_MAPS);
    for (i = 0; i < NUM_MAPS; i++) {
        memset(&attr, 0, sizeof(attr));
        attr.map_type = 2;  // BPF_MAP_TYPE_ARRAY
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 4;

        map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
        if (map_fd < 0) {
            perror("BPF_MAP_CREATE failed");
            return 1;
        }

        // Immediately close (no delay)
        close(map_fd);

        if ((i + 1) % 10 == 0) {
            printf("  Progress: %d/%d maps processed\n", i + 1, NUM_MAPS);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  ✓ All %d maps created and destroyed\n", NUM_MAPS);
    printf("  Time elapsed: %.2f seconds\n", elapsed);
    printf("  Rate: %.2f maps/sec\n\n", NUM_MAPS / elapsed);

    sleep(2);  // 给 HVMI 时间处理所有事件

    printf("=== Test completed ===\n");
    printf("\nVerification checklist:\n");
    printf("  [ ] %d MAP_CREATE events logged\n", NUM_MAPS);
    printf("  [ ] %d security_bpf_map_free events logged\n", NUM_MAPS);
    printf("  [ ] %d Map destroyed events logged\n", NUM_MAPS);
    printf("  [ ] No duplicate destruction (check DestroyTime deduplication)\n");
    printf("  [ ] No log spam (TRACE level should not flood console)\n");
    printf("  [ ] No memory leaks (check gLixBpfMapObjects list size)\n");

    return 0;
}
