//
// test_map_destroy_multi.c - Test multiple Map destruction (verify deduplication)
//
// Expected behavior:
// 1. Create 3 maps
// 2. Close all 3 fds
// 3. Each should trigger independent security_bpf_map_free
// 4. Verify MapId matching works correctly
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif

int main(void)
{
    union bpf_attr attr;
    int map_fds[3];
    int i;

    printf("=== Test: Multiple Map Destruction ===\n\n");

    // Step 1: Create 3 maps
    printf("[Step 1] Creating 3 BPF maps...\n");
    for (i = 0; i < 3; i++) {
        memset(&attr, 0, sizeof(attr));
        attr.map_type = 2;  // BPF_MAP_TYPE_ARRAY
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 4;

        map_fds[i] = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
        if (map_fds[i] < 0) {
            perror("BPF_MAP_CREATE failed");
            return 1;
        }
        printf("  ✓ map[%d] fd = %d\n", i, map_fds[i]);
    }
    printf("  Expected HVMI logs: 3x [luckybird] MAP_CREATE\n\n");

    sleep(1);  // 给 HVMI 时间处理

    // Step 2: Close all maps in sequence
    printf("[Step 2] Closing all maps (should trigger 3 independent free events)...\n");
    for (i = 0; i < 3; i++) {
        printf("  Closing map[%d] fd=%d...\n", i, map_fds[i]);
        close(map_fds[i]);
        sleep(1);  // 间隔观察日志
    }
    printf("  ✓ All maps closed\n");
    printf("  Expected HVMI logs:\n");
    printf("    3x [luckybird] security_bpf_map_free: map = 0x..., id = ...\n");
    printf("    3x [luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free\n\n");

    sleep(1);  // 给 HVMI 时间处理

    printf("=== Test completed ===\n");
    printf("\nVerification checklist:\n");
    printf("  [ ] 3 maps created with different MapGva/MapId\n");
    printf("  [ ] 3 independent security_bpf_map_free events\n");
    printf("  [ ] 3 independent Map destroyed logs\n");
    printf("  [ ] No duplicate destruction (DestroyTime deduplication works)\n");

    return 0;
}
