//
// test_map_destroy_simple.c - Test simple Map destruction (no pin)
//
// Expected behavior:
// 1. [luckybird] MAP_CREATE: map object created
// 2. [luckybird] security_bpf_map_free: map = 0x..., id = ...
// 3. [luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free
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
    int map_fd;

    printf("=== Test: Simple Map Destruction (No Pin) ===\n\n");

    // Step 1: Create a simple ARRAY map
    printf("[Step 1] Creating BPF map (ARRAY, 4 entries)...\n");
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
    printf("  ✓ map_fd = %d\n", map_fd);
    printf("  Expected HVMI logs:\n");
    printf("    [luckybird] MAP_CREATE: map object created\n\n");

    sleep(1);  // 给 HVMI 时间处理

    // Step 2: Close map FD immediately (should trigger security_bpf_map_free)
    printf("[Step 2] Closing map_fd (should destroy Map)...\n");
    close(map_fd);
    printf("  ✓ map_fd closed\n");
    printf("  Expected HVMI logs:\n");
    printf("    [luckybird] security_bpf_map_free: map = 0x..., id = ...\n");
    printf("    [luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free\n\n");

    sleep(1);  // 给 HVMI 时间处理

    printf("=== Test completed ===\n");
    printf("\nVerification checklist:\n");
    printf("  [ ] Map created with MapGva and MapId\n");
    printf("  [ ] security_bpf_map_free called\n");
    printf("  [ ] Map destroyed with source=security_bpf_map_free\n");
    printf("  [ ] DestroyTime != 0\n");

    return 0;
}
