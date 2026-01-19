//
// test_map_destroy_pinned.c - Test Map destruction with pin/unpin
//
// Expected behavior:
// 1. [luckybird] MAP_CREATE: map object created
// 2. [luckybird] OBJ_PIN: map pinned
// 3. close(map_fd) → NOT destroyed (pin holds reference)
// 4. unlink(pin_path) → triggers security_bpf_map_free
// 5. [luckybird] Map destroyed: source = security_bpf_map_free
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

#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#endif

int main(void)
{
    union bpf_attr attr;
    int map_fd;
    const char *pin_path = "/sys/fs/bpf/test_map_pinned";

    printf("=== Test: Map Destruction with Pin/Unpin ===\n\n");

    // Step 1: Create map
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

    // Step 2: Pin map to filesystem
    printf("[Step 2] Pinning map to %s...\n", pin_path);
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)pin_path;
    attr.bpf_fd = map_fd;

    if (syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr)) < 0) {
        perror("BPF_OBJ_PIN failed");
        close(map_fd);
        return 1;
    }
    printf("  ✓ Map pinned (refcnt now = 2)\n");
    printf("  Expected HVMI logs:\n");
    printf("    [luckybird] OBJ_PIN: map pinned (IsPinned=TRUE)\n\n");

    sleep(1);  // 给 HVMI 时间处理

    // Step 3: Close FD (refcnt>1, should NOT destroy)
    printf("[Step 3] Closing map_fd (refcnt>1, should NOT destroy)...\n");
    close(map_fd);
    printf("  ✓ map_fd closed\n");
    printf("  Expected: NO security_bpf_map_free log (pin holds reference)\n\n");

    sleep(2);  // 给足够时间观察（确认没有 free 日志）

    // Step 4: Unlink pin (should trigger security_bpf_map_free)
    printf("[Step 4] Unlinking pin (should destroy Map)...\n");
    if (unlink(pin_path) < 0) {
        perror("unlink failed");
        return 1;
    }
    printf("  ✓ Pin removed\n");
    printf("  Expected HVMI logs:\n");
    printf("    [luckybird] security_bpf_map_free: map = 0x..., id = ...\n");
    printf("    [luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free\n\n");

    sleep(1);  // 给 HVMI 时间处理

    printf("=== Test completed ===\n");
    printf("\nVerification checklist:\n");
    printf("  [ ] Map created and pinned\n");
    printf("  [ ] close(fd) did NOT trigger security_bpf_map_free\n");
    printf("  [ ] unlink(pin) triggered security_bpf_map_free\n");
    printf("  [ ] Map destroyed with source=security_bpf_map_free\n");
    printf("  [ ] DestroyTime != 0\n");

    return 0;
}
