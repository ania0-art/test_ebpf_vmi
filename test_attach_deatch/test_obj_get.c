#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>

int main() {
    printf("=== Testing BPF_OBJ_GET (cmd=7) ===\n\n");

    // Step 1: Create a simple ARRAY map
    union bpf_attr map_attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = 1,
    };

    printf("Step 1: Creating BPF map...\n");
    int map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));

    if (map_fd < 0) {
        printf("  ✗ BPF_MAP_CREATE failed: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }

    printf("  ✓ Map created successfully (fd=%d)\n", map_fd);
    printf("  ✓ Triggered cmd=0 (BPF_MAP_CREATE)\n\n");

    // Step 2: Pin the map
    const char *pin_path = "/sys/fs/bpf/test_obj_get_map";
    unlink(pin_path);  // Remove if exists

    union bpf_attr pin_attr = {
        .bpf_fd = map_fd,
        .pathname = (__u64)pin_path,
    };

    printf("Step 2: Pinning map to %s...\n", pin_path);
    int ret = syscall(__NR_bpf, BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));

    if (ret < 0) {
        printf("  ✗ BPF_OBJ_PIN failed: %s (errno=%d)\n", strerror(errno), errno);
        close(map_fd);
        return 1;
    }

    printf("  ✓ Map pinned successfully!\n");
    printf("  ✓ Triggered cmd=6 (BPF_OBJ_PIN)\n\n");

    // Step 3: Close the original fd
    printf("Step 3: Closing original fd...\n");
    close(map_fd);
    printf("  ✓ Original fd closed\n\n");

    // Step 4: Use BPF_OBJ_GET to retrieve the map from pinned file
    union bpf_attr get_attr = {
        .pathname = (__u64)pin_path,
        .bpf_fd = 0,
        .file_flags = 0,
    };

    printf("Step 4: Getting map from pinned file using BPF_OBJ_GET...\n");
    int new_fd = syscall(__NR_bpf, BPF_OBJ_GET, &get_attr, sizeof(get_attr));

    if (new_fd < 0) {
        printf("  ✗ BPF_OBJ_GET failed: %s (errno=%d)\n", strerror(errno), errno);
        unlink(pin_path);
        return 1;
    }

    printf("  ✓ BPF_OBJ_GET succeeded! New fd=%d\n", new_fd);
    printf("  ✓✓✓ Triggered cmd=7 (BPF_OBJ_GET) ← Check Task 9! ✓✓✓\n\n");

    // Step 5: Verify we can use the new fd
    printf("Step 5: Verifying the retrieved map...\n");
    __u32 key = 0;
    __u64 value = 12345;

    union bpf_attr update_attr = {
        .map_fd = new_fd,
        .key = (__u64)&key,
        .value = (__u64)&value,
        .flags = BPF_ANY,
    };

    ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr));

    if (ret == 0) {
        printf("  ✓ Successfully updated map through new fd\n");
        printf("  ✓ Map is functional!\n");
    } else {
        printf("  ✗ Failed to update map: %s\n", strerror(errno));
    }

    // Cleanup
    printf("\nCleaning up...\n");
    close(new_fd);
    unlink(pin_path);
    printf("  ✓ Done\n");

    return 0;
}
