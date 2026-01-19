#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define BPF_OBJ_NAME_LEN 16

static inline int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int main(void)
{
    union bpf_attr create_attr = {0};
    union bpf_attr pin_attr = {0};
    int map_fd;
    int ret;

    // Step 1: Create Map
    create_attr.map_type = 1;  // BPF_MAP_TYPE_HASH
    create_attr.key_size = 4;
    create_attr.value_size = 8;
    create_attr.max_entries = 256;
    create_attr.map_flags = 0;
    strncpy(create_attr.map_name, "xproc_test", BPF_OBJ_NAME_LEN - 1);

    printf("[PID %d] Creating Map...\n", getpid());
    map_fd = bpf(BPF_MAP_CREATE, &create_attr, sizeof(create_attr));
    if (map_fd < 0) {
        perror("BPF_MAP_CREATE failed");
        return 1;
    }
    printf("[PID %d] ✓ Map created, FD=%d\n", getpid(), map_fd);

    // Step 2: PIN Map
    pin_attr.pathname = (unsigned long)"/sys/fs/bpf/xproc_shared";
    pin_attr.bpf_fd = map_fd;
    pin_attr.file_flags = 0;

    printf("[PID %d] Pinning Map to /sys/fs/bpf/xproc_shared...\n", getpid());
    ret = bpf(BPF_OBJ_PIN, &pin_attr, 16);
    if (ret < 0) {
        perror("BPF_OBJ_PIN failed");
        close(map_fd);
        return 1;
    }
    printf("[PID %d] ✓ Map pinned successfully\n", getpid());

    // Step 3: Keep process alive
    printf("\n");
    printf("=========================================\n");
    printf("Creator Process Info:\n");
    printf("  PID:     %d\n", getpid());
    printf("  Map FD:  %d\n", map_fd);
    printf("  Path:    /sys/fs/bpf/xproc_shared\n");
    printf("=========================================\n");
    printf("\nNow run test_get_only in ANOTHER TERMINAL\n");
    printf("Press Enter to cleanup and exit...\n");
    getchar();

    // Cleanup
    close(map_fd);
    unlink("/sys/fs/bpf/xproc_shared");
    printf("[PID %d] Cleaned up, exiting\n", getpid());

    return 0;
}
