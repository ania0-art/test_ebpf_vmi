#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

static inline int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int main(void)
{
    union bpf_attr get_attr = {0};
    union bpf_attr update_attr = {0};
    int map_fd;
    int ret;
    int key = 42;
    long value = 0x1234567890ABCDEFULL;

    // Step 1: GET Map
    get_attr.pathname = (unsigned long)"/sys/fs/bpf/xproc_shared";
    get_attr.file_flags = 0;

    printf("[PID %d] Getting Map from /sys/fs/bpf/xproc_shared...\n", getpid());
    map_fd = bpf(BPF_OBJ_GET, &get_attr, 16);
    if (map_fd < 0) {
        perror("BPF_OBJ_GET failed");
        printf("Make sure test_pin_only is running first!\n");
        return 1;
    }
    printf("[PID %d] ✓ Map retrieved, FD=%d\n", getpid(), map_fd);

    // Step 2: Update Map (optional, to verify it works)
    update_attr.map_fd = map_fd;
    update_attr.key = (unsigned long)&key;
    update_attr.value = (unsigned long)&value;
    update_attr.flags = 0;  // BPF_ANY

    printf("[PID %d] Updating Map...\n", getpid());
    ret = bpf(BPF_MAP_UPDATE_ELEM, &update_attr, 32);
    if (ret < 0) {
        perror("BPF_MAP_UPDATE_ELEM failed");
    } else {
        printf("[PID %d] ✓ Map updated successfully\n", getpid());
    }

    printf("\n");
    printf("=========================================\n");
    printf("Getter Process Info:\n");
    printf("  PID:     %d\n", getpid());
    printf("  Map FD:  %d\n", map_fd);
    printf("=========================================\n");
    printf("Press Enter to exit...\n");
    getchar();

    close(map_fd);
    printf("[PID %d] FD closed, exiting\n", getpid());

    return 0;
}
