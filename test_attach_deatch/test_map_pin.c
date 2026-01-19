#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

int main() {
    printf("=== Testing BPF_OBJ_PIN (cmd=7) ONLY ===\n\n");

    // Step 1: 找一个 BPF map
    printf("[Step 1] Finding BPF map...\n");

    int map_fd = -1;
    int map_id = -1;

    for (int id = 1; id < 1000; id++) {
        union bpf_attr attr = { .map_id = id };
        int fd = syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));

        if (fd >= 0) {
            struct bpf_map_info info = {0};
            union bpf_attr info_attr = {
                .info.bpf_fd = fd,
                .info.info_len = sizeof(info),
                .info.info = (__u64)&info,
            };

            if (syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr)) == 0) {
                // 找到 ARRAY map
                if (info.type == 2 && info.key_size == 4 && info.value_size == 8) {
                    map_fd = fd;
                    map_id = id;
                    printf("  ✓ Found map ID: %d (fd: %d)\n", id, fd);
                    break;
                }
            }
            close(fd);
        }
    }

    if (map_fd < 0) {
        printf("  ✗ No BPF map found!\n");
        printf("  → Make sure your eBPF program is running:\n");
        printf("     cd ~/myebpf && sudo ~/.eunomia/ecli run package.json &\n");
        return 1;
    }

    // Step 2: Pin map 到文件系统
    printf("\n[Step 2] Pinning map to /sys/fs/bpf/...\n");

    const char *pin_path = "/sys/fs/bpf/my_pinned_map";

    // 先删除旧的（如果存在）
    unlink(pin_path);

    union bpf_attr pin_attr = {
        .bpf_fd = map_fd,
        .pathname = (__u64)pin_path,
        .file_flags = 0,
    };

    // 调用 bpf(BPF_OBJ_PIN, ...)
    // 这会触发 Task 9 看到 cmd=7
    printf("  → Calling syscall(__NR_bpf, BPF_OBJ_PIN, ...)\n");

    int ret = syscall(__NR_bpf, BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));

    if (ret < 0) {
        printf("  ✗ BPF_OBJ_PIN failed: %s (errno=%d)\n", strerror(errno), errno);
        close(map_fd);
        return 1;
    }

    printf("  ✓ BPF_OBJ_PIN succeeded!\n");
    printf("  ✓ Map pinned to: %s\n", pin_path);
    printf("  ✓✓✓ Triggered cmd=7 (BPF_OBJ_PIN) ← Check Task 9! ✓✓✓\n");

    close(map_fd);

    // Step 3: 验证文件是否真的创建了
    printf("\n[Step 3] Verifying pinned file exists...\n");

    struct stat st;
    if (stat(pin_path, &st) == 0) {
        printf("  ✓ File exists: %s\n", pin_path);
        printf("  ✓ File size: %ld bytes\n", st.st_size);
    } else {
        printf("  ✗ File not found\n");
    }

    // Step 4: 清理（删除 pinned 文件）
    printf("\n[Step 4] Cleaning up...\n");
    if (unlink(pin_path) == 0) {
        printf("  ✓ Unpinned: %s\n", pin_path);
    } else {
        printf("  ✗ Failed to unlink: %s\n", strerror(errno));
    }

    printf("\n=== Test Complete ===\n");
    printf("Task 9 should have recorded:\n");
    printf("  → cmd = 7 (BPF_OBJ_PIN)\n");
    printf("  → pathname = \"%s\"\n", pin_path);

    return 0;
}
