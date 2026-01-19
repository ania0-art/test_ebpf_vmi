// test_link_destroy_pinned.c - 兼容旧版本头文件
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>

#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE 28
#endif

#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#endif

int main() {
    int prog_fd = -1;
    int cgroup_fd = -1;
    int link_fd = -1;
    union bpf_attr attr = {0};
    const char *pin_path = "/sys/fs/bpf/test_link_pinned";

    printf("=== Test 2: Link destroy with pin ===\n");

    // 步骤 1：加载 BPF 程序
    printf("[1] Loading BPF program (CGROUP_SKB)...\n");

    struct bpf_insn insns[] = {
        {0xb7, 0, 0, 0, 0},
        {0x95, 0, 0, 0, 0}
    };

    attr.prog_type = 8;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (uint64_t)insns;
    attr.license = (uint64_t)"GPL";
    attr.expected_attach_type = 0;

    prog_fd = syscall(__NR_bpf, 5, &attr, sizeof(attr));
    if (prog_fd < 0) {
        printf("ERROR: Failed to load program: %s\n", strerror(errno));
        return 1;
    }
    printf("    Program loaded: prog_fd=%d\n", prog_fd);

    // 步骤 2：打开 cgroup
    printf("[2] Opening cgroup...\n");

    const char *cgroup_paths[] = {
        "/sys/fs/cgroup/unified",
        "/sys/fs/cgroup",
        NULL
    };

    for (int i = 0; cgroup_paths[i] != NULL; i++) {
        cgroup_fd = open(cgroup_paths[i], O_RDONLY);
        if (cgroup_fd >= 0) {
            printf("    Cgroup opened: %s (fd=%d)\n", cgroup_paths[i], cgroup_fd);
            break;
        }
    }

    if (cgroup_fd < 0) {
        printf("ERROR: Failed to open cgroup: %s\n", strerror(errno));
        close(prog_fd);
        return 1;
    }

    // 步骤 3：创建 Link
    printf("[3] Creating link...\n");
    memset(&attr, 0, sizeof(attr));

    // ✅ 使用偏移量设置字段
    *(uint32_t*)((char*)&attr + 0) = prog_fd;
    *(uint32_t*)((char*)&attr + 4) = cgroup_fd;
    *(uint32_t*)((char*)&attr + 8) = 0;

    link_fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (link_fd < 0) {
        printf("ERROR: Failed to create link: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("    Link created: link_fd=%d\n", link_fd);

    // 步骤 4：Pin link
    printf("[4] Pinning link to %s...\n", pin_path);
    unlink(pin_path);  // 删除旧文件

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)pin_path;
    attr.bpf_fd = link_fd;

    int ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
    if (ret < 0) {
        printf("ERROR: Failed to pin: %s\n", strerror(errno));
        close(link_fd);
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("    Link pinned\n");

    // 步骤 5：关闭 fd（refcnt>1）
    printf("[5] Closing link_fd (refcnt>1)...\n");
    close(link_fd);
    printf("    FD closed\n");

    printf("[6] Sleeping 2 seconds...\n");
    sleep(2);

    // 步骤 6：Unpin（refcnt==1）
    printf("[7] Unpinning link...\n");
    unlink(pin_path);
    printf("    Link unpinned\n");

    // 清理
    close(cgroup_fd);
    close(prog_fd);

    printf("\n=== Test 2 completed ===\n");
    return 0;
}
