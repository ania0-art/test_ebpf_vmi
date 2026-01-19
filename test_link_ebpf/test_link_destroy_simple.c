// test_link_destroy_simple.c - 兼容旧版本头文件
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>

#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE 28
#endif

int main() {
    int prog_fd = -1;
    int cgroup_fd = -1;
    int link_fd = -1;
    union bpf_attr attr = {0};

    printf("=== Test 1: Link destroy without pin (simple close) ===\n");

    // 步骤 1：加载 BPF 程序
    printf("[1] Loading BPF program (CGROUP_SKB)...\n");

    struct bpf_insn insns[] = {
        {0xb7, 0, 0, 0, 0},  // r0 = 0
        {0x95, 0, 0, 0, 0}   // BPF_EXIT
    };

    attr.prog_type = 8;  // BPF_PROG_TYPE_CGROUP_SKB
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (uint64_t)insns;
    attr.license = (uint64_t)"GPL";
    attr.expected_attach_type = 0;

    prog_fd = syscall(__NR_bpf, 5, &attr, sizeof(attr));// BPF_PROG_LOAD
    if (prog_fd < 0) {
        printf("ERROR: Failed to load BPF program: %s\n", strerror(errno));
        return 1;
    }
    printf("    Program loaded: prog_fd=%d\n", prog_fd);

    // 步骤 2：打开 cgroup
    printf("[2] Opening cgroup directory...\n");

    const char *cgroup_paths[] = {
        "/sys/fs/cgroup/unified",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/user.slice",
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

    // 步骤 3：创建 Link（使用原始偏移量）
    printf("[3] Creating BPF link...\n");
    memset(&attr, 0, sizeof(attr));

    // ✅ 使用原始偏移量设置字段（兼容旧头文件）
    *(uint32_t*)((char*)&attr + 0) = prog_fd;      // prog_fd at offset 0
    *(uint32_t*)((char*)&attr + 4) = cgroup_fd;    // target_fd at offset 4
    *(uint32_t*)((char*)&attr + 8) = 0;            // attach_type at offset 8

    link_fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (link_fd < 0) {
        printf("ERROR: Failed to create link: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("    Link created: link_fd=%d\n", link_fd);

    // 步骤 4：关闭 link_fd
    printf("[4] Closing link_fd...\n");
    close(link_fd);
    printf("    Link FD closed\n");

    // 清理
    close(cgroup_fd);
    close(prog_fd);

    printf("\n=== Test 1 completed ===\n");
    return 0;
}
