#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>

#define BPF_CGROUP_DEVICE 6

int main() {
    printf("========================================\n");
    printf("Test 1: Cgroup ATTACH/DETACH Basic Flow\n");
    printf("========================================\n");

    // 1. 创建简单的 cgroup device 程序
    struct bpf_insn insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 1},  // mov r0, 1
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},  // exit
    };

    union bpf_attr prog_attr;
    memset(&prog_attr, 0, sizeof(prog_attr));
    prog_attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
    prog_attr.insns = (__u64)(unsigned long)insns;
    prog_attr.insn_cnt = 2;
    prog_attr.license = (__u64)(unsigned long)"GPL";
    prog_attr.log_buf = 0;
    prog_attr.log_size = 0;
    prog_attr.log_level = 0;

    // 2. 加载程序
    printf("[TEST] Calling BPF_PROG_LOAD...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (prog_fd < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[TEST] ✓ PROG_LOAD success, prog_fd=%d\n", prog_fd);

    // 3. 打开 cgroup 目录
    int cgroup_fd = open("/sys/fs/cgroup/unified/system.slice", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "[ERROR] open cgroup failed: %s\n", strerror(errno));
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ Opened cgroup, cgroup_fd=%d\n", cgroup_fd);

    // 4. ATTACH 程序到 cgroup
    union bpf_attr attach_attr;
    memset(&attach_attr, 0, sizeof(attach_attr));
    attach_attr.target_fd = cgroup_fd;
    attach_attr.attach_bpf_fd = prog_fd;
    attach_attr.attach_type = BPF_CGROUP_DEVICE;
    attach_attr.attach_flags = 0;

    printf("[TEST] Calling BPF_PROG_ATTACH (attach_type=%d)...\n", BPF_CGROUP_DEVICE);
    int ret = syscall(__NR_bpf, BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_ATTACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ ATTACH success!\n");
    printf("[TEST] *** Check HVMI logs for ATTACH event ***\n");

    // 5. 暂停 3 秒（观察 HVMI 日志）
    printf("[TEST] Waiting 3 seconds...\n");
    sleep(3);

    // 6. DETACH 程序
    union bpf_attr detach_attr;
    memset(&detach_attr, 0, sizeof(detach_attr));
    detach_attr.target_fd = cgroup_fd;
    detach_attr.attach_bpf_fd = prog_fd;
    detach_attr.attach_type = BPF_CGROUP_DEVICE;

    printf("[TEST] Calling BPF_PROG_DETACH...\n");
    ret = syscall(__NR_bpf, BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_DETACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ DETACH success!\n");
    printf("[TEST] *** Check HVMI logs for DETACH event ***\n");

    close(cgroup_fd);
    close(prog_fd);

    printf("\n[TEST] Expected HVMI Log Checkpoints:\n");
    printf("  1. Target Type = 1 (Cgroup)\n");
    printf("  2. Target GVA = 0xffff888... (non-zero)\n");
    printf("  3. DETACH Tier-1 match success\n");
    printf("  4. Cross-Process = NO\n");
    printf("========================================\n");

    return 0;
}
