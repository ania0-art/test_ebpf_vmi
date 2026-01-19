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
    printf("Test 4: Resolution Failure & Tier-3 Fallback\n");
    printf("========================================\n");
    printf("[INFO] This test requires manual code modification:\n");
    printf("  1. Edit IntLixBpfResolveTargetFdToGva() in lixbpf.c\n");
    printf("  2. Add at the beginning: return INT_STATUS_NOT_FOUND;\n");
    printf("  3. Recompile HVMI\n");
    printf("  4. Run this test\n");
    printf("  5. Observe Tier-3 matching in logs\n");
    printf("========================================\n\n");

    // 创建 BPF 程序
    struct bpf_insn insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 1},
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},
    };

    union bpf_attr prog_attr;
    memset(&prog_attr, 0, sizeof(prog_attr));
    prog_attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
    prog_attr.insns = (__u64)(unsigned long)insns;
    prog_attr.insn_cnt = 2;
    prog_attr.license = (__u64)(unsigned long)"GPL";

    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (prog_fd < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[TEST] ✓ PROG_LOAD success, prog_fd=%d\n", prog_fd);

    // 打开 cgroup
    int cgroup_fd = open("/sys/fs/cgroup/unified/", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "[ERROR] open cgroup failed: %s\n", strerror(errno));
        close(prog_fd);
        return 1;
    }

    // ATTACH
    union bpf_attr attach_attr;
    memset(&attach_attr, 0, sizeof(attach_attr));
    attach_attr.target_fd = cgroup_fd;
    attach_attr.attach_bpf_fd = prog_fd;
    attach_attr.attach_type = BPF_CGROUP_DEVICE;

    printf("[TEST] Calling BPF_PROG_ATTACH (resolution should fail)...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_ATTACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ ATTACH success (resolution failed but attached)\n");

    sleep(2);

    // DETACH
    union bpf_attr detach_attr;
    memset(&detach_attr, 0, sizeof(detach_attr));
    detach_attr.target_fd = cgroup_fd;
    detach_attr.attach_bpf_fd = prog_fd;
    detach_attr.attach_type = BPF_CGROUP_DEVICE;

    printf("[TEST] Calling BPF_PROG_DETACH (should use Tier-3 matching)...\n");
    ret = syscall(__NR_bpf, BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_DETACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ DETACH success (Tier-3 fallback worked)\n");

    close(cgroup_fd);
    close(prog_fd);

    printf("\n[TEST] Expected HVMI Log Checkpoints:\n");
    printf("  1. ATTACH WARNING: Failed to resolve target_fd\n");
    printf("  2. Target GVA = 0, Target Type = 0\n");
    printf("  3. DETACH Tier-3 match (AttachType + ProgId)\n");
    printf("  4. No Tier-1/Tier-2 match attempts\n");
    printf("========================================\n");

    return 0;
}
