#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>

int main() {
    printf("=== Testing BPF Program PIN ===\n\n");

    // Step 1: Create a minimal BPF program (just returns 0)
    struct bpf_insn insns[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, // r0 = 0
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, // exit
    };

    char log_buf[4096];
    memset(log_buf, 0, sizeof(log_buf));

    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = 2,
        .insns = (__u64)insns,
        .license = (__u64)"GPL",
        .log_level = 1,
        .log_size = sizeof(log_buf),
        .log_buf = (__u64)log_buf,
    };

    printf("Step 1: Loading BPF program...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));

    if (prog_fd < 0) {
        printf("  ✗ BPF_PROG_LOAD failed: %s (errno=%d)\n", strerror(errno), errno);
        if (log_buf[0]) {
            printf("  Verifier log: %s\n", log_buf);
        }
        return 1;
    }

    printf("  ✓ Program loaded successfully (fd=%d)\n", prog_fd);
    printf("  ✓ Triggered cmd=5 (BPF_PROG_LOAD)\n\n");

    // Step 2: Pin the program
    const char *pin_path = "/sys/fs/bpf/my_pinned_prog";
    unlink(pin_path);  // Remove if exists

    union bpf_attr pin_attr = {
        .bpf_fd = prog_fd,
        .pathname = (__u64)pin_path,
    };

    printf("Step 2: Pinning program to %s...\n", pin_path);
    int ret = syscall(__NR_bpf, BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));

    if (ret < 0) {
        printf("  ✗ BPF_OBJ_PIN failed: %s (errno=%d)\n", strerror(errno), errno);
        close(prog_fd);
        return 1;
    }

    printf("  ✓ Program pinned successfully!\n");
    printf("  ✓✓✓ Triggered cmd=6 (BPF_OBJ_PIN for PROGRAM) ← Check Task 9! ✓✓✓\n\n");

    // Verify the pinned file exists
    if (access(pin_path, F_OK) == 0) {
        printf("Step 3: Verification\n");
        printf("  ✓ Pinned file exists: %s\n", pin_path);
    }

    // Cleanup
    printf("\nCleaning up...\n");
    close(prog_fd);
    unlink(pin_path);
    printf("  ✓ Done\n");

    return 0;
}
