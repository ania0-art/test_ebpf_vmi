#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>

#define BPF_CGROUP_DEVICE 6

// 子进程：执行 DETACH
int child_detach_process() {
    printf("[CHILD] Child process started (PID=%d)\n", getpid());
    printf("[CHILD] Waiting 2 seconds for parent ATTACH...\n");
    sleep(2);

    // 打开同一个 cgroup
    int cgroup_fd = open("/sys/fs/cgroup/unified/", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "[CHILD ERROR] open cgroup failed: %s\n", strerror(errno));
        return 1;
    }

    // DETACH（不提供 prog_fd，内核会 detach 该 cgroup 上的所有程序）
    union bpf_attr detach_attr;
    memset(&detach_attr, 0, sizeof(detach_attr));
    detach_attr.target_fd = cgroup_fd;
    detach_attr.attach_bpf_fd = 0;  // 不指定 prog_fd
    detach_attr.attach_type = BPF_CGROUP_DEVICE;

    printf("[CHILD] Calling BPF_PROG_DETACH from child process...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr));
    if (ret < 0) {
        fprintf(stderr, "[CHILD ERROR] BPF_PROG_DETACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        return 1;
    }
    printf("[CHILD] ✓ DETACH success from child!\n");
    printf("[CHILD] *** Check HVMI logs for Cross-Process warning ***\n");

    close(cgroup_fd);
    return 0;
}

// 父进程：执行 ATTACH 并等待
int parent_attach_process() {
    printf("[PARENT] Parent process started (PID=%d)\n", getpid());

    // 1. 创建 BPF 程序
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
        fprintf(stderr, "[PARENT ERROR] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[PARENT] ✓ PROG_LOAD success, prog_fd=%d\n", prog_fd);

    // 2. 打开 cgroup
    int cgroup_fd = open("/sys/fs/cgroup/unified/", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "[PARENT ERROR] open cgroup failed: %s\n", strerror(errno));
        close(prog_fd);
        return 1;
    }

    // 3. ATTACH
    union bpf_attr attach_attr;
    memset(&attach_attr, 0, sizeof(attach_attr));
    attach_attr.target_fd = cgroup_fd;
    attach_attr.attach_bpf_fd = prog_fd;
    attach_attr.attach_type = BPF_CGROUP_DEVICE;

    printf("[PARENT] Calling BPF_PROG_ATTACH...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        fprintf(stderr, "[PARENT ERROR] BPF_PROG_ATTACH failed: %s\n", strerror(errno));
        close(cgroup_fd);
        close(prog_fd);
        return 1;
    }
    printf("[PARENT] ✓ ATTACH success!\n");

    // 4. 等待子进程完成 DETACH
    printf("[PARENT] Waiting for child to DETACH...\n");
    int status;
    wait(&status);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[PARENT] ✓ Child process completed successfully\n");
    } else {
        printf("[PARENT] ! Child process exited with error\n");
    }

    close(cgroup_fd);
    close(prog_fd);
    return 0;
}

int main() {
    printf("========================================\n");
    printf("Test 2: Cross-Process DETACH Detection\n");
    printf("========================================\n");

    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "[ERROR] fork() failed: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        // 子进程
        int ret = child_detach_process();
        exit(ret);
    } else {
        // 父进程
        int ret = parent_attach_process();

        printf("\n[TEST] Expected HVMI Log Checkpoints:\n");
        printf("  1. ATTACH by parent PID (e.g., 12345)\n");
        printf("  2. DETACH by child PID (e.g., 12346)\n");
        printf("  3. DETACH Tier-2 match (prog_fd=0)\n");
        printf("  4. Cross-Process = YES ⚠️\n");
        printf("  5. Warning message with both PIDs\n");
        printf("========================================\n");

        return ret;
    }
}
