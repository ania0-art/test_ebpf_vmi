// mini_bpf_load.c
//  gcc -O2 -Wall mini_bpf_load.c -o mini_bpf_load
//  sudo ./mini_bpf_load
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

int main(void)
{
    // 最小 eBPF：r0 = 0; exit; （对 SOCKET_FILTER 有效）
    struct bpf_insn prog[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP   | BPF_EXIT },
    };

    char log_buf[1 << 20];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = (uint32_t)(sizeof(prog) / sizeof(prog[0]));
    attr.insns = (uint64_t)(uintptr_t)prog;
    attr.license = (uint64_t)(uintptr_t)"GPL";
    attr.log_buf = (uint64_t)(uintptr_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "BPF_PROG_LOAD failed: %s (%d)\n", strerror(errno), errno);
        fprintf(stderr, "verifier log:\n%s\n", log_buf);
        return 1;
    }

    printf("BPF_PROG_LOAD ok, prog_fd=%d\n", prog_fd);

    // 可选：跑一次 test_run（不依赖 attach），方便你观察后续行为
    memset(&attr, 0, sizeof(attr));
    attr.test.prog_fd = prog_fd;
    attr.test.repeat = 1;

    int ret = sys_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    if (ret < 0) {
        fprintf(stderr, "BPF_PROG_TEST_RUN failed: %s (%d)\n", strerror(errno), errno);
        // 不算致命
    } else {
        printf("BPF_PROG_TEST_RUN ok\n");
    }

    close(prog_fd);
    return 0;
}
