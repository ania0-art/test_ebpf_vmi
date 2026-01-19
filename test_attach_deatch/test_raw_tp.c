//
// 最小化测试用例：触发 BPF_RAW_TRACEPOINT_OPEN (cmd=17)
// 编译：gcc -o test_raw_tp test_raw_tp.c
// 运行：sudo ./test_raw_tp
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

// BPF syscall wrapper
static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int main()
{
    union bpf_attr attr;
    int prog_fd, raw_tp_fd;

    // 最小的 BPF 程序：只有 exit 指令
    struct bpf_insn {
        uint8_t  code;
        uint8_t  dst_reg:4;
        uint8_t  src_reg:4;
        int16_t  off;
        int32_t  imm;
    } insns[] = {
        // r0 = 0
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  // BPF_ALU64 | BPF_MOV | BPF_K
        // exit
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  // BPF_JMP | BPF_EXIT
    };

    printf("========================================\n");
    printf("[Test] BPF_RAW_TRACEPOINT_OPEN Test\n");
    printf("========================================\n");

    // ========== Step 1: 加载 BPF 程序 (BPF_PROG_LOAD, cmd=5) ==========

    printf("\n[Step 1] Loading BPF program (BPF_PROG_LOAD)...\n");

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = 17;  // BPF_PROG_TYPE_RAW_TRACEPOINT
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 0;
    attr.log_size = 0;
    attr.log_buf = 0;

    prog_fd = bpf(5, &attr, sizeof(attr));  // BPF_PROG_LOAD = 5
    if (prog_fd < 0) {
        perror("[Error] BPF_PROG_LOAD failed");
        printf("[Hint] You may need:\n");
        printf("  1. Run as root (sudo)\n");
        printf("  2. Kernel version >= 4.17 (for raw tracepoint support)\n");
        printf("  3. CONFIG_BPF_SYSCALL=y in kernel config\n");
        return 1;
    }

    printf("[Success] BPF program loaded, prog_fd=%d\n", prog_fd);

    // ========== Step 2: 附加到 raw tracepoint (BPF_RAW_TRACEPOINT_OPEN, cmd=17) ==========

    printf("\n[Step 2] Attaching to raw tracepoint (BPF_RAW_TRACEPOINT_OPEN)...\n");

    memset(&attr, 0, sizeof(attr));

    // 选择一个常见的 tracepoint：sched_process_exec
    // 这个 tracepoint 在进程执行新程序时触发
    const char *tp_name = "sched_process_exec";

    // 手动填充 bpf_attr（兼容老版本头文件）
    // offset 0: __u64 name (用户态指针)
    // offset 8: __u32 prog_fd
    *(uint64_t *)((char *)&attr + 0) = (uint64_t)(unsigned long)tp_name;
    *(uint32_t *)((char *)&attr + 8) = prog_fd;

    printf("[Info] Target tracepoint: '%s'\n", tp_name);
    printf("[Info] Program FD: %d\n", prog_fd);
    printf("[Info] *** HVMI should intercept this syscall in case 17! ***\n");

    raw_tp_fd = bpf(17, &attr, sizeof(attr));  // BPF_RAW_TRACEPOINT_OPEN = 17
    if (raw_tp_fd < 0) {
        perror("[Error] BPF_RAW_TRACEPOINT_OPEN failed");
        printf("[Hint] Common reasons:\n");
        printf("  1. Tracepoint '%s' doesn't exist on this kernel\n", tp_name);
        printf("  2. Permission denied (need CAP_SYS_ADMIN)\n");
        printf("  3. Program type mismatch\n");
        close(prog_fd);
        return 1;
    }

    printf("[Success] BPF_RAW_TRACEPOINT_OPEN succeeded!\n");
    printf("          raw_tp_fd=%d\n", raw_tp_fd);
    printf("          Raw tracepoint is now ACTIVE and monitoring system events\n");

    // ========== Step 3: 保持程序运行，便于观察 HVMI 日志 ==========

    printf("\n[Step 3] Keeping program alive for observation...\n");
    printf("[Info] The raw tracepoint will trigger on every process exec\n");
    printf("[Info] You can trigger it by running: ls, ps, etc.\n");
    printf("[Info] Sleeping 10 seconds...\n");

    sleep(10);

    // ========== Step 4: 清理 ==========

    printf("\n[Step 4] Cleaning up...\n");
    close(raw_tp_fd);  // Detach from raw tracepoint (close hook would trigger here)
    close(prog_fd);    // Close program fd

    printf("\n========================================\n");
    printf("[Test] Test completed successfully!\n");
    printf("========================================\n");

    return 0;
}
