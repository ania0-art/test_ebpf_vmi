/*
* test_main.c - BPF_PROG_GET_FD_BY_ID 测试程序
* 
* 编译: gcc -o test_main test_main.c
* 运行: sudo ./test_main
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>

/* BPF 系统调用包装 */
static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* ============================================================
* 测试场景1：正常同进程访问
* ============================================================ */
void test_same_process_access(void)
{
    printf("\n========================================\n");
    printf("Test 1: Same-Process Access (Normal)\n");
    printf("========================================\n");

    union bpf_attr attr;
    int prog_fd = -1;
    int new_fd = -1;
    unsigned int prog_id = 0;

    /* 步骤1：加载一个简单的 BPF 程序 */
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT }
    };

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (__u64)insns;
    attr.license = (__u64)"GPL";
    strncpy(attr.prog_name, "test_prog1", sizeof(attr.prog_name));

    prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("BPF_PROG_LOAD failed");
        printf("  Error: %s (errno=%d)\n", strerror(errno), errno);
        printf("  Note: Requires CAP_SYS_ADMIN or unprivileged BPF enabled\n");
        return;
    }

    printf("✅ Step 1: Program loaded successfully (fd=%d)\n", prog_fd);

    /* 步骤2：获取程序 ID */
    struct bpf_prog_info info = {0};
    unsigned int info_len = sizeof(info);

    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = prog_fd;
    attr.info.info_len = info_len;
    attr.info.info = (__u64)&info;

    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD failed");
        close(prog_fd);
        return;
    }

    prog_id = info.id;
    printf("✅ Step 2: Got program ID: %u\n", prog_id);

    /* 步骤3：通过 ID 重新获取 FD（同进程访问） */
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = prog_id;

    printf("📞 Calling BPF_PROG_GET_FD_BY_ID (prog_id=%u)...\n", prog_id);
    new_fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));

    if (new_fd < 0) {
        perror("BPF_PROG_GET_FD_BY_ID failed");
        printf("  Error: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("✅ Step 3: Got new FD: %d (same process)\n", new_fd);
        printf("Expected HVMI Log: ✅ Same-process access\n");
        close(new_fd);
    }

    close(prog_fd);
    printf("\nTest 1 completed.\n");
}

/* ============================================================
* 测试场景2：无效参数测试
* ============================================================ */
void test_invalid_prog_id(void)
{
    printf("\n========================================\n");
    printf("Test 2: Invalid prog_id=0\n");
    printf("========================================\n");

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = 0;  /* 无效的 prog_id */

    printf("📞 Calling BPF_PROG_GET_FD_BY_ID (prog_id=0)...\n");
    int fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));

    if (fd < 0) {
        printf("✅ Expected failure: %s (errno=%d)\n", strerror(errno), errno);
        printf("Expected HVMI Log: Invalid prog_id=0, ignoring request\n");
    } else {
        printf("❌ Unexpected success, got fd=%d\n", fd);
        close(fd);
    }

    printf("\nTest 2 completed.\n");
}

/* ============================================================
* 测试场景3：未知 prog_id 测试
* ============================================================ */
void test_unknown_prog_id(void)
{
    printf("\n========================================\n");
    printf("Test 3: Unknown prog_id=999999\n");
    printf("========================================\n");

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = 999999;  /* 不存在的 prog_id */

    printf("📞 Calling BPF_PROG_GET_FD_BY_ID (prog_id=999999)...\n");
    int fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));

    if (fd < 0) {
        printf("✅ Expected failure: %s (errno=%d)\n", strerror(errno), errno);
        printf("Expected HVMI Log: Original loader NOT found (if loaded before HVMI)\n");
    } else {
        printf("❌ Unexpected success, got fd=%d\n", fd);
        close(fd);
    }

    printf("\nTest 3 completed.\n");
}

/* ============================================================
* 测试场景4：持久化程序访问
* ============================================================ */
void test_pinned_program_access(void)
{
    printf("\n========================================\n");
    printf("Test 4: Pinned Program Access\n");
    printf("========================================\n");

    union bpf_attr attr;
    int prog_fd = -1;
    unsigned int prog_id = 0;
    const char *pin_path = "/sys/fs/bpf/test_pinned_prog";

    /* 步骤1：加载程序 */
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT }
    };

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (__u64)insns;
    attr.license = (__u64)"GPL";
    strncpy(attr.prog_name, "test_pinned", sizeof(attr.prog_name));

    prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("BPF_PROG_LOAD failed");
        return;
    }

    printf("✅ Step 1: Program loaded (fd=%d)\n", prog_fd);

    /* 步骤2：获取 prog_id */
    struct bpf_prog_info info = {0};
    unsigned int info_len = sizeof(info);

    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = prog_fd;
    attr.info.info_len = info_len;
    attr.info.info = (__u64)&info;

    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
        prog_id = info.id;
        printf("✅ Step 2: Got program ID: %u\n", prog_id);
    }

    /* 步骤3：持久化到 bpffs */
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64)pin_path;
    attr.bpf_fd = prog_fd;

    if (bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) < 0) {
        perror("BPF_OBJ_PIN failed");
        printf("  Note: /sys/fs/bpf may not be mounted\n");
    } else {
        printf("✅ Step 3: Program pinned to %s\n", pin_path);
    }

    close(prog_fd);

    /* 步骤4：从持久化路径重新打开 */
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64)pin_path;

    prog_fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("BPF_OBJ_GET failed");
    } else {
        printf("✅ Step 4: Re-opened from pin (fd=%d)\n", prog_fd);
        close(prog_fd);
    }

    /* 步骤5：通过 ID 访问持久化的程序 */
    if (prog_id > 0) {
        memset(&attr, 0, sizeof(attr));
        attr.prog_id = prog_id;

        printf("📞 Calling BPF_PROG_GET_FD_BY_ID for pinned program...\n");
        prog_fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));

        if (prog_fd >= 0) {
            printf("✅ Step 5: Accessed pinned program by ID\n");
            close(prog_fd);
        }
    }

    /* 清理 */
    unlink(pin_path);
    printf("\nTest 4 completed.\n");
}

/* ============================================================
* 主函数
* ============================================================ */
int main(int argc, char **argv)
{
    printf("╔════════════════════════════════════════╗\n");
    printf("║  BPF_PROG_GET_FD_BY_ID Test Suite     ║\n");
    printf("║  Cross-Process Detection Testing      ║\n");
    printf("╚════════════════════════════════════════╝\n");

    printf("\nProcess Info:\n");
    printf("  PID: %d\n", getpid());
    printf("  UID: %d\n", getuid());
    printf("  EUID: %d\n", geteuid());

    if (geteuid() != 0) {
        printf("\n⚠️  Warning: Not running as root\n");
        printf("   BPF operations may fail without CAP_SYS_ADMIN\n");
    }

    /* 运行所有测试 */
    test_same_process_access();
    test_invalid_prog_id();
    test_unknown_prog_id();
    test_pinned_program_access();

    printf("\n╔════════════════════════════════════════╗\n");
    printf("║  All Tests Completed                   ║\n");
    printf("╚════════════════════════════════════════╝\n");

    printf("\nNext Steps:\n");
    printf("1. Check HVMI logs for detection messages\n");
    printf("2. Run cross-process test: ./test_cross_process\n");

    return 0;
}

