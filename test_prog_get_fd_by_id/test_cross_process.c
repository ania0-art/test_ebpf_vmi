/*
* test_cross_process.c - 跨进程访问测试
* 
* 场景：父进程加载 BPF 程序，子进程尝试通过 ID 访问
* 预期：HVMI 检测到跨进程访问并告警
* 
* 编译: gcc -o test_cross_process test_cross_process.c
* 运行: sudo ./test_cross_process
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/bpf.h>

/* BPF 系统调用包装 */
static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* 在共享内存中传递 prog_id（简化版：使用文件） */
#define PROG_ID_FILE "/tmp/bpf_test_prog_id"

/* ============================================================
* 父进程：加载 BPF 程序
* ============================================================ */
int parent_load_program(void)
{
    union bpf_attr attr;
    int prog_fd = -1;
    unsigned int prog_id = 0;

    printf("[PARENT PID=%d] Loading BPF program...\n", getpid());

    /* 加载简单程序 */
    struct bpf_insn insns[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
        { .code = BPF_JMP | BPF_EXIT }
    };

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (__u64)insns;
    attr.license = (__u64)"GPL";
    strncpy(attr.prog_name, "cross_proc", sizeof(attr.prog_name));

    prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("[PARENT] BPF_PROG_LOAD failed");
        return -1;
    }

    printf("[PARENT PID=%d] ✅ Program loaded (fd=%d)\n", getpid(), prog_fd);

    /* 获取 prog_id */
    struct bpf_prog_info info = {0};
    unsigned int info_len = sizeof(info);

    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = prog_fd;
    attr.info.info_len = info_len;
    attr.info.info = (__u64)&info;

    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        perror("[PARENT] BPF_OBJ_GET_INFO_BY_FD failed");
        close(prog_fd);
        return -1;
    }

    prog_id = info.id;
    printf("[PARENT PID=%d] ✅ Program ID: %u\n", getpid(), prog_id);

    /* 保存 prog_id 到文件供子进程读取 */
    FILE *fp = fopen(PROG_ID_FILE, "w");
    if (fp) {
        fprintf(fp, "%u", prog_id);
        fclose(fp);
        printf("[PARENT PID=%d] ✅ Saved prog_id to %s\n", getpid(), PROG_ID_FILE);
    }

    /* 保持程序存活 */
    printf("[PARENT PID=%d] Keeping program alive, waiting for child...\n", getpid());
    sleep(5);  /* 等待子进程执行 */

    close(prog_fd);
    unlink(PROG_ID_FILE);

    return 0;
}

/* ============================================================
* 子进程：通过 ID 访问父进程的程序
* ============================================================ */
int child_access_program(void)
{
    union bpf_attr attr;
    unsigned int prog_id = 0;
    int fd = -1;

    sleep(1);  /* 等待父进程加载完成 */

    printf("\n[CHILD PID=%d] Attempting cross-process access...\n", getpid());

    /* 从文件读取 prog_id */
    FILE *fp = fopen(PROG_ID_FILE, "r");
    if (!fp) {
        perror("[CHILD] Failed to open prog_id file");
        return -1;
    }

    if (fscanf(fp, "%u", &prog_id) != 1) {
        fprintf(stderr, "[CHILD] Failed to read prog_id\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    printf("[CHILD PID=%d] Read prog_id: %u from parent\n", getpid(), prog_id);

    /* 通过 ID 访问程序 */
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = prog_id;

    printf("[CHILD PID=%d] 📞 Calling BPF_PROG_GET_FD_BY_ID (prog_id=%u)...\n",
            getpid(), prog_id);

    fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));

    if (fd < 0) {
        perror("[CHILD] BPF_PROG_GET_FD_BY_ID failed");
        printf("[CHILD] Error: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    printf("[CHILD PID=%d] ⚠️  Got FD: %d (CROSS-PROCESS ACCESS!)\n", getpid(), fd);
    printf("[CHILD PID=%d] Expected HVMI Log:\n", getpid());
    printf("   ⚠️ ⚠️ ⚠️  CROSS-PROCESS ACCESS DETECTED ⚠️ ⚠️ ⚠️\n");
    printf("   - Original Owner: PID=%d (parent)\n", getppid());
    printf("   - Current Accessor: PID=%d (child)\n", getpid());

    close(fd);
    return 0;
}

/* ============================================================
* 主函数
* ============================================================ */
int main(int argc, char **argv)
{
    pid_t pid;
    int status;

    printf("╔════════════════════════════════════════╗\n");
    printf("║  Cross-Process BPF Access Test         ║\n");
    printf("║  Parent loads, Child accesses          ║\n");
    printf("╚════════════════════════════════════════╝\n");

    if (geteuid() != 0) {
        fprintf(stderr, "Error: Must run as root\n");
        return 1;
    }

    printf("\nTest Scenario:\n");
    printf("  1. Parent process (PID=%d) loads BPF program\n", getpid());
    printf("  2. Parent writes prog_id to temp file\n");
    printf("  3. Child process reads prog_id from file\n");
    printf("  4. Child calls BPF_PROG_GET_FD_BY_ID\n");
    printf("  5. HVMI should detect: Child PID ≠ Parent PID\n");
    printf("\n");

    pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        /* 子进程 */
        child_access_program();
        exit(0);
    } else {
        /* 父进程 */
        parent_load_program();

        /* 等待子进程完成 */
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("\n[PARENT] Child exited with status: %d\n", WEXITSTATUS(status));
        }
    }

    printf("\n╔════════════════════════════════════════╗\n");
    printf("║  Cross-Process Test Completed          ║\n");
    printf("╚════════════════════════════════════════╝\n");

    printf("\nVerification Steps:\n");
    printf("1. Check HVMI logs for cross-process detection\n");
    printf("2. Look for lines containing:\n");
    printf("   - 'CROSS-PROCESS ACCESS DETECTED'\n");
    printf("   - 'Original Owner: PID=%d'\n", getpid());
    printf("   - 'Current Accessor: PID=%d'\n", pid);

    return 0;
}

