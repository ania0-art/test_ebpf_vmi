// test_cross_process.c - 跨进程 BPF 对象共享测试
// 测试：GET_FD_BY_ID、MAP_GET_FD_BY_ID、OBJ_PIN、OBJ_GET
//
// 编译：gcc -o test_cross_process test_cross_process.c
// 运行：sudo ./test_cross_process

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PIN_PATH "/sys/fs/bpf/test_prog_lifecycle"
#define MAP_PIN_PATH "/sys/fs/bpf/test_map_lifecycle"

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// 获取 BPF 对象的 ID
static int get_prog_id(int prog_fd)
{
    struct bpf_prog_info info = {};
    union bpf_attr attr = {
        .info.bpf_fd = prog_fd,
        .info.info_len = sizeof(info),
        .info.info = (unsigned long)&info,
    };

    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        return -1;
    }

    return info.id;
}

static int get_map_id(int map_fd)
{
    struct bpf_map_info info = {};
    union bpf_attr attr = {
        .info.bpf_fd = map_fd,
        .info.info_len = sizeof(info),
        .info.info = (unsigned long)&info,
    };

    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        return -1;
    }

    return info.id;
}

int main(void)
{
    int prog_fd = -1;
    int map_fd = -1;
    int prog_id, map_id;
    pid_t child_pid;

    printf("========================================\n");
    printf("跨进程 BPF 对象共享测试\n");
    printf("========================================\n");
    printf("Parent PID: %d\n", getpid());
    printf("========================================\n\n");

    // 确保 bpffs 已挂载
    system("mkdir -p /sys/fs/bpf 2>/dev/null");
    system("mount -t bpf bpf /sys/fs/bpf 2>/dev/null");

    // ============================================================
    // 父进程：创建 BPF 对象
    // ============================================================
    printf("📍 [PARENT] Step 1: Creating BPF Map...\n");

    union bpf_attr map_attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = 8,
        .max_entries = 10,
    };
    snprintf(map_attr.map_name, sizeof(map_attr.map_name), "shared_map");

    map_fd = bpf(BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (map_fd < 0) {
        perror("❌ BPF_MAP_CREATE failed");
        return 1;
    }

    map_id = get_map_id(map_fd);
    printf("✅ Map created: fd=%d, map_id=%d\n\n", map_fd, map_id);

    printf("📍 [PARENT] Step 2: Loading BPF Program...\n");

    struct bpf_insn prog_insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 1},
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},
    };

    char log_buf[4096];
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = 2,
        .insns = (unsigned long)prog_insns,
        .license = (unsigned long)"GPL",
        .log_level = 1,
        .log_size = sizeof(log_buf),
        .log_buf = (unsigned long)log_buf,
    };
    snprintf(prog_attr.prog_name, sizeof(prog_attr.prog_name), "shared_prog");

    prog_fd = bpf(BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (prog_fd < 0) {
        perror("❌ BPF_PROG_LOAD failed");
        close(map_fd);
        return 1;
    }

    prog_id = get_prog_id(prog_fd);
    printf("✅ Program loaded: fd=%d, prog_id=%d\n\n", prog_fd, prog_id);

    // ============================================================
    // 测试 1: OBJ_PIN (父进程持久化)
    // ============================================================
    printf("📍 [PARENT] Step 3: Pinning objects to filesystem...\n");

    // Pin 程序
    union bpf_attr pin_prog_attr = {
        .pathname = (unsigned long)PIN_PATH,
        .bpf_fd = prog_fd,
        .file_flags = 0,
    };

    unlink(PIN_PATH);  // 删除旧文件
    if (bpf(BPF_OBJ_PIN, &pin_prog_attr, sizeof(pin_prog_attr)) < 0) {
        perror("❌ BPF_OBJ_PIN (prog) failed");
    } else {
        printf("✅ Program pinned to %s\n", PIN_PATH);
        printf("   Expected HVMI log: OBJ_PIN detected, prog_id=%d\n", prog_id);
    }

    // Pin Map
    union bpf_attr pin_map_attr = {
        .pathname = (unsigned long)MAP_PIN_PATH,
        .bpf_fd = map_fd,
        .file_flags = 0,
    };

    unlink(MAP_PIN_PATH);
    if (bpf(BPF_OBJ_PIN, &pin_map_attr, sizeof(pin_map_attr)) < 0) {
        perror("❌ BPF_OBJ_PIN (map) failed");
    } else {
        printf("✅ Map pinned to %s\n", MAP_PIN_PATH);
        printf("   Expected HVMI log: OBJ_PIN detected, map_id=%d\n\n", map_id);
    }

    sleep(1);

    // ============================================================
    // 创建子进程进行跨进程访问测试
    // ============================================================
    printf("📍 Step 4: Forking child process for cross-process tests...\n\n");

    child_pid = fork();
    if (child_pid < 0) {
        perror("❌ fork failed");
        goto cleanup;
    }

    if (child_pid == 0) {
        // ============================================================
        // 子进程：测试跨进程访问
        // ============================================================
        printf("========================================\n");
        printf("[CHILD PID=%d] Cross-Process Access Tests\n", getpid());
        printf("========================================\n\n");

        sleep(1);  // 等待父进程完成 PIN

        // ----------------------------------------
        // 测试 2: BPF_PROG_GET_FD_BY_ID
        // ----------------------------------------
        printf("📍 [CHILD] Test 1: BPF_PROG_GET_FD_BY_ID (prog_id=%d)\n", prog_id);

        union bpf_attr get_prog_attr = {0};
        *(unsigned int *)&get_prog_attr = prog_id;  // prog_id at offset 0

        int child_prog_fd = bpf(BPF_PROG_GET_FD_BY_ID, &get_prog_attr, sizeof(unsigned int));
        if (child_prog_fd < 0) {
            perror("❌ BPF_PROG_GET_FD_BY_ID failed");
        } else {
            printf("✅ Got program FD: %d\n", child_prog_fd);
            printf("   ⚠️  Expected HVMI log: CROSS-PROCESS PROGRAM ACCESS DETECTED\n");
            printf("   - Parent PID: %d\n", getppid());
            printf("   - Child PID: %d\n", getpid());
            close(child_prog_fd);
        }
        printf("\n");

        // ----------------------------------------
        // 测试 3: BPF_MAP_GET_FD_BY_ID
        // ----------------------------------------
        printf("📍 [CHILD] Test 2: BPF_MAP_GET_FD_BY_ID (map_id=%d)\n", map_id);

        union bpf_attr get_map_attr = {0};
        *(unsigned int *)&get_map_attr = map_id;

        int child_map_fd = bpf(BPF_MAP_GET_FD_BY_ID, &get_map_attr, sizeof(unsigned int));
        if (child_map_fd < 0) {
            perror("❌ BPF_MAP_GET_FD_BY_ID failed");
        } else {
            printf("✅ Got map FD: %d\n", child_map_fd);
            printf("   ⚠️  Expected HVMI log: CROSS-PROCESS MAP ACCESS DETECTED\n");
            printf("   - Parent PID: %d\n", getppid());
            printf("   - Child PID: %d\n", getpid());
            close(child_map_fd);
        }
        printf("\n");

        // ----------------------------------------
        // 测试 4: BPF_OBJ_GET (程序)
        // ----------------------------------------
        printf("📍 [CHILD] Test 3: BPF_OBJ_GET (pinned program)\n");

        union bpf_attr get_obj_prog_attr = {
            .pathname = (unsigned long)PIN_PATH,
            .file_flags = 0,
        };

        int obj_prog_fd = bpf(BPF_OBJ_GET, &get_obj_prog_attr, sizeof(get_obj_prog_attr));
        if (obj_prog_fd < 0) {
            perror("❌ BPF_OBJ_GET (prog) failed");
        } else {
            printf("✅ Got pinned program FD: %d\n", obj_prog_fd);
            printf("   ⚠️  Expected HVMI log: CROSS-PROCESS OBJ_GET DETECTED\n");
            printf("   - Original pinner: Parent PID=%d\n", getppid());
            printf("   - Current accessor: Child PID=%d\n", getpid());
            close(obj_prog_fd);
        }
        printf("\n");

        // ----------------------------------------
        // 测试 5: BPF_OBJ_GET (Map)
        // ----------------------------------------
        printf("📍 [CHILD] Test 4: BPF_OBJ_GET (pinned map)\n");

        union bpf_attr get_obj_map_attr = {
            .pathname = (unsigned long)MAP_PIN_PATH,
            .file_flags = 0,
        };

        int obj_map_fd = bpf(BPF_OBJ_GET, &get_obj_map_attr, sizeof(get_obj_map_attr));
        if (obj_map_fd < 0) {
            perror("❌ BPF_OBJ_GET (map) failed");
        } else {
            printf("✅ Got pinned map FD: %d\n", obj_map_fd);
            printf("   ⚠️  Expected HVMI log: CROSS-PROCESS OBJ_GET DETECTED\n");
            close(obj_map_fd);
        }
        printf("\n");

        printf("========================================\n");
        printf("[CHILD] All cross-process tests completed\n");
        printf("========================================\n");

        exit(0);
    }

    // ============================================================
    // 父进程：等待子进程完成
    // ============================================================
    printf("[PARENT] Waiting for child process...\n\n");
    waitpid(child_pid, NULL, 0);
    printf("[PARENT] Child process finished\n\n");

cleanup:
    // ============================================================
    // 清理
    // ============================================================
    printf("📍 [PARENT] Cleanup...\n");

    if (prog_fd >= 0) close(prog_fd);
    if (map_fd >= 0) close(map_fd);
    unlink(PIN_PATH);
    unlink(MAP_PIN_PATH);

    printf("✅ Cleanup completed\n\n");

    printf("========================================\n");
    printf("测试完成！\n");
    printf("========================================\n");
    printf("请检查 HVMI 日志，应包含以下跨进程检测：\n");
    printf("1. ✅ OBJ_PIN (父进程)\n");
    printf("2. ⚠️  PROG_GET_FD_BY_ID (子进程访问父进程的程序)\n");
    printf("3. ⚠️  MAP_GET_FD_BY_ID (子进程访问父进程的 Map)\n");
    printf("4. ⚠️  OBJ_GET (子进程获取父进程 PIN 的程序)\n");
    printf("5. ⚠️  OBJ_GET (子进程获取父进程 PIN 的 Map)\n");
    printf("========================================\n");

    return 0;
}

