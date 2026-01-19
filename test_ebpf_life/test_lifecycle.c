// test_lifecycle.c - BPF 程序完整生命周期测试
// 测试：LOAD → ATTACH → DETACH → 卸载
//
// 编译：gcc -o test_lifecycle test_lifecycle.c
// 运行：sudo ./test_lifecycle

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <fcntl.h>

// BPF 系统调用包装
static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// 打开或创建 cgroup
static int open_cgroup(void)
{
    int cgroup_fd;
    char cgroup_path[] = "/sys/fs/cgroup/unified/test_bpf";

    // 尝试创建 cgroup 目录
    system("mkdir -p /sys/fs/cgroup/unified/test_bpf 2>/dev/null");

    // 打开 cgroup
    cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        // 尝试备用路径
        cgroup_fd = open("/sys/fs/cgroup/unified", O_RDONLY | O_DIRECTORY);
        if (cgroup_fd < 0) {
            perror("Failed to open cgroup");
            return -1;
        }
    }

    printf("✅ Opened cgroup_fd: %d\n", cgroup_fd);
    return cgroup_fd;
}

int main(void)
{
    int prog_fd = -1;
    int map_fd = -1;
    int cgroup_fd = -1;
    int ret;

    printf("========================================\n");
    printf("BPF 完整生命周期测试\n");
    printf("========================================\n");
    printf("PID: %d\n", getpid());
    printf("========================================\n\n");

    // ============================================================
    // 步骤 1: 创建 BPF Map
    // ============================================================
    printf("📍 Step 1: Creating BPF Map...\n");

    union bpf_attr map_attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = 8,
        .max_entries = 10,
        .map_flags = 0,
    };
    snprintf(map_attr.map_name, sizeof(map_attr.map_name), "test_map");

    map_fd = bpf(BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (map_fd < 0) {
        perror("❌ BPF_MAP_CREATE failed");
        return 1;
    }

    printf("✅ Map created: fd=%d\n", map_fd);
    printf("   Expected HVMI log: MAP_CREATE detected\n\n");
    sleep(1);

    // ============================================================
    // 步骤 2: 加载 BPF 程序
    // ============================================================
    printf("📍 Step 2: Loading BPF Program...\n");

    // 简单的 cgroup/skb 程序（仅返回 1 允许通过）
    struct bpf_insn prog_insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 1},  // r0 = 1
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},  // exit
    };

    char log_buf[4096];
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
        .insn_cnt = sizeof(prog_insns) / sizeof(struct bpf_insn),
        .insns = (unsigned long)prog_insns,
        .license = (unsigned long)"GPL",
        .log_level = 1,
        .log_size = sizeof(log_buf),
        .log_buf = (unsigned long)log_buf,
    };
    snprintf(prog_attr.prog_name, sizeof(prog_attr.prog_name), "test_prog");

    prog_fd = bpf(BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (prog_fd < 0) {
        perror("❌ BPF_PROG_LOAD failed");
        printf("Verifier log:\n%s\n", log_buf);
        close(map_fd);
        return 1;
    }

    printf("✅ Program loaded: fd=%d\n", prog_fd);
    printf("   Expected HVMI logs:\n");
    printf("   1. PROG_LOAD detected (系统调用入口)\n");
    printf("   2. bpf_prog_new_fd confirmed (验证成功)\n\n");
    sleep(1);

    // ============================================================
    // 步骤 3: 附加程序到 cgroup
    // ============================================================
    printf("📍 Step 3: Attaching program to cgroup...\n");

    cgroup_fd = open_cgroup();
    if (cgroup_fd < 0) {
        printf("⚠️  Cannot open cgroup, skipping ATTACH/DETACH test\n");
        printf("   (PROG_LOAD test already completed)\n\n");
        goto cleanup;
    }

    union bpf_attr attach_attr = {
        .target_fd = cgroup_fd,
        .attach_bpf_fd = prog_fd,
        .attach_type = BPF_CGROUP_INET_INGRESS,
        .attach_flags = 0,
    };

    ret = bpf(BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        perror("❌ BPF_PROG_ATTACH failed");
        printf("   Error: %s (errno=%d)\n", strerror(errno), errno);
        printf("   This might be expected if cgroup v2 is not available\n\n");
        goto cleanup;
    }

    printf("✅ Program attached successfully\n");
    printf("   Expected HVMI log: PROG_ATTACH detected\n");
    printf("   - Prog ID should be recorded\n");
    printf("   - ATTACH_EVENT created with IsActive=TRUE\n\n");
    sleep(1);

    // ============================================================
    // 步骤 4: 分离程序
    // ============================================================
    printf("📍 Step 4: Detaching program...\n");

    union bpf_attr detach_attr = {
        .target_fd = cgroup_fd,
        .attach_type = BPF_CGROUP_INET_INGRESS,
    };

    ret = bpf(BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr));
    if (ret < 0) {
        perror("❌ BPF_PROG_DETACH failed");
        goto cleanup;
    }

    printf("✅ Program detached successfully\n");
    printf("   Expected HVMI log: PROG_DETACH detected\n");
    printf("   - Should match ATTACH_EVENT via Tier-1/2/3 strategy\n");
    printf("   - Update IsActive=FALSE, record DetachTime\n\n");
    sleep(1);

cleanup:
    // ============================================================
    // 步骤 5: 清理资源（触发卸载检测）
    // ============================================================
    printf("📍 Step 5: Cleaning up (unload detection)...\n");

    if (cgroup_fd >= 0) {
        close(cgroup_fd);
        printf("✅ Closed cgroup_fd\n");
    }

    if (prog_fd >= 0) {
        close(prog_fd);
        printf("✅ Closed prog_fd (refcount should decrease)\n");
        printf("   Expected HVMI log (after refcount reaches 0):\n");
        printf("   - __bpf_prog_put_noref triggered\n");
        printf("   - Program unload detected, mappings cleaned\n");
    }

    if (map_fd >= 0) {
        close(map_fd);
        printf("✅ Closed map_fd\n");
    }

    printf("\n========================================\n");
    printf("测试完成！\n");
    printf("========================================\n");
    printf("请检查 HVMI 日志，应包含以下检测点：\n");
    printf("1. ✅ MAP_CREATE\n");
    printf("2. ✅ PROG_LOAD (系统调用入口)\n");
    printf("3. ✅ bpf_prog_new_fd (验证成功确认)\n");
    printf("4. ✅ PROG_ATTACH (如果 cgroup 可用)\n");
    printf("5. ✅ PROG_DETACH (如果 cgroup 可用)\n");
    printf("6. ✅ __bpf_prog_put_noref (程序卸载)\n");
    printf("========================================\n");

    return 0;
}
