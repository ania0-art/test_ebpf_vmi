#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <errno.h>

#define BPF_MAP_TYPE_SOCKMAP 15
#define BPF_SK_SKB_STREAM_VERDICT 5

int main() {
    printf("========================================\n");
    printf("Test 3: Sockmap ATTACH Resolution\n");
    printf("========================================\n");

    // 1. 创建 sockmap
    union bpf_attr map_attr;
    memset(&map_attr, 0, sizeof(map_attr));
    map_attr.map_type = BPF_MAP_TYPE_SOCKMAP;
    map_attr.key_size = 4;
    map_attr.value_size = 4;
    map_attr.max_entries = 10;

    printf("[TEST] Calling BPF_MAP_CREATE (SOCKMAP)...\n");
    int map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (map_fd < 0) {
        fprintf(stderr, "[ERROR] BPF_MAP_CREATE failed: %s\n", strerror(errno));
        fprintf(stderr, "[INFO] Sockmap may require kernel >= 4.14\n");
        return 1;
    }
    printf("[TEST] ✓ MAP_CREATE success, map_fd=%d\n", map_fd);

    // 2. 创建 SK_SKB 程序
    struct bpf_insn insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},  // mov r0, 0 (SK_PASS)
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0},  // exit
    };

    union bpf_attr prog_attr;
    memset(&prog_attr, 0, sizeof(prog_attr));
    prog_attr.prog_type = BPF_PROG_TYPE_SK_SKB;
    prog_attr.insns = (__u64)(unsigned long)insns;
    prog_attr.insn_cnt = 2;
    prog_attr.license = (__u64)(unsigned long)"GPL";
    prog_attr.expected_attach_type = BPF_SK_SKB_STREAM_VERDICT;

    printf("[TEST] Calling BPF_PROG_LOAD (SK_SKB)...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (prog_fd < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_LOAD failed: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }
    printf("[TEST] ✓ PROG_LOAD success, prog_fd=%d\n", prog_fd);

    // 3. ATTACH 程序到 sockmap
    union bpf_attr attach_attr;
    memset(&attach_attr, 0, sizeof(attach_attr));
    attach_attr.target_fd = map_fd;  // 注意：这里是 map_fd
    attach_attr.attach_bpf_fd = prog_fd;
    attach_attr.attach_type = BPF_SK_SKB_STREAM_VERDICT;

    printf("[TEST] Calling BPF_PROG_ATTACH (sockmap, attach_type=%d)...\n",
            BPF_SK_SKB_STREAM_VERDICT);
    int ret = syscall(__NR_bpf, BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_ATTACH failed: %s\n", strerror(errno));
        close(map_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ ATTACH success!\n");
    printf("[TEST] *** Check HVMI logs for Sockmap resolution ***\n");

    sleep(2);

    // 4. DETACH
    union bpf_attr detach_attr;
    memset(&detach_attr, 0, sizeof(detach_attr));
    detach_attr.target_fd = map_fd;
    detach_attr.attach_bpf_fd = prog_fd, 
    detach_attr.attach_type = BPF_SK_SKB_STREAM_VERDICT;

    printf("[TEST] Calling BPF_PROG_DETACH...\n");
    ret = syscall(__NR_bpf, BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] BPF_PROG_DETACH failed: %s\n", strerror(errno));
        close(map_fd);
        close(prog_fd);
        return 1;
    }
    printf("[TEST] ✓ DETACH success!\n");

    close(map_fd);
    close(prog_fd);

    printf("\n[TEST] Expected HVMI Log Checkpoints:\n");
    printf("  1. Target Type = 2 (Sockmap)\n");
    printf("  2. Target GVA = <map_id> (small value < 1000)\n");
    printf("  3. DETACH Tier-1 match success\n");
    printf("========================================\n");

    return 0;
}
