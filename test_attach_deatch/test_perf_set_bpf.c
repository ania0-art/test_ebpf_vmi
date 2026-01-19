/*
* 修正版：使用静态tracepoint触发perf_event_attach_bpf_prog
* 编译：gcc -o test_perf_set_bpf test_perf_set_bpf.c
* 运行：sudo ./test_perf_set_bpf
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// 读取tracepoint ID
static int read_tracepoint_id(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    int id;
    if (fscanf(fp, "%d", &id) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return id;
}

static int load_bpf_prog(void)
{
    struct bpf_insn prog[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  // r0 = 0
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  // return
    };

    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_TRACEPOINT,
        .insn_cnt = sizeof(prog) / sizeof(prog[0]),
        .insns = (unsigned long)prog,
        .license = (unsigned long)"GPL",
    };

    int prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("BPF_PROG_LOAD failed");
        return -1;
    }

    printf("[+] BPF program loaded, fd=%d\n", prog_fd);
    return prog_fd;
}

static int create_perf_event(void)
{
    // 尝试多个常见的tracepoint（按优先级）
    const char *tracepoint_paths[] = {
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_nanosleep/id",
        "/sys/kernel/debug/tracing/events/sched/sched_process_exec/id",
        "/sys/kernel/debug/tracing/events/sched/sched_process_fork/id",
        "/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/id",
        NULL
    };

    int tracepoint_id = -1;
    const char *used_path = NULL;

    // 查找第一个可用的tracepoint
    for (int i = 0; tracepoint_paths[i] != NULL; i++) {
        tracepoint_id = read_tracepoint_id(tracepoint_paths[i]);
        if (tracepoint_id > 0) {
            used_path = tracepoint_paths[i];
            break;
        }
    }

    if (tracepoint_id < 0) {
        fprintf(stderr, "[-] Failed to read any tracepoint ID\n");
        fprintf(stderr, "[-] Make sure /sys/kernel/debug/tracing is mounted:\n");
        fprintf(stderr, "    sudo mount -t debugfs none /sys/kernel/debug\n");
        return -1;
    }

    printf("[+] Using tracepoint: %s (id=%d)\n", used_path, tracepoint_id);

    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = tracepoint_id;  // 使用读取的真实ID
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.disabled = 1;

    int perf_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (perf_fd < 0) {
        perror("perf_event_open failed");
        return -1;
    }

    printf("[+] Perf event created, fd=%d\n", perf_fd);
    return perf_fd;
}

int main(void)
{
    int prog_fd, perf_fd, ret;

    printf("=== Test for perf_event_attach_bpf_prog hook ===\n\n");

    prog_fd = load_bpf_prog();
    if (prog_fd < 0) return 1;

    perf_fd = create_perf_event();
    if (perf_fd < 0) {
        close(prog_fd);
        return 1;
    }

    printf("\n[*] Attaching BPF program to perf_event...\n");
    printf("[*] This will trigger: perf_event_attach_bpf_prog(event, prog)\n\n");

    ret = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (ret < 0) {
        perror("ioctl(PERF_EVENT_IOC_SET_BPF) failed");
        close(perf_fd);
        close(prog_fd);
        return 1;
    }

    printf("[+] SUCCESS! ioctl(PERF_EVENT_IOC_SET_BPF) completed\n");
    printf("[+] Check HVMI logs for:\n");
    printf("    'luckybird *** [BPF][PERF_EVENT] perf_event_attach_bpf_prog called'\n\n");

    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    sleep(1);
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    close(perf_fd);
    close(prog_fd);
    return 0;
}
