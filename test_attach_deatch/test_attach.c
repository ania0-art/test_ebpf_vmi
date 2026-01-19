#include <linux/bpf.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    // 1. 加载一个简单的 cgroup/skb 程序
    struct bpf_insn insns[] = {
        { .code = 0xb7, .dst_reg = 0, .imm = 1 },  // mov r0, 1
        { .code = 0x95 },                          // exit
    };

    union bpf_attr attr = {};
    attr.prog_type = BPF_PROG_TYPE_CGROUP_SKB;
    attr.insn_cnt = 2;
    attr.insns = (unsigned long)insns;
    attr.license = (unsigned long)"GPL";

    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("prog_fd=%d\n", prog_fd);

    // 2. 打开 cgroup FD
    int cgroup_fd = open("/sys/fs/cgroup/unified", O_RDONLY);
    printf("cgroup_fd=%d\n", cgroup_fd);

    // 3. ATTACH 程序到 cgroup
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cgroup_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = BPF_CGROUP_INET_INGRESS;  // type=0
    attr.attach_flags = 0;

    int ret = syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
    printf("attach ret=%d\n", ret);

    sleep(2);  // 保持附加状态 2 秒
    return 0;
}
