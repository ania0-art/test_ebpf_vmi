/* simple_prog.c - 用于测试的最简单 BPF 程序 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int simple_prog(struct __sk_buff *skb)
{
    return 0;  /* 接受所有数据包 */
}

char _license[] SEC("license") = "GPL";
