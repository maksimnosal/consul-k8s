// +build ignore

#include "common.h"
#include <errno.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <stdbool.h>

#define SYS_REJECT 0
#define SYS_PROCEED 1
#define DEFAULT_MAX_EBPF_MAP_ENNTRIES 65536

char __license[] SEC("license") = "Dual BSD/GPL";

struct consul_servers {
  __u32 address;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __be32);
  __type(value, struct consul_servers);
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENNTRIES);
} v4_svc_map SEC(".maps");

static __always_inline struct consul_servers *
lb4_lookup_service(__be32 key) {
  struct consul_servers *svc;
  svc = bpf_map_lookup_elem(&v4_svc_map, &key);
  if (svc) {
    return svc;
  }

  return NULL;
}

static __always_inline int __sock4_fwd(struct bpf_sock_addr *ctx) {

  __be32  key = ctx->user_ip4;


  struct consul_servers *svc;

  svc = lb4_lookup_service(key);

  if (!svc) {
    const char debug_str[] = "server not found for key:0x%x";
    bpf_trace_printk(debug_str, sizeof(debug_str), key);
    return 0;
  }

  // Logs are in /sys/kernel/debug/tracing/trace_pipe

  const char debug_str[] =
      "Hello, world, from BPF! I am in the proxy program. I caught a packet destined for my VIP, the address is: 0x%x\n";
  bpf_trace_printk(debug_str, sizeof(debug_str), key);

  ctx->user_ip4 = svc->address;

  return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {

  __sock4_fwd(ctx);
  return SYS_PROCEED;
}
