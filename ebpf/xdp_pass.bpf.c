// XDP program with rate limiting, blocklist, and counters.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define STAT_PASS 0
#define STAT_DROP_BLOCK 1
#define STAT_DROP_RL 2
#define STAT_PARSE_ERR 3

struct rate_limit_cfg {
    __u64 rate_per_sec;
    __u64 burst;
};

struct rate_state {
    __u64 tokens;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_cfg);
} rate_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 saddr (network order)
    __type(value, __u8);  // 1 = block
} rules_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) {
        __sync_fetch_and_add(v, 1);
    }
}

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *saddr) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return -1;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return -1;
    }
    *saddr = iph->saddr; // network order
    return 0;
}

static __always_inline int allow_by_rate(__u32 saddr) {
    __u32 k = 0;
    struct rate_limit_cfg *cfg = bpf_map_lookup_elem(&rate_cfg, &k);
    if (!cfg || cfg->rate_per_sec == 0) {
        return 1; // no rate limiting
    }

    struct rate_state *st = bpf_map_lookup_elem(&rate_state_map, &saddr);
    struct rate_state tmp = {};
    if (!st) {
        tmp.tokens = cfg->burst > 0 ? cfg->burst : cfg->rate_per_sec;
        tmp.last_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&rate_state_map, &saddr, &tmp, BPF_ANY);
        st = bpf_map_lookup_elem(&rate_state_map, &saddr);
        if (!st) {
            return 1;
        }
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now - st->last_ns;
    __u64 add = (cfg->rate_per_sec * delta) / 1000000000ULL;
    __u64 tokens = st->tokens + add;
    __u64 burst = cfg->burst > 0 ? cfg->burst : cfg->rate_per_sec;
    if (tokens > burst) {
        tokens = burst;
    }

    if (tokens == 0) {
        st->last_ns = now;
        st->tokens = 0;
        return 0;
    }

    tokens -= 1;
    st->tokens = tokens;
    st->last_ns = now;
    return 1;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 saddr = 0;
    if (parse_ipv4(data, data_end, &saddr) < 0) {
        bump_stat(STAT_PARSE_ERR);
        return XDP_PASS;
    }

    __u8 *blocked = bpf_map_lookup_elem(&rules_blocklist, &saddr);
    if (blocked && *blocked == 1) {
        bump_stat(STAT_DROP_BLOCK);
        return XDP_DROP;
    }

    if (!allow_by_rate(saddr)) {
        bump_stat(STAT_DROP_RL);
        return XDP_DROP;
    }

    bump_stat(STAT_PASS);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
