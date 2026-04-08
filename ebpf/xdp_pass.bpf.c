// XDP program with rate limiting, blocklist, TCP signatures, conntrack, and rule epoch.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define STAT_PASS 0
#define STAT_DROP_BLOCK_IP 1
#define STAT_DROP_BLOCK_CIDR 2
#define STAT_DROP_RL 3
#define STAT_DROP_SIG_TCP 4
#define STAT_PARSE_ERR 5
#define STAT_SYN_SEEN 6
#define STAT_SYN_ACKED 7
#define STAT_DROP_SYN_PROXY 8
#define STAT_CT_ESTABLISHED 9

#define CT_STATE_SYN_RECV 1
#define CT_STATE_ESTABLISHED 2

struct rate_limit_cfg {
    __u64 rate_per_sec;
    __u64 burst;
};

struct rate_state {
    __u64 tokens;
    __u64 last_ns;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct tcp_signature_cfg {
    __u8 block_null_scan;
    __u8 block_xmas_scan;
    __u8 _pad[6];
};

struct conntrack_cfg {
    __u8 enable_syn_proxy;
    __u8 _pad0[3];
    __u32 max_half_open;
    __u64 syn_timeout_ns;
    __u64 est_timeout_ns;
};

struct flow5_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 _pad0;
    __u16 _pad1;
};

struct conntrack_state {
    __u64 last_seen_ns;
    __u32 expected_ack;
    __u8 state;
    __u8 _pad0[3];
};

struct parsed_pkt {
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u32 saddr;
    __u32 daddr;
    __u8 is_tcp;
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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} rules_cidr_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_signature_cfg);
} rules_tcp_sig SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct conntrack_cfg);
} conntrack_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct flow5_key);
    __type(value, struct conntrack_state);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} conntrack_half_open SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Control-plane epoch for rules. Increment on any rules update.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rules_epoch SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) {
        __sync_fetch_and_add(v, 1);
    }
}

static __always_inline void adjust_half_open(int delta) {
    __u32 k = 0;
    __u64 *v = bpf_map_lookup_elem(&conntrack_half_open, &k);
    if (!v) {
        return;
    }
    if (delta > 0) {
        __sync_fetch_and_add(v, 1);
    } else if (delta < 0 && *v > 0) {
        __sync_fetch_and_sub(v, 1);
    }
}

static __always_inline int parse_packet(void *data, void *data_end, struct parsed_pkt *out) {
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

    out->iph = iph;
    out->saddr = iph->saddr;
    out->daddr = iph->daddr;
    out->is_tcp = 0;
    out->tcph = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) {
            return -1;
        }
        out->is_tcp = 1;
        out->tcph = tcph;
    }

    return 0;
}

static __always_inline int tcp_signature_drop(struct parsed_pkt *pkt) {
    __u32 k = 0;

    if (!pkt->is_tcp) {
        return 0;
    }

    struct tcp_signature_cfg *cfg = bpf_map_lookup_elem(&rules_tcp_sig, &k);
    if (!cfg) {
        return 0;
    }

    __u8 flags = *((__u8 *)pkt->tcph + 13);
    if (cfg->block_null_scan && flags == 0) {
        return 1;
    }
    if (cfg->block_xmas_scan && flags == 0x29) {
        return 1;
    }
    return 0;
}

static __always_inline int allow_by_rate(__u32 saddr) {
    __u32 k = 0;
    struct rate_limit_cfg *cfg = bpf_map_lookup_elem(&rate_cfg, &k);
    if (!cfg || cfg->rate_per_sec == 0) {
        return 1;
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

static __always_inline int allow_by_conntrack(struct parsed_pkt *pkt) {
    __u32 k = 0;
    struct conntrack_cfg *cfg = bpf_map_lookup_elem(&conntrack_cfg_map, &k);
    if (!cfg || cfg->enable_syn_proxy == 0 || !pkt->is_tcp) {
        return 1;
    }

    struct flow5_key key = {
        .saddr = pkt->saddr,
        .daddr = pkt->daddr,
        .sport = pkt->tcph->source,
        .dport = pkt->tcph->dest,
        .proto = IPPROTO_TCP,
    };

    struct conntrack_state *st = bpf_map_lookup_elem(&conntrack_map, &key);
    __u64 now = bpf_ktime_get_ns();

    if (pkt->tcph->rst || pkt->tcph->fin) {
        if (st) {
            if (st->state == CT_STATE_SYN_RECV) {
                adjust_half_open(-1);
            }
            bpf_map_delete_elem(&conntrack_map, &key);
        }
        return 1;
    }

    if (pkt->tcph->syn && !pkt->tcph->ack) {
        if (!st) {
            __u64 *half = bpf_map_lookup_elem(&conntrack_half_open, &k);
            if (cfg->max_half_open > 0 && half && *half >= cfg->max_half_open) {
                bump_stat(STAT_DROP_SYN_PROXY);
                return 0;
            }
        }

        struct conntrack_state next = {
            .last_seen_ns = now,
            .expected_ack = bpf_htonl(bpf_ntohl(pkt->tcph->seq) + 1),
            .state = CT_STATE_SYN_RECV,
        };
        bpf_map_update_elem(&conntrack_map, &key, &next, BPF_ANY);
        if (!st) {
            adjust_half_open(1);
        }
        bump_stat(STAT_SYN_SEEN);
        return 1;
    }

    if (!st) {
        bump_stat(STAT_DROP_SYN_PROXY);
        return 0;
    }

    if (st->state == CT_STATE_SYN_RECV) {
        if (now - st->last_seen_ns > cfg->syn_timeout_ns) {
            adjust_half_open(-1);
            bpf_map_delete_elem(&conntrack_map, &key);
            bump_stat(STAT_DROP_SYN_PROXY);
            return 0;
        }
        if (pkt->tcph->ack && pkt->tcph->ack_seq == st->expected_ack) {
            st->state = CT_STATE_ESTABLISHED;
            st->last_seen_ns = now;
            adjust_half_open(-1);
            bump_stat(STAT_SYN_ACKED);
            bump_stat(STAT_CT_ESTABLISHED);
            return 1;
        }
        bump_stat(STAT_DROP_SYN_PROXY);
        return 0;
    }

    if (st->state == CT_STATE_ESTABLISHED) {
        if (now - st->last_seen_ns > cfg->est_timeout_ns) {
            bpf_map_delete_elem(&conntrack_map, &key);
            bump_stat(STAT_DROP_SYN_PROXY);
            return 0;
        }
        st->last_seen_ns = now;
        return 1;
    }

    bump_stat(STAT_DROP_SYN_PROXY);
    return 0;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct parsed_pkt pkt = {};
    if (parse_packet(data, data_end, &pkt) < 0) {
        bump_stat(STAT_PARSE_ERR);
        return XDP_PASS;
    }

    __u8 *blocked = bpf_map_lookup_elem(&rules_blocklist, &pkt.saddr);
    if (blocked && *blocked == 1) {
        bump_stat(STAT_DROP_BLOCK_IP);
        return XDP_DROP;
    }

    struct ipv4_lpm_key lpm_key = {
        .prefixlen = 32,
        .addr = pkt.saddr,
    };
    blocked = bpf_map_lookup_elem(&rules_cidr_blocklist, &lpm_key);
    if (blocked && *blocked == 1) {
        bump_stat(STAT_DROP_BLOCK_CIDR);
        return XDP_DROP;
    }

    if (tcp_signature_drop(&pkt)) {
        bump_stat(STAT_DROP_SIG_TCP);
        return XDP_DROP;
    }

    if (!allow_by_conntrack(&pkt)) {
        return XDP_DROP;
    }

    if (!allow_by_rate(pkt.saddr)) {
        bump_stat(STAT_DROP_RL);
        return XDP_DROP;
    }

    bump_stat(STAT_PASS);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
