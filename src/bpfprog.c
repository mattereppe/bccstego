/* SPDX-License-Identifier: GPL-2.0 */

/* Detect BCC vs libbpf mode
 */
#ifdef BCC_SEC
#define __BCC__
#endif

#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>		// struct ethhdr
#include <linux/pkt_cls.h>
#include <linux/time.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#ifndef __BCC__
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 		// bpf_ntohs
#include <iproute2/bpf_elf.h>
#endif

SETBINBASE
#define NBINS 0x1<<BINBASE


/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40



/* TODO: Improve performance by using multiple per-cpu hash maps.
 */
#ifdef __BCC__
BPF_ARRAY(ipv6_stats_map, __u32, NBINS);
#else
struct bpf_map_def SEC("maps") ipv6_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = NBINS,
	.map_flags = BPF_ANY
};
#endif

#ifndef __BCC__
#define VLAN_MAX_DEPTH 4		/* Max number of VLAN headers parsed */
#endif

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
        void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

#ifndef __BCC__
/*
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 *
 *      It is not clear why this structure is not present in
 *      the user header files. It is only present in kernel
 *      headers, but I cannot include that file otherwise
 *      I get other errors.
 */
struct vlan_hdr {
        __be16  h_vlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};
#endif

/*
	   * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
	   *  * structures.
	   *   */
struct icmphdr_common {
        __u8	type;
	__u8    code;
	__sum16 cksum;
};


/* Parse the Ethernet header and return protocol.
 * Ignore VLANs.
 *
 * Protocol is returned in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
       struct ethhdr *eth = nh->pos;
        int hdrsize = sizeof(*eth);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

        /* Byte-count bounds check; check if current pointer + size of header
         * is after data_end.
         */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *ethhdr = eth;
        vlh = nh->pos;
        h_proto = eth->h_proto;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto))
                        break;

                if ( (void *)(vlh + 1) > data_end)
                        break;

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        nh->pos = vlh;
        return h_proto; /* network-byte-order */


}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
 	if ( (void *)(ip6h + 1) > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}
			
#ifdef __BCC__
BCC_SEC("ipv6_stats")
#else
SEC("ipv6_stats")
#endif
int  ipv6_stats(struct __sk_buff *skb)
{
	/* Preliminary step: cast to void*.
	 * (Not clear why data/data_end are stored as long)
	 */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	__u32 ipv6field = 0;
	__u32 len = 0;
	__u32 init_value = 1;
	int eth_proto, ip_proto = 0;
	/* int eth_proto, ip_proto, icmp_type = 0; */
/*	struct flowid flow = { 0 }; */
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct ipv6hdr* iph6;
	__u64 ts, te;

	ts = bpf_ktime_get_ns();	
	
	/* Parse Ethernet header and verify protocol number. */
	nh.pos = data;
	len = data_end - data;
	eth = (struct ethhdr *)data;
	eth_proto = parse_ethhdr(&nh, data_end, &eth);
	if ( eth_proto < 0 ) {
		bpf_trace_printk("Unknown ethernet protocol/Too many nested VLANs.");
		return TC_ACT_OK; /* TODO: XDP_ABORT? */
	}
	if ( eth_proto != bpf_htons(ETH_P_IPV6) )
	{
		return TC_ACT_OK;
	}

	/* Parse IP header and verify protocol number. */
	if( (ip_proto = parse_ip6hdr(&nh, data_end, &iph6)) < 0 ) {
		return TC_ACT_OK;
	}	

	/* Check flow label
	 */
	if( (void*) iph6 + sizeof(struct ipv6hdr) < data_end) {
		UPDATE_STATISTICS
	}

	/* Collect the required statistics. */
	__u32 key = ipv6field >> (IPV6FIELDLENGTH-BINBASE);
	__u32 *counter = 
#ifndef __BCC__
		bpf_map_lookup_elem(&ipv6_stats_map, &key);
#else
		ipv6_stats_map.lookup(&key);
#endif
	if(!counter)
#ifndef __BCC__
		bpf_map_update_elem(&ipv6_stats_map, &key, &init_value, BPF_ANY);
#else
		ipv6_stats_map.update(&key, &init_value);
#endif
	else
		__sync_fetch_and_add(counter, 1);

	te = bpf_ktime_get_ns();
	/*
	bpf_trace_printk("Time elapsed: %d", te-ts);
	*/
	
	return TC_ACT_OK;
}

#ifndef __BCC__
char _license[] SEC("license") = "GPL";
#endif
