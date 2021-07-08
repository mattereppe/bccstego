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
BPF_ARRAY(nw_stats_map, __u32, NBINS);
#else
struct bpf_map_def SEC("maps") nw_stats_map = {
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

/* TCP options */
#define TCP_OPT_END	0
#define TCP_OPT_NONE	1
#define TCP_OPT_MSS	2
#define TCP_OPT_WNDWS	3
#define TCP_OPT_SACKP	4
#define TCP_OPT_SACK	5
#define TCP_OPT_TS	8

struct tcp_opt_none {
	__u8 type;
};

struct tcp_opt_mss {
	__u8 type;
	__u8 len;
	__u16 data;
};

struct tcp_opt_wndw_scale {
	__u8 type;
	__u8 len;
	__u8 data;
};

struct tcp_opt_sackp {
	__u8 type;
	__u8 len;
};

/* Bypassing the verifier check is not simple with variable data,
 * but for now I don't need to parse sack data.
 */
struct tcp_opt_sack {
	__u8 type;
	__u8 len;
//	__u32 data[8];
};

struct tcp_opt_ts {
	__u8 type;
	__u8 len;
	__u32 data[2];
};

struct tcpopt {
	struct tcp_opt_mss *op_mss;
	struct tcp_opt_wndw_scale *op_wndw_scale;
	struct tcp_opt_sackp *op_sackp;
	struct tcp_opt_sack *op_sack;
	struct tcp_opt_ts *op_ts;
};

struct optvalues {
	__u16 mss;
	__u8 wndw_scale;
	__u32 timestamp1;
	__u32 timestamp2;
};

static __always_inline int tcpopt_type(void * tcph, unsigned int offset, void *data_end)
{
	struct tcp_opt_none *opn;

	opn = (struct tcp_opt_none *)(tcph+offset);

	if ( (void *)(opn+1) > data_end )
		return -1;
	else
		return opn->type;
	
}

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
        return bpf_ntohs(h_proto); /* host-byte-order */


}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                   void *data_end,
                   struct iphdr **iphdr)
{
   struct iphdr *iph = nh->pos;
   int hdrsize;

   if ( (void *)(iph + 1) > data_end)
      return -1;

   hdrsize = iph->ihl * 4;
   // Sanity check packet field is valid/
   if(hdrsize < sizeof(iph))
      return -1;

   // Variable-length IPv4 header, need to use byte-based arithmetic 
   if (nh->pos + hdrsize > data_end)
      return -1;

   nh->pos += hdrsize;
   *iphdr = iph;

   return iph->protocol;
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
			

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

static __always_inline int parse_tcpopt(struct tcphdr *tcph,
					void *data_end,
					struct optvalues *value)
{
	unsigned short op_tot_len = 0;
	unsigned short last_op = 0;
	struct tcp_opt_mss *mss = 0;
	struct tcp_opt_wndw_scale *wndw_scale = 0;
	struct tcp_opt_sackp *sackp = 0;
	struct tcp_opt_sack *sack = 0;
	struct tcp_opt_ts *ts = 0;
	unsigned int offset = 20;
	__u8 type;

	op_tot_len = (tcph->doff - 5)*4;

	if( op_tot_len < 0 )
		return -1;
	
	if( (void *)(tcph+1)+op_tot_len > data_end )
		return -1;

	/* 10 loops is arbitrary, hoping this could cover most use-cases.
	 * A fixed boundary is required by the internal verifier.
	 */
	for(unsigned int i=0; i<5; i++)
	{
		type = tcpopt_type((void *) tcph, offset,data_end);
	
		switch ( type ) {
			case TCP_OPT_END:
				last_op = 1;
			case TCP_OPT_NONE:
				offset++;
				op_tot_len--;
				break;
			case TCP_OPT_MSS:
				mss = (struct tcp_opt_mss *)((void *)tcph+offset);
				if( (void *)(mss+1) > data_end )
					return -1;
				offset+=mss->len;
				op_tot_len-=mss->len;
				value->mss = bpf_ntohs(mss->data);
				break;
			case TCP_OPT_WNDWS:
				wndw_scale = (struct tcp_opt_wndw_scale *)((void *)tcph+offset);
				if( (void *)(wndw_scale+1) > data_end )
					return -1;
				offset+=wndw_scale->len;
				op_tot_len-=wndw_scale->len;
				value->wndw_scale = wndw_scale->data;
				break;
			case TCP_OPT_SACKP:
				sackp = (struct tcp_opt_sackp *)((void *)tcph+offset);
				if( (void *)(sackp+1) > data_end)
					return -1;
				offset+=sackp->len;
				op_tot_len-=sackp->len;
				// No data read for this option
				break;
			case TCP_OPT_SACK:
				sack = (struct tcp_opt_sack *)((void *)tcph+offset);
				if( (void *)(sack+1) > data_end)
					return -1;
				offset+=sack->len;
				op_tot_len-=sack->len;
				// No data read for this option
				break;
			case TCP_OPT_TS:
				ts = (struct tcp_opt_ts *)((void *)tcph+offset);
				if( (void *)(ts+1) > data_end)
					return -1;
				offset+=ts->len;
				op_tot_len-=ts->len;
				value->timestamp1=bpf_ntohl(ts->data[0]);
				value->timestamp2=bpf_ntohl(ts->data[1]);
				break;
			default:
				last_op = 1;
				break;

		}

		if ( last_op || op_tot_len <= 0)
			break;
	}

	return op_tot_len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if ((void *)(h + 1) > data_end)
		return -1;

	len = h->doff * 4;
	// Sanity check packet field is valid 
	if(len < sizeof(h))
		return -1;

	// Variable-length TCP header, need to use byte-based arithmetic 
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return data_end - nh->pos;
}



#ifdef __BCC__
BCC_SEC("ip_stats")
#else
SEC("ip_stats")
#endif
int  ip_stats(struct __sk_buff *skb)
{
	/* Preliminary step: cast to void*.
	 * (Not clear why data/data_end are stored as long)
	 */
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	__u32 ipfield = 0;
	__u32 len = 0;
	__u32 init_value = 1;
	unsigned int vers = 0;
	int op_len=0;
	int eth_proto, ip_proto = 0;
	/* int eth_proto, ip_proto, icmp_type = 0; */
/*	struct flowid flow = { 0 }; */
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct ipv6hdr* iph6;
	struct iphdr *iph4;
	struct tcphdr *tcphdr = 0;
	struct udphdr *udphdr = 0;
	struct optvalues tcpopts = { 0 };
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

	/* Parse IP header and verify protocol number. */
	switch (eth_proto) {
		case ETH_P_IP:
			ip_proto = parse_iphdr(&nh, data_end, &iph4);
			vers = 4;
			break;
		case ETH_P_IPV6:
			ip_proto = parse_ip6hdr(&nh, data_end, &iph6);
			vers = 6;
			break;
		default:
			return TC_ACT_OK;
	}

	if( ip_proto < 0 ) {
		return TC_ACT_OK;
	}	

	switch (ip_proto) {
	/*	case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			if( process_icmp_header(&nh, data_end, &icmphdrc, &key) < 0 )
				return TC_ACT_OK;
			break;*/
		case IPPROTO_TCP:
			if( parse_tcphdr(&nh, data_end, &tcphdr) < 0 ) {
				return TC_ACT_OK;
			}
			else
				op_len = parse_tcpopt(tcphdr, data_end, &tcpopts);
			break;
		case IPPROTO_UDP:
			if( parse_udphdr(&nh, data_end, &udphdr) < 0 )
				return TC_ACT_OK;
			break;
		default:
			/* TODO: cound how many packets/bytes are seen from
			 * unmanaged protocols, so we can understand the impact
			 * of such traffic. 
			 * Hints: a common line with IPPROTO_MAX may be used.
			 */
			return TC_ACT_OK;
	}

	/* Check statistics
	 */
	if ( vers == 6 ) {
		if( (void*) iph6 + sizeof(struct ipv6hdr) < data_end) {
			UPDATE_STATISTICS_V6
		}
	}
	else {
		if ( (void*) iph4 + sizeof(struct iphdr) < data_end) {
			UPDATE_STATISTICS_V4
		}
	}

	UPDATE_STATISTICS_L4
			

	/* Collect the required statistics. */
	__u32 key = ipfield >> (IPFIELDLENGTH-BINBASE);
	__u32 *counter = 
#ifndef __BCC__
		bpf_map_lookup_elem(&nw_stats_map, &key);
#else
		nw_stats_map.lookup(&key);
#endif
	if(!counter)
#ifndef __BCC__
		bpf_map_update_elem(&nw_stats_map, &key, &init_value, BPF_ANY);
#else
		nw_stats_map.update(&key, &init_value);
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
