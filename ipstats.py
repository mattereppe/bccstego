#!/usr/bin/python3
# 
# flowlabel BPF programs to analyse flow label 
#           statistics in IPv6 header. Conceived
#           to detect steganographic channels.
#
# Copyright (C) 2020 Matteo Repetto.
# Licensed under the GNU Public License v2.0.
#

from bcc import BPF
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import time
import sys
import subprocess
import argparse
import pathlib
import re

class InvalidParameterError(Exception):
    """Exception raised for invalid parameters in the input

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message

# Parse parameters from the command line
parser = argparse.ArgumentParser(description='Run bpf inspectors on IPv6 header.',
		epilog='Beware to select the correct bin number!')
parser.add_argument('-t','--type', choices=['fl','tc','hl','nh','pl','tos','ttl','ihl', 'id','fo','ts1','ts2','ack','res','chk'],
        help='Type of statistics to collect. Allowed values for IPv6: fl (flow label), tc (traffic class), hl (hop limit), nh (next header), pl (payload length). Allowed valued for IPv4: tos (type of service), ttl (time-to-live), ihl (internet header length), id (identification), fo (fragment offset). Allowed values for TCP: ts1 (timestamp), ts2 (timestamp echo), ack (acknowledge number), res (reserved bits). Allowed values for UDP: chk (checksum)',
        metavar='PROG', required=True)
parser.add_argument('-d','--dev', 
		help='Network interface to attach the program to', required=True)
parser.add_argument('-b','--binbase', default=4, type=int, 
		help='Exponent for the number of bins (nbins is computed as 2^BINBASE)', metavar='BINBASE')
parser.add_argument('-i','--interval', default=5, type=int, 
		help='Polling interval of the bpf program', metavar='INT')
parser.add_argument('-w','--write',default='stdout', 
		help='Output of the program (default: stdout)',metavar='FILE')
parser.add_argument('--dir', help='Direction to apply the filter (default: egress)', default='egress', 
		choices=['ingress','egress'])
parser.add_argument('-p','--print', help='Print the built bpf program', action='store_true')
param = parser.parse_args()

dev=param.dev
bpfsec='ip_stats'
direction=param.dir
prog=param.type
binbase=param.binbase
output_interval=param.interval
output_file_name=param.write

ipv6_fields = {"fl", "tc", "hl", "nh", "pl"}
ipv4_fields = {"tos", "ttl", "ihl", "id", "fo"}
tcp_fields = {"ts1","ts2","ack","res"}
udp_fields = {"chk"}
if prog == "fl":
    ipfieldlength=20
elif prog == "pl" or prog == "id" or prog == "chk":
    ipfieldlength=16
elif prog == "ihl":
    ipfieldlength=4
elif prog == "fo":
    ipfieldlength=13
elif prog == "ack" or prog == "ts1" or prog == "ts2":
	ipfieldlength=32
elif prog == "res":
	ipfieldlength=4
else:
    ipfieldlength=8

# Check that the number of required bins is no larger
# than the space of field values
if binbase > ipfieldlength:
    raise InvalidParameterError("Number of bins too big!")

ipr = IPRoute()

idx = ipr.link_lookup(ifname=dev)[0]
try:
    ipr.tc("add", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 17:
        print("Skipping creation of clsact qdisc on " + dev)

# This Section to compile and load the BPF program. BCC has its own BPF class for all
# of these operations, but they use their internal compilation structure and it is not
# straightforward to use the with libbpf. Simply putting libbpf in the kernel tree creates
# a lot of name collisions.
#text = """
#int hello(struct __sk_buff *skb) {
#  return 1;
#}
#"""
#prog = BPF(text=text,debug=0)
#fn = prog.load_func("hello", BPF.SCHED_CLS)

bpfprog = """
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
"""
# Set the required number of bins in the source file
bpfprog = re.sub(r'SETBINBASE',r'#define BINBASE ' + str(binbase), bpfprog)
# Set the length of field to be monitored
bpfprog = re.sub(r'IPFIELDLENGTH',str(ipfieldlength), bpfprog)
# Set the specific code to read the required field
if prog == 'fl':
    src = """
            for(short i=0;i<3;i++) {
                ipfield |= iph6->flow_lbl[i];
                if(i==0) {
                    /* Remove DSCP value */
                    ipfield &=0x0f;
                }
                if(i!=2)
                    ipfield <<= 8;
            }
    """
elif prog == 'tc':
    src = """
            ipfield = iph6->priority;
            ipfield <<=4;
            /* Remove the byte used for the flow label */
            ipfield |= (iph6->flow_lbl[0] >> 4);
    """
elif prog == 'hl': # prog = 'hl'
    src = """
            ipfield = iph6->hop_limit;
    """
elif prog == 'nh': 
    src = """
            ipfield = iph6->nexthdr;
    """
elif prog == 'pl':
    src = """
            ipfield = bpf_ntohs(iph6->payload_len);
    """
elif prog == 'tos':
    src = """
        ipfield = iph4->tos;
    """
elif prog == 'ttl':
    src = """
        ipfield = iph4->ttl;
    """
elif prog == 'ihl':
    src = """
        ipfield = iph4->ihl;
    """
elif prog == 'id':
    src = """
        ipfield = bpf_ntohs(iph4->id);
    """
elif prog == 'fo':
    src = """
        ipfield = bpf_ntohs(iph4->frag_off) & 0x1fff;
    """
elif prog == 'ts1':
	src = """
        ipfield = tcpopts.timestamp1;
	"""
elif prog == 'ts2':
	src = """
        ipfield = tcpopts.timestamp2;
	"""
elif prog == 'ack':
	src = """
		ipfield = bpf_ntohl(tcphdr->ack_seq);
	"""
elif prog == 'res':
	src = """
		ipfield = tcphdr->res1;
	"""
elif prog == 'chk':
	src = """
	    if ( udphdr != NULL )
	    	ipfield = bpf_ntohs(udphdr->check);
	"""
else:
    raise ValueErr("Invalid field name!")


if prog in ipv6_fields:
    bpfprog = re.sub(r'UPDATE_STATISTICS_V6',src, bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_V4',"", bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_L4',"", bpfprog)
elif prog in ipv4_fields:
    bpfprog = re.sub(r'UPDATE_STATISTICS_V6',"", bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_V4',src, bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_L4',"", bpfprog)
elif prog in tcp_fields or prog in udp_fields:
    bpfprog = re.sub(r'UPDATE_STATISTICS_V6',"", bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_V4',"", bpfprog)
    bpfprog = re.sub(r'UPDATE_STATISTICS_L4',src, bpfprog)
else:
    raise ValueErr("Unmanaged field!!!")

if param.print:
    print(bpfprog)

prog = BPF(text=bpfprog, cflags=["-I/usr/include/"], debug=0)
fn = prog.load_func("ip_stats", BPF.SCHED_CLS)
if direction == "ingress":
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff2", classid=1, direct_action=True)
else:
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff3", classid=1, direct_action=True)
        
hist = prog.get_table('nw_stats_map')

try:
    prev_values = hist.items() # Read initial values, but do not print them
    prev = time.time()
    if output_file_name != "stdout":
        orig_stdout = sys.stdout
        output_file = open(output_file_name,'w')
        sys.stdout = output_file
    while True:
        time.sleep(output_interval) # Wait for next values to be available
        hist_values = hist.items()
        now = time.time()
        # -- TODO: Put the following in a function 
        num = len(hist_values)
        print("Bin value\tNo packets\tTotal\tInterval\n")
        for i in range(0,num):
            #print(len(hist_values[i])) # This is a num X 2 bi-dimensional array
            #print(type(hist_values[i])) # <class 'tuple'>
            period = now - prev
            packets = int((hist_values[i][1]).value) - int((prev_values[i][1]).value)
            print("{0:05x}".format(i),"\t\t", packets, "\t\t", (hist_values[i][1]).value, "\t[",period, "s]")
        # -- End function
        print('\n')
except KeyboardInterrupt:
    sys.stdout.close()
    pass
finally:
    try:
        sys.stdout = orig_stdout
        output_file.close()
    except NameError:
        # Do nothing
        no_op = 0


#subprocess.run("./tc_fl_user")

try:
    ipr.tc("del", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 22:
        print("Unable to remove clsact qdisc on " + dev)

