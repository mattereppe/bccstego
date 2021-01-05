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
parser.add_argument('-t','--type', choices=['fl','tc','hl'],
        help='Type of statistics to collect: fl (flow label), tc (traffic class), hl (hop limit)',
        metavar='PROG', required=True)
parser.add_argument('-d','--dev', 
		help='Network interface to attach the program to', required=True)
parser.add_argument('-b','--binbase', default=4, type=int, 
		help='Exponent for the number of bins (nbins is computed as 2^BINBASE)', metavar='BINBASE')
parser.add_argument('-i','--interval', default=5, type=int, 
		help='Polling interval of the bpf program', metavar='INT')
parser.add_argument('-w','--write',default='stdout', 
		help='Output of the program',metavar='FILE')
parser.add_argument('--dir', help='Direction to apply the filter', default='egress', 
		choices=['ingress','egress'])
parser.add_argument('-p','--print', help='Print the built bpf program', action='store_true')
param = parser.parse_args()

dev=param.dev
bpfsec='ipv6_stats'
direction=param.dir
prog=param.type
binbase=param.binbase
output_interval=param.interval
output_file_name=param.write

print("REMINDER: insert a check on BINBASE value for the different programs!!!")
if prog == "fl":
    ipv6fieldlength=20
else:
    ipv6fieldlength=8

# Check that the number of required bins is no larger
# than the space of field values
if binbase >= ipv6fieldlength:
    raise InvalidParameterError("Number of bins too big!")

print("prog: ", prog)

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
"""
# Set the required number of bins in the source file
bpfprog = re.sub(r'SETBINBASE',r'#define BINBASE ' + str(binbase), bpfprog)
# Set the length of field to be monitored
bpfprog = re.sub(r'IPV6FIELDLENGTH',str(ipv6fieldlength), bpfprog)
# Set the specific code to read the required field
if prog == 'fl':
    src = """
            for(short i=0;i<3;i++) {
                ipv6field |= iph6->flow_lbl[i];
                if(i==0) {
                    /* Remove DSCP value */
                    ipv6field &=0x0f;
                }
                if(i!=2)
                    ipv6field <<= 8;
            }
    """
elif prog == 'tc':
    src = """
            ipv6field = iph6->priority;
            ipv6field <<=4;
            /* Remove the byte used for the flow label */
            ipv6field |= (iph6->flow_lbl[0] >> 4);
    """
else: # prog = 'hl'
    src = """
            ipv6field = iph6->hop_limit;
    """
bpfprog = re.sub(r'UPDATE_STATISTICS',src, bpfprog)

if param.print:
    print(bpfprog)

prog = BPF(text=bpfprog, cflags=["-I/usr/include/"], debug=0)
fn = prog.load_func("ipv6_stats", BPF.SCHED_CLS)
if direction == "ingress":
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff2", classid=1, direct_action=True)
else:
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff3", classid=1, direct_action=True)
        
hist = prog.get_table('ipv6_stats_map')

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

