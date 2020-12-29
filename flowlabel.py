#!/usr/bin/python
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

# TODO: include parameters from the command line
dev="eth2"
#bpfprog="tc_fl_kern.c"
bpfprog="test.c"
bpfsec="tc_flowlabel_stats"
direction="in" # "in" or "out"

print("Hello world!")

ipr = IPRoute()

idx = ipr.link_lookup(ifname=dev)[0]
try:
    ipr.tc("add", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 17:
        print("Skipping creation of clsact qdisc on " + dev)

text = """
int hello(struct __sk_buff *skb) {
  return 1;
}
"""

prog = BPF(src_file=bpfprog, cflags=["-I/usr/include/x86_64-linux-gnu/"], debug=0)
#prog = BPF(text=text,debug=0)

#fn = b.load_func("tc_flowlabel_stats", BPF.SCHED_CLS)


try:
    ipr.tc("del", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 22:
        print("Unable to remove clsact qdisc on " + dev)

