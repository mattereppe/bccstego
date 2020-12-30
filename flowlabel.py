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
import subprocess

# TODO: include parameters from the command line
dev="eth2"
bpfprog="tc_fl_kern.c"
bpfsec="tc_flowlabel_stats"
direction="egress" # "ingress" or "egress"

print("Hello world!")

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

prog = BPF(src_file=bpfprog, cflags=["-I/usr/include/"], debug=0)
fn = prog.load_func("flow_label_stats", BPF.SCHED_CLS)
if direction == "ingress":
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff2", classid=1, direct_action=True)
else:
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, 
            parent="ffff:fff3", classid=1, direct_action=True)
        
#try:
#    subprocess.run(["make", bpfprog], check=True);
#except subprocess.CalledProcessError:
#    print("Unable to compile bpf program!")
#else:
#    print("Compilation successfull!")
#
#try:
#    subprocess.run(["tc","filter","add","dev",dev,direction,"bpf","da","obj",bpfprog,"sec",bpfsec],check=True)
#except subprocess.CalledProcessError:
#    print("Unable to load/attach bpf program!")
#else:
#    print("Bpf program successfully loaded!")
#
#

hist = prog.get_table('fl_stats')




#subprocess.run("./tc_fl_user")

try:
    ipr.tc("del", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 22:
        print("Unable to remove clsact qdisc on " + dev)

