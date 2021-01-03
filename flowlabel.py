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

# Parse parameters from the command line
parser = argparse.ArgumentParser(description='Run bpf inspectors on IPv6 header.',
		epilog='Only the flow label field is support so far.')
parser.add_argument('-p','--program', type=pathlib.Path,
		help='Name of the bpf program to use',metavar='PROG', required=True)
parser.add_argument('-d','--dev', 
		help='Network interface to attach the program to', required=True)
parser.add_argument('-i','--interval', default=5, type=int, 
		help='Polling interval of the bpf program', metavar='INT')
parser.add_argument('-w','--write',default='stdio', type=pathlib.Path,
		help='Output of the program',metavar='FILE')
parser.add_argument('-s','--section', default="ProgSec",
		help='Section of the program to load',metavar='SEC')
parser.add_argument('--dir', help='Direction to apply the filter', default='egress', 
		choices=['ingress','egress'])
param = parser.parse_args()

dev=param.dev
bpfprog=str(param.program)
#bpfprog='tc_kern.c'
bpfsec=param.section
direction=param.dir
output_interval=param.interval
output_file=param.write

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

try:
    prev_values = hist.items() # Read initial values, but do not print them
    prev = time.time()
    while True:
        time.sleep(output_interval) # Wait for next values to be available
        hist_values = hist.items()
        now = time.time()
        # -- TODO: Put the following in a function 
        num = len(hist_values)
        print("Flow label\tNo packets\tTotal\tInterval\n")
        for i in range(0,num):
            #print(len(hist_values[i])) # This is a num X 2 bi-dimensional array
            #print(type(hist_values[i])) # <class 'tuple'>
            period = now - prev
            packets = int((hist_values[i][1]).value) - int((prev_values[i][1]).value)
            print("{0:05x}".format(i),"\t\t", packets, "\t\t", (hist_values[i][1]).value, "\t[",period, "s]")
        # -- End function
        print
except KeyboardInterrupt:
    sys.stdout.close()
    pass

#subprocess.run("./tc_fl_user")

try:
    ipr.tc("del", "clsact", idx, "ffff:")
except NetlinkError as err:
    if err.code == 22:
        print("Unable to remove clsact qdisc on " + dev)

