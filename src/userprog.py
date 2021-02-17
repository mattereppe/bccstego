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
		help='Output of the program (default: stdout)',metavar='FILE')
parser.add_argument('--dir', help='Direction to apply the filter (default: egress)', default='egress', 
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

if prog == "fl":
    ipv6fieldlength=20
else:
    ipv6fieldlength=8

# Check that the number of required bins is no larger
# than the space of field values
if binbase > ipv6fieldlength:
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
BPFPROG_SRC_CODE
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

