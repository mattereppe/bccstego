# bccstego

This tool inspects IP packets and creates an histogram of seen values used for a specific header field. Version 0.1 only supported IPv6, version 0.2 added support for IPv4, and finally version 0.3 extended to L4 headers as well. According, the name of the main executable is now <code>ipstats.py</code>. The list of supported fields includes those that can be likely used for creating covert channels, and currently includes both IPv6 (flow label, traffic class, hop limit), IPv4 (type of service/differentiated service code pointer, identification, time-to-live, fragment offset, internet header length), TCP (ack, reserved bits, timestamp), and UDP (checksum). 


The histogram is made of a given number of bins, and all possible field values are equally divided into the available bins, in a consecutive way. Practically speaking, the field values grouped into the same bin share the same prefix, which is also used as the <i>key</i> in the output (the number of shared bits depends on the number of bins). 
The number of bins and the sampling interval can be both set on the command line; however, the former must be lower than the number of possible values for the specific field.
Beware that the larger is the number of bins, the higher will be internal memory usage; of course, also the delay to retrieve the whole histogram will increase. Currently, it seems that no errors are reported up to 2^20 bins (tested on Debian virtual machine with 2GB vRAM).

The tool can be used to check how the kernel generates these values, and to detect covert channels hidden in the IP headers [1][2]. A collection of tools for creating covert channels in different header fields of IPv6 can be retrieved from [3].

## Usage

The program installs an eBPF filter on the ingress/egress path of a specific network interface and collects the measurements. The output can be printed on the standard output or saved in a file.

The program is rather simple to use, and just requires a couple of mandatory parameters: the field in the IP header to be monitored and the network interface.
The in-line help provides a short summary of all main options.

```Shell
% sudo ./ipstats.py -h
usage: ipstats.py [-h] -t PROG -d DEV [-b BINBASE] [-i INT] [-w FILE] [--dir {ingress,egress}]
                  [-p]

Run bpf inspectors on IPv6 header.

optional arguments:
  -h, --help            show this help message and exit
  -t PROG, --type PROG  Type of statistics to collect. Allowed values for IPv6: fl (flow label),
                        tc (traffic class), hl (hop limit), nh (next header), pl (payload length).
                        Allowed valued for IPv4: tos (type of service), ttl (time-to-live), ihl
                        (internet header length), id (identification), fo (fragment offset).
                        Allowed values for TCP: ts1 (timestamp), ts2 (timestamp echo), ack
                        (acknowledge number), res (reserved bits). Allowed values for UDP: chk
                        (checksum)
  -d DEV, --dev DEV     Network interface to attach the program to
  -b BINBASE, --binbase BINBASE
                        Exponent for the number of bins (nbins is computed as 2^BINBASE)
  -i INT, --interval INT
                        Polling interval of the bpf program
  -w FILE, --write FILE
                        Output of the program (default: stdout)
  --dir {ingress,egress}
                        Direction to apply the filter (default: egress)
  -p, --print           Print the built bpf program

Beware to select the correct bin number!
```

## Dependencies

This software makes use of the <A href="https://github.com/iovisor/bcc">BPF Compiler Collection (BCC)</A>. On Debian, the following packages are required: <code>bpfcc-tools</code>, <code>libbpfcc</code>, <code>python3-bpfcc</code>, version >= 0.18.

## Build process

The program is a single python script which embeds all the necessary code to assemble, compile and install the BPF filter. The github repository maintains the latest version already built and ready to use.

Anyway, additional modifications might be necessary to include additional use cases or to modify the output. For instance, it should be extended to work with other protocols (ICMP) and additional fields (TCP/IP options).

The preferred way to make modifications is to edit the source templates in the <code>src/</code> directory and build a new executable through the provided Makefile.
There are two templates in the <code>src</code> directory, which make it simpler to maintain and update the source code for the user and kernel spaces.

<code>bpfprog.c</code> is the main source code for the bpf program, including all instructions for parsing the packet headers and updating the map. 
It can be modified to parse additional packet headers, or to collect different kinds of statistics. Currently, there are three placeholders which are replaced at run time by the python code with parameters read from the command line:
<ul>
<li>SETBINBASE: This is replaced by the exponent that defines the number of bins to be used for the histogram. 
<li>IPFIELDLENGTH: This is replaced by the bitlength of the field to be monitored (which must be computed by the python code).
<li>UPDATE_STATISTICS_V4/UPDATE_STATISTICS_V6/UPDATE_STATISTICS_L4: This is replaced by the code snippet that handles the specific field (be aware that some fields in the IPv6 header are not byte aligned). There are three different placeholders for IPv4, IPv6, and TCP/UDP fields, respectively. 
</ul>

<code>userprog.py</code> is the python program alone, with placeholders for the bpf code. 
It can be directly modified to include additional options, or to change the format and content of the output. 
It also includes code snippets for handling different header fields, which are merged into the main bpf program template. If you only want to add support for additional IP header fields, you should follow these steps:
<ul>
  <li> Add the codename for the new fields in the inline help (edit both _choises_ and _help_ of the _type_ argument).
  <li> Set the maxiumum field length through the <code>ipfieldlength</code> variable, if different from 8 (check the cascading if-elif definition).
  <li> Look for the cascading if-elif definition for the <code>ipfield</code> variable and add the case for the new field. You have to put the code to load the field value into the <code>ipfield</code> variable; this is usually as simple as reading data from a <code>struct iphdr/struct ipv6hdr/struct tcphdr/struct udphdr</code>.
</ul>

After changing the code, just run <code>make</code> to build the new python executable.

## Examples

Run the script on egress packets from <code>eth1</code> interface and monitor the values of the <code>Traffic Class</code> field with 16 bins (2^4):

```Shell
% sudo ./iphstats.py -d eth1 -b 4 -t tc 
[...]
Bin value	No packets	Total	Interval

00000 		 1 		 1 	[ 55.065359354019165 s]
00001 		 54 		 54 	[ 55.065359354019165 s]
00002 		 0 		 0 	[ 55.065359354019165 s]
00003 		 0 		 0 	[ 55.065359354019165 s]
00004 		 0 		 0 	[ 55.065359354019165 s]
00005 		 0 		 0 	[ 55.065359354019165 s]
00006 		 0 		 0 	[ 55.065359354019165 s]
00007 		 0 		 0 	[ 55.065359354019165 s]
00008 		 0 		 0 	[ 55.065359354019165 s]
00009 		 0 		 0 	[ 55.065359354019165 s]
0000a 		 0 		 0 	[ 55.065359354019165 s]
0000b 		 0 		 0 	[ 55.065359354019165 s]
0000c 		 0 		 0 	[ 55.065359354019165 s]
0000d 		 0 		 0 	[ 55.065359354019165 s]
0000e 		 0 		 0 	[ 55.065359354019165 s]
0000f 		 0 		 0 	[ 55.065359354019165 s]

[...]
```
The output was taken when generating ICMP traffic:

```Shell
$ ping6 -Q 0x13 fe80::f816:3eff:fe36:da7d
```
[Note that the filter monitors any traffic, not only the one generated by the test program.]

Run the script on ingress packets on <code>eth1>/code>, monitor the values of the <code>Flow Label</code>, use 2^8 bins, and save the histogram to <code>hist.cvs</code>:
  
 
```Shell
% sudo ./ip6hstats.py -d eth1 -b 8 -t fl --dir ingress -w hist.csv
```
And the content of the <code>hist.csv</code> looks like the following (snippet):

```Shell
$ % cat hist.csv 
[...]
Bin value	No packets	Total	Interval

00000 		 2 		 2 	[ 50.10093283653259 s]
00001 		 0 		 0 	[ 50.10093283653259 s]
00002 		 0 		 0 	[ 50.10093283653259 s]
00003 		 0 		 0 	[ 50.10093283653259 s]
00004 		 0 		 0 	[ 50.10093283653259 s]
00005 		 0 		 0 	[ 50.10093283653259 s]
00006 		 0 		 0 	[ 50.10093283653259 s]
00007 		 0 		 0 	[ 50.10093283653259 s]
00008 		 0 		 0 	[ 50.10093283653259 s]
00009 		 0 		 0 	[ 50.10093283653259 s]
0000a 		 0 		 0 	[ 50.10093283653259 s]
0000b 		 0 		 0 	[ 50.10093283653259 s]
0000c 		 0 		 0 	[ 50.10093283653259 s]
0000d 		 49 		 49 	[ 50.10093283653259 s]
0000e 		 0 		 0 	[ 50.10093283653259 s]
0000f 		 0 		 0 	[ 50.10093283653259 s]
[...]
000fb 		 0 		 0 	[ 50.10093283653259 s]
000fc 		 0 		 0 	[ 50.10093283653259 s]
000fd 		 0 		 0 	[ 50.10093283653259 s]
000fe 		 0 		 0 	[ 50.10093283653259 s]
000ff 		 0 		 0 	[ 50.10093283653259 s]
```

The output was taken when generating ICMP traffic:

```Shell
$  ping6 fe80::f816:3eff:fe36:da7d
```
[In this case, the content of the <code>Flow Label</code> field is automatically generated by the kernel.]

  
## Limitations and known bugs
  
The current implementation only inspects a single field, to simplify the automatic derivation of the bpf code. If you want to monitor multiple fields, many instances of the tool must be run (mind that this is still largely untested). 
  
Extending the software to cover additional protocols (e.g., ICMP) requires modification of the bpf code. An additional function to parse the protocol header must be defined, together with the proper switch cases in the main function (<code>nw_stats</code>).
 
Extending the software to cover option fields requires modification of the bpf code too. Parsing of IP options has not been implemented so far because dealing with variable fields is not trivial with eBPF, and it is likely that the resulting code exceeds the current limitations of the verifier.
  
With kernel versions > 5.10, there are at least 3 warnings about redefinition of macros (at least with BCC libraries <= 0.18). This does not affect the compilation and verification of the bpf code.
  
 
## References

[1] L. Caviglione, W. Mazurczyk, M. Repetto, A. Schaffhauser, M. Zuppelli. Kernel-level Tracing for Detecting Stegomalware and Covert Channels in Linux Environments, <i>Computer Networks</i>, Volume 191, May 2021. DOI: <A href="https://doi.org/10.1016/j.comnet.2021.108010">10.1016/j.comnet.2021.108010</A>.

[2] L. Caviglione, M. Zuppelli, W. Mazurczyk, A. Shaffhauser, M. Repetto. Code Augmentation for Detecting Covert Channels Targeting the IPv6 Flow Label. 3rd International Workshop on Cyber-Security Threats, Trust and Privacy Management in Software-defined and Virtualized Infrastructures (SecSoft), July 2nd, 2021, Tokyo, Japan. <i>To appear</i>.

[3] The IPv6CC suite. Soon available...

## Acknowledgements

This work has received funding from the European Commission under Grant Agreement no. 786922 (<A href="https://www.astrid-project.eu/">ASTRID</A>), Grant Agreement no. 833456 (<A href="https://guard-project.eu/">GUARD</A>) and Grant Agreement no. 833042 (<A href="https://simargl.eu/">SIMARGL</A>).
