# bpfstego

This tool inspects IPv6 packets and creates an histogram of values used in selectable header fields (currently supported fields: flow label, traffic class, hop limit). The histogram is made of a given number of bins, and all possible field values are equally divided into the available bins, in a consecutive way. Practically speaking, the field values grouped into the same bin share the same prefix, which is also used as the <i>key</i> in the output (the number of shared bits depends on the number of bins). 
The number of bins and the sampling interval can be both set on the command line; however, the former must be lower than the number of possible values for the specific field.
Beware that the larger is the number of bins, the higher will be internal memory usage; of course, also the delay to retrieve the whole histogram will increase. Currently, it seems that no errors are reported up to 2^18 bins.

The tool can be used to check how the kernel generates these values, and to detect covert channels hidden in the IPv6 header [1]. A collection of tools for creating covert channels in different header fields of IPv6 can be retrieved from [2].

## Usage

The program installs an eBPF filter on the ingress/egress path of a specific network interface and collects the measurements. The output can be printed on the standard output or saved in a file.

The program is rather simple to use, and just requires a couple of mandatory parameters: the field in the IPv6 header to be monitored and the network interface.
The in-line help provides a short summary of all main options.

```Shell
% ./ip6hstats.py -h
usage: ip6hstats.py [-h] -t PROG -d DEV [-b BINBASE] [-i INT] [-w FILE] [--dir {ingress,egress}] [-p]

Run bpf inspectors on IPv6 header.

optional arguments:
  -h, --help            show this help message and exit
  -t PROG, --type PROG  Type of statistics to collect: fl (flow label), tc (traffic class), hl (hop limit)
  -d DEV, --dev DEV     Network interface to attach the program to
  -b BINBASE, --binbase BINBASE
                        Exponent for the number of bins (nbins is computed as 2^BINBASE)
  -i INT, --interval INT
                        Polling interval of the bpf program
  -w FILE, --write FILE
                        Output of the program
  --dir {ingress,egress}
                        Direction to apply the filter
  -p, --print           Print the built bpf program

Beware to select the correct bin number!
```

## Build process

The program is a single python script which embeds all the necessary code to assemble, compile and install the BPF filter. Anyway, additional modifications might be necessary to include additional use cases or to modify the output. For instance, it should be extended to work with other protocols: IPv6, TCP, UDP.
The preferred way to make modifications is to edit the source templates in the <code>src/</code> directory and build a new executable through the provided Makefile.

There are two templates in the <code>src</code> directory, which make it simpler to maintain and update the source code for the user and kernel spaces.
<code>userprog.py</code> is the python program alone, with placeholders for the bpf code. 
It can be directly modified to include additional options, or to change the format and content of the output. 
It also includes code snippets for handling different header fields, which are merged into the main bpf program template.
<code>bpfprog.c</code> is the main source code for the bpf program, including all instructions for parsing the packet headers and updating the map. 
It can be modified to parse additional packet headers, or to collect different kinds of statistics. Currently, there are three placeholders which are replaced at run time by the python code with parameters read from the command line:
<ul>
<li>SETBINBASE: This is replaced by the exponent that defines the number of bins to be used for the histogram. 
<li>IPV6FIELDLENGTH: This is replaced by the bitlength of the field to be monitored (which must be computed by the python code).
<li>UPDATE_STATISTICS: This is replaced by the code snippet that handles the specific field (some fields in the IPv6 header are not byte aligned).
</ul>

## Examples



## References

[1] 

## Acknoledgements
