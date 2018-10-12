FAQ - Frequently Asked Questions
================================


## MIB issues

Why not use the system  MIBs ?

- Because I found some broken MIBs on some distros. I prefer to use a bit more disk space, and have a consistent and tested set of MIBs instead of spending time telling Cisco how messy they are.

## Why is SMIPATH defined in the code ?

- This is not strictly necessary, but I have found that on some platform (notably Ubuntu), SMI has built-in default compiled SMIPATH, making it to go to its own PATH to find and load MIBs. It then produce all sorts of strange problems like segfaults and SMI lint errors.
- Renaming /etc/smi.conf to /etc/smi.conf_orig might provide a hint or even fix issues.

## Errors and Warnings

I'm getting ERROR or WARNING fn=InterfaceAPI/get : devicename : SNMP get failed : long() argument must be a string or a number, not 'NoneType'

Be sure to install the latest version of Agent-Jones. I have added some sanity code to cover Cisco creativity in dot1dBasePortIfIndex.

I'm getting "EntryPoint object has no attribute resolve". Update setuptools.

## StopIteration exception

- PEP 479 seems to break ProxyIter/iteritems() in snimpy/manager.py.
- [This patch](https://github.com/vincentbernat/snimpy/issues/83#issue-368722597) might be needed.

## Errors with MAC addresses

I'm getting a lot of unknown vendors when using showmac=1

You may want to update the netaddr pip module using

    pip install --upgrade netaddr

However, I have found some gear vendors using MAC prefixes out of nowhere, unknown from the official IEEE/OUI database. I'm not sure if those vendors shall be blamed or if I misunderstood the OUI standard.

## macs or showmac give timeouts with vlan-based community SNMP-get.

I'm not yet sure about this case, it looks like it's an IOS bug for stacked switches, or very slow and big Cisco stacks. I have added a distinct timeout for those operations.

## duplicated macs on switch ports

Caused by Avaya phones. See the Release notes and install the latest version, it shows the VLAN for which each MAC is seen.

## why no support for SNMP contexts

Because the underlying snimpy library does not support them.

## you get `prettyOut` from a SNMP-get on sysObjectID or another similar get returning an OID

[This patch](https://github.com/vincentbernat/snimpy/commit/d3a36082d417bb451e469f33938e1d0821b615ea) might be needed depending on your combination of snimpy and PySNMP versions.
