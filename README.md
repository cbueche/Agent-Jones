Agent-Jones
===========

Agent-Jones is a web-service used to configure and retrieve info from Cisco devices.
Mostly switches, but it could as well be used for routers. Its goal is to serve as a back-end
for nice GUIs and collectors applications. As such, it doesn't have any GUI.

The whole stuff is written in Python, using the [Flask](http://flask.pocoo.org/) micro-framework, and a very nice SNMP lib for Python called snimpy [1](http://vincent.bernat.im/en/blog/2013-snimpy.html), [2](https://github.com/vincentbernat/snimpy).


Status
------

- Version `11.3.2020` with Python 3.x should be considered as beta, because I could not try every case. Especially the "write-functions" haven't been tested. Get in touch if you see an issue. This version is not deployed anywhere, because the intended use (cbQoS polling on Cisco 3850) is not working (a Cisco limitation).
- Version `22.5.2017` with Python 2.x is considered stable, and deployed on at least 3 major networks with 1'000+ devices, WAN and LAN, routers and switches, all Cisco.

Features
--------

- Get info from a single device.
- Save the running-config to startup-config.
- Assign an interface to a VLAN.
- Get the vlan list from a device (currently only native vlans).
- Get the voice-vlan for an interface.
- GET interfaces from a device. Option to list the MAC addresses of devices connected to each port.
- Configure an interface : adminStatus and ifAlias (called description in Cisco language).
- List the connected MAC addresses : MAC (ethernet) to interface mappings from a device.
- CDP information for each interface.
- DHCP snooping information for each interface.
- Trunk status for each interface.
- Get the interface counters of one interface.
- Get the ARP table (MAC to IP).
- SNMP get or walk on a OID
- CBQoS (Class-Based Quality of Service) information for each interface.
- command-line CBQoS parser script. 
- Run commands over SSH


Screenshots
-----------

Everyone wants screenshots. Here are some for "device info" and "interface list", when tested from [Postman](http://www.getpostman.com/).
	![device info](doc/aj_device.png?raw=true).
	![interface list](doc/aj_interfaces.png?raw=true).


Limitations
-----------

- not tested on non-Cisco devices. It could work because I used mostly "standard" MIBs (whatever "standard" means in this context).


Assumptions
-----------

The following IOS commands might be present on modeled devices to allow for long-term indices persistence, but their presence is not mandatory. They are anyway a good starting point for your Cisco configuration templates.

    snmp-server ifindex persist
    snmp mib persist cbqos


Release Notes
-------------

See the [release notes](doc/RELEASES.md).


Installation
------------

Read the [installation guide](doc/INSTALL.md).


Usage
-----

Using the web-service is as easy as any such web-service. This is an example with curl, adapt to your own language.

    curl -u user:password http://0.0.0.0:5000/aj/api/v1/device/switch1.domain.com

Using ssh commands is a bit more complicated. You have to provide 3 parameters to a PUT request:

- CmdList : ["terminal length 0", "show users", "show version”]
- uuid as usual
- driver : ios

A corresponding curl command would be something like:

    curl -X PUT -H Authorization:Basic FIXME -H Content-Type:multipart/form-data; -F CmdList={["terminal length 0", "show users", "show version"]} -F uuid=345abc -F driver=ios http://0.0.0.0:5000/aj/api/v1/device/ssh/switch1.domain.com

If you expect any long output, you need to pass “terminal length 0” as first command. In fact, I would recommend to always pass it.

[See more examples](doc/examples.md).


command-line CBQoS parser script
--------------------------------

This script is a utility tool, not directly used within Agent-Jones. It is here to debug / visualize Cisco CBQoS configuration (if you have looked at the CISCO-CLASS-BASED-QOS-MIB, you know what I mean). See `util/qos_parser.py`. You need a virtualenv with `pysnmp` installed to run it, tested with Python 3.7 and 3.8.

Cookbook:

```
python3 -m venv utilvenv
source utilvenv/bin/activate
pip install pysnmp
python3 ./qos_parser.py -c community -d device -p 161 -j /tmp/output.json [-D]
```

The JSON output file is similar to what Agent-Jones provides with the `/qos/` API endpoint.


API Documentation
-----------------

    http://0.0.0.0:5000/xdoc/


Troubleshooting
---------------

There is a log file defined in config.py. Tail it. Same way, check the Apache log files if you implemented it as a WSGI application.


Dependencies
------------

- works as a virtualenv to protect your instance from courageaous system-admins using OS-upgrade without too much knowledge.
- python 3.7 or 3.8 (might work for older 3.x versions if you get the dependencies installed)

Todo
----

- See [ToDO](doc/TODO.md)


Extension / development
-----------------------

be sure to understand Flask-restful and snimpy, then the code should be easy to extend.


License
-------

GPL V2.


Author
------

- [Charles Bueche](http://www.netnea.com/cms/netnea-the-team/charles-bueche/) wrote the initial version.


Support
-------

Start by [reading the FAQ](doc/FAQ.md).

For easy questions, [feel free to email me](http://address-protector.com/frTvcQ8oOaRDkfAzpUdS3oXFYt7cPQ8kLrI4lg2n4TblNc83DGf4yhBUfdrndqvn). For more, I will be very happy to provide commercial support.


Credits
-------

- [SPIE ICS AG, Bern](http://www.spie-ics.ch)
- [Vincent Bernat](http://vincent.bernat.im/en/)
- [Christian Ramseyer](http://www.netnea.com/cms/netnea-the-team/christian-ramseyer/)
