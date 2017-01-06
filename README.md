Agent-Jones
===========

Agent-Jones is a web-service used to configure and retrieve info from Cisco devices.
Mostly switches, but it could as well be used for routers. Its goal is to serve as a back-end
for nice GUIs and collectors applications. As such, it doesn't have any GUI.

The whole stuff is written in Python, using the [Flask](http://flask.pocoo.org/) micro-framework, and a very nice SNMP lib for Python called snimpy [1](http://vincent.bernat.im/en/blog/2013-snimpy.html), [2](https://github.com/vincentbernat/snimpy).


Status
------

It is deployed in a network with about 1'000 devices, WAN and LAN, routers and switches, all Cisco. It works, but I would gladly accept patches and enhancements.


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


API Documentation
-----------------

    http://0.0.0.0:5000/xdoc/


Troubleshooting
---------------

There is a log file defined in config.py. Tail it. Same way, check the Apache log files if you implemented it as a WSGI application.


Dependencies
------------

- works as a virtualenv to protect your instance from courageaous system-admins using OS-upgrade without too much knowledge.
- python 2.7 (might work for 2.6)


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
