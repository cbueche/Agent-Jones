Release notes
=============


15.1.2016
---------

- add DHCP snoop collection on each port with /aj/api/v1/interfaces/device.name?showdhcp=1


5.5.2015
--------

- fix a bug, when calling interfaces() and specifying the show flags as xxx=0, the flags are now correctly interpreted as False.


28.7.2014
---------

- support full IANA enterprise file for sysObjectID to vendor mapping.


7.7.2014
--------

- provide CDP information on each port with url:/aj/api/v1/interfaces/device.name?showcdp=1 or url:/aj/api/v1/cdp/device.name


18.6.2014
---------

- if asking POE info from a switch without POE, return 0/null values instead of "End of MIB was reached".
- interfaces call now shows the Voice VLAN-id (and name if asked so with showvlannames=1)


17.6.2014
---------

- add vlan of MAC entries, so duplicates MACs for ports are identifiable. Case happens (at least) with Avaya phones when connected to a dual-VLAN (data & voice) access port.


28.4.2014
---------

- avoid issue with unexistant ports returned by dot1dBasePortIfIndex. It was producing exceptions when using showmac=1 on Cisco C2960S and possibly other models as well.


24.3.2014
---------

- SNMP timeout and retries are not configurable in config.py (see how in config_template.py)



21.3.3014
---------

- added log rotation. Add these entries into your app/etc/config.py :

Code:

    # how we do log. This would be a rotation of 10 files of 1 Mb in size
    LOG_MAX_SIZE = 1000000
    LOG_BACKUP_COUNT = 10

- configuration of device config-save timeout. Add these entries into your app/etc/config.py :

Code:

    # how long we should wait for a device config-save operation
    DEVICE_SAVE_TIMEOUT = 20

- added duplex-mode to interface list

- added POE collection in device and interface APIs

Be sure to install the Crypto and exscript according to the INSTALL guide.
