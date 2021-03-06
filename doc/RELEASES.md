Release notes
=============


10.10.2018
----------

- ported to Python 3.7.
- add Cisco CBQoS parsing.
- add `util/qos_parser.py`.
- upgrade `CISCO-ENTITY-VENDORTYPE-OID-MIB.my`.


22.5.2017
---------

- Fix an issue in `interfaces/get` API call : some NetModules 3G routers (notably NB1600) have empty IF-MIB::ifName and Entity tables. Adds some belts and holders to the interface entity-matching loop to detect future inconsistencies.

10.5.2017
--------

- Fix an issue in the `interfaces/get` API call : some Cisco switches (notably WS-C3750X-12S-E under IOS 15.0(2)SE6 fc2) show phantom entries in dot3StatsDuplexStatus. They are now ignored.
- Fix an issue in the `interfaces/get` API call : some Cisco switches (notably WS-C3750X-12S under IOS 15.0(2)SE7 fc1) show incomplete EntityMIB on interfaces types `cevPortGigBaseSX`. This can be reproduced by polling `entPhysicalContainedIn`, the resulting value is `0`, meaning "not contained in any other physical entity". In these cases, Agent-Jones returns the MIB value of `0`. This is not perfect, but Agent-Jones cannot fix Cisco IOS.
- Detect non-existent devices when creating the SNMP manager.
- streamline the logging.


6.1.2017
--------

- re-organized using a standard application layout
- add a PostgreSQL credential example

7.12.2016
----------

- better detection and logging of unsupported Entity MIB
- SNMPv1 support
- SNMPv3 support (without SNMP contexts)
- fix SNMP-GET and WALK call
- added  logaction() to each API call (one line per action distinct log file)
- added `clientinfo` parameter to a few commands to identify the upstream user
- added modular authentication. You must create etc/auth_external.py (use the provided template)

25.11.2016
----------

- better logging for ssh commands

23.11.2016
----------

- fix empty vendorType for Cisco 3850

21.11.2016
----------

- add vendorType to the interface table. Details for the value in CISCO-ENTITY-VENDORTYPE-OID-MIB

14.11.2016
----------

- add ifName to the interface API call to match the physical entity interfaces under IOS-XE

9.11.2016
---------

- update enterprise-numbers.json
- replace deprecated flask.ext.restful by flask_restful
- replace deprecated flask.ext.httpauth by flask_httpauth
- enhance MIB-load logged information during start
- replace SNMP get by SNMP bulk-get
- move several debug statements to the newly added TRACE level. You need to add `TRACE = False` in the top-level of the config.py's Config class. See the example in `etc/templates/config_template.py`.

11.5.2016
---------

- entity-index matching between device (chassis) and interfaces. You need to match device.physicalIndex and interface[index].physicalIndex
- device info provides the entity class and more (chassis, psu, module, stack) types of entities. You might want to filter on the desired class, e.g. to get almost the same results as the previous version, extract the entities where physicalClass = "chassis".


15.4.2016
---------

- add trunk collection with /aj/api/v1/trunk/device.name
- get the same info attached to each interface with /aj/api/v1/interfaces/device.name?showtrunks=1
- configurable port_binding for Flask


13.4.2016
---------

- add ARP collection with /aj/api/v1/arp/device.name
- fix get_serial for devices without Entity-MIB support


6.4.2016
---------

- add DHCP snoop collection on each port with /aj/api/v1/interfaces/device.name?showdhcp=1
- fix ssh credential request
- be tolerant with Cisco POE pretending to be present but being in fact absent
- updated CISCO-PRODUCTS-MIB
- enhanced logging
- enhance serial-# detection for old IOS versions and stacks


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
