Release notes
=============


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

- configuration of device config-save timeout. Sdd these entries into your app/etc/config.py :

Code:

    # how long we should wait for a device config-save operation
    DEVICE_SAVE_TIMEOUT = 20

- added duplex-mode to interface list

- added POE collection in device and interface APIs

Be sure to install the Crypto and exscript according to the INSTALL guide.
