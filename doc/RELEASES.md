Release notes
=============


21.3.3014
---------

- added log rotation

add these entries into your app/etc/config.py :

    # how we do log. This would be a rotation of 10 files of 1 Mb in size
    LOG_MAX_SIZE = 1000000
    LOG_BACKUP_COUNT = 10


- configuration of device config-save timeout

add these entries into your app/etc/config.py :

    # how long we should wait for a device config-save operation
    DEVICE_SAVE_TIMEOUT = 20