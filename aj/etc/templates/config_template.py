# config.py
#
# config file for aj.py
#
# rename to config.py to use
#

import os

# default values
class Config(object):
    DEBUG = False
    TRACE = False
    ENVI = 'base'

    LOGFILE = '/var/log/aj/aj.log'
    ACTIONLOGFILE = '/var/log/aj/actions.log'

    # if True, PUT and POST requests will need to contain a uuid parameter
    MANDATE_UUID = True

    # how we do log. This would be a rotation of 10 files of 1 Mb in size
    LOG_MAX_SIZE = 100000000
    LOG_BACKUP_COUNT = 10

    # how long we should wait for a device config-save operation
    DEVICE_SAVE_TIMEOUT = 20

    # global SNMP timeout and retry
    SNMP_TIMEOUT = 2
    SNMP_RETRIES = 2

    # timeout for VLAN-based SNMP get (used eg in getMAC())
    SNMP_TIMEOUT_LONG = 30
    SNMP_RETRIES_NONE = 0

    # SNMP cache for snimpy [seconds]
    SNMP_CACHE = 20
    # SNMP_CACHE = False

    # IP we listen to. 0.0.0.0 will listen to all interfaces
    BIND_IP = '192.168.7.6'
    BIND_PORT = 80

    # how do we use ping on this platform
    sysname = os.uname()[0]
    if sysname == 'Linux':    # ok for at least Ubuntu and CentOS
        PING_COMMAND = ["ping", "-n", "-w", "5", "-c", "5", "-i", "0.3"]

    elif sysname == 'Darwin':   # ok for at least OS X 10.10
        PING_COMMAND = ["ping", "-n", "-t", "5", "-c", "5", "-i", "0.3"]

    else:
        # some sane feedback
        logger.warn('Config : unknown system <%s>, using stock ping command' % sysname)
        PING_COMMAND = ["ping", "-c", "5", "-i", "0.3"]

# values for prod
class ProductionConfig(Config):
    ENVI = 'production'


# values for int
class IntegrationConfig(Config):
    ENVI = 'integration'


# values for devel
class DevelopmentConfig(Config):
    DEBUG = True
    TRACE = False
    ENVI = 'development'
    BIND_PORT = 5000

