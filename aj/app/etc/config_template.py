# config.py
#
# config file for aj.py
#
# rename to config.py to use
#


# default values
class Config(object):
    DEBUG = False
    ENVI = 'base'

    # those are used to protect the web-service with Basic-Auth, passed by Apache
    BASIC_AUTH_USER = 'user'
    BASIC_AUTH_PASSWORD = 'password'

    LOGFILE = '/var/log/aj/aj.log'


# values for prod
class ProductionConfig(Config):
    ENVI = 'production'


# values for int
class IntegrationConfig(Config):
    ENVI = 'integration'


# values for devel
class DevelopmentConfig(Config):
    DEBUG = True
    ENVI = 'development'

