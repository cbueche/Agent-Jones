#!/usr/bin/env python
'''

access_checks.py - SNMP checks

Author : Ch. Bueche

'''



# -----------------------------------------------------------------------------------
class AccessChecks():

    '''
    SNMP access checks
    '''

    def check_snmp(self, logger, M, devicename, community, check_type):
        '''
        check if a SNMP GET and SET works
        '''

        # detect if SNMP works
        try:
            if check_type == 'RO':
                # we try a GET only
                logger.debug('fn=AccessChecks/SNMP-GET : asking for sysName')
                m = M(host = devicename, community = community, version = 2, timeout=1, retries=1)
                sysName = m.sysName
                logger.debug('fn=AccessChecks/SNMP-GET : success, sysName=%s' % sysName)
                return True
            else:
                # we try a GET followed by SET, using the same value. It's only to find out
                # if we can write to the config using this community
                m = M(host = devicename, community = community, version = 2, timeout=1, retries=1)
                logger.debug('fn=AccessChecks/SNMP-SET : asking for sysName')
                sysName = m.sysName
                logger.debug('fn=AccessChecks/SNMP-SET : success, sysName=%s' % sysName)
                logger.debug('fn=AccessChecks/SNMP-SET : writing back sysName')
                m.sysName = sysName
                logger.debug('fn=AccessChecks/SNMP-SET : write success')
                return True

        except Exception, e:
            logger.error("fn=AccessChecks/SNMP-SET : test failed : %s" % e)
            return False

