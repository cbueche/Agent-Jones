#!/usr/bin/env python
'''

access_checks.py - SNMP checks

Author : Ch. Bueche

'''

import logging

# -----------------------------------------------------------------------------------
class AccessChecks():

    '''
    SNMP access checks
    '''

    def __init__(self):
        self.logger = logging.getLogger('aj.access_checks')
        self.logger.info('creating an instance of access_checks')

    def check_snmp(self, logger, M, devicename, community, check_type):
        '''
        check if a SNMP GET and SET works
        '''

        # detect if SNMP works
        try:
            if check_type == 'RO':
                # we try a GET only
                self.logger.debug(
                    'fn=AccessChecks/SNMP-GET : %s : asking for sysName' % devicename)
                m = M(host=devicename, community=community,
                      version=2, timeout=1, retries=1)
                sysName = m.sysName
                self.logger.debug(
                    'fn=AccessChecks/SNMP-GET : %s : success, sysName=%s' % (devicename, sysName))
                return True
            else:
                # we try a GET followed by SET, using the same value. It's only to find out
                # if we can write to the config using this community
                m = M(host=devicename, community=community,
                      version=2, timeout=1, retries=1)
                self.logger.debug(
                    'fn=AccessChecks/SNMP-SET : %s : asking for sysName' % devicename)
                sysName = m.sysName
                self.logger.debug(
                    'fn=AccessChecks/SNMP-SET : %s : success, sysName=%s' % (devicename, sysName))
                self.logger.debug(
                    'fn=AccessChecks/SNMP-SET : %s : writing back sysName' % devicename)
                m.sysName = sysName
                self.logger.debug(
                    'fn=AccessChecks/SNMP-SET : %s : write success' % devicename)
                return True

        except Exception, e:
            self.logger.error(
                "fn=AccessChecks/SNMP-GET or SNMP-SET : %s : test failed : %s" % (devicename, e))
            return False
