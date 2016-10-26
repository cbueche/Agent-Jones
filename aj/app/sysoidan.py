#!/usr/bin/env python
'''

sysoidan.py - sysOid analysis function for Agent-Jones

Author : Ch. Bueche

'''

import logging

# -----------------------------------------------------------------------------------
class SysOidAn():

    '''
    sysOid analysis
    '''

    from snimpy import mib
    import json
    import re
    import os

    def __init__(self, logger, root_path):
        '''
        construct enterprise table
        '''

        self.logger = logging.getLogger('aj.sysoidan')
        self.logger.info('creating an instance of sysoidan')

        enterprise_file = self.os.path.join(
            root_path, 'etc/enterprise-numbers.json')
        self.logger.debug(
            'fn=SysOidAn/init : start loading IANA enterprise mapping file %s' % enterprise_file)
        with open(enterprise_file) as enterprise_fh:
            self.enterprises = self.json.load(enterprise_fh)
        enterprise_number = len(self.enterprises)
        self.logger.debug(
            'fn=SysOidAn/init : done loading IANA enterprise mapping file, %s enterprises found' % enterprise_number)

        '''
        construct ciscoProducts table
        '''
        self.logger.debug('fn=SysOidAn/init : start loading Cisco product MIB')
        self.ciscoProducts = {}
        counter = 0
        for entry in self.mib.getNodes("CISCO-PRODUCTS-MIB"):
            oid = '.'.join(map(str, entry.oid))
            self.ciscoProducts[oid] = str(entry)
            counter += 1
        self.logger.debug('fn=SysOidAn/init : done loading Cisco product MIB, %s products found' % counter)

    def translate_sysoid(self, sysoid):
        '''
        translate sysOid to vendor and model
        this is currently only implement for Cisco, but other vendors might be added
        '''

        self.logger.debug('fn=SysOidAn/translate_sysoid : got sysoid = %s' % sysoid)

        # match sysoid to vendor
        vendor = ''
        model = ''
        regex = self.re.compile(r'^1\.3\.6\.1\.4\.1\.(\d+)\.')
        match = regex.search(sysoid)
        if match:
            vendor_id = match.group(1)
            self.logger.debug(
                'fn=SysOidAn/translate_sysoid : vendor id = %s' % vendor_id)
            if vendor_id in self.enterprises:
                vendor = self.enterprises[vendor_id]['o']
            else:
                vendor = 'unknown vendor (%s)' % vendor_id
                self.logger.warn(
                    'fn=SysOidAn/translate_sysoid : vendor id %s not found, maybe you need to refresh the enterprise-numbers.json file' % vendor_id)
        else:
            self.logger.warn(
                'fn=SysOidAn/translate_sysoid : broken sysoid string' % sysoid)
            vendor = "unknown"

        # where we know how to do it, map sysoid to model
        if vendor == 'ciscoSystems':
            model = self.ciscoProducts.get(sysoid, 'unknown')

        self.logger.debug(
            'fn=SysOidAn/translate_sysoid : vendor = %s, model = %s' % (vendor, model))
        return(vendor, model)
