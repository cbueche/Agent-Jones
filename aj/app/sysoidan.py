#!/usr/bin/env python
'''

sysoidan.py - sysOid analysis function for Agent-Jones

Author : Ch. Bueche

'''



# -----------------------------------------------------------------------------------
class SysOidAn():

    '''
    sysOid analysis
    '''

    from snimpy import mib

    def __init__(self):
        '''
        construct ciscoProducts table
        '''
        self.ciscoProducts = {}
        for entry in self.mib.getNodes("CISCO-PRODUCTS-MIB"):
            oid = '.'.join(map(str, entry.oid))
            self.ciscoProducts[oid] = str(entry)


    def translate_sysoid(self, sysoid):
        '''
        translate sysOid to vendor and model
        this is currently only implement for Cisco, but other vendors might be added
        hence the primitive code. Will need to be implemented differently for multi-vendors

        a start would be to parse http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
        in a dict to have nice vendor mappings
        '''

        vendor = ''
        if sysoid.startswith('1.3.6.1.4.1.9'):
            vendor = 'Cisco'
        else:
            vendor = 'unknown'

        model = self.ciscoProducts.get(sysoid, 'unknown')

        return (vendor, model)