#!/usr/bin/env python
'''

entity_vendortype.py - entPhysicalVendorType decoding function for Agent-Jones

	maps entPhysicalVendorType --> item human name
    currently only for Cisco

Author : Ch. Bueche

'''

import logging


# -----------------------------------------------------------------------------------
class EntityVendorType():
	from snimpy import mib
	#import json
	import re
	#import os

	def __init__(self, logger):

		'''
		construct entity_vendortype table.
		'''

		self.logger = logging.getLogger('aj.en_vendortype')
		self.logger.info('creating an instance of entity_vendortype')

		self.logger.debug('fn=EntityVendorType/init : start loading CISCO-ENTITY-VENDORTYPE-OID-MIB')
		self.entityproduct = {}
		counter = 0
		for entry in self.mib.getNodes("CISCO-ENTITY-VENDORTYPE-OID-MIB"):
			oid = '.'.join(map(str, entry.oid))
			self.entityproduct[oid] = str(entry)
			#logger.trace('fn=EntityVendorType/init : oid = <%s>, entry = <%s>' % (oid, str(entry)))
			counter += 1
		self.logger.debug('fn=SysOidAn/init : done loading CISCO-ENTITY-VENDORTYPE-OID-MIB, %s entities types found' % counter)

	def translate_oid(self, oid):

		'''
		translate entPhysicalVendorType to entityproduct
		this is currently only implement for Cisco, but other vendors might be added
		'''

		self.logger.debug('fn=EntityVendorType/translate_oid : got oid = %s' % oid)

		regex = self.re.compile(r'^1\.3\.6\.1\.4\.1\.9\.12\.3\.1')
		match = regex.search(oid)
		if match:
			self.logger.trace('fn=EntityVendorType/translate_oid : vendor is probably Cisco')
		else:
			self.logger.info('fn=EntityVendorType/translate_oid : unknown vendor/oid' % oid)

		# either we find a mapping or we fallback to the oid
		model = self.entityproduct.get(oid, oid)

		self.logger.debug('fn=EntityVendorType/translate_oid : model = %s' % (model))
		return model
