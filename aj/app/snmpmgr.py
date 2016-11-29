#!/usr/bin/env python
'''

snmpmgr.py - create SNMP managers for Agent-Jones

A SNMP manager is an SNMP client for snimpy

Author : Ch. Bueche

'''

import logging
from snimpy.manager import Manager as M


# -----------------------------------------------------------------------------------
class SNMPmgr():
	'''
	SNMP manager
	'''

	def __init__(self, logger, app, credmgr):
		'''
		construct enterprise table
		'''

		self.logger = logging.getLogger('aj.snmpmgr')
		self.logger.info('fn=SNMPmgr/init : creating an instance of snmpmgr')
		self.app = app
		self.credmgr = credmgr

	def create(self,
	           devicename='localhost',
	           timeout=None,
	           retries=None,
	           cache=None,
	           bulk=True,
	           none=True,
	           rw=False,
	           community_format='{}'):

		self.logger.debug('fn=SNMPmgr/create : %s : creating the snimpy manager' % (devicename))

		if timeout is None:
			timeout = self.app.config['SNMP_TIMEOUT']
		if retries is None:
			retries = self.app.config['SNMP_RETRIES']
		if cache is None:
			cache = self.app.config['SNMP_CACHE']

		# get credentials and connection info for this device
		credentials = self.credmgr.get_credentials(devicename)

		# if SNMP V2, read-only or read-write ?
		if rw:
			community = credentials['rw_community']
		else:
			community = credentials['ro_community']

		self.logger.debug('fn=SNMPmgr/create : %s : parameters : version=%s, timeout=%s, retries=%s, cache=%s, bulk=%s, none=%s, read-write=%s, community_format=%s' % (devicename, credentials['snmp_version'], timeout, retries, cache, bulk, none, rw, community_format))

		# the community might be adjusted using the format if it is defined.
		# mostly used for VLAN-based communities
		# Used for Cisco gear, where it is called "community string indexing"
		community = community_format.format(community)

		# and now try tro create a manager.
		try:
			m = M(host=devicename,
			      community=community,
			      version=credentials['snmp_version'],
			      secname=credentials['secname'],
			      authprotocol=credentials['authprotocol'],
			      authpassword=credentials['authpassword'],
			      privprotocol=credentials['privprotocol'],
			      privpassword=credentials['privpassword'],
			      timeout=timeout,
			      retries=retries,
			      cache=cache,
			      bulk=bulk,
			      none=none)
		except Exception, e:
			self.logger.warn('fn=SNMPmgr/create : %s : cannot create SNMP manager : <%s>' % (devicename, e))
			return None

		self.logger.debug('fn=SNMPmgr/create : %s : returning manager' % (devicename))
		return (m)
