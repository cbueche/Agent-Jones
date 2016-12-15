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
		"""Create a new SNMP manager.

			:param devicename: The hostname or IP address of the agent to
				connect to. Optionally, the port can be specified
				separated with a double colon.
			:type host: str
			:param timeout: Use the specified value in seconds as timeout.
			:type timeout: int
			:param retries: How many times the request should be retried?
			:type retries: int
			:param cache: Should caching be enabled? This can be either a
				boolean or an integer to specify the cache timeout in
				seconds. If `True`, the default timeout is 5 seconds.
			:type cache: bool or int
			:param bulk: Max-repetition to use to speed up MIB walking
				with `GETBULK`. Set to `0` to disable.
			:type bulk: int
			:param none: Should `None` be returned when the agent does not
				know the requested OID? If `True`, `None` will be returned
				when requesting an inexisting scalar or column.
			:type none: bool
			:param rw: if True, use the SNMPv2 write community instead of the
				read-only community.
			:type rw : bool
			:param community_format : string to use to format the community string
				used mainly for Cisco VLAN-based communities.
			:type host: str
			"""
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

		self.logger.debug(
			'fn=SNMPmgr/create : %s : parameters : version=%s, timeout=%s, retries=%s, cache=%s, bulk=%s, none=%s, read-write=%s, community_format=%s' % (
				devicename, credentials['snmp_version'], timeout, retries, cache, bulk, none, rw, community_format))

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
