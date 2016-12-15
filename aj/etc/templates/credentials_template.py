#!/usr/bin/env python
'''

credentials.py - credential manager for Agent-Jones
Author : Ch. Bueche

Rename this file to credentials.py before usage.

'''


# -----------------------------------------------------------------------------------
class Credentials():
	'''
	A wrapper to get device credentials

	This is a callback that Agent-Jones uses to get credentials for a device.
	You will need to adapt this to return your communities and login, or with a more
	elaborate code, eg getting them from a CDMB.

	The function gets the devicename as parameter, and must return a dict containing
	the SNMP communities, user and password. Alternatively, the SNMPv3 credentials.
	'''

	def get_credentials(self, devicename):

		if devicename == 'switch-snmp2':
			return {
				'ro_community': 'public',
				'rw_community': 'private',
				'username': 'switch_user',
				'password': 'switch_password',
				'snmp_version': 2,
				'secname': None,
				'authprotocol': None,
				'authpassword': None,
				'privprotocol': None,
				'privpassword': None
			}

		if devicename in ['router-snmp3', '192.168.22.60']:
			return {
				'ro_community': None,
				'rw_community': '',
				'username': 'FIXME',
				'password': '',
				'snmp_version': 3,
				'secname': 'MYUSER',
				'authprotocol': 'MD5',
				'authpassword': 'MYPASS456',
				'privprotocol': 'AES',
				'privpassword': 'MYKEY678'
			}
