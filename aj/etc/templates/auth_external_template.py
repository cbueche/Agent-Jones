#!/usr/bin/env python
'''

	RENAME THIS FILE TO ../auth_external.py AND ADAPT to use

auth_external.py - multiple-authentication manager for Agent-Jones

Author : Ch. Bueche

The verify_credentials function can be extremely simple (e.g. control a username/password pair against a table)
or much more complete, e.g. control access based on HTTL headers present in the request.headers.environ dict.

The example below uses a fallback of 3 possible methods.

A typical example would be a SSO layer in front of Agent-Jones. The HTTP ICAP draft proposes the header
to be X-Authenticated-User. This de facto standard has been adopted by a number of tools.

http://tools.ietf.org/html/draft-stecher-icap-subid-00#section-3.4

'''

import logging


class AuthExternal():
	'''
	external authentication
	'''

	def __init__(self, scheme=None):
		self.logger = logging.getLogger('aj.authext')
		self.logger.info('fn=AuthExternal/init : creating an instance of AuthExternal')
		self.scheme = scheme

		def default_auth_error():
			return "Unauthorized Access : external"

	def verify_credentials(self, username, password, request):
		"""
		:param username: the username
		:param password: its password
		:param request: the HTTP request object
		:return: boolean (True means login ok)
		"""

		self.logger.debug('fn=AuthExternal/verify_credentials : got username = <%s>' % username)

		# auth by user, password, and HTTP headers. Be sure they aree passwd to Flask by the WSGI layer
		remote_addr = request.headers.environ['REMOTE_ADDR']
		if remote_addr in ['127.0.0.10', '192.168.10.100']:
			self.logger.debug('authentified by remote-addr')
			return True

		# this is one possibility, one or several users
		users = {'userXX': 'passwordYY', 'user2': 'hispassword2'}
		if username in users and users[username] == password:
			self.logger.debug('authentified by user+password')
			return True

		# ICAP SSO
		sso_header = 'HTTP_X_AUTHENTICATED_USER'
		if sso_header in request.headers.environ:
			auth_user = request.headers.environ[sso_header]
			# log user, check whatever you want
			self.logger.debug('authentified by ICAP <%s>' % auth_user)
			return True

		self.logger.warning('authentification denied')
		return False