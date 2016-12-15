#!/usr/bin/env python
'''

etc/templates/credentials_template_postgres.py - PostgreSQL credential manager for Agent-Jones
A contribution by Christian Ramseyer, netnea AG

Rename this file to credentials.py before usage.

'''

import psycopg2
import psycopg2.extras


# -----------------------------------------------------------------------------------
class Credentials():

	def get_credentials(self, devicename):
		conn = psycopg2.connect("host='mainframe.neanet.com' dbname='CLOUD' user='KarlBucher' password='XXXX'")

		cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
		sql = """    SELECT name,
	                readauthpass as ro_community,
	                snmp_version,
	                readauthuser as secname,
	                snmpauthmethod as authprotocol,
	                readauthpass as authpassword,
	                snmpprivmethod as privprotocol,
	                readprivkey as privpassword
	            from allv3_view where name = %s limit 1"""
		bind = (devicename,)
		cur.execute(sql, bind)

		rows = cur.fetchall()
		for row in rows:
			return {
				'ro_community': row['ro_community'],
				'rw_community': 'noaccess',
				'username': 'noaccess',
				'password': 'noaccess',
				'snmp_version': int(row['snmp_version']),
				'secname': row['secname'],
				'authprotocol': row['authprotocol'],
				'authpassword': row['authpassword'],
				'privprotocol': row['privprotocol'],
				'privpassword': row['privpassword']
			}
