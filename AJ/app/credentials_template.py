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
    the SNMP communities, user and password.
    '''

    def get_credentials(self, devicename):
  
        return {
            'ro_community': 'public',
            'rw_community': 'private',
            'username':     'switch_user',
            'password':     'switch_password'
        }
