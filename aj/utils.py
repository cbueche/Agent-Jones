#!/usr/bin/env python
'''

utils.py - utility functions for Agent-Jones

Author : Ch. Bueche

'''

import socket

# -----------------------------------------------------------------------------------
class Utilities():

    '''
    utility functions
    '''

    def translate_status(self, status):
        '''
        translate Admin/Oper status to humanized formats
        '''

        status_map = {
            'up(1)': [1, 'up'],
            'down(2)': [2, 'down'],
            'testing(3)': [3, 'testing'],
            'unknown(4)': [4, 'unknown'],
            'dormant(5)': [5, 'dormant'],
            'notPresent(6)': [6, 'notPresent'],
            'lowerLayerDown(7)': [7, 'lowerLayerDown']
        }

        if status in status_map:
            return status_map[status]
        else:
            logger.warning("could not translate status <%s>" % status)
            return [status, status]


    def convert_ip_from_snmp_format(self, address_type, ip_address):

        if address_type in ('ipv4', 'ipv4z'):
            return socket.inet_ntoa(ip_address)
        elif address_type in ('ipv6', 'ipv6z'):
            return socket.inet_ntop(AF_INET6, ip_address)
        elif address_type == 'dns':
            return ip_address
        else:
            logger.warning('IP conversion not yet supported for type %s, ip %s' % (address_type, ip_address))
            return 'IP conversion not yet supported for type %s, ip %s' % (address_type, ip_address)


    # for Python 3 port, source https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3/46037362#46037362
    def to_bytes(self, bytes_or_str):
        if isinstance(bytes_or_str, str):
            value = bytes_or_str.encode()  # uses 'utf-8' for encoding
        else:
            value = bytes_or_str
        return value  # Instance of bytes

    def to_str(self, bytes_or_str):
        if isinstance(bytes_or_str, bytes):
            value = bytes_or_str.decode()  # uses 'utf-8' for encoding
        else:
            value = bytes_or_str
        return value  # Instance of str
