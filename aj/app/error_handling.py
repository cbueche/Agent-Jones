#!/usr/bin/env python
'''

error_handling.py - standardized error codes for Agent-Jones

Author : Ch. Bueche

'''


# -----------------------------------------------------------------------------------
class Errors():

    '''
    standardized error codes for Agent-Jones
    '''

    statii = {

        # 'OK':               {'nr': 0,   'code': 'OK',               'text': 'success'},
        'ERROR_SNMP':       {'nr': 10,  'code': 'ERROR_SNMP',       'text': 'SNMP timeout or wrong communities'},
        'ERROR_SNMP_PDU':   {'nr': 11,  'code': 'ERROR_SNMP_PDU',   'text': 'SNMP PDU is unknown, must be "get" or "walk"'},
        'ERROR_SNMP_OP':    {'nr': 12,  'code': 'ERROR_SNMP_OP',    'text': 'SNMP operation failed'},
        'ERROR_MIB_ENTITY': {'nr': 20,  'code': 'ERROR_MIB_ENTITY', 'text': 'Issue with Entity MIB'},
        'ERROR_OP':         {'nr': 30,  'code': 'ERROR_OP',         'text': 'Operation failed'},

    }

    def status(self, status_idx, msg):

        if status_idx in self.statii:
            return {'error':
                    {'nr':      self.statii[status_idx]['nr'],
                     'code':    self.statii[status_idx]['code'],
                     'text':    self.statii[status_idx]['text'],
                     'details': msg
                     }
                    }
        else:
            return {'error':
                    {'nr':      999,
                     'code':    'unknown status code in error_handling.py',
                     'text':    'unknown status text in error_handling.py',
                     'details': msg
                     }
                    }
