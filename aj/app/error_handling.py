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

        # 'OK':               {'status_nr': 0,   'status_code': 'OK',               'status_text': 'success'},
        'ERROR_SNMP':       {'status_nr': 10,  'status_code': 'ERROR_SNMP',       'status_text': 'SNMP timeout or wrong communities'},
        'ERROR_SNMP_PDU':   {'status_nr': 11,  'status_code': 'ERROR_SNMP_PDU',   'status_text': 'SNMP PDU is unknown, must be "get" or "walk"'},
        'ERROR_SNMP_OP':    {'status_nr': 12,  'status_code': 'ERROR_SNMP_OP',    'status_text': 'SNMP operation failed'},
        'ERROR_MIB_ENTITY': {'status_nr': 20,  'status_code': 'ERROR_MIB_ENTITY', 'status_text': 'Issue with Entity MIB'},
        'ERROR_OP':         {'status_nr': 30,  'status_code': 'ERROR_OP',         'status_text': 'Operation failed'},

    }

    def status(self, status_idx, msg):

        if status_idx in self.statii:
            return {'error' : 
                        {'nr':      self.statii[status_idx]['status_nr'], 
                         'code':    self.statii[status_idx]['status_code'],
                         'text':    self.statii[status_idx]['status_text'],
                         'details': msg
                        }
                    }
        else:
            return {'error' :
                        {'nr':      999,
                         'code':    'unknown status_code in error_handling.py',
                         'text':    'unknown status_text in error_handling.py',
                         'details': msg
                        }
                    }