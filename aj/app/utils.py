#!/usr/bin/env python
'''

utils.py - utility functions for Agent-Jones

Author : Ch. Bueche

'''


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
            logger.warn("could not translate status <%s>" % status)
            return [status, status]
