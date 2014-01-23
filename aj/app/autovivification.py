#!/usr/bin/env python
'''
autovivification.py - direct deep dict keys creation
'''

# ----

# -----------------------------------------------------------------------------------
class AutoVivification(dict):

    '''
    direct deep dict keys creation
    allows for stuff like

        deviceinfo = AutoVivification()
        deviceinfo['interfaces'][1]['ifAlias'] = 'dummy text'

    without having to create deviceinfo['interfaces'] and deviceinfo['interfaces'][1] first.
    '''

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


