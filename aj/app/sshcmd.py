#!/usr/bin/env python
'''

sshcmd.py - run commands by ssh for Agent-Jones

https://github.com/knipknap/exscript/wiki/Python-API-Tutorial

Author : Ch. Bueche

'''



# -----------------------------------------------------------------------------------
class SshCmd():

    '''
    run commands by ssh

    call sequence:

    import sshcmd
    commander = sshcmd.SshCmd()
    cmdlist = ['terminal length 0', 'show users', 'show version']
    (status, output_global, output_indexed) = commander.run_by_ssh(device, user, password, driver, cmdlist)

    '''

    import Exscript
    from Exscript.protocols import SSH2
    from Exscript import Account
    import time


    def run_by_ssh(self, device, user, password, driver, cmdlist):
        '''
        login to a device using ssh, and run a set of commands
        return a status, error-list, and the unfiltered output from the device
        '''

        # that's a bit dumb, python doesn't allow to import from a variable
        if driver == 'aix': 
            from Exscript.protocols.drivers import aix
        elif driver == 'arbor_peakflow': 
            from Exscript.protocols.drivers import arbor_peakflow
        elif driver == 'aruba': 
            from Exscript.protocols.drivers import aruba
        elif driver == 'brocade': 
            from Exscript.protocols.drivers import brocade
        elif driver == 'enterasys': 
            from Exscript.protocols.drivers import enterasys
        elif driver == 'generic': 
            from Exscript.protocols.drivers import generic
        elif driver == 'hp_pro_curve': 
            from Exscript.protocols.drivers import hp_pro_curve
        elif driver == 'ios': 
            from Exscript.protocols.drivers import ios
        elif driver == 'ios_xr': 
            from Exscript.protocols.drivers import ios_xr
        elif driver == 'junos': 
            from Exscript.protocols.drivers import junos
        elif driver == 'junos_erx': 
            from Exscript.protocols.drivers import junos_erx
        elif driver == 'one_os': 
            from Exscript.protocols.drivers import one_os
        elif driver == 'shell': 
            from Exscript.protocols.drivers import shell
        elif driver == 'smart_edge_os': 
            from Exscript.protocols.drivers import smart_edge_os
        elif driver == 'sros': 
            from Exscript.protocols.drivers import sros
        elif driver == 'vrp': 
            from Exscript.protocols.drivers import vrp
        else:
            return (2, 'invalid driver, please check list from http://knipknap.github.io/exscript/api/Exscript.protocols.drivers-module.html', [])
 
        output_global = ''
        output_indexed = []
        try:
            conn = self.SSH2()
            conn.set_driver(driver)
            conn.connect(device)
            conn.login(self.Account(user, password))

            for command in cmdlist:
                conn.execute(command)
                output_global = output_global + conn.response
                output_indexed.append({command: conn.response})

            conn.send('exit')
            conn.close()

        except Exception, e:
            return (1, e, output_indexed)

        return (0, output_global, output_indexed)
