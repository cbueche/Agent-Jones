#!/usr/bin/env python
'''

aj.py - main script for Agent-Jones web-service

Agent-Jones is a web-service used retrieve info from and configure Cisco devices.
Mostly switches, but it could as well be used for routers. It is the back-end part of
Magic-Button and other nice front-ends we are developing.

Author : Ch. Bueche
Repository & documentation : https://github.com/cbueche/Agent-Jones

'''

# -----------------------------------------------------------------------------------
# initialization
# -----------------------------------------------------------------------------------

from flask import Flask, url_for, make_response, jsonify, send_from_directory, request
from flask import render_template
from flask.json import loads

from flask.ext import restful
from flask.ext.restful import reqparse

from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

import time
from datetime import datetime
from random import randint
import os
import sys
import ConfigParser
import netaddr
from subprocess import Popen, PIPE, STDOUT
import socket

import autovivification

# find where we are to create the correct path to the MIBs below and to know where is etc/
full_path = os.path.realpath(__file__)
script_path = os.path.split(full_path)[0]
sys.path.insert(0, script_path + '/etc')

import credentials

import utils
import access_checks
import error_handling
import sysoidan
import sshcmd

# Snimpy SNMP lib and MIB loading
from snimpy.manager import Manager as M
from snimpy.manager import load
from snimpy import snmp

mib_path = script_path + '/mibs/'

# RTF FAQ
os.environ['SMIPATH'] = mib_path

# base MIBs that everyone uses at some point
load(mib_path + "SNMPv2-SMI.my")
load(mib_path + "SNMPv2-TC.my")
load(mib_path + "SNMPv2-CONF.my")
load(mib_path + "SNMP-FRAMEWORK-MIB.my")
load(mib_path + "INET-ADDRESS-MIB.my")
load(mib_path + "RMON-MIB.my")
load(mib_path + "IANAifType-MIB.my")
load(mib_path + "IF-MIB.my")
load(mib_path + "SNMPv2-MIB.my")

# entity, for serial-#
load(mib_path + "ENTITY-MIB.my")

# Cisco stacks
load(mib_path + "CISCO-SMI.my")
load(mib_path + "CISCO-TC.my")
load(mib_path + "CISCO-STACKWISE-MIB.my")

# for config writes
load(mib_path + "CISCO-ST-TC.my")
load(mib_path + "CISCO-CONFIG-COPY-MIB.my")

# for VLANs
load(mib_path + "CISCO-VTP-MIB.my")
load(mib_path + "CISCO-VLAN-MEMBERSHIP-MIB.my")

# for Mac collection
load(mib_path + "BRIDGE-MIB.my")

# to identify Cisco products
load(mib_path + "CISCO-PRODUCTS-MIB.my")

# to get the duplex mode
load(mib_path + "EtherLike-MIB.my")

# Power over Ethernet info
load(mib_path + "POWER-ETHERNET-MIB.my")
load(mib_path + "CISCO-POWER-ETHERNET-EXT-MIB.my")

# CDP / Cisco Discovery Protocol
load(mib_path + "CISCO-CDP-MIB.my")

# DHCP snooping on Cisco switches
load(mib_path + "P-BRIDGE-MIB.my")
load(mib_path + "RFC-1212.my")
load(mib_path + "RFC1155-SMI.my")
load(mib_path + "RFC1213-MIB.my")
load(mib_path + "RFC1271-MIB.my")
load(mib_path + "TOKEN-RING-RMON-MIB.my")
load(mib_path + "RMON2-MIB.my")
load(mib_path + "Q-BRIDGE.my")
load(mib_path + "CISCO-DHCP-SNOOPING-MIB.my")


# -----------------------------------------------------------------------------------
# collect the API dynamic documentation
# -----------------------------------------------------------------------------------
class DocCollection():

    apidoc = autovivification.AutoVivification()

    def add(self, stanza, uri, methods):

        name = stanza['name']
        self.apidoc[name]['description'] = stanza['description']
        self.apidoc[name]['uri']         = uri
        self.apidoc[name]['methods']     = methods
        self.apidoc[name]['auth']        = stanza['auth']
        self.apidoc[name]['auth-type']   = stanza['auth-type']
        self.apidoc[name]['params']      = stanza['params']
        self.apidoc[name]['returns']     = stanza['returns']


# -----------------------------------------------------------------------------------
# GET on a single device
# -----------------------------------------------------------------------------------
class DeviceAPI(restful.Resource):
    __doc__ = '''{
        "name": "DeviceAPI",
        "description": "GET info from a single device.",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A lot of device attributes."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):

        logger.debug('fn=DeviceAPI/get : %s' % devicename)

        tstart = datetime.now()

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name']      = devicename

        logger.debug('fn=DeviceAPI/get : %s : creating the snimpy manager' % devicename)
        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=DeviceAPI/get : %s : request device info' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName']     = m.sysName
            deviceinfo['sysDescr']    = m.sysDescr
            deviceinfo['sysContact']  = m.sysContact
            deviceinfo['sysLocation'] = m.sysLocation
            deviceinfo['sysObjectID'] = str(m.sysObjectID)
            deviceinfo['sysUpTime']   = int(m.sysUpTime) / 100

            # POE
            poe_modules = []
            for poe_module in m.pethMainPseConsumptionPower:
                poe_modules.append({
                    'poe_module': poe_module,
                    'measured_power': m.pethMainPseConsumptionPower[poe_module],
                    'nominal_power': m.pethMainPsePower[poe_module]
                    })
            deviceinfo['pethMainPsePower'] = poe_modules

            logger.debug('fn=DeviceAPI/get : %s : get serial numbers' % devicename)
            (max_switches, deviceinfo['entities']) = self.get_serial(m, devicename)
            deviceinfo['cswMaxSwitchNum'] = max_switches

            # sysoid mapping
            (deviceinfo['hwVendor'], deviceinfo['hwModel']) = sysoidmap.translate_sysoid(logger, deviceinfo['sysObjectID'])

        except Exception, e:
            logger.error("fn=DeviceAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DeviceAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo


    def get_serial(self, m, devicename):
        ''' get the serial numbers using the Entity-MIB
            https://raw.github.com/vincentbernat/snimpy/master/examples/get-serial.py

            return a list of entries, as we might have a stacked switch configuration
        '''
        # first, find out if the switch is stacked :
        # when working, use 0 for non stack and 1 for stacks in the top-parent search below
        max_switches = m.cswMaxSwitchNum

        if max_switches is not None:
            parent_search_stop_at = 1
        else:
            parent_search_stop_at = 0

        hardware_info = []
        parent = None
        for i in m.entPhysicalContainedIn:
            if m.entPhysicalContainedIn[i] == parent_search_stop_at:
                parent = i
                hardware_info.append({
                    'physicalDescr':        m.entPhysicalDescr[parent],
                    'physicalHardwareRev':  m.entPhysicalHardwareRev[parent],
                    'physicalFirmwareRev':  m.entPhysicalFirmwareRev[parent],
                    'physicalSoftwareRev':  m.entPhysicalSoftwareRev[parent],
                    'physicalSerialNum':    m.entPhysicalSerialNum[parent],
                    'physicalName':         m.entPhysicalName[parent]
                })
        if parent is None:
            logger.warn("fn=DeviceAPI/get_serial : %s : could not get an entity parent" % devicename)
            return errst.status('ERROR_MIB_ENTITY', 'could not get an entity parent in get_serial')
        else:
            return (max_switches, hardware_info)


# -----------------------------------------------------------------------------------
# POST on a single $device/action
# -----------------------------------------------------------------------------------
class DeviceActionAPI(restful.Resource):
    __doc__ = '''{
        "name": "DeviceActionAPI",
        "description": "POST action to a single device. Only possible action for now is ping",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["type=ping"],
        "returns": "Results of the action."
    }'''

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('type', type = str, required = True, help = 'No action provided')
        super(DeviceActionAPI, self).__init__()

    decorators = [auth.login_required]

    def post(self, devicename):

        args = self.reqparse.parse_args()
        action = args['type']

        logger.debug('fn=DeviceActionAPI/post : %s / %s' % (devicename, action))

        tstart = datetime.now()

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename
        deviceinfo['action'] = action


        if action == 'ping':

            logger.debug('fn=DeviceActionAPI/post : %s : run action %s' % (devicename, action))

            ping_command = app.config['PING_COMMAND'][:]
            ping_command.append(devicename)

            logger.debug("running ping-command <" + ' '.join(ping_command) + ">")
            deviceinfo['cmd'] = ' '.join(ping_command)

            try:
                cm = Popen(ping_command, stdout=PIPE, stderr=STDOUT)
                stdout, stderr = cm.communicate()
                rc = cm.returncode
                stderr = '' if stderr is None else stderr.encode('utf-8')
                logger.debug('fn=DeviceActionAPI/post : %s : rc=<%s>, stdout=<%s>, stderr=<%s>' % (devicename, rc, stdout, stderr))
            except Exception, e:
                logger.error("fn=DeviceActionAPI/post : %s : ping action failed : %s" % (devicename, e))
                return errst.status('ERROR_OP', 'ping action for %s failed, cause : %s' % (devicename, e)), 200

            deviceinfo['status'] = 'failed' if rc else 'ok'
            deviceinfo['rc'] = rc
            deviceinfo['stdout'] = stdout
            deviceinfo['stderr'] = stderr

        else:
            return errst.status('ERROR_OP', 'unknown action <%s>' % action), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DeviceActionAPI/post : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo



# -----------------------------------------------------------------------------------
# PUT on a single device : save the running-config to startup-config
# -----------------------------------------------------------------------------------
class DeviceSaveAPI(restful.Resource):
    '''
    {
        "name": "DeviceSaveAPI",
        "description": "save the running-config to startup-config",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["uuid=UUID (optional, used to identify the write request in logs)"],
        "returns": "status info"
    }
    '''
    decorators = [auth.login_required]

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('uuid', type = str, required = mandate_uuid, help = 'No uuid provided')
        super(DeviceSaveAPI, self).__init__()

    def put(self, devicename):

        args = self.reqparse.parse_args()
        uuid = args['uuid']

        logger.info('fn=DeviceSaveAPI/put : %s, uuid=%s' % (devicename, uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']

        if not check.check_snmp(logger, M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=DeviceSaveAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = rw_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # random operation index
        opidx = randint(1, 1000)
        logger.debug('fn=DeviceSaveAPI/put : %s : operation %d' % (devicename, opidx))

        # some devices will for sure fail, so catch them
        try:
            # set the source to be the running-config
            logger.debug('fn=DeviceSaveAPI/put : %s : operation %d : set the source to be the running-config' % (devicename, opidx))
            m.ccCopySourceFileType[opidx] = 4
            # set the dest to be the startup-config
            logger.debug('fn=DeviceSaveAPI/put : %s : operation %d : set the dest to be the startup-config' % (devicename, opidx))
            m.ccCopyDestFileType[opidx] = 3
            # start the transfer
            logger.debug('fn=DeviceSaveAPI/put : %s : operation %d : start the transfer' % (devicename, opidx))
            m.ccCopyEntryRowStatus[opidx] = 1

            # detect timeout and return a failure in case
            write_timeout = app.config['DEVICE_SAVE_TIMEOUT']
            waited = 0
            step = 0.5
            while(waited < write_timeout):
                waited += step
                state = m.ccCopyState[opidx]
                if state == 3 or state == 4:
                    break
                logger.debug("fn=DeviceSaveAPI/put : %s : operation %d : waiting for config save to finish" % (devicename, opidx))
                time.sleep(step)

            logger.debug("fn=DeviceSaveAPI/put : %s : operation %d : waited=%s seconds" % (devicename, opidx, waited))

            if waited == write_timeout:
                logger.error("fn=DeviceSaveAPI/put : %s : operation %d : copy failed, cause = timeout" % (devicename, opidx))
                return errst.status('ERROR_OP', 'config save for %s failed, cause : timeout, operation-nr : %d' % (devicename, opidx)), 200

            # check
            if m.ccCopyState == 4:
                # failure
                cause = m.ConfigCopyFailCause
                logger.error("fn=DeviceSaveAPI/put : %s : operation %d : copy failed, cause = %s" % (devicename, cause, opidx))
                return errst.status('ERROR_OP', 'config save for %s failed, cause : %s, operation-nr : %s' % (devicename, cause, opidx)), 200
            else:
                # success
                logger.info("fn=DeviceSaveAPI/put : %s : operation %d : copy successful" % (devicename, opidx))

            # delete op
            logger.debug("fn=DeviceSaveAPI/put : %s : operation %d : clear operation" % (devicename, opidx))
            m.ccCopyEntryRowStatus[opidx] = 6

        except Exception, e:
            logger.error("fn=DeviceSaveAPI/put : %s : copy failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'config save for %s failed, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.info('fn=DeviceSaveAPI/put : %s : duration=%s' % (devicename, duration))
        return {'info': 'config save for %s successful' % devicename, 'duration': duration, 'operation-nr': opidx}



# -----------------------------------------------------------------------------------
# GET interfaces from a device
# -----------------------------------------------------------------------------------
class InterfaceAPI(restful.Resource):
    __doc__ = '''{
        "name": "InterfaceAPI",
        "description": "GET interfaces from a device. Adding ?showmac=1 to the URI will list the MAC addresses of devices connected to ports. Be aware that it makes the query much slower. Adding ?showvlannames=1 will show the vlan names for each vlan. It will as well make the query slower. Adding ?showpoe=1 will provide the power consumption for each port. Again, it will make the query slower. Adding ?showcdp=1 will provide CDP information for each port, at cost of some more time.",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of device interfaces."
    }'''
    decorators = [auth.login_required]

    # check arguments
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('showmac', default=0, type = int, required = False, help = 'showmac=0|1. List the MAC addresses of devices connected to ports.')
        self.reqparse.add_argument('showvlannames', default=0, type = int, required = False, help = 'showvlannames=0|1. Show the vlan names for each vlan.')
        self.reqparse.add_argument('showpoe', default=0, type = int, required = False, help = 'showpoe=0|1. Provide the power consumption for each port.')
        self.reqparse.add_argument('showcdp', default=0, type = int, required = False, help = 'showcdp=0|1. Provide the CDP information for each port.')
        self.reqparse.add_argument('showdhcp', default=0, type = int, required = False, help = 'showdhcp=0|1. Provide the DHCP snooped information for each port.')
        super(InterfaceAPI, self).__init__()

    def get(self, devicename):

        logger.debug('fn=InterfaceAPI/get : %s' % devicename)

        tstart = datetime.now()

        # decode query parameters and transform them into booleans. Does apparently not work if done in reqparse.add_argument() above
        args = self.reqparse.parse_args()
        showmac = True if args['showmac'] else False
        showvlannames = True if args['showvlannames'] else False
        showpoe = True if args['showpoe'] else False
        showcdp = True if args['showcdp'] else False
        showdhcp = True if args['showdhcp'] else False
        logger.info('fn=InterfaceAPI/get : %s : showmac=%s, showvlannames=%s, showpoe=%s, showcdp=%s, showdhcp=%s' % (devicename, showmac, showvlannames, showpoe, showcdp, showdhcp))

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=InterfaceAPI/get : %s : creating the snimpy manager' % devicename)
        # FIXME : the timeout here is probably a bad idea. The summ of apps is likely to fail
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName

            # get the mac list
            if showmac:
                macAPI = MacAPI()
                macs = macAPI.get_macs_from_device(devicename, m, ro_community)

            # collect the voice vlans
            vlanAPI = vlanlistAPI()
            voice_vlans = vlanAPI.get_voice_vlans(devicename, m, ro_community)

            if showvlannames:
                vlans = vlanAPI.get_vlans(devicename, m, ro_community)

            if showpoe:
                poe = self.get_poe(devicename, m)

            if showcdp:
                cdpAPI = CDPAPI()
                cdps = cdpAPI.get_cdp_from_device(devicename, m, ro_community)

            if showdhcp:
                dhcpAPI = DHCPsnoopAPI()
                dhcp_snooping_entries = dhcpAPI.get_dhcp_snooping_from_device(devicename, m, ro_community)

            logger.debug('fn=InterfaceAPI/get : %s : get interface info' % devicename)
            interfaces = []
            for index in m.ifDescr:
                interface = {}
                logger.debug('fn=InterfaceAPI/get : %s : get interface info for index %s' % (devicename, index))
                interface['index']                                         = index
                interface['ifAdminStatus'], interface['ifAdminStatusText'] = util.translate_status(str(m.ifAdminStatus[index]))
                interface['ifOperStatus'], interface['ifOperStatusText']   = util.translate_status(str(m.ifOperStatus[index]))
                interface['ifType']                                        = str(m.ifType[index])
                interface['ifMtu']                                         = m.ifMtu[index]
                interface['ifSpeed']                                       = m.ifSpeed[index]
                interface['ifDescr']                                       = str(m.ifDescr[index])
                interface['ifAlias']                                       = str(m.ifAlias[index])
                interface['dot3StatsDuplexStatus']                         = str(m.dot3StatsDuplexStatus[index])

                # try to get vlan numbers (data and voice)
                vlan_nr = m.vmVlan[index]
                if index in voice_vlans:
                    voice_vlan_nr = int(voice_vlans[index])
                else:
                    voice_vlan_nr = None

                # get vlan names if asked so
                if showvlannames:
                    # data
                    if vlan_nr in vlans:
                        vlan_name = vlans[vlan_nr]['name']
                    else:
                        vlan_name = ''
                    # voice
                    if voice_vlan_nr in vlans:
                        voice_vlan_name = vlans[voice_vlan_nr]['name']
                    else:
                        voice_vlan_name = ''

                else:
                    vlan_name = ''
                    voice_vlan_name = ''

                interface['vmVlanNative'] = {'nr': vlan_nr, 'name': vlan_name}
                interface['vmVoiceVlanId'] = {'nr': voice_vlan_nr, 'name': voice_vlan_name}

                # Macs
                if showmac:
                    if index in macs:
                        interface['macs'] = macs[index]
                    else:
                        interface['macs'] = []

                # POE
                if showpoe:
                    if interface['ifDescr'] in poe:
                        interface['poeStatus'] = str(poe[interface['ifDescr']]['status'])
                        interface['poePower'] = poe[interface['ifDescr']]['power']
                    else:
                        interface['poeStatus'] = ''
                        interface['poePower'] = None

                # CDP
                if showcdp:
                    interface['cdp'] = {}
                    if index in cdps:
                        interface['cdp']["cdpCacheDeviceId"] = cdps[index]["cdpCacheDeviceId"]
                        interface['cdp']["cdpCacheDevicePort"] = cdps[index]["cdpCacheDevicePort"]
                        interface['cdp']["cdpCachePlatform"] = cdps[index]["cdpCachePlatform"]
                        interface['cdp']["cdpCacheLastChange"] = cdps[index]["cdpCacheLastChange"]
                    else:
                        interface['cdp']["cdpCacheDeviceId"] = None
                        interface['cdp']["cdpCacheDevicePort"] = None
                        interface['cdp']["cdpCachePlatform"] = None
                        interface['cdp']["cdpCacheLastChange"] = None

                # DHCP
                if showdhcp:
                    # an interface might have more than one MAC-IP binding so make this is a list
                    interface['dhcpsnoop'] = []
                    for entry in dhcp_snooping_entries:
                        # the code below removes the idx key-value from the dict
                        # so for the next interface, the equality match below would fail.
                        # this avoids that case.
                        if 'interface_idx' in entry:
                            if entry['interface_idx'] == index:
                                # no need to add the idx element, it's redundant here
                                del entry['interface_idx']
                                interface['dhcpsnoop'].append(entry)

                # all infos are added to this interface, add it to the final list
                interfaces.append(interface)

            deviceinfo['interfaces'] = interfaces

        except Exception, e:
            logger.error("fn=InterfaceAPI/get : %s : at end, SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        # TODO : an interface could belong to many VLANs when trunking.
        # in Netdisco, named "VLAN Membership". The Native VLAN is now done using vmVlan,
        # the listing of secondary VLANs is not implemented yet

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=InterfaceAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo

    def get_poe(self, devicename, m):
        ''' get the POE info using the CISCO-POWER-ETHERNET-EXT-MIB and Entity-MIB

            return a list of poe entries, indexed by port name (eg FastEthernet1/0/15)
        '''
        # first, create a mapping EntPhyIndex --> port name (eg FastEthernet1/0/6), as we don't have the if-idx in POE table below
        logger.debug('fn=InterfaceAPI/get_poe : %s : create a mapping EntPhyIndex --> port name' % (devicename))
        port_mapping = {}
        for entry in m.entPhysicalName:
            port_mapping[entry] = m.entPhysicalName[entry]
            logger.debug('fn=InterfaceAPI/get_poe : %s : ent-idx=%s, port-name=%s' % (devicename, entry, port_mapping[entry]))

        # then, get the poe info. Returned entries are indexed by the port-name
        logger.debug('fn=InterfaceAPI/get_poe : %s : get poe info' % (devicename))
        poe = {}
        # some switches cannot do any POE and answer with "End of MIB was reached"
        # and some clients might ask for POE for those even if the get-device API call
        # said "no POE". In this case, only log and return an empty table
        try:
            for entry in m.cpeExtPsePortPwrConsumption:
                entry_status = m.pethPsePortDetectionStatus[entry]
                entry_power  = m.cpeExtPsePortPwrConsumption[entry]
                entry_idx    = m.cpeExtPsePortEntPhyIndex[entry]
                entry_port_name = port_mapping[entry_idx]
                logger.debug('fn=InterfaceAPI/get_poe : %s : status=%s, power=%s, ent-idx=%s, port-name=%s' % (devicename, entry_status, entry_power, entry_idx, entry_port_name))
                poe[entry_port_name] = {'status': entry_status, 'power': entry_power}

        except Exception, e:
            logger.debug("fn=InterfaceAPI/get_poe : %s : could not get poe info, probably a device without POE. Status : %s" % (devicename, e))

        return poe


# -----------------------------------------------------------------------------------
# GET interfaces counters of one interface
# -----------------------------------------------------------------------------------
class InterfaceCounterAPI(restful.Resource):
    __doc__ = '''{
        "name": "InterfaceCounterAPI",
        "description": "GET interface counters of one interface",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of interfaces counters. Use inOctets and outOctets to get an octet counter independent of 64 bit (ifX HC) capabilities of the target."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename, ifindex):

        logger.debug('fn=InterfaceCounterAPI/get : %s : index=%s' % (devicename, ifindex))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=InterfaceCounterAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName
            deviceinfo['interface'] = str(m.ifDescr[ifindex])

            logger.debug('fn=InterfaceCounterAPI/get : %s : get interface counters' % devicename)
            counters = {}
            counters['ifHCInOctets']  = m.ifHCInOctets[ifindex]
            counters['ifHCOutOctets'] = m.ifHCOutOctets[ifindex]
            counters['ifInErrors']    = m.ifInErrors[ifindex]
            counters['ifOutErrors']   = m.ifOutErrors[ifindex]

            if counters['ifHCInOctets'] and counters['ifHCInOctets']:
                counters['inOctets']  = counters['ifHCInOctets']
                counters['outOctets'] = counters['ifHCOutOctets']
            else:
                counters['inOctets']  = m.ifInOctets[ifindex]
                counters['outOctets'] = m.ifOutOctets[ifindex]

            deviceinfo['counters'] = counters

        except Exception, e:
            logger.error("fn=InterfaceCounterAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=InterfaceCounterAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo



# -----------------------------------------------------------------------------------
# GET MAC(ethernet) to port mappings from a device
# -----------------------------------------------------------------------------------
class MacAPI(restful.Resource):
    __doc__ = '''{
        "name": "MacAPI",
        "description": "MAC(ethernet) to port mappings from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of MAC addresses indexed by ifIndex."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
    #-------------------------
        logger.debug('fn=MacAPI/get : %s' % devicename)

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=MacAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        try:
            deviceinfo['sysName'] = m.sysName

            macs = self.get_macs_from_device(devicename, m, ro_community)

            macs_organized = []
            for ifindex in macs:
                entry = {}
                entry["index"] = ifindex
                entry["macs"] = macs[ifindex]
                macs_organized.append(entry)

        except snmp.SNMPException, e:
            logger.error("fn=MacAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=MacAPI/get : %s : duration=%s' % (devicename, duration))
        deviceinfo['macs'] = macs_organized
        return deviceinfo


    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info when knowing the ifIndex
    def get_macs_from_device(self, devicename, m, ro_community):
    #-------------------------
        logger.debug('fn=MacAPI/get_macs_from_device : %s' % devicename)
        macs = {}

        for entry in m.vtpVlanName:
            vlan_nr = entry[1]
            try:
                logger.debug('fn=MacAPI/get_macs_from_device vlan_nr = %s' % (vlan_nr))
                vlan_type = m.vtpVlanType[entry]
                vlan_state = m.vtpVlanState[entry]
                vlan_name = m.vtpVlanName[entry]
            except:
                logger.warn("fn=MacAPI/get_macs_from_device : failed to get vlan detail infos. Skip to next vlan")
                continue

            # only ethernet VLANs
            if vlan_type == 'ethernet' and vlan_state == 'operational':
                logger.debug('fn=MacAPI/get_macs_from_device : %s : polling vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

                # VLAN-based community, have a local manager for each VLAN
                vlan_community = "%s@%s" % (ro_community, vlan_nr)
                # can be slow for big switches, so try only once but longer
                lm = M(host=devicename, community=vlan_community, version=2, timeout=app.config['SNMP_TIMEOUT_LONG'], retries=app.config['SNMP_RETRIES_NONE'], none=True)

                # we pull them in an array so we can catch timeouts for broken IOS versions
                # happened on a big stack of 8 Cisco 3750 running 12.2(46)SE (fc2)
                try:
                    logger.debug('fn=MacAPI/get_macs_from_device : trying to pull all mac_entries for vlan %s (%s)' % (vlan_nr, vlan_name))
                    for mac_entry in lm.dot1dTpFdbAddress:
                        port = lm.dot1dTpFdbPort[mac_entry]
                        if port == None:
                            logger.debug("fn=MacAPI/get_macs_from_device : %s : skip port=None" % (devicename))
                            continue

                        try:
                            ifindex = lm.dot1dBasePortIfIndex[port]
                        except Exception, e:
                            logger.debug("fn=MacAPI/get_macs_from_device : %s : port=%s, mac_entry_idx lookup failed : %s" % (devicename, port, e))

                        try:
                            mac = netaddr.EUI(mac_entry)
                            vendor = mac.oui.registration().org
                        except Exception, e:
                            #logger.info("fn=MacAPI/get_macs_from_device : %s : vendor lookup failed : %s" % (devicename, e))
                            vendor = 'unknown'

                        #logger.debug("STORAGE: idx=%s, vlan=%s, mac=%s, vendor=%s" % (ifindex, vlan_nr, str(mac), vendor))
                        mac_record = {'mac': str(mac), 'vendor': vendor, 'vlan': vlan_nr}
                        if ifindex in macs:
                            macs[ifindex].append(mac_record)
                        else:
                            macs[ifindex] = [mac_record]

                except:
                    logger.warn("fn=MacAPI/get_macs_from_device : failed, probably an unused VLAN (%s) on a buggy IOS producing SNMP timeout. Ignoring this VLAN" % (vlan_nr))
                    #pass

        logger.debug("fn=MacAPI/get_macs_from_device : returning data")
        return macs



# -----------------------------------------------------------------------------------
# GET CDP info from a device
# -----------------------------------------------------------------------------------
class CDPAPI(restful.Resource):
    __doc__ = '''{
        "name": "CDPAPI",
        "description": "GET CDP info from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of info indexed by ifIndex."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
    #-------------------------
        logger.debug('fn=CDPAPI/get : %s' % devicename)

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=CDPAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        try:
            deviceinfo['sysName'] = m.sysName

            cdps = self.get_cdp_from_device(devicename, m, ro_community)

            cdps_organized = []
            for ifindex in cdps:
                entry = {}
                entry["index"] = ifindex
                entry["cdpCacheDeviceId"] = cdps[ifindex]['cdpCacheDeviceId']
                entry["cdpCacheDevicePort"] = cdps[ifindex]['cdpCacheDevicePort']
                entry["cdpCachePlatform"] = cdps[ifindex]['cdpCachePlatform']
                entry["cdpCacheLastChange"] = cdps[ifindex]['cdpCacheLastChange']
                cdps_organized.append(entry)

        except snmp.SNMPException, e:
            logger.error("fn=CDPAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=CDPAPI/get : %s : duration=%s' % (devicename, duration))
        deviceinfo['cdp'] = cdps_organized
        return deviceinfo


    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info when knowing the ifIndex
    def get_cdp_from_device(self, devicename, m, ro_community):
    #-------------------------
        logger.debug('fn=CDPAPI/get_cdp_from_device : %s' % devicename)

        cdps = autovivification.AutoVivification()
        try:
            for cdp_idx in m.cdpCacheDeviceId:
                ifindex = cdp_idx[0]
                device = m.cdpCacheDeviceId[cdp_idx]
                interface = m.cdpCacheDevicePort[cdp_idx]
                platform = m.cdpCachePlatform[cdp_idx]
                lastchange = m.cdpCacheLastChange[cdp_idx]
                cdps[ifindex]['cdpCacheDeviceId'] = device
                cdps[ifindex]['cdpCacheDevicePort'] = interface
                cdps[ifindex]['cdpCachePlatform'] = platform
                cdps[ifindex]['cdpCacheLastChange'] = lastchange
        except:
            logger.warn("fn=CDPAPI/get_cdp_from_device : failed SNMP get for CDP")

        logger.debug("fn=CDPAPI/get_cdp_from_device : returning data")
        return cdps



# -----------------------------------------------------------------------------------
# GET DHCP snooping info from a device
# -----------------------------------------------------------------------------------
class DHCPsnoopAPI(restful.Resource):
    __doc__ = '''{
        "name": "DHCPsnoopAPI",
        "description": "GET DHCP snooping info from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "FIXME : A list of info indexed by ifIndex."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
    #-------------------------
        logger.debug('fn=DHCPsnoopAPI/get : %s' % devicename)

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=DHCPsnoopAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        try:
            deviceinfo['sysName'] = m.sysName
            deviceinfo['dhcpsnoop'] = self.get_dhcp_snooping_from_device(devicename, m, ro_community)

        except snmp.SNMPException, e:
            logger.error("fn=DHCPsnoopAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DHCPsnoopAPI/get : %s : duration=%s' % (devicename, duration))
        return deviceinfo


    # list of DHCP snopped entries. some interfaces (idx) can occur multiple times,
    # called from DHCPsnoopAPI/get above, and optionally by InterfaceAPI/get if asked so
    def get_dhcp_snooping_from_device(self, devicename, m, ro_community):
    #-------------------------

        inet_address_types = {
            0: 'unknown',
            1: 'ipv4',
            2: 'ipv6',
            3: 'ipv4z',
            4: 'ipv6z',
            16: 'dns'
        }

        binding_status = {
            1: 'active',
            2: 'notInService',
            3: 'notReady',
            4: 'createAndGo',
            5: 'createAndWait',
            6: 'destroy'
        }

        logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s' % devicename)
        dhcp_snooping_entries = []
        try:
            for entry in m.cdsBindingsAddrType:
                vlan = int(entry[0])
                mac = str(entry[1])
                # reformat mac: comes as "0:22:90:1b:6:e6" and should be "00-22-90-1B-06-E6"
                mac_e = netaddr.EUI(mac)
                mac_f = str(mac_e)
                # add vendor
                try:
                    vendor = mac_e.oui.registration().org
                except netaddr.NotRegisteredError as e:
                    logger.warn('fn=DHCPsnoopAPI: %s : error %s : unknown vendor for %s' % (devicename, e, mac_f))
                    vendor = 'unknown'
                address_type = inet_address_types.get(m.cdsBindingsAddrType[entry], 'unsupported')
                ip = self.convert_ip_from_snmp_format(address_type, m.cdsBindingsIpAddress[entry])
                interface_idx = m.cdsBindingsInterface[entry]
                leased_time = m.cdsBindingsLeasedTime[entry]
                status = binding_status.get(m.cdsBindingsStatus[entry], 'unsupported')
                hostname = m.cdsBindingsHostname[entry]

                logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : vlan=%s, mac=%s, vendor=%s, address_type=%s, ip=%s, interface_idx=%s, leased_time=%s, status=%s, hostname=%s' % (vlan, mac_f, vendor, address_type, ip, interface_idx, leased_time, status, hostname))
                dhcp_entry = {'interface_idx': interface_idx,
                              'vlan': vlan,
                              'mac': mac_f,
                              'vendor': vendor,
                              'type': address_type,
                              'ip': ip,
                              'leased_time': leased_time,
                              'status': status,
                              'hostname': hostname
                              }
                dhcp_snooping_entries.append(dhcp_entry)
        except snmp.SNMPException, e:
            logger.warn("fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : failed SNMP get for DHCP snooping : %s" % e)

        logger.debug("fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : returning data")
        return dhcp_snooping_entries


    def convert_ip_from_snmp_format(self, address_type, ip_address):

        if address_type in ('ipv4', 'ipv4z'):
            return socket.inet_ntoa(ip_address)
        elif address_type in ('ipv6', 'ipv6z'):
            return socket.inet_ntop(AF_INET6, ip_address)
        elif address_type == 'dns':
            return ip_address
        else:
            return 'IP conversion not yet supported for type %s, ip %s' % (address_type, ip_address)


# -----------------------------------------------------------------------------------
# GET vlan list from a device
# -----------------------------------------------------------------------------------
class vlanlistAPI(restful.Resource):
    __doc__ = '''{
        "name": "vlanlistAPI",
        "description": "GET vlan list from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of vlans for a device."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):

        logger.debug('fn=vlanlistAPI/get : %s' % devicename)

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=vlanlistAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = ro_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName

            logger.debug('fn=vlanlistAPI/get : %s : get vlan list' % devicename)
            vlans_lookup_table = self.get_vlans(devicename, m, ro_community)

            vlans = []
            for entry in vlans_lookup_table:
                vlan = {}
                vlan['nr'] = entry
                vlan['type'] = vlans_lookup_table[entry]['type']
                vlan['state'] = vlans_lookup_table[entry]['state']
                vlan['name']  = vlans_lookup_table[entry]['name']
                vlans.append(vlan)
            deviceinfo['vlans'] = vlans

        except Exception, e:
            logger.error("fn=vlanlistAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=vlanlistAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo


    def get_vlans(self, devicename, m, ro_community):
        ''' return a VLAN dict indexed by vlan-nr '''

        logger.debug('fn=vlanlistAPI/get_vlans : %s : get vlan list' % devicename)
        vlans = {}
        for entry in m.vtpVlanName:
            vlan = {}
            logger.debug('fn=vlanlistAPI/get_vlans : %s : get vlan info for entry %s/%s' % (devicename, entry[0], entry[1]))
            vlan['type']  = str(m.vtpVlanType[entry])
            vlan['state'] = str(m.vtpVlanState[entry])
            vlan['name']  = m.vtpVlanName[entry]
            vlans[entry[1]] = vlan

        return vlans


    def get_voice_vlans(self, devicename, m, ro_community):
        ''' return a VOICE_VLAN dict indexed by vlan-nr '''

        logger.debug('fn=vlanlistAPI/get_voice_vlans : %s : get voice vlan list' % devicename)
        voice_vlans = {}
        for index in m.vmVoiceVlanId:
            logger.debug('fn=vlanlistAPI/get_voice_vlans : %s : get voice vlan info for index %s' % (devicename, index))
            voice_vlans[index] = str(m.vmVoiceVlanId[index])

        return voice_vlans



# -----------------------------------------------------------------------------------
# PUT on a vlan : assign the port to a VLAN
# /aj/api/v1/interfaces/vlan/$fqdn/$ifindex
# -----------------------------------------------------------------------------------
class PortToVlanAPI(restful.Resource):
    __doc__ = '''{
        "name": "PortToVlanAPI",
        "description": "PUT on a vlan : assign the port to a VLAN",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["vlan=NNN", "uuid=UUID (optional, used to identify the write request in logs)"],
        "returns": "status"
    }'''
    decorators = [auth.login_required]

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('vlan', type = str, required = True, help = 'No vlan number provided')
        self.reqparse.add_argument('uuid', type = str, required = mandate_uuid, help = 'No uuid provided')
        super(PortToVlanAPI, self).__init__()

    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        vlan = args['vlan']
        uuid = args['uuid']

        logger.info('fn=PortToVlanAPI/put : %s : ifindex=%s, vlan=%s, uuid=%s' % (devicename, ifindex, vlan, uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']
        if not check.check_snmp(logger, M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=PortToVlanAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = rw_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        # all SNMP ops under one big try
        try:

            # assign the vlan to the port
            m.vmVlan[ifindex] = vlan

        except Exception, e:
            logger.error("fn=PortToVlanAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug('fn=PortToVlanAPI/put : %s : VLAN %s assigned to interface-idx %s successfully' % (devicename, vlan, ifindex))

        return {'info': '%s : VLAN %s assigned to interface-idx %s successfully' % (devicename, vlan, ifindex), 'duration': duration}




# -----------------------------------------------------------------------------------
# PUT on an interface : configure the interface
# /aj/api/v1/interface/config/$fqdn/$ifindex
# -----------------------------------------------------------------------------------
class InterfaceConfigAPI(restful.Resource):
    __doc__ = '''{
        "name": "InterfaceConfigAPI",
        "description": "PUT on an interface : configure the interface",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["ifAlias=TXT", "ifAdminStatus={1(up)|2(down)}", "uuid=UUID (optional, used to identify the write request in logs)"],
        "returns": "status"
    }'''
    """ PUT on an interface : configure the interface """
    decorators = [auth.login_required]

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('ifAdminStatus', type = int, required = False, help = 'No ifAdminStatus value')
        self.reqparse.add_argument('ifAlias',       type = str, required = False, help = 'No ifAlias value')
        self.reqparse.add_argument('uuid',          type = str, required = mandate_uuid, help = 'No uuid provided')
        super(InterfaceConfigAPI, self).__init__()

    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        ifAdminStatus = args['ifAdminStatus']
        ifAlias       = args['ifAlias']
        uuid          = args['uuid']

        logger.info('fn=InterfaceConfigAPI/put : %s : ifindex=%s, ifAdminStatus=%s, ifAlias=%s, uuid=%s' % (devicename, ifindex, ifAdminStatus, ifAlias, uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']
        if not check.check_snmp(logger, M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=InterfaceConfigAPI/put : %s : creating the snimpy manager' % devicename)
        m = M(host = devicename, community = rw_community, version = 2, timeout=app.config['SNMP_TIMEOUT'], retries=app.config['SNMP_RETRIES'], none=True)

        try:
            # assign the values to the port
            if ifAdminStatus is not None:
                logger.debug('fn=InterfaceConfigAPI/put : %s : set ifAdminStatus' % devicename)
                m.ifAdminStatus[ifindex] = ifAdminStatus
            if ifAlias is not None:
                logger.debug('fn=InterfaceConfigAPI/put : %s : set ifAlias' % devicename)
                m.ifAlias[ifindex]       = ifAlias
        except Exception, e:
            logger.error("fn=InterfaceConfigAPI/put : %s : interface configuration failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'interface configuration failed : %s' % e), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug('fn=InterfaceConfigAPI/put : %s : interface configured successfully' % devicename)
        return {'info': 'interface configured successfully', 'duration': duration}



# -----------------------------------------------------------------------------------
# SNMP get or walk on a OID
# this goes a bit beside the idea of this web-service, but it brings flexibility
# FIXME: walk provide too much info if eg done on a single get instance like 1.3.6.1.2.1.1.3.0
# -----------------------------------------------------------------------------------
class OIDpumpAPI(restful.Resource):
    __doc__ = '''{
        "name": "OIDpumpAPI",
        "description": "SNMP get or walk on a OID. This is not completely tested, and walk tend to give back too much data. get can be used but usually needs a .0 at the end of the OID, so the URI to get sysUptime would be `/aj/api/v1/oidpump/devicename/get/1.3.6.1.2.1.1.3.0`, while the URI to walk ifName would be `/aj/api/v1/oidpump/devicename/walk/1.3.6.1.2.1.31.1.1.1.1`",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A complete data structure containing the results of the get/walk."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename, pdu, oid):

        logger.debug('fn=OIDpumpAPI/get : %s : pdu=%s, oid=%s' % (devicename, pdu, oid))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(logger, M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=OIDpumpAPI/get : %s : creating the SNMP session' % devicename)
        session = snmp.Session(devicename, community = ro_community, version=2)

        if pdu == 'get':
            try:
                data = session.get(str(oid))
            except Exception, e:
                logger.error("fn=OIDpumpAPI/get : %s : oid get failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid get failed: %s' % e), 200

        elif pdu == 'walk':
            try:
                data = session.walk(str(oid))
            except Exception, e:
                logger.error("fn=OIDpumpAPI/get : %s : oid walk failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid walk failed: %s' % e), 200

        else:
            return errst.status('ERROR_SNMP_PDU', 'unknown PDU value : %s' % pdu), 200

        # try to unpack the Python tuples. Not sure it will work with all sorts of get/walk results
        entries = {}
        for entry in data:
            oid = '.'.join(map(str,entry[0]))
            if type(entry[1]) == tuple:
                value = '.'.join(map(str,entry[1]))
            else:
                value = str(entry[1])
            entries[oid] = value

        deviceinfo['data'] = entries

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=OIDpumpAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
        return deviceinfo



# -----------------------------------------------------------------------------------
# PUT on a device : run commands over ssh
# /aj/api/v1/device/ssh/$fqdn
# -----------------------------------------------------------------------------------
class DeviceSshAPI(restful.Resource):
    __doc__ = '''{
        "name": "DeviceSshAPI",
        "description": "PUT on a device : run commands over ssh",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["driver=ios", "CmdList=list (JSON ordered list)", "uuid=UUID (optional, used to identify the write request in logs)"],
        "returns": "status and output indexed by commands"
    }'''
    """ PUT on a device : run commands over ssh """
    decorators = [auth.login_required]

    # check arguments
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('CmdList',       type = str, required = True, help = 'missing command list')
        self.reqparse.add_argument('uuid',          type = str, required = mandate_uuid, help = 'No uuid provided')
        self.reqparse.add_argument('driver',        type = str, required = True, help = 'missing driver, use one of http://knipknap.github.io/exscript/api/Exscript.protocols.drivers-module.html, eg ios')
        super(DeviceSshAPI, self).__init__()

    def put(self, devicename):

        args = self.reqparse.parse_args()
        uuid = args['uuid']
        driver = args['driver']
        logger.debug("fn=DeviceSshAPI/put : Received CmdList = <%s>" % (args['CmdList']))
        try:
            cmdlist = loads(args['CmdList'])
        except Exception, e:
            logger.error("fn=DeviceSshAPI/put : %s : %s : device configuration failed : cmds list is no valid JSON. Received CmdList = <%s>" % (devicename, e, args['CmdList']))
            return errst.status('ERROR_OP', 'device configuration failed : cmds list is no valid JSON : %s. Try with something like this without the backslashes : ["terminal length 0", "show users", "show version"]' % e), 500

        logger.info('fn=DeviceSshAPI/put : %s : commands=%s, uuid=%s' % (devicename, cmdlist, uuid))

        tstart = datetime.now()

        # WSGI does not accept playing with stdin and stdout. Save them before doing ssh and restore them afterwards
        save_stdout = sys.stdout
        save_stdin = sys.stdin
        sys.stdout = sys.stderr
        sys.stdin = ''
        (status, output_global, output_indexed) = commander.run_by_ssh(devicename, app.config['SSH_USER'], app.config['SSH_PASSWORD'], driver, cmdlist)
        sys.stdout = save_stdout
        sys.stdin = save_stdin

        if status == 0:
            logger.debug('fn=DeviceSshAPI/put : %s : status = %s, output_indexed=%s, output_global = %s' % (devicename, status, output_indexed, output_global))
        else:
            logger.error('fn=DeviceSshAPI/put : %s : status = %s, output_indexed=%s, output global = %s' % (devicename, status, output_indexed, output_global))
            return errst.status('ERROR_OP', 'device commands by ssh failed : status=%s, output_indexed=%s, output_global=%s' % (status, output_indexed, output_global)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug('fn=DeviceSshAPI/put : %s : device commands successful' % devicename)
        return {'info': 'device commands successful', 'duration': duration, 'output_indexed': output_indexed}



# -----------------------------------------------------------------------------------
# instanciate the Flask application and the REST api
# -----------------------------------------------------------------------------------
app = Flask(__name__)



# -----------------------------------------------------------------------------------
# configuration
# -----------------------------------------------------------------------------------

try:
    envconfig = ConfigParser.ConfigParser()
    envfile = os.path.join(app.root_path, 'etc/environment.conf')
    envconfig.read(envfile)
    environment = envconfig.get('main', 'environment')
except Exception, e:
    print "FATAL, cannot read environment from %s: %s" % (envfile, e)
    sys.exit(1)

if environment == 'PROD':
    app.config.from_object('config.ProductionConfig')
elif environment == 'INT':
    app.config.from_object('config.IntegrationConfig')
elif environment == 'DEV':
    app.config.from_object('config.DevelopmentConfig')
else:
    print "FATAL ERROR: environment must be set in etc/environment.conf"
    sys.exit(1)



# -----------------------------------------------------------------------------------
# REST API
# -----------------------------------------------------------------------------------
api = restful.Api(app)



# -----------------------------------------------------------------------------------
# logging
# -----------------------------------------------------------------------------------

import logging
import logging.handlers
log_file = app.config['LOGFILE']
global logger
logger = logging.getLogger('AJ')
hdlr = logging.handlers.RotatingFileHandler(log_file, maxBytes=app.config['LOG_MAX_SIZE'], backupCount=app.config['LOG_BACKUP_COUNT'])
# we have the PID in each log entry to differentiate parallel processes writing to the log
formatter = logging.Formatter('%(asctime)s - %(process)d - %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
# avoid propagation to console
logger.propagate = False
if app.config['DEBUG']:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

logger.info('environment  : <%s>' % app.config['ENVI'])
mandate_uuid = app.config['MANDATE_UUID']
logger.info('mandate_uuid : <%s>' % mandate_uuid)


# -----------------------------------------------------------------------------------
# add all URLs and their corresponding classes
# -----------------------------------------------------------------------------------
doc = DocCollection()

api.add_resource(DeviceAPI,                 '/aj/api/v1/device/<string:devicename>')
doc.add(loads(DeviceAPI.__doc__),           '/aj/api/v1/device/<string:devicename>',                                DeviceAPI.__dict__['methods'])

api.add_resource(DeviceActionAPI,           '/aj/api/v1/device/<string:devicename>/action')
doc.add(loads(DeviceActionAPI.__doc__),     '/aj/api/v1/device/<string:devicename>/action',                         DeviceActionAPI.__dict__['methods'])

api.add_resource(DeviceSaveAPI,             '/aj/api/v1/devicesave/<string:devicename>')
doc.add(loads(DeviceSaveAPI.__doc__),       '/aj/api/v1/devicesave/<string:devicename>',                            DeviceSaveAPI.__dict__['methods'])

api.add_resource(InterfaceAPI,              '/aj/api/v1/interfaces/<string:devicename>')
doc.add(loads(InterfaceAPI.__doc__),        '/aj/api/v1/interfaces/<string:devicename>',                            InterfaceAPI.__dict__['methods'])

api.add_resource(InterfaceCounterAPI,       '/aj/api/v1/interface/counter/<string:devicename>/<string:ifindex>')
doc.add(loads(InterfaceCounterAPI.__doc__), '/aj/api/v1/interface/counter/<string:devicename>/<string:ifindex>',    InterfaceCounterAPI.__dict__['methods'])

api.add_resource(MacAPI,                    '/aj/api/v1/macs/<string:devicename>')
doc.add(loads(MacAPI.__doc__),              '/aj/api/v1/macs/<string:devicename>',                                  MacAPI.__dict__['methods'])

api.add_resource(DHCPsnoopAPI,              '/aj/api/v1/dhcpsnoop/<string:devicename>')
doc.add(loads(DHCPsnoopAPI.__doc__),        '/aj/api/v1/dhcpsnoop/<string:devicename>',                             DHCPsnoopAPI.__dict__['methods'])

api.add_resource(vlanlistAPI,               '/aj/api/v1/vlans/<string:devicename>')
doc.add(loads(vlanlistAPI.__doc__),         '/aj/api/v1/vlans/<string:devicename>',                                 vlanlistAPI.__dict__['methods'])

api.add_resource(PortToVlanAPI,             '/aj/api/v1/vlan/<string:devicename>/<string:ifindex>')
doc.add(loads(PortToVlanAPI.__doc__),       '/aj/api/v1/vlan/<string:devicename>/<string:ifindex>',                 PortToVlanAPI.__dict__['methods'])

api.add_resource(InterfaceConfigAPI,        '/aj/api/v1/interface/config/<string:devicename>/<string:ifindex>')
doc.add(loads(InterfaceConfigAPI.__doc__),  '/aj/api/v1/interface/config/<string:devicename>/<string:ifindex>',     InterfaceConfigAPI.__dict__['methods'])

api.add_resource(OIDpumpAPI,                '/aj/api/v1/oidpump/<string:devicename>/<string:pdu>/<string:oid>')
doc.add(loads(OIDpumpAPI.__doc__),          '/aj/api/v1/oidpump/<string:devicename>/<string:pdu>/<string:oid>',     OIDpumpAPI.__dict__['methods'])

api.add_resource(DeviceSshAPI,              '/aj/api/v1/device/ssh/<string:devicename>')
doc.add(loads(DeviceSshAPI.__doc__),        '/aj/api/v1/device/ssh/<string:devicename>',                            DeviceSshAPI.__dict__['methods'])

api.add_resource(CDPAPI,                    '/aj/api/v1/cdp/<string:devicename>')
doc.add(loads(CDPAPI.__doc__),              '/aj/api/v1/cdp/<string:devicename>',                                  CDPAPI.__dict__['methods'])



# -----------------------------------------------------------------------------------
# auto-doc for API
# -----------------------------------------------------------------------------------
doc.add(loads('{"name": "DocAPI", "description": "GET / : API documentation", "auth": false, "auth-type": "", "params": [], "returns": "API documentation"}'), '/', ['GET'])
@app.route('/')
def index():
    return jsonify(doc.apidoc)

@app.route('/xdoc/')
def xdoc(name=None):
    return render_template('xdoc.html', apidoc=doc.apidoc)

# -----------------------------------------------------------------------------------

# to get user, passwords and SNMP communites for network devices
credmgr = credentials.Credentials()

# to do some checks (SNMP, logins, etc)
check = access_checks.AccessChecks()

# some utility functions
util = utils.Utilities()

# standardized error codes
errst = error_handling.Errors()

# sysoid mapping
sysoidmap = sysoidan.SysOidAn(logger, app.root_path)

# for SSH commands
commander = sshcmd.SshCmd()


# -----------------------------------------------------------------------------------
# authentication when needed
# -----------------------------------------------------------------------------------

@auth.get_password
def get_password(username):
    logger.debug('username : <%s>' % username)
    if username == app.config['BASIC_AUTH_USER']:
        return app.config['BASIC_AUTH_PASSWORD']
    return None

@auth.error_handler
def unauthorized():
    logger.debug('not authorized')
    return make_response(jsonify( { 'message': 'Unauthorized access' } ), 401)
    # returning 403 instead of 401 would prevent browsers from displaying the default auth dialog


# -----------------------------------------------------------------------------------
# browser will ask for a favicon. Avoid 404 by defining one
# -----------------------------------------------------------------------------------

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')



# -----------------------------------------------------------------------------------
# when running interactively
# -----------------------------------------------------------------------------------

# to profile the script:
if False:
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.config['PROFILE'] = True
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions = [30])
    app.run(host='0.0.0.0', debug = True)

# normal run
if True:
    if __name__ == '__main__':
        logger.info('AJ start')
        app.run(host='0.0.0.0', debug=True)
        logger.info('AJ end')
