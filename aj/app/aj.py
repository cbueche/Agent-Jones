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

# update doc/RELEASES.md when touching this
__version__ = '26.10.2016'

from flask import Flask, url_for, make_response, jsonify, send_from_directory, request
from flask import render_template
from flask.json import loads

from flask_restful import Resource, Api
from flask_restful import reqparse

from flask_httpauth import HTTPBasicAuth
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
import logging
import logging.handlers
import re

import autovivification

# find where we are to create the correct path to the MIBs below and to
# know where is etc/
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

# ARP
load(mib_path + "IP-MIB.my")


# -----------------------------------------------------------------------------------
# collect the API dynamic documentation
# -----------------------------------------------------------------------------------
class DocCollection():

    apidoc = autovivification.AutoVivification()

    def add(self, stanza, uri, methods):

        name = stanza['name']
        self.apidoc[name]['description'] = stanza['description']
        self.apidoc[name]['uri'] = uri
        self.apidoc[name]['methods'] = methods
        self.apidoc[name]['auth'] = stanza['auth']
        self.apidoc[name]['auth-type'] = stanza['auth-type']
        self.apidoc[name]['params'] = stanza['params']
        self.apidoc[name]['returns'] = stanza['returns']


# -----------------------------------------------------------------------------------
# GET on a single device
# -----------------------------------------------------------------------------------
class DeviceAPI(Resource):
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

        logger.debug('fn=DeviceAPI/get : src=%s, device=%s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=DeviceAPI/get : %s : creating the snimpy manager' % devicename)
        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=DeviceAPI/get : %s : request device info' %
                     devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              bulk=False,
              none=True)

        # generic SNMP stuff
        try:

            # generic device stuff
            deviceinfo['sysName'] = m.sysName
            deviceinfo['sysDescr'] = m.sysDescr
            deviceinfo['sysContact'] = m.sysContact
            deviceinfo['sysLocation'] = m.sysLocation

            # if this breaks, it means we use PySNMP 4.3 and this patch isn't applied
            # https://github.com/vincentbernat/snimpy/commit/d3a36082d417bb451e469f33938e1d0821b615ea
            # https://github.com/vincentbernat/snimpy/issues/47
            deviceinfo['sysObjectID'] = str(m.sysObjectID)

            deviceinfo['sysUpTime'] = int(m.sysUpTime) / 100

            logger.debug('fn=DeviceAPI/get : %s : get serial numbers' % devicename)
            (deviceinfo['cswMaxSwitchNum'], deviceinfo['entities']) = self.get_serial(m, devicename)

            # sysoid mapping
            (deviceinfo['hwVendor'], deviceinfo['hwModel']) = sysoidmap.translate_sysoid(deviceinfo['sysObjectID'])

        except Exception, e:
            logger.error(
                "fn=DeviceAPI/get : %s : SNMP get of generic aspects for device failed : %s" % (devicename,
                                                                            e))
            return errst.status('ERROR_OP', 'SNMP get of generic aspects failed on %s, cause : %s' % (devicename, e)), 200

        try:
            # POE is picky, segregate it to avoid polluting output with errors
            logger.debug('fn=DeviceAPI/get : %s : get poe info' % devicename)
            poe_modules = []
            for poe_module in m.pethMainPseConsumptionPower:
                poe_modules.append({
                    'poe_module': poe_module,
                    'measured_power': m.pethMainPseConsumptionPower[poe_module],
                    'nominal_power': m.pethMainPsePower[poe_module]
                })
            deviceinfo['pethMainPsePower'] = poe_modules
            logger.debug('fn=DeviceAPI/get : %s : poe info collection ok' % devicename)

        except Exception, e:
            # POE is not that important, do not generate errors for it
            logger.info(
                "fn=DeviceAPI/get : %s : SNMP get for POE aspects for device failed : %s" % (devicename, e))
            # return errst.status('ERROR_OP', 'SNMP get for POE aspects failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DeviceAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo



    def get_serial(self, m, devicename):
        ''' get the serial numbers using the Entity-MIB

            return a list of entries, as we might have a stacked switch configuration
            we return only interesting entities (chassis, psu, module, stack)
        '''

        # first, find out if the switch is stacked :
        # when working, use 0 for non stack and 1 for stacks in the top-parent search below
        logger.debug("fn=DeviceAPI/get_serial : %s : count switch members" % devicename)
        counter = 0
        try:
            for index, value in m.cswSwitchNumCurrent.iteritems():
                logging.debug(
                    'fn=DeviceAPI/get_serial cswSwitchNumCurrent entry %s, %s' % (
                    index, value))
                counter += 1
        except snmp.SNMPException, e:
            logger.info(
                "fn=DeviceAPI/get_serial : %s : exception in get_serial/get-cswSwitchNumCurrent : <%s>" % (
                devicename, e))

        # see OBJECT entPhysicalClass in ENTITY-MIB.my
        interesting_classes = [3, 6, 9, 11]    # chassis, psu, module, stack
        # to reformat the class for humans
        class_regex = re.compile(r'\(\d+\)$')
        try:
            hardware_info = []
            for index, value in m.entPhysicalClass.iteritems():
                if value in interesting_classes:
                    hardware_info.append({
                        'physicalIndex':        index,
                        'physicalDescr':        m.entPhysicalDescr[index],
                        'physicalHardwareRev':  m.entPhysicalHardwareRev[index],
                        'physicalFirmwareRev':  m.entPhysicalFirmwareRev[index],
                        'physicalSoftwareRev':  m.entPhysicalSoftwareRev[index],
                        'physicalSerialNum':    m.entPhysicalSerialNum[index],
                        'physicalName':         m.entPhysicalName[index],
                        'physicalClass':        re.sub(class_regex, '', str(m.entPhysicalClass[index]))
                    })
        except snmp.SNMPException, e:
            logger.info(
                "fn=DeviceAPI/get_serial : %s : exception in get_serial/get-entPhysicalContainedIn : <%s>" % (
                devicename, e))

        # found something ?
        if len(hardware_info) == 0:
            logger.warn(
                "fn=DeviceAPI/get_serial : %s : could not get an entity parent" % devicename)
        else:
            logger.debug("fn=DeviceAPI/get_serial : %s : got %s serial(s)" % (
            devicename, len(hardware_info)))

        return (counter, hardware_info)


# -----------------------------------------------------------------------------------
# POST on a single $device/action
# -----------------------------------------------------------------------------------
class DeviceActionAPI(Resource):
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
        self.reqparse.add_argument(
            'type', type=str, required=True, help='No action provided')
        super(DeviceActionAPI, self).__init__()

    decorators = [auth.login_required]

    def post(self, devicename):

        args = self.reqparse.parse_args()
        action = args['type']

        logger.debug('fn=DeviceActionAPI/post : src=%s, %s / %s' %
                     (request.remote_addr, devicename, action))

        tstart = datetime.now()

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename
        deviceinfo['action'] = action

        if action == 'ping':

            logger.debug('fn=DeviceActionAPI/post : %s : run action %s' %
                         (devicename, action))

            ping_command = app.config['PING_COMMAND'][:]
            ping_command.append(devicename)

            logger.debug("running ping-command <" +
                         ' '.join(ping_command) + ">")
            deviceinfo['cmd'] = ' '.join(ping_command)

            try:
                cm = Popen(ping_command, stdout=PIPE, stderr=STDOUT)
                stdout, stderr = cm.communicate()
                rc = cm.returncode
                stderr = '' if stderr is None else stderr.encode('utf-8')
                logger.debug('fn=DeviceActionAPI/post : %s : rc=<%s>, stdout=<%s>, stderr=<%s>' %
                             (devicename, rc, stdout, stderr))
            except Exception, e:
                logger.error(
                    "fn=DeviceActionAPI/post : %s : ping action failed : %s" % (devicename, e))
                return errst.status('ERROR_OP', 'ping action for %s failed, cause : %s' % (devicename, e)), 200

            deviceinfo['status'] = 'failed' if rc else 'ok'
            deviceinfo['rc'] = rc
            deviceinfo['stdout'] = stdout
            deviceinfo['stderr'] = stderr

        else:
            return errst.status('ERROR_OP', 'unknown action <%s>' % action), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DeviceActionAPI/post : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo


# -----------------------------------------------------------------------------------
# PUT on a single device : save the running-config to startup-config
# -----------------------------------------------------------------------------------
class DeviceSaveAPI(Resource):
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
        self.reqparse.add_argument(
            'uuid', type=str, required=mandate_uuid, help='No uuid provided')
        super(DeviceSaveAPI, self).__init__()

    def put(self, devicename):

        args = self.reqparse.parse_args()
        uuid = args['uuid']

        logger.info('fn=DeviceSaveAPI/put : src=%s, %s, uuid=%s' % (
            request.remote_addr, devicename, uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']

        if not check.check_snmp(M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug(
            'fn=DeviceSaveAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=rw_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        # random operation index
        opidx = randint(1, 1000)
        logger.debug('fn=DeviceSaveAPI/put : %s : operation %d' %
                     (devicename, opidx))

        # some devices will for sure fail, so catch them
        try:
            # set the source to be the running-config
            logger.debug(
                'fn=DeviceSaveAPI/put : %s : operation %d : set the source to be the running-config' % (devicename, opidx))
            m.ccCopySourceFileType[opidx] = 4
            # set the dest to be the startup-config
            logger.debug(
                'fn=DeviceSaveAPI/put : %s : operation %d : set the dest to be the startup-config' % (devicename, opidx))
            m.ccCopyDestFileType[opidx] = 3
            # start the transfer
            logger.debug(
                'fn=DeviceSaveAPI/put : %s : operation %d : start the transfer' % (devicename, opidx))
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
                logger.debug(
                    "fn=DeviceSaveAPI/put : %s : operation %d : waiting for config save to finish" % (devicename, opidx))
                time.sleep(step)

            logger.debug("fn=DeviceSaveAPI/put : %s : operation %d : waited=%s seconds" %
                         (devicename, opidx, waited))

            if waited == write_timeout:
                logger.error(
                    "fn=DeviceSaveAPI/put : %s : operation %d : copy failed, cause = timeout" % (devicename, opidx))
                return errst.status('ERROR_OP', 'config save for %s failed, cause : timeout, operation-nr : %d' % (devicename, opidx)), 200

            # check
            if m.ccCopyState == 4:
                # failure
                cause = m.ConfigCopyFailCause
                logger.error(
                    "fn=DeviceSaveAPI/put : %s : operation %d : copy failed, cause = %s" % (devicename, cause, opidx))
                return errst.status('ERROR_OP', 'config save for %s failed, cause : %s, operation-nr : %s' % (devicename, cause, opidx)), 200
            else:
                # success
                logger.info(
                    "fn=DeviceSaveAPI/put : %s : operation %d : copy successful" % (devicename, opidx))

            # delete op
            logger.debug(
                "fn=DeviceSaveAPI/put : %s : operation %d : clear operation" % (devicename, opidx))
            m.ccCopyEntryRowStatus[opidx] = 6

        except Exception, e:
            logger.error(
                "fn=DeviceSaveAPI/put : %s : copy failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'config save for %s failed, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.info('fn=DeviceSaveAPI/put : %s : duration=%s' %
                    (devicename, duration))
        return {'info': 'config save for %s successful' % devicename, 'duration': duration, 'operation-nr': opidx}


# -----------------------------------------------------------------------------------
# GET interfaces from a device
# -----------------------------------------------------------------------------------
class InterfaceAPI(Resource):
    __doc__ = '''{
        "name": "InterfaceAPI",
        "description": "GET interfaces from a device. Adding ?showmac=1 to the URI will list the MAC addresses of devices connected to ports. Adding ?showvlannames=1 will show the vlan names for each vlan. Adding ?showpoe=1 will provide the power consumption for each port. Adding ?showcdp=1 will provide CDP information for each port. Adding ?showdhcp=1 will collect DHCP snooping information for each port. All these options add significant time and overhead to the collection process.",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of device interfaces."
    }'''
    decorators = [auth.login_required]

    # check arguments
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('showmac', default=0, type=int, required=False,
                                   help='showmac=0|1. List the MAC addresses of devices connected to ports.')
        self.reqparse.add_argument('showvlannames', default=0, type=int, required=False,
                                   help='showvlannames=0|1. Show the vlan names for each vlan.')
        self.reqparse.add_argument('showpoe', default=0, type=int, required=False,
                                   help='showpoe=0|1. Provide the power consumption for each port.')
        self.reqparse.add_argument('showcdp', default=0, type=int, required=False,
                                   help='showcdp=0|1. Provide the CDP information for each port.')
        self.reqparse.add_argument('showdhcp', default=0, type=int, required=False,
                                   help='showdhcp=0|1. Provide the DHCP snooped information for each port.')
        self.reqparse.add_argument('showtrunks', default=0, type=int, required=False,
                                   help='showtrunks=0|1. Provide the trunk information for each port.')
        super(InterfaceAPI, self).__init__()

    def get(self, devicename):

        logger.debug('fn=InterfaceAPI/get : src=%s, %s' % (request.remote_addr,
                                                           devicename))

        tstart = datetime.now()

        # decode query parameters and transform them into booleans. Does
        # apparently not work if done in reqparse.add_argument() above
        args = self.reqparse.parse_args()
        showmac = True if args['showmac'] else False
        showvlannames = True if args['showvlannames'] else False
        showpoe = True if args['showpoe'] else False
        showcdp = True if args['showcdp'] else False
        showdhcp = True if args['showdhcp'] else False
        showtrunks = True if args['showtrunks'] else False
        logger.info('fn=InterfaceAPI/get : %s : showmac=%s, showvlannames=%s, showpoe=%s, showcdp=%s, showdhcp=%s, showtrunks=%s' %
                    (devicename, showmac, showvlannames, showpoe, showcdp, showdhcp, showtrunks))

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=InterfaceAPI/get : %s : creating the snimpy manager' % devicename)
        # FIXME : the timeout here is probably a bad idea. The sum of apps is likely to fail
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              bulk=True,
              none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName

            # get the mac list
            if showmac:
                macAPI = MacAPI()
                macs, total_mac_entries = macAPI.get_macs_from_device(devicename, m, ro_community)

            # collect the voice vlans
            vlanAPI = vlanlistAPI()
            voice_vlans = vlanAPI.get_voice_vlans(devicename, m, ro_community)

            # collect the mapping between interfaces and entities
            # constructs a table (dict) 'ifname' --> 'enclosing-chassis'
            # e.g. {<String: GigabitEthernet1/0/5>: <Integer: 1001>, etc}
            entities = self.collect_entities(m, devicename)
            merged_entities = self.merge_entities(entities, devicename)
            entities_if_to_chassis = self.get_ports(merged_entities, devicename)

            if showvlannames:
                vlans = vlanAPI.get_vlans(devicename, m, ro_community)

            if showpoe:
                poe = self.get_poe(devicename, m)

            if showcdp:
                cdpAPI = CDPAPI()
                cdps = cdpAPI.get_cdp_from_device(devicename, m, ro_community)

            if showdhcp:
                dhcpAPI = DHCPsnoopAPI()
                dhcp_snooping_entries = dhcpAPI.get_dhcp_snooping_from_device(
                    devicename, m, ro_community)

            if showtrunks:
                trunkAPI = TrunkAPI()
                trunks_entries = trunkAPI.get_trunks_from_device(devicename, m, ro_community)

            logger.debug(
                'fn=InterfaceAPI/get : %s : get interface info' % devicename)
            interfaces = []
            for index in m.ifDescr:
                interface = {}
                logger.debug(
                    'fn=InterfaceAPI/get : %s : get interface info for index %s' % (devicename, index))
                interface['index'] = index
                interface['ifAdminStatus'], interface[
                    'ifAdminStatusText'] = util.translate_status(str(m.ifAdminStatus[index]))
                interface['ifOperStatus'], interface[
                    'ifOperStatusText'] = util.translate_status(str(m.ifOperStatus[index]))
                interface['ifType'] = str(m.ifType[index])
                interface['ifMtu'] = m.ifMtu[index]
                interface['ifSpeed'] = m.ifSpeed[index]
                interface['ifDescr'] = str(m.ifDescr[index])
                interface['ifAlias'] = str(m.ifAlias[index])
                interface['dot3StatsDuplexStatus'] = str(m.dot3StatsDuplexStatus[index])
                interface['physicalIndex'] = entities_if_to_chassis.get(interface['ifDescr'], None)

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
                interface['vmVoiceVlanId'] = {
                    'nr': voice_vlan_nr, 'name': voice_vlan_name}

                # Macs
                if showmac:
                    if index in macs:
                        interface['macs'] = macs[index]
                    else:
                        interface['macs'] = []

                # POE
                if showpoe:
                    if interface['ifDescr'] in poe:
                        interface['poeStatus'] = str(
                            poe[interface['ifDescr']]['status'])
                        interface['poePower'] = poe[
                            interface['ifDescr']]['power']
                    else:
                        interface['poeStatus'] = ''
                        interface['poePower'] = None

                # CDP
                if showcdp:
                    interface['cdp'] = {}
                    if index in cdps:
                        interface['cdp']["cdpCacheDeviceId"] = cdps[
                            index]["cdpCacheDeviceId"]
                        interface['cdp']["cdpCacheDevicePort"] = cdps[
                            index]["cdpCacheDevicePort"]
                        interface['cdp']["cdpCachePlatform"] = cdps[
                            index]["cdpCachePlatform"]
                        interface['cdp']["cdpCacheLastChange"] = cdps[
                            index]["cdpCacheLastChange"]
                    else:
                        interface['cdp']["cdpCacheDeviceId"] = None
                        interface['cdp']["cdpCacheDevicePort"] = None
                        interface['cdp']["cdpCachePlatform"] = None
                        interface['cdp']["cdpCacheLastChange"] = None

                # DHCP
                if showdhcp:
                    # an interface might have more than one MAC-IP binding so
                    # make this is a list
                    interface['dhcpsnoop'] = []
                    for entry in dhcp_snooping_entries:
                        # the code below removes the idx key-value from the dict
                        # so for the next interface, the equality match below would fail.
                        # this avoids that case.
                        if 'interface_idx' in entry:
                            if entry['interface_idx'] == index:
                                # no need to add the idx element, it's
                                # redundant here
                                del entry['interface_idx']
                                interface['dhcpsnoop'].append(entry)

                # Trunks
                if showtrunks:
                    if index in trunks_entries:
                        interface['trunkAdminState'] = trunks_entries[index]['trunkAdminState']
                        interface['trunkOperState'] = trunks_entries[index]['trunkOperState']
                    else:
                        interface['trunkAdminState'] = ''
                        interface['trunkOperState'] = ''

                # all infos are added to this interface, add it to the final
                # list
                interfaces.append(interface)

            deviceinfo['interfaces'] = interfaces

        except Exception, e:
            logger.error(
                "fn=InterfaceAPI/get : %s : at end, SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        # TODO : an interface could belong to many VLANs when trunking.
        # in Netdisco, named "VLAN Membership". The Native VLAN is now done using vmVlan,
        # the listing of secondary VLANs is not implemented yet

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=InterfaceAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo

    def get_poe(self, devicename, m):
        ''' get the POE info using the CISCO-POWER-ETHERNET-EXT-MIB and Entity-MIB

            return a list of poe entries, indexed by port name (eg FastEthernet1/0/15)
        '''
        # first, create a mapping EntPhyIndex --> port name (eg
        # FastEthernet1/0/6), as we don't have the if-idx in POE table below
        logger.debug(
            'fn=InterfaceAPI/get_poe : %s : create a mapping EntPhyIndex --> port name' % (devicename))
        port_mapping = {}
        for entry in m.entPhysicalName:
            port_mapping[entry] = m.entPhysicalName[entry]
            logger.debug('fn=InterfaceAPI/get_poe : %s : ent-idx=%s, port-name=%s' %
                         (devicename, entry, port_mapping[entry]))

        # then, get the poe info. Returned entries are indexed by the port-name
        logger.debug('fn=InterfaceAPI/get_poe : %s : get poe info' % (devicename))
        poe = {}
        # some switches cannot do any POE and answer with "End of MIB was reached"
        # and some clients might ask for POE for those even if the get-device API call
        # said "no POE". In this case, only log and return an empty table
        try:
            poe_entries = 0
            for entry in m.cpeExtPsePortPwrConsumption:
                entry_status = m.pethPsePortDetectionStatus[entry]
                entry_power = m.cpeExtPsePortPwrConsumption[entry]
                entry_idx = m.cpeExtPsePortEntPhyIndex[entry]
                # entries in poe list without a port
                if entry_idx in port_mapping:
                    entry_port_name = port_mapping[entry_idx]
                else:
                    entry_port_name = entry_idx
                logger.debug('fn=InterfaceAPI/get_poe : %s : status=%s, power=%s, ent-idx=%s, port-name=%s' %
                             (devicename, entry_status, entry_power, entry_idx, entry_port_name))
                poe[entry_port_name] = {'status': entry_status, 'power': entry_power}
                poe_entries += 1

            logger.info('fn=InterfaceAPI/get_poe : %s : got %s poe entries' % (devicename, poe_entries))

        except Exception, e:
            logger.info(
                "fn=InterfaceAPI/get_poe : %s : could not get poe info, probably a device without POE. Status : %s" % (devicename, e))

        return poe

    # -----------------------------------------------------------------------------------
    def collect_entities(self, m, devicename):

        # entPhysicalClass
        entries_entPhysicalClass = {}
        tstart = datetime.now()
        counter = 0
        logger.info('%s : loop over entPhysicalClass.iteritems' % devicename)
        for index, value in m.entPhysicalClass.iteritems():
            logger.debug('entPhysicalClass entry %s, %s' % (index, value))
            entries_entPhysicalClass[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('loop over entPhysicalClass.iteritems done in %s, %s entries found' % (duration, counter))

        # entPhysicalName
        entries_entPhysicalName = {}
        tstart = datetime.now()
        counter = 0
        logger.info('%s : loop over entPhysicalName.iteritems' % devicename)
        for index, value in m.entPhysicalName.iteritems():
            logger.debug('entPhysicalName entry %s, %s' % (index, value))
            entries_entPhysicalName[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('loop over entPhysicalName.iteritems done in %s, %s entries found' % (duration, counter))

        # entPhysicalContainedIn
        entries_entPhysicalContainedIn = {}
        tstart = datetime.now()
        counter = 0
        logger.info('%s : loop over entPhysicalContainedIn.iteritems' % devicename)
        for index, value in m.entPhysicalContainedIn.iteritems():
            logger.debug('entPhysicalContainedIn entry %s, %s' % (index, value))
            entries_entPhysicalContainedIn[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('loop over entPhysicalContainedIn.iteritems done in %s, %s entries found' % (duration, counter))

        return ({'entries_entPhysicalClass': entries_entPhysicalClass,
                 'entries_entPhysicalName': entries_entPhysicalName,
                 'entries_entPhysicalContainedIn': entries_entPhysicalContainedIn})

    # -----------------------------------------------------------------------------------
    def merge_entities(self, entities, devicename):

        # we merge entities based on the content of the class table
        # strategies if the 3 collected tables have different index values:
        # - if something is not in class table --> it will be ignored by this loop
        # - if something is in class table but has no name or cin --> None

        logger.info('%s : merge entities' % devicename)

        merged_entities = autovivification.AutoVivification()
        for idx, value in entities['entries_entPhysicalClass'].iteritems():
            logger.debug('merging index %s of class %s' % (idx, value))
            merged_entities[idx]['class'] = value
            merged_entities[idx]['name'] = entities['entries_entPhysicalName'].get(idx, None)
            merged_entities[idx]['cin'] = entities['entries_entPhysicalContainedIn'].get(idx, None)

        logger.info('%s : done merging entities' % devicename)

        return merged_entities

    # -----------------------------------------------------------------------------------
    def get_ports(self, merged_entities, devicename):

        # construct a table (dict) 'ifname' --> 'enclosing-chassis'
        # we go over the entity table, find out each interface (class=port)
        # and then find the enclosing-chassis of this interface

        logger.info('%s : get_ports' % devicename)

        port_table = {}
        for idx, entry in merged_entities.iteritems():
            # only ports
            if entry['class'] == 10:  # entPhysicalClass=10 are ports (interfaces of some sort)
                logger.debug('%s : port %s' % (devicename, entry['name']))
                # entPhysicalClass=3 are chassis, this function
                chassis_idx = self.find_parent_of_type(idx, 3, merged_entities)
                port_table[entry['name']] = chassis_idx

        logger.info('%s : done get_ports' % devicename)

        return port_table

    # -----------------------------------------------------------------------------------
    def find_parent_of_type(self, port_idx, searched_parent_type, merged_entities):

        # this is a recursive function walking up the entity tree to find
        # the first ancestor of desired type

        logger.debug('find_parent_of_type %s for entity %s' % (searched_parent_type, port_idx))

        parent_idx = merged_entities[port_idx]['cin']
        logger.debug('parent of port %s is %s' % (port_idx, parent_idx))

        type_of_parent = merged_entities[parent_idx]['class']
        logger.debug('type of parent %s is %s' % (parent_idx, type_of_parent))

        # is the parent already the desired type ?
        if type_of_parent == searched_parent_type:
            # yes !
            logger.debug('parent %s has the searched type %s' % (parent_idx, searched_parent_type))
            return parent_idx
        else:
            # no, go deeper
            return self.find_parent_of_type(parent_idx, 3, merged_entities)


# -----------------------------------------------------------------------------------
# GET interfaces from a device
# try to make this one quicker by using bulk-get
# -----------------------------------------------------------------------------------
class QuickInterfaceAPI(Resource):
    __doc__ = '''{
        "name": "QuickInterfaceAPI",
        "description": "FIXME : WARNING : IN CONSTRUCTION. GET interfaces from a device. Adding ?showmac=1 to the URI will list the MAC addresses of devices connected to ports. Adding ?showvlannames=1 will show the vlan names for each vlan. Adding ?showpoe=1 will provide the power consumption for each port. Adding ?showcdp=1 will provide CDP information for each port. Adding ?showdhcp=1 will collect DHCP snooping information for each port. All these options add significant time and overhead to the collection process.",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of device interfaces."
    }'''
    decorators = [auth.login_required]

    # check arguments
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('showmac', default=0, type=int, required=False,
                                   help='showmac=0|1. List the MAC addresses of devices connected to ports.')
        self.reqparse.add_argument('showvlannames', default=0, type=int,
                                   required=False,
                                   help='showvlannames=0|1. Show the vlan names for each vlan.')
        self.reqparse.add_argument('showpoe', default=0, type=int, required=False,
                                   help='showpoe=0|1. Provide the power consumption for each port.')
        self.reqparse.add_argument('showcdp', default=0, type=int, required=False,
                                   help='showcdp=0|1. Provide the CDP information for each port.')
        self.reqparse.add_argument('showdhcp', default=0, type=int, required=False,
                                   help='showdhcp=0|1. Provide the DHCP snooped information for each port.')
        super(QuickInterfaceAPI, self).__init__()

    def get(self, devicename):

        logger.debug('fn=QuickInterfaceAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        # decode query parameters and transform them into booleans. Does
        # apparently not work if done in reqparse.add_argument() above
        args = self.reqparse.parse_args()
        showmac = True if args['showmac'] else False
        showvlannames = True if args['showvlannames'] else False
        showpoe = True if args['showpoe'] else False
        showcdp = True if args['showcdp'] else False
        showdhcp = True if args['showdhcp'] else False
        logger.info(
            'fn=QuickInterfaceAPI/get : %s : showmac=%s, showvlannames=%s, showpoe=%s, showcdp=%s, showdhcp=%s' %
            (devicename, showmac, showvlannames, showpoe, showcdp, showdhcp))

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=QuickInterfaceAPI/get : %s : creating the snimpy manager' % devicename)
        # FIXME : the timeout here is probably a bad idea. The sum of apps is likely to fail
        # not specifying "bulk=N" is activating it
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        deviceinfo['sysName'] = m.sysName

        # get the mac list
        if showmac:
            macAPI = MacAPI()
            macs, total_mac_entries = macAPI.get_macs_from_device(devicename, m, ro_community)

        # collect the voice vlans
        if showvlannames:
            vlanAPI = vlanlistAPI()
            voice_vlans = vlanAPI.get_voice_vlans(devicename, m, ro_community)
            data_vlans = vlanAPI.get_vlans(devicename, m, ro_community)

        if showpoe:
            poe = self.get_poe(devicename, m)

        if showcdp:
            cdpAPI = CDPAPI()
            cdps = cdpAPI.get_cdp_from_device(devicename, m, ro_community)

        if showdhcp:
            dhcpAPI = DHCPsnoopAPI()
            dhcp_snooping_entries = dhcpAPI.get_dhcp_snooping_from_device(devicename, m, ro_community)

        # here, we collect all properties ("columns" in Snimpy speak) from the ifTable
        # we do this with single iteritems() loops, as they use Bulk-Get, which is much faster
        # the results of each loop enriches a "giant dict".
        # At the end, we do a final loop to add the stuff collected above

        # the "giant dict" indexed by the ifIndex
        interfaces = autovivification.AutoVivification()

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifDescr' % devicename)
        for index, desc in m.ifDescr.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, desc = %s' % (devicename, index, desc))
            interfaces[index]['ifDescr'] = desc

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifAdminStatus' % devicename)
        for index, adminstatus in m.ifAdminStatus.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, admin-status = %s' % (devicename, index, adminstatus))
            interfaces[index]['ifAdminStatus'], interfaces[index]['ifAdminStatusText'] = util.translate_status(str(adminstatus))

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifOperStatus' % devicename)
        for index, operstatus in m.ifOperStatus.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, oper-status = %s' % (devicename, index, operstatus))
            interfaces[index]['ifOperStatus'], interfaces[index]['ifOperStatusText'] = util.translate_status(str(operstatus))

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifType' % devicename)
        for index, iftype in m.ifType.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, iftype = %s' % (devicename, index, iftype))
            interfaces[index]['ifType'] = str(iftype)

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifMtu' % devicename)
        for index, ifmtu in m.ifMtu.iteritems():
            # logger.debug('fn=InterfaceAPI/get : %s : index = %s, ifmtu = %s' % (devicename, index, ifmtu))
            interfaces[index]['ifMtu'] = ifmtu

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifSpeed' % devicename)
        for index, ifspeed in m.ifSpeed.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, ifspeed = %s' % (devicename, index, ifspeed))
            interfaces[index]['ifSpeed'] = ifspeed

        logger.debug('fn=QuickInterfaceAPI/get : %s : get ifAlias' % devicename)
        for index, ifalias in m.ifAlias.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, ifalias = %s' % (devicename, index, ifalias))
            interfaces[index]['ifAlias'] = str(ifalias)

        logger.debug('fn=QuickInterfaceAPI/get : %s : get dot3StatsDuplexStatus' % devicename)
        for index, duplex in m.dot3StatsDuplexStatus.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, duplex = %s' % (devicename, index, duplex))
            interfaces[index]['dot3StatsDuplexStatus'] = str(duplex)
        # add a null value when an index has no entry in the dot3StatsDuplexStatus table
        for interface in interfaces:
            if not 'dot3StatsDuplexStatus' in interfaces[interface]:
                interfaces[interface]['dot3StatsDuplexStatus'] = None

        logger.debug('fn=QuickInterfaceAPI/get : %s : get vmVlan' % devicename)
        for index, vlan_id in m.vmVlan.iteritems():
            # logger.debug('fn=QuickInterfaceAPI/get : %s : index = %s, vlan_id = %s' % (devicename, index, vlan_id))
            interfaces[index]['vmVlanNative']['nr'] = vlan_id
        # add a null value when an index has no entry in the vmMembershipTable table
        for interface in interfaces:
            if not 'vmVlanNative' in interfaces[interface]:
                interfaces[interface]['vmVlanNative']['nr'] = None

        # now we add the stuff that we collected above the ifTable/get-bulk operations
        for index in interfaces:

            # ease the flatify below
            interfaces[index]['index'] = index

            # VLANs (data and voice)
            if showvlannames:

                # data vlans
                # use a temp variable for clarity
                vtpVlanIndex = interfaces[index]['vmVlanNative']['nr']
                if vtpVlanIndex in data_vlans:
                    data_vlan_name = data_vlans[vtpVlanIndex]['name']
                else:
                    data_vlan_name = None
                interfaces[index]['vmVlanNative']['name'] = data_vlan_name

                # voice vlans
                if index in voice_vlans:
                    voice_vlan_nr = int(voice_vlans[index])
                else:
                    voice_vlan_nr = 0
                interfaces[index]['vmVoiceVlanId']['nr'] = voice_vlan_nr
                if voice_vlan_nr in data_vlans:
                    voice_vlan_name = data_vlans[voice_vlan_nr]['name']
                else:
                    voice_vlan_name = ''
                interfaces[index]['vmVoiceVlanId']['name'] = voice_vlan_name

            else:

                interfaces[index]['vmVlanNative'] = {'nr': 0, 'name': None}
                interfaces[index]['vmVoiceVlanId'] = {'nr': 0, 'name': None}

            # Macs
            if showmac:
                if index in macs:
                    interfaces[index]['macs'] = macs[index]
                else:
                    interfaces[index]['macs'] = []

            # POE
            if showpoe:
                if interfaces[index]['ifDescr'] in poe:
                    interfaces[index]['poeStatus'] = str(poe[interfaces[index]['ifDescr']]['status'])
                    interfaces[index]['poePower'] = poe[interfaces[index]['ifDescr']]['power']
                else:
                    interfaces[index]['poeStatus'] = ''
                    interfaces[index]['poePower'] = None

        # now flatify the dict to an array, because that's what our consumer wants
        interfaces_array = []
        for index in interfaces:
            interfaces_array.append(interfaces[index])

        deviceinfo['interfaces'] = interfaces_array

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=QuickInterfaceAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo

    def get_poe(self, devicename, m):
        ''' get the POE info using the CISCO-POWER-ETHERNET-EXT-MIB and Entity-MIB

            return a list of poe entries, indexed by port name (eg FastEthernet1/0/15)
        '''
        # first, create a mapping EntPhyIndex --> port name (eg FastEthernet1/0/6),
        # as we don't have the if-idx in POE table below
        logger.debug('fn=QuickInterfaceAPI/get_poe : %s : create a mapping EntPhyIndex --> port name' % (devicename))

        tstart = datetime.now()

        port_mapping = {}
        # logger.info('%s : loop over entPhysicalName.iteritems' % devicename)
        counter = 0
        for index, value in m.entPhysicalName.iteritems():
            counter += 1
            port_mapping[index] = value
            # logger.debug('fn=QuickInterfaceAPI/get_poe : %s : port-mapping : ent-idx=%s, port-name=%s' %
            #             (devicename, index, port_mapping[index]))
        # logger.info('loop over entPhysicalName.iteritems done, %s entries found' % counter)


        # then, get the poe info. Returned entries are indexed by the port-name
        logger.debug('fn=QuickInterfaceAPI/get_poe : %s : get poe info' % (devicename))
        poe = {}
        # some switches cannot do any POE and answer with "End of MIB was reached"
        # and some clients might ask for POE for those even if the get-device API call
        # said "no POE". In this case, only log and return an empty table
        try:

            # new faster, bulkget-way of getting infos
            poe_parts = autovivification.AutoVivification()

            logger.debug('fn=QuickInterfaceAPI/get_poe : %s : get cpeExtPsePortPwrConsumption' % (devicename))
            for index, value in m.cpeExtPsePortPwrConsumption.iteritems():
                poe_parts[index]['cpeExtPsePortPwrConsumption'] = value

            logger.debug('fn=QuickInterfaceAPI/get_poe : %s : get pethPsePortDetectionStatus' % (devicename))
            for index, value in m.pethPsePortDetectionStatus.iteritems():
                poe_parts[index]['pethPsePortDetectionStatus'] = value

            logger.debug('fn=QuickInterfaceAPI/get_poe : %s : get cpeExtPsePortEntPhyIndex' % (devicename))
            for index, value in m.cpeExtPsePortEntPhyIndex.iteritems():
                poe_parts[index]['cpeExtPsePortEntPhyIndex'] = value

            # merge the tables to have it indexed by cpeExtPsePortEntPhyIndex so we can then
            # re-merge with port_mapping collected above
            poe_parts_merged = autovivification.AutoVivification()
            for index in poe_parts:
                poe_parts_merged[poe_parts[index]['cpeExtPsePortEntPhyIndex']]['Consumption'] = poe_parts[index]['cpeExtPsePortPwrConsumption']
                poe_parts_merged[poe_parts[index]['cpeExtPsePortEntPhyIndex']]['Status'] = poe_parts[index]['pethPsePortDetectionStatus']

            # and now the final merge
            poe_entries = 0
            for ifidx in poe_parts_merged:
                consumption = poe_parts_merged[ifidx]['Consumption']
                status = poe_parts_merged[ifidx]['Status']
                if ifidx in port_mapping:
                    port_name = port_mapping[ifidx]
                else:
                    port_name = ifidx
                '''
                logger.debug(
                    'fn=QuickInterfaceAPI/get_poe : %s : status=%s, power=%s, ent-idx=%s, port-name=%s' %
                    (devicename, status, consumption, ifidx, port_name))
                '''
                poe[port_name] = {'status': status, 'power': consumption}
                poe_entries += 1

            logger.info('fn=QuickInterfaceAPI/get_poe : %s : got %s poe entries' % (devicename, poe_entries))

        except Exception, e:
            logger.info("fn=QuickInterfaceAPI/get_poe : %s : could not get poe info, probably a device without POE. Status : %s" % (devicename, e))

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=QuickInterfaceAPI/get_poe : %s : POE collection duration=%s' % (devicename, duration))

        return poe


# -----------------------------------------------------------------------------------
# GET interfaces counters of one interface
# -----------------------------------------------------------------------------------
class InterfaceCounterAPI(Resource):
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

        logger.debug('fn=InterfaceCounterAPI/get : src=%s, %s : index=%s' %
                     (request.remote_addr, devicename, ifindex))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=InterfaceCounterAPI/get : %s : creating the snimpy manager' % devicename)
        # using no cache here to allow for quick polling
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=False,
              none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName
            deviceinfo['interface'] = str(m.ifDescr[ifindex])

            logger.debug(
                'fn=InterfaceCounterAPI/get : %s : get interface counters' % devicename)
            counters = {}
            counters['ifHCInOctets'] = m.ifHCInOctets[ifindex]
            counters['ifHCOutOctets'] = m.ifHCOutOctets[ifindex]
            counters['ifInErrors'] = m.ifInErrors[ifindex]
            counters['ifOutErrors'] = m.ifOutErrors[ifindex]

            if counters['ifHCInOctets'] and counters['ifHCInOctets']:
                counters['inOctets'] = counters['ifHCInOctets']
                counters['outOctets'] = counters['ifHCOutOctets']
            else:
                counters['inOctets'] = m.ifInOctets[ifindex]
                counters['outOctets'] = m.ifOutOctets[ifindex]

            deviceinfo['counters'] = counters

        except Exception, e:
            logger.error(
                "fn=InterfaceCounterAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=InterfaceCounterAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo


# -----------------------------------------------------------------------------------
# GET MAC(ethernet) to port mappings from a device
# -----------------------------------------------------------------------------------
class MacAPI(Resource):
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
        logger.debug('fn=MacAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=MacAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        try:
            deviceinfo['sysName'] = m.sysName

            # FIXME TODO
            # BUG : the *bulk version is probably wrong, at least it does not bring the same data set than the original version
            # macs, total_mac_entries = self.get_macs_from_device(devicename, m, ro_community)
            macs, total_mac_entries = self.get_macs_from_device_bulk(devicename, m, ro_community)

            macs_organized = []
            for ifindex in macs:
                entry = {}
                entry["index"] = ifindex
                entry["macs"] = macs[ifindex]
                macs_organized.append(entry)

        except snmp.SNMPException, e:
            logger.error("fn=MacAPI/get : %s : SNMP get failed : %s" %
                         (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration
        deviceinfo['total-mac-entries'] = total_mac_entries

        logger.info('fn=MacAPI/get : %s : duration=%s' %
                    (devicename, duration))
        deviceinfo['macs'] = macs_organized
        return deviceinfo


    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info when knowing
    # the ifIndex
    def get_macs_from_device(self, devicename, m, ro_community):
        #-------------------------
        logger.debug('fn=MacAPI/get_macs_from_device : %s' % devicename)
        macs = {}
        total_mac_entries = 0

        for entry in m.vtpVlanName:
            vlan_nr = entry[1]
            try:
                logger.debug('fn=MacAPI/get_macs_from_device : checking vlan_nr = %s' % (vlan_nr))
                vlan_type = m.vtpVlanType[entry]
                vlan_state = m.vtpVlanState[entry]
                vlan_name = m.vtpVlanName[entry]
            except:
                logger.warn(
                    "fn=MacAPI/get_macs_from_device %s : failed to get vlan detail infos. Skip to next vlan" % devicename)
                continue

            # only ethernet VLANs
            if vlan_type == 'ethernet' and vlan_state == 'operational':
                logger.debug('fn=MacAPI/get_macs_from_device : %s : polling vlan %s (%s)' %
                             (devicename, vlan_nr, vlan_name))

                # VLAN-based community, have a local manager for each VLAN
                vlan_community = "%s@%s" % (ro_community, vlan_nr)
                # can be slow for big switches, so try only once but longer
                lm = M(host=devicename,
                       community=vlan_community,
                       version=2,
                       timeout=app.config['SNMP_TIMEOUT_LONG'],
                       retries=app.config['SNMP_RETRIES_NONE'],
                       cache=app.config['SNMP_CACHE'],
                       none=True)

                # we pull them in an array so we can catch timeouts for broken IOS versions
                # happened on a big stack of 8 Cisco 3750 running 12.2(46)SE (fc2)
                try:
                    logger.debug(
                        'fn=MacAPI/get_macs_from_device : trying to pull all mac_entries for vlan %s (%s)' % (vlan_nr, vlan_name))
                    mac_entries = 0
                    for mac_entry in lm.dot1dTpFdbAddress:
                        port = lm.dot1dTpFdbPort[mac_entry]
                        if port == None:
                            logger.debug(
                                "fn=MacAPI/get_macs_from_device : %s : skip port=None" % (devicename))
                            continue

                        try:
                            ifindex = lm.dot1dBasePortIfIndex[port]
                        except Exception, e:
                            logger.debug(
                                "fn=MacAPI/get_macs_from_device : %s : port=%s, mac_entry_idx lookup failed : %s" % (devicename, port, e))

                        try:
                            mac = netaddr.EUI(mac_entry)
                            vendor = mac.oui.registration().org
                        except Exception, e:
                            #logger.info("fn=MacAPI/get_macs_from_device : %s : vendor lookup failed : %s" % (devicename, e))
                            vendor = 'unknown'

                        # logger.debug("TRACE: idx=%s, vlan=%s, mac=%s, vendor=%s" % (ifindex, vlan_nr, str(mac), vendor))
                        mac_record = {'mac': str(mac), 'vendor': vendor, 'vlan': vlan_nr}
                        if ifindex in macs:
                            macs[ifindex].append(mac_record)
                        else:
                            macs[ifindex] = [mac_record]

                        mac_entries += 1

                    total_mac_entries += mac_entries
                    logger.debug("fn=MacAPI/get_macs_from_device : %s mac entries found in vlan %s, total now %s" % (mac_entries, vlan_nr, total_mac_entries))

                except:
                    logger.info(
                        "fn=MacAPI/get_macs_from_device : failed, probably an unused VLAN (%s) on a buggy IOS producing SNMP timeout. Ignoring this VLAN" % (vlan_nr))
            else:
                logger.debug('fn=MacAPI/get_macs_from_device : %s : vlan %s (%s) skipped' % (devicename, vlan_nr, vlan_name))

        logger.debug("fn=MacAPI/get_macs_from_device : returning data, total %s mac entries found" % total_mac_entries)
        return macs, total_mac_entries

    # FIXME : BUG : the *bulk version is probably wrong, at least it does not bring the same data set than the original version
    #               and it is not really faster. Are we pulling several times the same info ? Are all dot*-table below really need to be
    #               pulled with the VLAN-based community ?
    def get_macs_from_device_bulk(self, devicename, m, ro_community):

        logger.debug('fn=MacAPI/get_macs_from_device_bulk : %s : get vlan list' % devicename)
        vlans = autovivification.AutoVivification()
        # names
        for index, value in m.vtpVlanName.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['name'] = value
        # types
        for index, value in m.vtpVlanType.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['type'] = str(value)
        # states
        for index, value in m.vtpVlanState.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['state'] = str(value)
        logger.debug('fn=MacAPI/get_macs_from_device : %s : got %s vlans' % (devicename, len(vlans)))

        # now loop across every VLAN
        macs = {}
        total_mac_entries = 0
        for vlan_nr in vlans:

            mac_entries = 0
            vlan_type = vlans[vlan_nr]['type']
            vlan_state = vlans[vlan_nr]['state']
            vlan_name = vlans[vlan_nr]['name']
            logger.debug('fn=MacAPI/get_macs_from_device : checking vlan_nr = %s, name = %s, type = %s, state = %s' % (vlan_nr, vlan_name, vlan_type, vlan_state))

            # only ethernet VLANs
            if vlan_type == 'ethernet(1)' and vlan_state == 'operational(1)':
                logger.debug('fn=MacAPI/get_macs_from_device : %s : polling vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

                # VLAN-based community, have a local manager for each VLAN
                vlan_community = "%s@%s" % (ro_community, vlan_nr)
                # can be slow for big switches, so try only once but longer
                lm = M(host=devicename,
                       community=vlan_community,
                       version=2,
                       timeout=app.config['SNMP_TIMEOUT_LONG'],
                       retries=app.config['SNMP_RETRIES_NONE'],
                       cache=app.config['SNMP_CACHE'],
                       none=True)

                # we pull them in an large block so we can catch timeouts for broken IOS versions
                # happened on a big stack of 8 Cisco 3750 running 12.2(46)SE (fc2)
                vlan_is_interesting = False
                try:
                    logger.debug('fn=MacAPI/get_macs_from_device : trying to pull all mac_entries for vlan %s (%s)' % (vlan_nr, vlan_name))

                    dot1dTpFdbAddress = {}
                    for index, mac_entry in lm.dot1dTpFdbAddress.iteritems():
                        dot1dTpFdbAddress[index] = mac_entry
                        mac_entries += 1
                    logger.debug('fn=MacAPI/get_macs_from_device : got %s dot1dTpFdbAddress entries for vlan %s (%s)' % (len(dot1dTpFdbAddress), vlan_nr, vlan_name))
                    if mac_entries > 0:
                        vlan_is_interesting = True

                    dot1dTpFdbPort = {}
                    dot1dBasePortIfIndex = {}
                    if vlan_is_interesting:
                        for index, port in lm.dot1dTpFdbPort.iteritems():
                            dot1dTpFdbPort[index] = port
                        logger.debug('fn=MacAPI/get_macs_from_device : got %s dot1dTpFdbPort entries for vlan %s (%s)' % (len(dot1dTpFdbPort), vlan_nr, vlan_name))

                        for index, ifindex in lm.dot1dBasePortIfIndex.iteritems():
                            dot1dBasePortIfIndex[index] = ifindex
                        logger.debug('fn=MacAPI/get_macs_from_device : got %s dot1dBasePortIfIndex entries for vlan %s (%s)' % (len(dot1dBasePortIfIndex), vlan_nr, vlan_name))
                    else:
                        logger.debug('fn=MacAPI/get_macs_from_device : vlan %s (%s) skipped, no MAC found on it' % (vlan_nr, vlan_name))

                except:
                    logger.info("fn=MacAPI/get_macs_from_device : failed, probably an unused VLAN (%s) on a buggy IOS producing SNMP timeout. Ignoring this VLAN" % (vlan_nr))

                if vlan_is_interesting:
                    logger.debug('fn=MacAPI/get_macs_from_device : enrich MAC table for vlan %s (%s)' % (vlan_nr, vlan_name))
                    for mac_entry in dot1dTpFdbAddress:
                        port = dot1dTpFdbPort[mac_entry]
                        if port == None:
                            logger.debug("fn=MacAPI/get_macs_from_device : %s vlan %s : skip port=None" % (devicename, vlan_nr))
                            continue

                        try:
                            ifindex = dot1dBasePortIfIndex[port]
                        except Exception, e:
                            logger.debug("fn=MacAPI/get_macs_from_device : %s : port=%s, mac_entry_idx lookup failed : %s" % (devicename, port, e))

                        try:
                            mac = netaddr.EUI(mac_entry)
                            vendor = mac.oui.registration().org
                        except Exception, e:
                            # logger.info("fn=MacAPI/get_macs_from_device : %s : vendor lookup failed : %s" % (devicename, e))
                            vendor = 'unknown'

                        # logger.debug("TRACE: idx=%s, vlan=%s, mac=%s, vendor=%s" % (ifindex, vlan_nr, str(mac), vendor))
                        mac_record = {'mac': str(mac), 'vendor': vendor, 'vlan': vlan_nr}
                        if ifindex in macs:
                            macs[ifindex].append(mac_record)
                        else:
                            macs[ifindex] = [mac_record]
                else:
                    logger.debug('fn=MacAPI/get_macs_from_device : vlan %s (%s) skipped, no MAC found on it' % (vlan_nr, vlan_name))

            else:
                logger.debug('fn=MacAPI/get_macs_from_device : %s : skipping vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

            logger.debug("fn=MacAPI/get_macs_from_device : %s mac entries found in vlan %s (%s)" % (mac_entries, vlan_nr, vlan_name))
            total_mac_entries += mac_entries

        logger.debug("fn=MacAPI/get_macs_from_device : returning data, total %s mac entries found" % total_mac_entries)
        return macs, total_mac_entries


# -----------------------------------------------------------------------------------
# GET CDP info from a device
# -----------------------------------------------------------------------------------
class CDPAPI(Resource):
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
        logger.debug('fn=CDPAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=CDPAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        try:
            deviceinfo['sysName'] = m.sysName

            cdps = self.get_cdp_from_device(devicename, m, ro_community)

            cdps_organized = []
            for ifindex in cdps:
                entry = {}
                entry["index"] = ifindex
                entry["cdpCacheDeviceId"] = cdps[ifindex]['cdpCacheDeviceId']
                entry["cdpCacheDevicePort"] = cdps[
                    ifindex]['cdpCacheDevicePort']
                entry["cdpCachePlatform"] = cdps[ifindex]['cdpCachePlatform']
                entry["cdpCacheLastChange"] = cdps[
                    ifindex]['cdpCacheLastChange']
                cdps_organized.append(entry)

        except snmp.SNMPException, e:
            logger.error("fn=CDPAPI/get : %s : SNMP get failed : %s" %
                         (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=CDPAPI/get : %s : duration=%s' %
                    (devicename, duration))
        deviceinfo['cdp'] = cdps_organized
        return deviceinfo

    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info when knowing
    # the ifIndex
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
            logger.warn(
                "fn=CDPAPI/get_cdp_from_device : failed SNMP get for CDP")

        logger.debug("fn=CDPAPI/get_cdp_from_device : returning data")
        return cdps


# -----------------------------------------------------------------------------------
# GET interface trunk info from a device
# -----------------------------------------------------------------------------------
class TrunkAPI(Resource):
    __doc__ = '''{
        "name": "TrunkAPI",
        "description": "GET interface Trunk info from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of info indexed by ifIndex."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
        #-------------------------
        logger.debug('fn=TrunkAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=TrunkAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        try:
            deviceinfo['sysName'] = m.sysName

            trunks = self.get_trunks_from_device(devicename, m, ro_community)

        except snmp.SNMPException, e:
            logger.error("fn=TrunkAPI/get : %s : SNMP get failed : %s" %
                         (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=TrunkAPI/get : %s : duration=%s' % (devicename, duration))
        deviceinfo['trunks'] = trunks
        return deviceinfo

    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info
    def get_trunks_from_device(self, devicename, m, ro_community):

        logger.debug('fn=TrunkAPI/get_trunks_from_device : %s' % devicename)

        trunks = autovivification.AutoVivification()
        try:

            for index, value in m.vlanTrunkPortDynamicState.iteritems():
                logger.debug("fn=TrunkAPI/get_trunks_from_device/1 : trunk : %s, %s" % (index, value))
                trunks[index]['trunkAdminState'] = str(value)

            for index, value in m.vlanTrunkPortDynamicStatus.iteritems():
                logger.debug("fn=TrunkAPI/get_trunks_from_device/2 : trunk : %s, %s" % (index, value))
                trunks[index]['trunkOperState'] = str(value)

        except snmp.SNMPException, e:
            logger.warn("fn=TrunkAPI/get_trunks_from_device : failed SNMP get for Trunks : %s" % e)

        logger.debug("fn=TrunkAPI/get_trunks_from_device : returning data")
        return trunks


# -----------------------------------------------------------------------------------
# GET ARP info from a device
# -----------------------------------------------------------------------------------
class ARPAPI(Resource):
    __doc__ = '''{
        "name": "ARPAPI",
        "description": "GET ARP info from a device (MAC to IP)",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of entries."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
        # -------------------------
        logger.debug('fn=ARPAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=ARPAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              bulk=True,
              none=True)

        try:
            deviceinfo['sysName'] = m.sysName
            oid_used, nbr_arp_entries, arps = self.get_arp_from_device(devicename, m, ro_community)

        except snmp.SNMPException, e:
            logger.error("fn=ARPAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=ARPAPI/get : %s : duration=%s' % (devicename, duration))
        deviceinfo['arp'] = arps
        deviceinfo['arp_nbr_entries'] = nbr_arp_entries
        deviceinfo['oid_used'] = oid_used
        return deviceinfo

    # the real collection stuff
    def get_arp_from_device(self, devicename, m, ro_community):

        nbr_of_entries = 0
        logger.debug('fn=ARPAPI/get_arp_from_device : %s : trying current OID' % devicename)
        try:
            i = 0
            oid_used = 'ipNetToPhysicalPhysAddress (current)'
            arps = []
            for index, value in m.ipNetToPhysicalPhysAddress.iteritems():
                ipNetToPhysicalIfIndex, ipNetToPhysicalNetAddressType, ipNetToPhysicalNetAddress = index
                entry = {}
                entry['ifindex'] = ipNetToPhysicalIfIndex
                entry['mac'] = str(netaddr.EUI(str(value)))
                entry['ip'] = util.convert_ip_from_snmp_format(ipNetToPhysicalNetAddressType, ipNetToPhysicalNetAddress)
                arps.append(entry)
                i += 1

            nbr_of_entries = i
            logger.info("fn=ARPAPI/get_arp_from_device : %s : got %s ARP entries" % (devicename, nbr_of_entries))

        except snmp.SNMPException, e:
            if str(e) == 'no more stuff after this OID':
                logger.info('fn=ARPAPI/get_arp_from_device : %s : empty results, probably unsupported OID: %s' % (devicename, e))
            else:
                logger.warn('fn=ARPAPI/get_arp_from_device : %s : %s' % (devicename, e))

        # success, do not try deprecated MIB/OID below
        if nbr_of_entries > 0:
            logger.debug(
                "fn=ARPAPI/get_arp_from_device : %s : returning %s ARP entries gathered using %s" % (
                devicename, nbr_of_entries, oid_used))
            return oid_used, nbr_of_entries, arps

        # continue with deprecated MIB/OID
        logger.debug('fn=ARPAPI/get_arp_from_device %s retry using deprecated OID (ipNetToMediaPhysAddress)' % devicename)
        try:
            i = 0
            oid_used = 'ipNetToMediaPhysAddress (deprecated)'
            for index, value in m.ipNetToMediaPhysAddress.iteritems():
                ipNetToMediaIfIndex, ipNetToMediaNetAddress = index
                entry = {}
                entry['ifindex'] = ipNetToMediaIfIndex
                entry['mac'] = str(netaddr.EUI(netaddr.strategy.eui48.packed_to_int(value)))
                entry['ip'] = str(ipNetToMediaNetAddress)
                arps.append(entry)
                i += 1

            nbr_of_entries = i
            logger.info("fn=ARPAPI/get_arp_from_device : %s : got %s ARP entries" % (devicename, nbr_of_entries))

        except snmp.SNMPException, e:
            logger.warn('fn=ARPAPI/get_arp_from_device : %s : %s' % (devicename, e))

        # possible enhancement: if both ipNetToPhysicalPhysAddress and ipNetToMediaPhysAddress
        # bring empty results, 1.3.6.1.2.1.3.1 (RFC1213-MIB) might do the job.

        logger.debug(
            "fn=ARPAPI/get_arp_from_device : %s : returning %s ARP entries gathered using %s" % (
            devicename, nbr_of_entries, oid_used))
        return oid_used, nbr_of_entries, arps


# -----------------------------------------------------------------------------------
# GET DHCP snooping info from a device
# -----------------------------------------------------------------------------------
class DHCPsnoopAPI(Resource):
    __doc__ = '''{
        "name": "DHCPsnoopAPI",
        "description": "GET DHCP snooping info from a device",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": [],
        "returns": "A list of DHCP snooped entries indexed by ifIndex."
    }'''
    decorators = [auth.login_required]

    def get(self, devicename):
        #-------------------------
        logger.debug('fn=DHCPsnoopAPI/get : src=%s, %s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=DHCPsnoopAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        try:
            deviceinfo['sysName'] = m.sysName
            deviceinfo['dhcpsnoop'] = self.get_dhcp_snooping_from_device(
                devicename, m, ro_community)

        except snmp.SNMPException, e:
            logger.error(
                "fn=DHCPsnoopAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=DHCPsnoopAPI/get : %s : duration=%s' %
                    (devicename, duration))
        return deviceinfo

    # list of DHCP snopped entries. some interfaces (idx) can occur multiple times,
    # called from DHCPsnoopAPI/get above, and optionally by InterfaceAPI/get
    # if asked so
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

        logger.debug(
            'fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s' % devicename)
        dhcp_snooping_entries = []
        try:
            for entry in m.cdsBindingsAddrType:
                vlan = int(entry[0])
                mac = str(entry[1])
                # reformat mac: comes as "0:22:90:1b:6:e6" and should be
                # "00-22-90-1B-06-E6"
                mac_e = netaddr.EUI(mac)
                mac_f = str(mac_e)
                # add vendor
                try:
                    vendor = mac_e.oui.registration().org
                except netaddr.NotRegisteredError as e:
                    logger.warn('fn=DHCPsnoopAPI: %s : error %s : unknown vendor for %s' % (
                        devicename, e, mac_f))
                    vendor = 'unknown'
                address_type = inet_address_types.get(
                    m.cdsBindingsAddrType[entry], 'unsupported')
                ip = util.convert_ip_from_snmp_format(address_type, m.cdsBindingsIpAddress[entry])
                interface_idx = m.cdsBindingsInterface[entry]
                leased_time = m.cdsBindingsLeasedTime[entry]
                status = binding_status.get(
                    m.cdsBindingsStatus[entry], 'unsupported')
                hostname = m.cdsBindingsHostname[entry]

                logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device %s : vlan=%s, mac=%s, vendor=%s, address_type=%s, ip=%s, interface_idx=%s, leased_time=%s, status=%s, hostname=%s' %
                             (devicename, vlan, mac_f, vendor, address_type, ip, interface_idx, leased_time, status, hostname))
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
            logger.warn(
                "fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : failed SNMP get for DHCP snooping : %s" % e)

        logger.debug(
            "fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : returning data")
        return dhcp_snooping_entries


# -----------------------------------------------------------------------------------
# GET vlan list from a device
# -----------------------------------------------------------------------------------
class vlanlistAPI(Resource):
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

        logger.debug('fn=vlanlistAPI/get : src=%s, device=%s' % (request.remote_addr, devicename))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=vlanlistAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=ro_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName

            logger.debug('fn=vlanlistAPI/get : %s : get data vlan list' %
                         devicename)
            vlans_lookup_table = self.get_vlans(devicename, m, ro_community)

            vlans = []
            for entry in vlans_lookup_table:
                vlan = {}
                vlan['nr'] = entry
                vlan['type'] = vlans_lookup_table[entry]['type']
                vlan['state'] = vlans_lookup_table[entry]['state']
                vlan['name'] = vlans_lookup_table[entry]['name']
                vlans.append(vlan)
            deviceinfo['vlans'] = vlans

        except Exception, e:
            logger.error(
                "fn=vlanlistAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=vlanlistAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo

    def get_vlans(self, devicename, m, ro_community):
        ''' return a VLAN dict indexed by vlan-nr '''

        logger.debug('fn=vlanlistAPI/get_vlans : %s : get data vlan list' % devicename)

        vlans = autovivification.AutoVivification()
        # names
        for index, value in m.vtpVlanName.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['name'] = value
        # types
        for index, value in m.vtpVlanType.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['type'] = str(value)
        # states
        for index, value in m.vtpVlanState.iteritems():
            managementDomainIndex, vtpVlanIndex = index
            vlans[vtpVlanIndex]['state'] = str(value)

        return vlans


    def get_voice_vlans(self, devicename, m, ro_community):
        ''' return a VOICE_VLAN dict indexed by vlan-nr '''

        logger.debug('fn=vlanlistAPI/get_voice_vlans : %s : get voice vlan list' % devicename)
        voice_vlans = {}
        # some routers (Cisco 1921) return empty list, producing an error upstream.
        # Catch it and return an empty list
        try:

            for index, value in m.vmVoiceVlanId.iteritems():
                # logger.debug('fn=vlanlistAPI/get_voice_vlans : %s : got voice vlan %s for index %s' % (devicename, value, index))
                voice_vlans[index] = str(value)

        except Exception, e:
            logger.info("fn=vlanlistAPI/get_voice_vlans : %s : SNMP get failed : %s" % (devicename, e))

        return voice_vlans


# -----------------------------------------------------------------------------------
# PUT on a vlan : assign the port to a VLAN
# /aj/api/v1/interfaces/vlan/$fqdn/$ifindex
# -----------------------------------------------------------------------------------
class PortToVlanAPI(Resource):
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
        self.reqparse.add_argument(
            'vlan', type=str, required=True, help='No vlan number provided')
        self.reqparse.add_argument(
            'uuid', type=str, required=mandate_uuid, help='No uuid provided')
        super(PortToVlanAPI, self).__init__()

    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        vlan = args['vlan']
        uuid = args['uuid']

        logger.info('fn=PortToVlanAPI/put : src=%s, %s : ifindex=%s, vlan=%s, uuid=%s' %
                    (request.remote_addr, devicename, ifindex, vlan, uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']
        if not check.check_snmp(M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug(
            'fn=PortToVlanAPI/get : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=rw_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        # all SNMP ops under one big try
        try:

            # assign the vlan to the port
            m.vmVlan[ifindex] = vlan

        except Exception, e:
            logger.error(
                "fn=PortToVlanAPI/get : %s : SNMP get failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'SNMP get failed on %s, cause : %s' % (devicename, e)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug('fn=PortToVlanAPI/put : %s : VLAN %s assigned to interface-idx %s successfully' %
                     (devicename, vlan, ifindex))

        return {'info': '%s : VLAN %s assigned to interface-idx %s successfully' % (devicename, vlan, ifindex), 'duration': duration}


# -----------------------------------------------------------------------------------
# PUT on an interface : configure the interface
# /aj/api/v1/interface/config/$fqdn/$ifindex
# -----------------------------------------------------------------------------------
class InterfaceConfigAPI(Resource):
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
        self.reqparse.add_argument(
            'ifAdminStatus', type=int, required=False, help='No ifAdminStatus value')
        self.reqparse.add_argument(
            'ifAlias',       type=str, required=False, help='No ifAlias value')
        self.reqparse.add_argument(
            'uuid',          type=str, required=mandate_uuid, help='No uuid provided')
        super(InterfaceConfigAPI, self).__init__()

    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        ifAdminStatus = args['ifAdminStatus']
        ifAlias = args['ifAlias']
        uuid = args['uuid']

        logger.info('fn=InterfaceConfigAPI/put : src=%s,, %s : ifindex=%s, '
                    'ifAdminStatus=%s, ifAlias=%s, uuid=%s' %
                    (request.remote_addr, devicename, ifindex, ifAdminStatus, ifAlias,
                     uuid))

        tstart = datetime.now()

        rw_community = credmgr.get_credentials(devicename)['rw_community']
        if not check.check_snmp(M, devicename, rw_community, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug(
            'fn=InterfaceConfigAPI/put : %s : creating the snimpy manager' % devicename)
        m = M(host=devicename,
              community=rw_community,
              version=2,
              timeout=app.config['SNMP_TIMEOUT'],
              retries=app.config['SNMP_RETRIES'],
              cache=app.config['SNMP_CACHE'],
              none=True)

        try:
            # assign the values to the port
            if ifAdminStatus is not None:
                logger.debug(
                    'fn=InterfaceConfigAPI/put : %s : set ifAdminStatus' % devicename)
                m.ifAdminStatus[ifindex] = ifAdminStatus
            if ifAlias is not None:
                logger.debug(
                    'fn=InterfaceConfigAPI/put : %s : set ifAlias' % devicename)
                m.ifAlias[ifindex] = ifAlias
        except Exception, e:
            logger.error(
                "fn=InterfaceConfigAPI/put : %s : interface configuration failed : %s" % (devicename, e))
            return errst.status('ERROR_OP', 'interface configuration failed : %s' % e), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug(
            'fn=InterfaceConfigAPI/put : %s : interface configured successfully' % devicename)
        return {'info': 'interface configured successfully', 'duration': duration}


# -----------------------------------------------------------------------------------
# SNMP get or walk on a OID
# this goes a bit beside the idea of this web-service, but it brings flexibility
# FIXME: walk provide too much info if eg done on a single get instance like 1.3.6.1.2.1.1.3.0
# -----------------------------------------------------------------------------------
class OIDpumpAPI(Resource):
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

        logger.debug('fn=OIDpumpAPI/get : src=%s, %s : pdu=%s, oid=%s' %
                     (request.remote_addr, devicename, pdu, oid))

        tstart = datetime.now()

        ro_community = credmgr.get_credentials(devicename)['ro_community']
        if not check.check_snmp(M, devicename, ro_community, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug(
            'fn=OIDpumpAPI/get : %s : creating the SNMP session' % devicename)
        session = snmp.Session(devicename, community=ro_community, version=2)

        if pdu == 'get':
            try:
                data = session.get(str(oid))
            except Exception, e:
                logger.error(
                    "fn=OIDpumpAPI/get : %s : oid get failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid get failed: %s' % e), 200

        elif pdu == 'walk':
            try:
                data = session.walk(str(oid))
            except Exception, e:
                logger.error(
                    "fn=OIDpumpAPI/get : %s : oid walk failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid walk failed: %s' % e), 200

        else:
            return errst.status('ERROR_SNMP_PDU', 'unknown PDU value : %s' % pdu), 200

        # try to unpack the Python tuples. Not sure it will work with all sorts
        # of get/walk results
        entries = {}
        for entry in data:
            oid = '.'.join(map(str, entry[0]))
            if type(entry[1]) == tuple:
                value = '.'.join(map(str, entry[1]))
            else:
                value = str(entry[1])
            entries[oid] = value

        deviceinfo['data'] = entries

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=OIDpumpAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo


# -----------------------------------------------------------------------------------
# PUT on a device : run commands over ssh
# /aj/api/v1/device/ssh/$fqdn
# -----------------------------------------------------------------------------------
class DeviceSshAPI(Resource):
    __doc__ = '''{
        "name": "DeviceSshAPI",
        "description": "PUT on a device : run commands over ssh. Do NOT terminate your command list with logout/exit/etc.",
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
        self.reqparse.add_argument(
            'CmdList',       type=str, required=True, help='missing command list')
        self.reqparse.add_argument(
            'uuid',          type=str, required=mandate_uuid, help='No uuid provided')
        self.reqparse.add_argument('driver',        type=str, required=True,
                                   help='missing driver, use one of http://knipknap.github.io/exscript/api/Exscript.protocols.drivers-module.html, eg ios')
        super(DeviceSshAPI, self).__init__()

    def put(self, devicename):

        args = self.reqparse.parse_args()
        uuid = args['uuid']
        driver = args['driver']
        logger.debug("fn=DeviceSshAPI/put : src=%s, Received CmdList = <%s>" %
                     (request.remote_addr, args['CmdList']))
        try:
            cmdlist = loads(args['CmdList'])
        except Exception, e:
            logger.error("fn=DeviceSshAPI/put : %s : %s : device configuration failed : cmds list is no valid JSON. Received CmdList = <%s>" %
                         (devicename, e, args['CmdList']))
            return errst.status('ERROR_OP', 'device configuration failed : cmds list is no valid JSON : %s. Try with something like this without the backslashes : ["terminal length 0", "show users", "show version"]' % e), 500

        logger.info('fn=DeviceSshAPI/put : %s : commands=%s, uuid=%s' %
                    (devicename, cmdlist, uuid))

        # we need the credentials from outside
        credentials = credmgr.get_credentials(devicename)


        tstart = datetime.now()

        # WSGI does not accept playing with stdin and stdout. Save them before
        # doing ssh and restore them afterwards
        save_stdout = sys.stdout
        save_stdin = sys.stdin
        sys.stdout = sys.stderr
        sys.stdin = ''
        (status, output_global, output_indexed) = \
            commander.run_by_ssh(
                devicename,
                credentials['username'],
                credentials['password'],
                driver,
                cmdlist)
        sys.stdout = save_stdout
        sys.stdin = save_stdin

        if status == 0:
            logger.debug('fn=DeviceSshAPI/put : %s : status = %s, output_indexed=%s, output_global = %s' %
                         (devicename, status, output_indexed, output_global))
        else:
            logger.error('fn=DeviceSshAPI/put : %s : status = %s, output_indexed=%s, output global = %s' %
                         (devicename, status, output_indexed, output_global))
            return errst.status('ERROR_OP', 'device commands by ssh failed : status=%s, output_indexed=%s, output_global=%s' % (status, output_indexed, output_global)), 200

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000

        logger.debug(
            'fn=DeviceSshAPI/put : %s : device commands successful' % devicename)
        return {'info': 'device commands successful', 'duration': duration, 'output_indexed': output_indexed}


# -----------------------------------------------------------------------------------
# instantiate the Flask application and the REST api
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
api = Api(app)


# -----------------------------------------------------------------------------------
# logging
# -----------------------------------------------------------------------------------

log_file = app.config['LOGFILE']
global logger
logger = logging.getLogger('aj')
hdlr = logging.handlers.RotatingFileHandler(log_file,
                                            maxBytes=app.config['LOG_MAX_SIZE'],
                                            backupCount=app.config['LOG_BACKUP_COUNT'])
# we have the PID in each log entry to differentiate parallel processes writing to the log
FORMAT = "%(asctime)s - %(process)d - %(name)-16s - %(levelname)-7s - %(" \
         "message)s"
formatter = logging.Formatter(FORMAT)
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
# avoid propagation to console
logger.propagate = False
if app.config['DEBUG']:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

logger.info('version : <%s>' % __version__)
logger.info('environment : <%s>' % app.config['ENVI'])
mandate_uuid = app.config['MANDATE_UUID']
logger.info('mandate_uuid : <%s>' % mandate_uuid)
logger.info('SNMP cache = %ss' % app.config['SNMP_CACHE'])
logger.info('SNMP timeout = %ss' % app.config['SNMP_TIMEOUT'])
logger.info('SNMP retries = %ss' % app.config['SNMP_RETRIES'])


# -----------------------------------------------------------------------------------
# add all URLs and their corresponding classes
# -----------------------------------------------------------------------------------
doc = DocCollection()

api.add_resource(DeviceAPI,
                 '/aj/api/v1/device/<string:devicename>')
doc.add(loads(DeviceAPI.__doc__),
        '/aj/api/v1/device/<string:devicename>',
        DeviceAPI.__dict__['methods'])

api.add_resource(DeviceActionAPI,
                 '/aj/api/v1/device/<string:devicename>/action')
doc.add(loads(DeviceActionAPI.__doc__),
        '/aj/api/v1/device/<string:devicename>/action',
        DeviceActionAPI.__dict__['methods'])

api.add_resource(DeviceSaveAPI,
                 '/aj/api/v1/devicesave/<string:devicename>')
doc.add(loads(DeviceSaveAPI.__doc__),
        '/aj/api/v1/devicesave/<string:devicename>',
        DeviceSaveAPI.__dict__['methods'])

api.add_resource(InterfaceAPI,
                 '/aj/api/v1/interfaces/<string:devicename>')
doc.add(loads(InterfaceAPI.__doc__),
        '/aj/api/v1/interfaces/<string:devicename>',
        InterfaceAPI.__dict__['methods'])

api.add_resource(QuickInterfaceAPI,
                 '/aj/api/v2/interfaces/<string:devicename>')
doc.add(loads(QuickInterfaceAPI.__doc__),
        '/aj/api/v2/interfaces/<string:devicename>',
        QuickInterfaceAPI.__dict__['methods'])

api.add_resource(InterfaceCounterAPI,
                 '/aj/api/v1/interface/counter/<string:devicename>/<string:ifindex>')
doc.add(loads(InterfaceCounterAPI.__doc__),
        '/aj/api/v1/interface/counter/<string:devicename>/<string:ifindex>',
        InterfaceCounterAPI.__dict__['methods'])

api.add_resource(MacAPI,
                 '/aj/api/v1/macs/<string:devicename>')
doc.add(loads(MacAPI.__doc__),
        '/aj/api/v1/macs/<string:devicename>',
        MacAPI.__dict__['methods'])

api.add_resource(DHCPsnoopAPI,
                 '/aj/api/v1/dhcpsnoop/<string:devicename>')
doc.add(loads(DHCPsnoopAPI.__doc__),
        '/aj/api/v1/dhcpsnoop/<string:devicename>',
        DHCPsnoopAPI.__dict__['methods'])

api.add_resource(vlanlistAPI,
                 '/aj/api/v1/vlans/<string:devicename>')
doc.add(loads(vlanlistAPI.__doc__),
        '/aj/api/v1/vlans/<string:devicename>',
        vlanlistAPI.__dict__['methods'])

api.add_resource(PortToVlanAPI,
                 '/aj/api/v1/vlan/<string:devicename>/<string:ifindex>')
doc.add(loads(PortToVlanAPI.__doc__),
        '/aj/api/v1/vlan/<string:devicename>/<string:ifindex>',
        PortToVlanAPI.__dict__['methods'])

api.add_resource(InterfaceConfigAPI,
                 '/aj/api/v1/interface/config/<string:devicename>/<string:ifindex>')
doc.add(loads(InterfaceConfigAPI.__doc__),
        '/aj/api/v1/interface/config/<string:devicename>/<string:ifindex>',
        InterfaceConfigAPI.__dict__['methods'])

api.add_resource(OIDpumpAPI,
                 '/aj/api/v1/oidpump/<string:devicename>/<string:pdu>/<string:oid>')
doc.add(loads(OIDpumpAPI.__doc__),
        '/aj/api/v1/oidpump/<string:devicename>/<string:pdu>/<string:oid>',
        OIDpumpAPI.__dict__['methods'])

api.add_resource(DeviceSshAPI,
                 '/aj/api/v1/device/ssh/<string:devicename>')
doc.add(loads(DeviceSshAPI.__doc__),
        '/aj/api/v1/device/ssh/<string:devicename>',
        DeviceSshAPI.__dict__['methods'])

api.add_resource(CDPAPI,
                 '/aj/api/v1/cdp/<string:devicename>')
doc.add(loads(CDPAPI.__doc__),
        '/aj/api/v1/cdp/<string:devicename>',
        CDPAPI.__dict__['methods'])

api.add_resource(TrunkAPI,
                 '/aj/api/v1/trunk/<string:devicename>')
doc.add(loads(TrunkAPI.__doc__),
        '/aj/api/v1/trunk/<string:devicename>',
        TrunkAPI.__dict__['methods'])

api.add_resource(ARPAPI,
                 '/aj/api/v1/arp/<string:devicename>')
doc.add(loads(ARPAPI.__doc__),
        '/aj/api/v1/arp/<string:devicename>',
        ARPAPI.__dict__['methods'])


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
commander = sshcmd.SshCmd(logger)


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
    return make_response(jsonify({'message': 'Unauthorized access'}), 401)
    # returning 403 instead of 401 would prevent browsers from displaying the
    # default auth dialog


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
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
    app.run(host=app.config['BIND_IP'],
            port=app.config['BIND_PORT'],
            debug=app.config['DEBUG'])

# normal run
if True:
    if __name__ == '__main__':
        logger.info('AJ start')
        app.run(host=app.config['BIND_IP'],
                port=app.config['BIND_PORT'],
                debug=app.config['DEBUG'])
        logger.info('AJ end')
