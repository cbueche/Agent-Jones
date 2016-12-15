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
__version__ = '7.12.2016'

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

# etc/credentials.py knows how to get the credentials for a device (SNMMP, login, etc)
import credentials

# etc/auth_external.py controls how Agent-Jones is accessed
import auth_external


import utils
import access_checks
import error_handling
import sysoidan
import entity_vendortype
import sshcmd
import snmpmgr

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

# VendorType matching
load(mib_path + "CISCO-ENTITY-VENDORTYPE-OID-MIB.my")


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

    @auth.login_required
    def get(self, devicename):

        logger.debug('fn=DeviceAPI/get : src=%s, device=%s' % (request.remote_addr, devicename))
        logaction(classname='DeviceAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        logger.debug('fn=DeviceAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, bulk=False)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        logger.debug('fn=DeviceAPI/get : %s : request device info' % devicename)
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
            logger.trace('fn=DeviceAPI/get : %s : back from get_serial' % devicename)

            # sysoid mapping
            logger.trace('fn=DeviceAPI/get : %s : translate_sysoid %s' % (devicename, deviceinfo['sysObjectID']))
            (deviceinfo['hwVendor'], deviceinfo['hwModel']) = sysoidmap.translate_sysoid(deviceinfo['sysObjectID'])

        except Exception, e:
            logger.error(
                "fn=DeviceAPI/get : %s : SNMP get of generic aspects for device failed : %s" % (devicename, e))
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
                "fn=DeviceAPI/get_serial : %s : SNMPException in get_serial/get-cswSwitchNumCurrent : <%s>" % (
                devicename, e))
        except Exception, e:
            logger.info(
                "fn=DeviceAPI/get_serial : %s : Exception in get_serial/get-cswSwitchNumCurrent : <%s>" % (
                devicename, e))

        logger.debug("fn=DeviceAPI/get_serial : %s : walk entPhysicalClass" % devicename)
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
                "fn=DeviceAPI/get_serial : %s : SNMPException in get_serial/get-entPhysicalClass : <%s>" % (
                devicename, e))
        except Exception, e:
            logger.info(
                "fn=DeviceAPI/get_serial : %s : Exception in get_serial/get-entPhysicalClass : <%s>" % (
                devicename, e))

        # found something ?
        if len(hardware_info) == 0:
            logger.warn("fn=DeviceAPI/get_serial : %s : could not get an entity parent" % devicename)
        else:
            logger.debug("fn=DeviceAPI/get_serial : %s : got %s serial(s)" % (devicename, len(hardware_info)))

        logger.trace("fn=DeviceAPI/get_serial : %s : returning counter=%s, hardware_info=%s)" % (devicename, len(hardware_info), hardware_info))
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
        "params": ["type=ping", "clientinfo=JoBar"],
        "returns": "Results of the action."
    }'''

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('type', type=str, required=True, help='No action provided')
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(DeviceActionAPI, self).__init__()

    @auth.login_required
    def post(self, devicename):

        args = self.reqparse.parse_args()
        action = args['type']

        logger.debug('fn=DeviceActionAPI/post : src=%s, %s / %s' %
                     (request.remote_addr, devicename, action))
        logaction(classname='DeviceActionAPI', methodname='post', devicename=devicename, params=args,
                  mode='rw', src_ip=request.remote_addr, src_user=auth.username())

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
        "params": ["uuid=UUID (optional, used to identify the write request in logs)", "clientinfo=JoBar"],
        "returns": "status info"
    }
    '''

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('uuid', type=str, required=mandate_uuid, help='No uuid provided')
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(DeviceSaveAPI, self).__init__()

    @auth.login_required
    def put(self, devicename):

        args = self.reqparse.parse_args()
        uuid = args['uuid']

        logger.info('fn=DeviceSaveAPI/put : src=%s, %s, uuid=%s' % (
            request.remote_addr, devicename, uuid))
        logaction(classname='DeviceSaveAPI', methodname='put', devicename=devicename, params=args,
                  mode='rw', src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=DeviceSaveAPI/put : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, cache=0, rw=True)

        if not check.check_snmp(m, devicename, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

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
# uses bulk-get where possible
# -----------------------------------------------------------------------------------
class InterfaceAPI(Resource):
    __doc__ = '''{
        "name": "InterfaceAPI",
        "description": "GET interfaces from a device. Adding ?showmac=1 to the URI will list the MAC addresses of devices connected to ports. Adding ?showvlannames=1 will show the vlan names for each vlan. Adding ?showpoe=1 will provide the power consumption for each port. Adding ?showcdp=1 will provide CDP information for each port. Adding ?showdhcp=1 will collect DHCP snooping information for each port. Adding showtrunks=1 will collect trunk attributes for each interfaces. All these options add significant time and overhead to the collection process.",
        "auth": true,
        "auth-type": "BasicAuth",
        "params": ["clientinfo=JoBar"],
        "returns": "A list of device interfaces."
    }'''

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
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(InterfaceAPI, self).__init__()

    @auth.login_required
    def get(self, devicename):

        logger.debug('fn=InterfaceAPI/get : src=%s, %s' % (request.remote_addr, devicename))

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
        logaction(classname='InterfaceAPI', methodname='get', devicename=devicename,
                  params=args, src_ip=request.remote_addr, src_user=auth.username())

        logger.debug('fn=InterfaceAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename
        deviceinfo['sysName'] = m.sysName

        # collect the mapping between interfaces and entities
        # constructs a table (dict) 'ifname' --> 'enclosing-chassis'
        # e.g. {<String: GigabitEthernet1/0/5>: <Integer: 1001>, etc}
        entities = self.collect_entities(m, devicename)
        merged_entities = self.merge_entities(entities, devicename)
        entities_if_to_chassis = self.get_ports(merged_entities, devicename)

        # get the mac list
        if showmac:
            macAPI = MacAPI()
            macs, total_mac_entries = macAPI.get_macs_from_device(devicename, m)

        # collect the voice vlans
        if showvlannames:
            vlanAPI = vlanlistAPI()
            voice_vlans = vlanAPI.get_voice_vlans(devicename, m)
            data_vlans = vlanAPI.get_vlans(devicename, m)

        if showpoe:
            poe = self.get_poe(devicename, m)

        if showcdp:
            cdpAPI = CDPAPI()
            cdps = cdpAPI.get_cdp_from_device(devicename, m)

        if showdhcp:
            dhcpAPI = DHCPsnoopAPI()
            dhcp_snooping_entries = dhcpAPI.get_dhcp_snooping_from_device(devicename, m)

        if showtrunks:
            trunkAPI = TrunkAPI()
            trunks_entries = trunkAPI.get_trunks_from_device(devicename, m)

        # here, we collect all properties ("columns" in Snimpy speak) from the ifTable & ifXTable
        # we do this with single iteritems() loops, as they use Bulk-Get, which is much faster
        # the results of each loop enriches a "giant dict".
        # At the end, we do a final loop to add the stuff collected above

        # the "giant dict" indexed by the ifIndex
        interfaces = autovivification.AutoVivification()

        # ifDescr has most of the time the format "GigabitEthernet1/0/1"
        logger.debug('fn=InterfaceAPI/get : %s : get ifDescr' % devicename)
        for index, desc in m.ifDescr.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, desc = %s' % (devicename, index, desc))
            interfaces[index]['ifDescr'] = desc

        # ifName has most of the time the format "Gi1/0/1"
        logger.debug('fn=InterfaceAPI/get : %s : get ifName' % devicename)
        for index, name in m.ifName.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, name = %s' % (devicename, index, name))
            interfaces[index]['ifName'] = name

        logger.debug('fn=InterfaceAPI/get : %s : get ifAdminStatus' % devicename)
        for index, adminstatus in m.ifAdminStatus.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, admin-status = %s' % (devicename, index, adminstatus))
            interfaces[index]['ifAdminStatus'], interfaces[index]['ifAdminStatusText'] = util.translate_status(str(adminstatus))

        logger.debug('fn=InterfaceAPI/get : %s : get ifOperStatus' % devicename)
        for index, operstatus in m.ifOperStatus.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, oper-status = %s' % (devicename, index, operstatus))
            interfaces[index]['ifOperStatus'], interfaces[index]['ifOperStatusText'] = util.translate_status(str(operstatus))

        logger.debug('fn=InterfaceAPI/get : %s : get ifType' % devicename)
        for index, iftype in m.ifType.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, iftype = %s' % (devicename, index, iftype))
            interfaces[index]['ifType'] = str(iftype)

        logger.debug('fn=InterfaceAPI/get : %s : get ifMtu' % devicename)
        for index, ifmtu in m.ifMtu.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, ifmtu = %s' % (devicename, index, ifmtu))
            interfaces[index]['ifMtu'] = ifmtu

        logger.debug('fn=InterfaceAPI/get : %s : get ifSpeed' % devicename)
        for index, ifspeed in m.ifSpeed.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, ifspeed = %s' % (devicename, index, ifspeed))
            interfaces[index]['ifSpeed'] = ifspeed

        logger.debug('fn=InterfaceAPI/get : %s : get ifAlias' % devicename)
        for index, ifalias in m.ifAlias.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, ifalias = %s' % (devicename, index, ifalias))
            interfaces[index]['ifAlias'] = str(ifalias)

        logger.debug('fn=InterfaceAPI/get : %s : get dot3StatsDuplexStatus' % devicename)
        for index, duplex in m.dot3StatsDuplexStatus.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, duplex = %s' % (devicename, index, duplex))
            interfaces[index]['dot3StatsDuplexStatus'] = str(duplex)
        # add a null value when an index has no entry in the dot3StatsDuplexStatus table
        for interface in interfaces:
            if not 'dot3StatsDuplexStatus' in interfaces[interface]:
                interfaces[interface]['dot3StatsDuplexStatus'] = None

        logger.debug('fn=InterfaceAPI/get : %s : get vmVlan' % devicename)
        for index, vlan_id in m.vmVlan.iteritems():
            logger.trace('fn=InterfaceAPI/get : %s : index = %s, vlan_id = %s' % (devicename, index, vlan_id))
            interfaces[index]['vmVlanNative']['nr'] = vlan_id
        # add a null value when an index has no entry in the vmMembershipTable table
        for interface in interfaces:
            if not 'vmVlanNative' in interfaces[interface]:
                interfaces[interface]['vmVlanNative']['nr'] = None

        # now we add the stuff that we collected above the ifTable/get-bulk operations
        logger.debug('fn=InterfaceAPI/get : %s : loop over the interfaces' % devicename)
        for index in interfaces:

            # ease the flatify below
            interfaces[index]['index'] = index

            # try to map the ifDescr / ifName to a physical entity, namely the enclosing chassis
            # 1. try ifDesc first
            desc = interfaces[index]['ifDescr']
            logger.debug('fn=InterfaceAPI/get : %s : matching interface %s (%s)' % (devicename, index, desc))
            name = interfaces[index]['ifName']
            if desc in entities_if_to_chassis:
                interfaces[index]['physicalIndex'] = entities_if_to_chassis[desc]['chassis']
                logger.trace('fn=InterfaceAPI/get : %s : ifDescr (%s) found in physical entities' % (devicename, desc))
                interfaces[index]['vendorType'] = entities_if_to_chassis[desc]['vendtypename']

            # 2. try ifName (works for IOS-XE)
            elif name in entities_if_to_chassis:
                interfaces[index]['physicalIndex'] = entities_if_to_chassis[name]['chassis']
                logger.trace('fn=InterfaceAPI/get : %s : ifName (%s) found in physical entities' % (devicename, name))
                interfaces[index]['vendorType'] = entities_if_to_chassis[name]['vendtypename']

            # this interface does not exist in entity table. That would be normal in a lot of cases,
            # e.g. interface containers without module, virtual interfaces, trunks, etc.
            else:
                interfaces[index]['physicalIndex'] = None
                logger.trace('fn=InterfaceAPI/get : %s : ifDescr (%s) or ifName (%s) not found in physical entities' % (devicename, desc,name))
                interfaces[index]['vendorType'] = None

            # VLANs (data and voice)
            if showvlannames:

                # data vlans
                # use a temp variable for clarity
                logger.trace('fn=InterfaceAPI/get : %s : adding vlan names to %s' % (devicename, desc))
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
                logger.trace('fn=InterfaceAPI/get : %s : adding MAC collection to %s' % (devicename, desc))
                if index in macs:
                    interfaces[index]['macs'] = macs[index]
                else:
                    interfaces[index]['macs'] = []

            # POE
            if showpoe:
                logger.trace('fn=InterfaceAPI/get : %s : adding POE info to %s' % (devicename, desc))
                if interfaces[index]['ifDescr'] in poe:
                    interfaces[index]['poeStatus'] = str(poe[interfaces[index]['ifDescr']]['status'])
                    interfaces[index]['poePower'] = poe[interfaces[index]['ifDescr']]['power']
                else:
                    interfaces[index]['poeStatus'] = ''
                    interfaces[index]['poePower'] = None

            # CDP
            if showcdp:
                logger.trace('fn=InterfaceAPI/get : %s : adding CDP info to %s' % (devicename, desc))
                interfaces[index]['cdp'] = {}
                if index in cdps:
                    address_type = cdps[index]['cdpCacheAddressType']
                    if address_type in ('ipv4', 'ipv6'):
                        interfaces[index]['cdp']["cdpCacheAddress"] = util.convert_ip_from_snmp_format(address_type, cdps[index]['cdpCacheAddress'])
                    else:
                        interfaces[index]['cdp']["cdpCacheAddress"] = 'cannot convert SNMP value for address, unsupported type %s' % address_type
                    interfaces[index]['cdp']["cdpCacheVersion"] = cdps[index]["cdpCacheVersion"]
                    interfaces[index]['cdp']["cdpCacheDeviceId"] = cdps[index]["cdpCacheDeviceId"]
                    interfaces[index]['cdp']["cdpCacheDevicePort"] = cdps[index]["cdpCacheDevicePort"]
                    interfaces[index]['cdp']["cdpCachePlatform"] = cdps[index]["cdpCachePlatform"]
                    interfaces[index]['cdp']["cdpCacheLastChange"] = cdps[index]["cdpCacheLastChange"]
                else:
                    interfaces[index]['cdp']["cdpCacheAddressType"] = None
                    interfaces[index]['cdp']["cdpCacheAddress"] = None
                    interfaces[index]['cdp']["cdpCacheVersion"] = None
                    interfaces[index]['cdp']["cdpCacheDeviceId"] = None
                    interfaces[index]['cdp']["cdpCacheDevicePort"] = None
                    interfaces[index]['cdp']["cdpCachePlatform"] = None
                    interfaces[index]['cdp']["cdpCacheLastChange"] = None


            # DHCP
            if showdhcp:
                logger.trace('fn=InterfaceAPI/get : %s : adding DHCP info to %s' % (devicename, desc))
                # an interface might have more than one MAC-IP binding so
                # make this is a list
                interfaces[index]['dhcpsnoop'] = []
                for entry in dhcp_snooping_entries:
                    # the code below removes the idx key-value from the dict
                    # so for the next interface, the equality match below would fail.
                    # this avoids that case.
                    if 'interface_idx' in entry:
                        if entry['interface_idx'] == index:
                            # no need to add the idx element, it's redundant here
                            del entry['interface_idx']
                            interfaces[index]['dhcpsnoop'].append(entry)

            # Trunks
            if showtrunks:
                logger.trace('fn=InterfaceAPI/get : %s : adding trunks info to %s' % (devicename, desc))
                if index in trunks_entries:
                    interfaces[index]['trunkAdminState'] = trunks_entries[index]['trunkAdminState']
                    interfaces[index]['trunkOperState'] = trunks_entries[index]['trunkOperState']
                else:
                    interfaces[index]['trunkAdminState'] = ''
                    interfaces[index]['trunkOperState'] = ''


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

        logger.info('fn=InterfaceAPI/get : %s : duration=%s' %
                    (devicename, deviceinfo['query-duration']))
        return deviceinfo

    def get_poe(self, devicename, m):
        ''' get the POE info using the CISCO-POWER-ETHERNET-EXT-MIB and Entity-MIB

            return a list of poe entries, indexed by port name (eg FastEthernet1/0/15)
        '''
        # first, create a mapping EntPhyIndex --> port name (eg FastEthernet1/0/6),
        # as we don't have the if-idx in POE table below
        logger.debug('fn=InterfaceAPI/get_poe : %s : create a mapping EntPhyIndex --> port name' % (devicename))

        tstart = datetime.now()

        port_mapping = {}
        logger.trace('%s : loop over entPhysicalName.iteritems' % devicename)
        counter = 0
        for index, value in m.entPhysicalName.iteritems():
            counter += 1
            port_mapping[index] = value
            logger.trace('fn=InterfaceAPI/get_poe : %s : port-mapping : ent-idx=%s, port-name=%s' %
                         (devicename, index, port_mapping[index]))
        logger.trace('loop over entPhysicalName.iteritems done, %s entries found' % counter)


        # then, get the poe info. Returned entries are indexed by the port-name
        logger.debug('fn=InterfaceAPI/get_poe : %s : get poe info' % (devicename))
        poe = {}
        # some switches cannot do any POE and answer with "End of MIB was reached"
        # and some clients might ask for POE for those even if the get-device API call
        # said "no POE". In this case, only log and return an empty table
        try:

            # new faster, bulkget-way of getting infos
            poe_parts = autovivification.AutoVivification()

            logger.debug('fn=InterfaceAPI/get_poe : %s : get cpeExtPsePortPwrConsumption' % (devicename))
            for index, value in m.cpeExtPsePortPwrConsumption.iteritems():
                poe_parts[index]['cpeExtPsePortPwrConsumption'] = value

            logger.debug('fn=InterfaceAPI/get_poe : %s : get pethPsePortDetectionStatus' % (devicename))
            for index, value in m.pethPsePortDetectionStatus.iteritems():
                poe_parts[index]['pethPsePortDetectionStatus'] = value

            logger.debug('fn=InterfaceAPI/get_poe : %s : get cpeExtPsePortEntPhyIndex' % (devicename))
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
                    'fn=InterfaceAPI/get_poe : %s : status=%s, power=%s, ent-idx=%s, port-name=%s' %
                    (devicename, status, consumption, ifidx, port_name))
                '''
                poe[port_name] = {'status': status, 'power': consumption}
                poe_entries += 1

            logger.info('fn=InterfaceAPI/get_poe : %s : got %s poe entries' % (devicename, poe_entries))

        except Exception, e:
            logger.info("fn=InterfaceAPI/get_poe : %s : could not get poe info, probably a device without POE. Status : %s" % (devicename, e))

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=InterfaceAPI/get_poe : %s : POE collection duration=%s' % (devicename, duration))

        return poe

    # -----------------------------------------------------------------------------------
    def collect_entities(self, m, devicename):

        # entPhysicalClass
        entries_entPhysicalClass = {}
        tstart = datetime.now()
        counter = 0
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalClass' % devicename)
        for index, value in m.entPhysicalClass.iteritems():
            logger.trace('fn=InterfaceAPI/collect_entities : %s : entPhysicalClass entry %s, %s' % (devicename, index, value))
            entries_entPhysicalClass[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalClass done in %s, %s entries found' % (devicename, duration, counter))

        # entPhysicalName
        entries_entPhysicalName = {}
        tstart = datetime.now()
        counter = 0
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalName' % devicename)
        for index, value in m.entPhysicalName.iteritems():
            logger.trace('fn=InterfaceAPI/collect_entities : %s : entPhysicalName entry %s, %s' % (devicename, index, value))
            entries_entPhysicalName[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalName done in %s, %s entries found' % (devicename, duration, counter))

        # entPhysicalContainedIn
        entries_entPhysicalContainedIn = {}
        tstart = datetime.now()
        counter = 0
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalContainedIn' % devicename)
        for index, value in m.entPhysicalContainedIn.iteritems():
            logger.trace('fn=InterfaceAPI/collect_entities : %s : entPhysicalContainedIn entry %s, %s' % (devicename, index, value))
            entries_entPhysicalContainedIn[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalContainedIn done in %s, %s entries found' % (devicename, duration, counter))

        # entPhysicalVendorType
        entries_entPhysicalVendorType = {}
        tstart = datetime.now()
        counter = 0
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalVendorType' % devicename)
        for index, value in m.entPhysicalVendorType.iteritems():
            logger.trace('fn=InterfaceAPI/collect_entities : %s : entPhysicalVendorType entry %s, %s' % (devicename, index, value))
            entries_entPhysicalVendorType[index] = value
            counter += 1
        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        logger.info('fn=InterfaceAPI/collect_entities : %s : loop over entPhysicalVendorType done in %s, %s entries found' % (devicename, duration, counter))

        return ({'entries_entPhysicalClass': entries_entPhysicalClass,
                 'entries_entPhysicalName': entries_entPhysicalName,
                 'entries_entPhysicalContainedIn': entries_entPhysicalContainedIn,
                 'entries_entPhysicalVendorType': entries_entPhysicalVendorType})

    # -----------------------------------------------------------------------------------
    def merge_entities(self, entities, devicename):

        # we merge entities based on the content of the class table
        # strategies if the 3 collected tables have different index values:
        # - if something is not in class table --> it will be ignored by this loop
        # - if something is in class table but has no name or cin --> None

        logger.info('fn=InterfaceAPI/merge_entities : %s : start merge entities' % devicename)

        merged_entities = autovivification.AutoVivification()
        for idx, value in entities['entries_entPhysicalClass'].iteritems():
            logger.trace('fn=InterfaceAPI/merge_entities : %s : merging index %s of class %s' % (devicename, idx, value))
            merged_entities[idx]['class'] = value
            merged_entities[idx]['name'] = entities['entries_entPhysicalName'].get(idx, None)
            merged_entities[idx]['cin'] = entities['entries_entPhysicalContainedIn'].get(idx, None)
            merged_entities[idx]['vendtype'] = entities['entries_entPhysicalVendorType'].get(idx, None)

        logger.trace('fn=InterfaceAPI/merge_entities : %s : done merging entities' % devicename)

        return merged_entities

    # -----------------------------------------------------------------------------------
    def get_ports(self, merged_entities, devicename):

        # construct a table (dict) 'ifname' --> 'enclosing-chassis'
        # we go over the entity table, find out each interface (class=port)
        # and then find the enclosing-chassis of this interface

        logger.info('fn=InterfaceAPI/get_ports : %s : get_ports' % devicename)

        port_table = autovivification.AutoVivification()
        for idx, entry in merged_entities.iteritems():
            # only ports
            if entry['class'] == 10:  # entPhysicalClass=10 are ports (interfaces of some sort)
                logger.trace('fn=InterfaceAPI/get_ports : %s : searching for port %s' % (devicename, entry['name']))
                # entPhysicalClass=3 are chassis
                chassis_idx = self.find_parent_of_type(devicename, idx, 3, merged_entities)
                port_table[entry['name']]['chassis'] = chassis_idx
                logger.trace('fn=InterfaceAPI/get_ports : %s : port %s is part of chassis %s' % (devicename, entry['name'], chassis_idx))

                # vendortype of port
                vendor_type_oid = str(entry['vendtype'])
                vendor_type_name = entityvendortypeoidmap.translate_oid(vendor_type_oid)
                port_table[entry['name']]['vendtypename'] = vendor_type_name
                logger.debug('fn=InterfaceAPI/get_ports : %s : port %s has vendor-type %s (%s)' % (devicename, entry['name'], vendor_type_oid, vendor_type_name))

        logger.trace('fn=InterfaceAPI/get_ports : %s : done get_ports' % devicename)
        return port_table

    # -----------------------------------------------------------------------------------
    def find_parent_of_type(self, devicename, port_idx, searched_parent_type, merged_entities):

        # this is a recursive function walking up the entity tree to find
        # the first ancestor of desired type

        logger.trace('fn=InterfaceAPI/find_parent_of_type : %s : find_parent_of_type %s for entity %s' % (devicename, searched_parent_type, port_idx))

        parent_idx = merged_entities[port_idx]['cin']
        logger.trace('fn=InterfaceAPI/find_parent_of_type : %s : parent of port %s is %s' % (devicename, port_idx, parent_idx))

        type_of_parent = merged_entities[parent_idx]['class']
        logger.trace('fn=InterfaceAPI/find_parent_of_type : %s : type of parent %s is %s' % (devicename, parent_idx, type_of_parent))

        # is the parent already the desired type ?
        if type_of_parent == searched_parent_type:
            # yes !
            logger.trace('fn=InterfaceAPI/find_parent_of_type : %s : parent %s has the searched type %s, search done' % (devicename, parent_idx, searched_parent_type))
            return parent_idx
        else:
            # no, go deeper
            return self.find_parent_of_type(devicename, parent_idx, 3, merged_entities)


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

    @auth.login_required
    def get(self, devicename, ifindex):

        logger.debug('fn=InterfaceCounterAPI/get : src=%s, %s : index=%s' %
                     (request.remote_addr, devicename, ifindex))
        logaction(classname='InterfaceCounterAPI', methodname='get', devicename=devicename,
                  params=ifindex, src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=InterfaceCounterAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, cache=False)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

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

    @auth.login_required
    def get(self, devicename):
        #-------------------------
        logger.debug('fn=MacAPI/get : src=%s, %s' % (request.remote_addr, devicename))
        logaction(classname='MacAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=MacAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        try:
            deviceinfo['sysName'] = m.sysName

            macs, total_mac_entries = self.get_macs_from_device(devicename, m)

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
    # it's then easier when having to enrich an interface info when knowing the ifIndex
    def get_macs_from_device(self, devicename, m):
        # see http://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/44800-mactoport44800.html

        logger.debug('fn=MacAPI/get_macs_from_device : %s : get vlan list' % devicename)
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
        vlan_numbers = len(vlans)
        logger.debug('fn=MacAPI/get_macs_from_device : %s : got %s vlans' % (devicename, vlan_numbers))

        # now loop across every VLAN
        macs = {}
        total_mac_entries = 0
        vlan_counter = 0
        for vlan_nr in vlans:

            mac_entries = 0
            vlan_type = vlans[vlan_nr]['type']
            vlan_state = vlans[vlan_nr]['state']
            vlan_name = vlans[vlan_nr]['name']
            vlan_counter += 1
            logger.debug('fn=MacAPI/get_macs_from_device : %s : checking vlan_nr = %s (%s of %s), name = %s, type = %s, state = %s' % (devicename, vlan_nr, vlan_counter, vlan_numbers, vlan_name, vlan_type, vlan_state))

            # only ethernet VLANs
            if vlan_type == 'ethernet(1)' and vlan_state == 'operational(1)':
                logger.debug('fn=MacAPI/get_macs_from_device : %s : polling vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

                # VLAN-based community, have a local manager for each VLAN
                # this works probably only for Cisco, where it is called "community string indexing"
                # http://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/40367-camsnmp40367.html
                logger.debug('fn=MacAPI/get_macs_from_device : %s : requesting a SNMP manager' % (devicename))
                lm = snimpy.create(devicename=devicename, community_format='{}@%s' % vlan_nr)

                # we pull them in an large block so we can catch timeouts for broken IOS versions
                # happened on a big stack of 8 Cisco 3750 running 12.2(46)SE (fc2)
                try:
                    logger.debug('fn=MacAPI/get_macs_from_device : %s : trying to pull all mac_entries for vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

                    dot1dTpFdbAddress = {}
                    dot1dTpFdbPort = {}
                    dot1dBasePortIfIndex = {}

                    for index, mac_entry in lm.dot1dTpFdbAddress.iteritems():
                        dot1dTpFdbAddress[index] = mac_entry
                        mac_entries += 1
                    logger.debug('fn=MacAPI/get_macs_from_device : %s : got %s dot1dTpFdbAddress entries for vlan %s (%s)' % (devicename, len(dot1dTpFdbAddress), vlan_nr, vlan_name))
                    if mac_entries > 0:
                        # vlan is interesting, it has at least 1 MAC
                        for index, port in lm.dot1dTpFdbPort.iteritems():
                            dot1dTpFdbPort[index] = port
                        logger.debug('fn=MacAPI/get_macs_from_device : %s : got %s dot1dTpFdbPort entries for vlan %s (%s)' % (devicename, len(dot1dTpFdbPort), vlan_nr, vlan_name))

                        for index, ifindex in lm.dot1dBasePortIfIndex.iteritems():
                            dot1dBasePortIfIndex[index] = ifindex
                        logger.debug('fn=MacAPI/get_macs_from_device : %s : got %s dot1dBasePortIfIndex entries for vlan %s (%s)' % (devicename, len(dot1dBasePortIfIndex), vlan_nr, vlan_name))

                        logger.debug('fn=MacAPI/get_macs_from_device : %s : enrich MAC table for vlan %s (%s)' % (devicename, vlan_nr, vlan_name))
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
                                logger.trace("fn=MacAPI/get_macs_from_device : %s : vendor lookup failed : %s" % (devicename, e))
                                vendor = 'unknown'

                            logger.trace("idx=%s, vlan=%s, mac=%s, vendor=%s" % (ifindex, vlan_nr, str(mac), vendor))
                            mac_record = {'mac': str(mac), 'vendor': vendor, 'vlan': vlan_nr}
                            if ifindex in macs:
                                macs[ifindex].append(mac_record)
                            else:
                                macs[ifindex] = [mac_record]

                    else:
                        logger.debug('fn=MacAPI/get_macs_from_device : %s : vlan %s (%s) skipped, no MAC found on it' % (devicename, vlan_nr, vlan_name))

                except:
                    logger.info("fn=MacAPI/get_macs_from_device : %s : failed, probably an unused VLAN (%s) on a buggy IOS producing SNMP timeout. Ignoring this VLAN" % (devicename, vlan_nr))

            else:
                logger.debug('fn=MacAPI/get_macs_from_device : %s : skipping vlan %s (%s)' % (devicename, vlan_nr, vlan_name))

            logger.debug("fn=MacAPI/get_macs_from_device : %s : %s mac entries found in vlan %s (%s)" % (devicename, mac_entries, vlan_nr, vlan_name))
            total_mac_entries += mac_entries

        logger.debug("fn=MacAPI/get_macs_from_device : %s : returning data, total %s mac entries found" % (devicename, total_mac_entries))
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


    def get(self, devicename):
        logger.debug('fn=CDPAPI/get : src=%s, %s' % (request.remote_addr, devicename))
        logaction(classname='CDPAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=CDPAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        try:
            deviceinfo['sysName'] = m.sysName

            cdps = self.get_cdp_from_device(devicename, m)

            cdps_organized = []
            for ifindex in cdps:
                entry = {}

                entry["index"] = ifindex

                address_type = cdps[ifindex]['cdpCacheAddressType']
                if address_type in ('ipv4', 'ipv6'):
                    entry["cdpCacheAddress"] = util.convert_ip_from_snmp_format(address_type, cdps[ifindex]['cdpCacheAddress'])
                else:
                    entry["cdpCacheAddress"] = 'cannot convert SNMP value for address, unsupported type %s' % address_type

                entry["cdpCacheVersion"] = cdps[ifindex]['cdpCacheVersion']
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
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=CDPAPI/get : %s : duration=%s' %
                    (devicename, duration))
        deviceinfo['cdp'] = cdps_organized
        return deviceinfo

    # we create a dict indexed by ifIndex,
    # it's then easier when having to enrich an interface info when knowing the ifIndex
    def get_cdp_from_device(self, devicename, m):
        logger.debug('fn=CDPAPI/get_cdp_from_device : %s' % devicename)

        cdps = autovivification.AutoVivification()
        try:
            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheAddressType' % devicename)
            for index, value in m.cdpCacheAddressType.iteritems():
                # map to standard values so we can then translate it with our util function
                # hope it will work with IPv6, no way to test at development time
                if str(value) == 'ip(1)':
                    cdps[index[0]]['cdpCacheAddressType'] = 'ipv4'
                elif str(value) == 'ipv6(20)':
                    cdps[index[0]]['cdpCacheAddressType'] = 'ipv6'
                else:
                    cdps[index[0]]['cdpCacheAddressType'] = 'unsupported' % value
                    logger.warn('fn=CDPAPI/get_cdp_from_device : %s : unsupported cdpCacheAddressType <%s>' % (devicename, value))

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheAddress' % devicename)
            for index, value in m.cdpCacheAddress.iteritems():
                cdps[index[0]]['cdpCacheAddress'] = value

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheVersion' % devicename)
            for index, value in m.cdpCacheVersion.iteritems():
                cdps[index[0]]['cdpCacheVersion'] = value

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheDeviceId' % devicename)
            for index, value in m.cdpCacheDeviceId.iteritems():
                cdps[index[0]]['cdpCacheDeviceId'] = value

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheDevicePort' % devicename)
            for index, value in m.cdpCacheDevicePort.iteritems():
                cdps[index[0]]['cdpCacheDevicePort'] = value

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCachePlatform' % devicename)
            for index, value in m.cdpCachePlatform.iteritems():
                cdps[index[0]]['cdpCachePlatform'] = value

            logger.debug('fn=CDPAPI/get_cdp_from_device : %s : get cdpCacheLastChange' % devicename)
            for index, value in m.cdpCacheLastChange.iteritems():
                cdps[index[0]]['cdpCacheLastChange'] = value

        except snmp.SNMPException, e:
            logger.warn("fn=CDPAPI/get_cdp_from_device : failed SNMP get for CDP : %s" % e)

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

    @auth.login_required
    def get(self, devicename):
        #-------------------------
        logger.debug('fn=TrunkAPI/get : src=%s, %s' % (request.remote_addr, devicename))
        logaction(classname='TrunkAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=TrunkAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        try:
            deviceinfo['sysName'] = m.sysName

            trunks = self.get_trunks_from_device(devicename, m)

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
    def get_trunks_from_device(self, devicename, m):

        logger.debug('fn=TrunkAPI/get_trunks_from_device : %s' % devicename)

        trunks = autovivification.AutoVivification()
        try:

            for index, value in m.vlanTrunkPortDynamicState.iteritems():
                logger.trace("fn=TrunkAPI/get_trunks_from_device/1 : trunk : %s, %s" % (index, value))
                trunks[index]['trunkAdminState'] = str(value)

            for index, value in m.vlanTrunkPortDynamicStatus.iteritems():
                logger.trace("fn=TrunkAPI/get_trunks_from_device/2 : trunk : %s, %s" % (index, value))
                trunks[index]['trunkOperState'] = str(value)

        except snmp.SNMPException, e:
            logger.warn("fn=TrunkAPI/get_trunks_from_device : failed SNMP get for Trunks : %s" % e)

        logger.debug("fn=TrunkAPI/get_trunks_from_device : returning data : %s trunks entries found" % len(trunks))
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

    @auth.login_required
    def get(self, devicename):
        # -------------------------
        logger.debug('fn=ARPAPI/get : src=%s, %s' % (request.remote_addr, devicename))
        logaction(classname='ARPAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=ARPAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        try:
            deviceinfo['sysName'] = m.sysName
            oid_used, nbr_arp_entries, arps = self.get_arp_from_device(devicename, m)

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
    def get_arp_from_device(self, devicename, m):

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

    @auth.login_required
    def get(self, devicename):
        logger.debug('fn=DHCPsnoopAPI/get : src=%s, %s' % (request.remote_addr, devicename))
        logaction(classname='DHCPsnoopAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=DHCPsnoopAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        try:
            deviceinfo['sysName'] = m.sysName
            deviceinfo['dhcpsnoop'] = self.get_dhcp_snooping_from_device(devicename, m)

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
    # called from DHCPsnoopAPI/get above, and optionally by InterfaceAPI/get if asked so
    def get_dhcp_snooping_from_device(self, devicename, m):

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
        try:

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsAddrType' % devicename)
            cdsBindingsAddrType = {}
            for index, value in m.cdsBindingsAddrType.iteritems():
                cdsBindingsAddrType[index] = value

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsIpAddress' % devicename)
            cdsBindingsIpAddress = {}
            for index, value in m.cdsBindingsIpAddress.iteritems():
                cdsBindingsIpAddress[index] = value

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsInterface' % devicename)
            cdsBindingsInterface = {}
            for index, value in m.cdsBindingsInterface.iteritems():
                cdsBindingsInterface[index] = value

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsLeasedTime' % devicename)
            cdsBindingsLeasedTime = {}
            for index, value in m.cdsBindingsLeasedTime.iteritems():
                cdsBindingsLeasedTime[index] = value

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsStatus' % devicename)
            cdsBindingsStatus = {}
            for index, value in m.cdsBindingsStatus.iteritems():
                cdsBindingsStatus[index] = value

            logger.debug('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : %s : get cdsBindingsHostname' % devicename)
            cdsBindingsHostname = {}
            for index, value in m.cdsBindingsHostname.iteritems():
                cdsBindingsHostname[index] = value

            # now loop over the entries and merge the diverse tables
            dhcp_snooping_entries = []
            for index in cdsBindingsAddrType:
                vlan = int(index[0])
                mac = str(index[1])
                # reformat mac: comes as "0:22:90:1b:6:e6" and should be "00-22-90-1B-06-E6"
                mac_e = netaddr.EUI(mac)
                mac_f = str(mac_e)
                # add vendor
                try:
                    vendor = mac_e.oui.registration().org
                except netaddr.NotRegisteredError as e:
                    logger.warn('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device: %s : error %s : unknown vendor for %s' % (devicename, e, mac_f))
                    vendor = 'unknown'
                address_type = inet_address_types.get(cdsBindingsAddrType[index], 'unsupported')
                ip = util.convert_ip_from_snmp_format(address_type, cdsBindingsIpAddress[index])
                interface_idx = cdsBindingsInterface[index]
                leased_time = cdsBindingsLeasedTime[index]
                status = binding_status.get(cdsBindingsStatus[index], 'unsupported')
                hostname = cdsBindingsHostname.get(index, None)

                logger.trace('fn=DHCPsnoopAPI/get_dhcp_snooping_from_device %s : vlan=%s, mac=%s, vendor=%s, address_type=%s, ip=%s, interface_idx=%s, leased_time=%s, status=%s, hostname=%s' %
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
            logger.warn("fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : failed SNMP get for DHCP snooping : %s" % e)

        logger.debug("fn=DHCPsnoopAPI/get_dhcp_snooping_from_device : returning data : %s entries found" % len(dhcp_snooping_entries))
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

    @auth.login_required
    def get(self, devicename):

        logger.debug('fn=vlanlistAPI/get : src=%s, device=%s' % (request.remote_addr, devicename))
        logaction(classname='vlanlistAPI', methodname='get', devicename=devicename,
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=vlanlistAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename)

        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        # all SNMP gets under one big try
        try:

            deviceinfo['sysName'] = m.sysName

            logger.debug('fn=vlanlistAPI/get : %s : get data vlan list' %
                         devicename)
            vlans_lookup_table = self.get_vlans(devicename, m)

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

    def get_vlans(self, devicename, m):
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


    def get_voice_vlans(self, devicename, m):
        ''' return a VOICE_VLAN dict indexed by vlan-nr '''

        logger.debug('fn=vlanlistAPI/get_voice_vlans : %s : get voice vlan list' % devicename)
        voice_vlans = {}
        # some routers (Cisco 1921) return empty list, producing an error upstream.
        # Catch it and return an empty list
        try:

            for index, value in m.vmVoiceVlanId.iteritems():
                logger.trace('fn=vlanlistAPI/get_voice_vlans : %s : got voice vlan %s for index %s' % (devicename, value, index))
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
        "params": ["vlan=NNN", "uuid=UUID (optional, used to identify the write request in logs)", "clientinfo=JoBar"],
        "returns": "status"
    }'''

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument(
            'vlan', type=str, required=True, help='No vlan number provided')
        self.reqparse.add_argument(
            'uuid', type=str, required=mandate_uuid, help='No uuid provided')
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(PortToVlanAPI, self).__init__()

    @auth.login_required
    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        vlan = args['vlan']
        uuid = args['uuid']

        logger.info('fn=PortToVlanAPI/put : src=%s, %s : ifindex=%s, vlan=%s, uuid=%s' %
                    (request.remote_addr, devicename, ifindex, vlan, uuid))
        logaction(classname='PortToVlanAPI', methodname='put', devicename=devicename,
                  params=args, mode='rw', src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=PortToVlanAPI/put : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, rw=True)

        if not check.check_snmp(m, devicename, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

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
        "params": ["ifAlias=TXT", "ifAdminStatus={1(up)|2(down)}", "uuid=UUID (optional, used to identify the write request in logs)", "clientinfo=JoBar"],
        "returns": "status"
    }'''
    """ PUT on an interface : configure the interface """

    # check argument
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument(
            'ifAdminStatus', type=int, required=False, help='No ifAdminStatus value')
        self.reqparse.add_argument(
            'ifAlias', type=str, required=False, help='No ifAlias value')
        self.reqparse.add_argument(
            'uuid', type=str, required=mandate_uuid, help='No uuid provided')
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(InterfaceConfigAPI, self).__init__()

    @auth.login_required
    def put(self, devicename, ifindex):

        args = self.reqparse.parse_args()
        ifAdminStatus = args['ifAdminStatus']
        ifAlias = args['ifAlias']
        uuid = args['uuid']

        logger.info('fn=InterfaceConfigAPI/put : src=%s,, %s : ifindex=%s, '
                    'ifAdminStatus=%s, ifAlias=%s, uuid=%s' %
                    (request.remote_addr, devicename, ifindex, ifAdminStatus, ifAlias,
                     uuid))
        logaction(classname='InterfaceConfigAPI', methodname='put', devicename=devicename,
                  params=args, mode='rw', src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        logger.debug('fn=InterfaceConfigAPI/put : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, rw=True)

        if not check.check_snmp(m, devicename, 'RW'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200

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

    @auth.login_required
    def get(self, devicename, pdu, oid):

        logger.debug('fn=OIDpumpAPI/get : src=%s, %s : pdu=%s, oid=%s' %
                     (request.remote_addr, devicename, pdu, oid))
        logaction(classname='OIDpumpAPI', methodname='get', devicename=devicename,
                  params="{'pdu': '%s', 'oid': '%s'}" % (pdu, oid),
                  src_ip=request.remote_addr, src_user=auth.username())

        tstart = datetime.now()

        # it's a bit overkill to create a manager and only use the underlying session
        # but it keeps the code tidy and orthogonal. Besides, it will work for SNMPv3 as well.
        # recommended method by the developer of snimpy.
        # https://github.com/vincentbernat/snimpy/issues/62
        logger.debug('fn=OIDpumpAPI/get : %s : requesting a SNMP manager' % (devicename))
        m = snimpy.create(devicename=devicename, bulk=False, cache=0)
        if not check.check_snmp(m, devicename, 'RO'):
            return errst.status('ERROR_SNMP', 'SNMP test failed'), 200
        session = m._session._session

        deviceinfo = autovivification.AutoVivification()
        deviceinfo['name'] = devicename

        if pdu == 'get':
            try:
                logger.debug('fn=OIDpumpAPI/get : %s : SNMP get on %s' % (devicename, oid))
                data = session.get(str(oid))
            except Exception, e:
                logger.error("fn=OIDpumpAPI/get : %s : oid get failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid get failed: %s' % e), 200

        elif pdu == 'walk':
            try:
                logger.debug('fn=OIDpumpAPI/get : %s : SNMP walk on %s' % (devicename, oid))
                data = session.walkmore(str(oid))
            except Exception, e:
                logger.error("fn=OIDpumpAPI/get : %s : oid walk failed: %s" % (devicename, e))
                return errst.status('ERROR_SNMP_OP', 'oid walk failed: %s' % e), 200

        else:
            return errst.status('ERROR_SNMP_PDU', 'unknown PDU value : %s' % pdu), 200

        # try to unpack the Python tuples. Not sure it will work with all sorts of get/walk results
        entries = {}
        for entry in data:
            logger.trace('entry=<%s>' % str(entry))
            oid = '.'.join(map(str, entry[0]))
            if type(entry[1]) == tuple:
                value = '.'.join(map(str, entry[1]))
            else:
                value = str(entry[1])
            entries[oid] = value

        deviceinfo['data'] = entries
        deviceinfo['entries'] = len(entries)

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10**6) / 1000
        deviceinfo['query-duration'] = duration

        logger.info('fn=OIDpumpAPI/get : %s : duration=%s' % (devicename, deviceinfo['query-duration']))
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
        "params": ["driver=ios", "CmdList=list (JSON ordered list)", "uuid=UUID (optional, used to identify the write request in logs)", "clientinfo=JoBar"],
        "returns": "status and output indexed by commands"
    }'''
    """ PUT on a device : run commands over ssh """

    # check arguments
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument(
            'CmdList', type=str, required=True, help='missing command list')
        self.reqparse.add_argument(
            'uuid', type=str, required=mandate_uuid, help='No uuid provided')
        self.reqparse.add_argument('driver', type=str, required=True,
                                   help='missing driver, use one of http://knipknap.github.io/exscript/api/Exscript.protocols.drivers-module.html, eg ios')
        self.reqparse.add_argument('clientinfo', type=str, required=False,
                                   help='Passed by the client to log the upstream user information, e.g. its username.')
        super(DeviceSshAPI, self).__init__()

    @auth.login_required
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
        logaction(classname='DeviceSshAPI', methodname='put', devicename=devicename,
                  params=args, mode='rw', src_ip=request.remote_addr, src_user=auth.username())

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

# add TRACE log level
logging.TRACE = 5
logging.addLevelName(logging.TRACE, "TRACE")
logging.Logger.trace = lambda inst, msg, *args, **kwargs: inst.log(logging.TRACE, msg, *args, **kwargs)
logging.trace = lambda msg, *args, **kwargs: logging.log(logging.TRACE, msg, *args, **kwargs)

# the main logger
log_file = app.config['LOGFILE']
global logger
logger = logging.getLogger('aj')
hdlr = logging.handlers.RotatingFileHandler(log_file,
                                            maxBytes=app.config['LOG_MAX_SIZE'],
                                            backupCount=app.config['LOG_BACKUP_COUNT'])
# we have the PID in each log entry to differentiate parallel processes writing to the log
FORMAT = "%(asctime)s - %(process)d - %(name)-16s - %(levelname)-7s - %(message)s"
formatter = logging.Formatter(FORMAT)
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
# avoid propagation to console
logger.propagate = False

# level from config.
logger.setLevel(logging.INFO)
if app.config['DEBUG']:
     logger.setLevel(logging.DEBUG)
if app.config['TRACE']:
    logger.setLevel(logging.TRACE)

logger.info('version : <%s>' % __version__)
logger.info('environment : <%s>' % app.config['ENVI'])
mandate_uuid = app.config['MANDATE_UUID']
logger.info('mandate_uuid : <%s>' % mandate_uuid)
logger.info('SNMP cache = %ss' % app.config['SNMP_CACHE'])
logger.info('SNMP timeout = %ss' % app.config['SNMP_TIMEOUT'])
logger.info('SNMP retries = %s' % app.config['SNMP_RETRIES'])

# the action logger
action_log_file = app.config['ACTIONLOGFILE']
global actionlogger
actionlogger = logging.getLogger('aja')
actionhdlr = logging.handlers.RotatingFileHandler(action_log_file,
                                                  maxBytes=app.config['LOG_MAX_SIZE'],
                                                  backupCount=app.config['LOG_BACKUP_COUNT'])
FORMAT = "%(asctime)s - %(process)d - %(name)-3s - %(levelname)-5s - %(message)s"
actionformatter = logging.Formatter(FORMAT)
actionhdlr.setFormatter(actionformatter)
actionlogger.addHandler(actionhdlr)
actionlogger.setLevel(logging.INFO)





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

# entPhysicalVendorType
entityvendortypeoidmap = entity_vendortype.EntityVendorType(logger)

# for SSH commands
commander = sshcmd.SshCmd(logger)

# for SNMP traffic
snimpy = snmpmgr.SNMPmgr(logger, app, credmgr)


# -----------------------------------------------------------------------------------
# authentication
# -----------------------------------------------------------------------------------

extauth = auth_external.AuthExternal()

@auth.verify_password
def verify_pw(username, password):
    return extauth.verify_credentials(username, password, request)

@auth.error_handler
def unauthorized():
    logger.debug('not authorized')
    # returning 403 instead of 401 would prevent browsers from displaying the default auth dialog
    return make_response(jsonify({'message': 'Unauthorized access'}), 401)


# -----------------------------------------------------------------------------------
# browser will ask for a favicon. Avoid 404 by defining one
# -----------------------------------------------------------------------------------

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


# -----------------------------------------------------------------------------------
# call login
# -----------------------------------------------------------------------------------
def logaction(classname=None,
              methodname=None,
              devicename=None,
              params=None,
              mode='ro',
              src_ip=None,
              src_user=None):

    actionlogger.info('%s/%s : dev=%s params=%s mode=%s ip=%s srvuser=%s' % (classname, methodname, devicename, params, mode, src_ip, src_user))


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
        logaction(classname='main', methodname='start')
        app.run(host=app.config['BIND_IP'],
                port=app.config['BIND_PORT'],
                debug=app.config['DEBUG'])
        logger.info('AJ end')
        logaction(classname='main', methodname='end')
