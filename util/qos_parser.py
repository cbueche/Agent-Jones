#!/usr/bin/env python3.7
#
# a QoS discovery tool
#
# Ch. Bueche <bueche@netnea.com>
#
# 4.8.2011    : CB    : initial version to decode the QoS configuration of a device
# 1.11.2013   : CB    : support non-standard indexing of cbQosObjectsTable in Cisco ASR
# 15.9.2016   : CB    : use getbulk instead of getnext
# 2.10.2018   : CB    : port to Python 3
# 8.10.2018   : CB    : streamline the numerous tables lookups
# 10.10.2018  : CB    : optparse to argparse
#
# Usage :
#           ./qos_parser.py -c community -d device -p 161 -j /tmp/output.json [-D]
#

import sys
import logging
import pprint
import json
import datetime
from pysnmp.hlapi import *
import argparse
from timeit import default_timer as timer


# OID definitions
# ---------------------------------------------------------------------------------------

oids = {}
oids['ifDescr'] = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
oids['cbQosServicePolicyEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 1, 1, 1)
oids['cbQosObjectsEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 5, 1, 1)
oids['cbQosPolicyMapCfgEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 6, 1, 1)
oids['cbQosCMCfgEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 7, 1, 1)
oids['cbQosQueueingCfgEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 9, 1, 1)
oids['cbQosPoliceCfgEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 12, 1, 1)
oids['cbQosTSCfgEntry'] = (1, 3, 6, 1, 4, 1, 9, 9, 166, 1, 13, 1, 1)

qos_oids = {}
qos_oids['cbQosCMPostPolicyByte64'] = '1.3.6.1.4.1.9.9.166.1.15.1.1.10'
qos_oids['cbQosCMDropPkt64'] = '1.3.6.1.4.1.9.9.166.1.15.1.1.14'

# a few lookup tables,, mostly to avoid the MIB lookups
# ---------------------------------------------------------------------------------------
policy_traffic_direction_names = {'1': 'input', '2': 'output'}
queueing_bandwidth_units = {'1': 'kbps', '2': '%', '3': '% remaining', '4': 'ratioRemaining'}
# kbps for 1 because we divide by 1000 in getpolice
police_rate_types = {'1': 'kbps', '2': '%', '3': 'cps', '4': 'perThousand', '5': 'perMillion'}
shaping_rate_types = {'1': 'kbps', '2': '%', '3': 'cps', '4': 'perThousand', '5': 'perMillion'}
object_types = {'1': 'policymap',
                '2': 'classmap',
                '3': 'matchStatement',
                '4': 'queueing',
                '5': 'randomDetect',
                '6': 'trafficShaping',
                '7': 'police',
                '8': 'set',
                '9': 'compression',
                '10': 'ipslaMeasure',
                '11': 'account',
                'policymap': '1',
                'classmap': '2',
                'matchStatement': '3',
                'queueing': '4',
                'randomDetect': '5',
                'trafficShaping': '6',
                'police': '7',
                'set': '8',
                'compression': '9',
                'ipslaMeasure': '10',
                'account': '11'}

cbQosServicePolicyEntry_lookup = {'1': 'cbQosPolicyIndex',
                                  '2': 'cbQosIfType',
                                  '3': 'cbQosPolicyDirection',
                                  '4': 'cbQosIfIndex',
                                  '5': 'cbQosFrDLCI',
                                  '6': 'cbQosAtmVPI',
                                  '7': 'cbQosAtmVCI',
                                  '8': 'cbQosEntityIndex',
                                  '9': 'cbQosVlanIndex',
                                  '10': 'cbQosEVC',
                                  '11': 'cbQosPolicyDiscontinuityTime',
                                  '12': 'cbQosParentPolicyIndex',
                                  '13': 'cbQosServicePolicyNotInMib13',
                                  '14': 'cbQosServicePolicyNotInMib14'}

cbQosObjectsEntry_lookup = {'1': 'cbQosObjectsIndex',
                            '2': 'cbQosConfigIndex',
                            '3': 'cbQosObjectsType',
                            '4': 'cbQosParentObjectsIndex'}

cbQosPolicyMapCfgEntry_lookup = {'1': 'cbQosPolicyMapName',
                                 '2': 'cbQosPolicyMapDesc'}

cbQosCMCfgEntry_lookup = {'1': 'cbQosCMName',
                          '2': 'cbQosCMDesc',
                          '3': 'cbQosCMInfo'}

cbQosQueueingCfgEntry_lookup = {'1': 'cbQosQueueingCfgBandwidth',
                                '2': 'cbQosQueueingCfgBandwidthUnits',
                                '3': 'cbQosQueueingCfgFlowEnabled',
                                '4': 'cbQosQueueingCfgPriorityEnabled',
                                '5': 'cbQosQueueingCfgAggregateQSize',
                                '6': 'cbQosQueueingCfgIndividualQSize',
                                '7': 'cbQosQueueingCfgDynamicQNumber',
                                '8': 'cbQosQueueingCfgPrioBurstSize',
                                '9': 'cbQosQueueingCfgQLimitUnits',
                                '10': 'cbQosQueueingCfgAggregateQLimit',
                                '11': 'cbQosQueueingCfgAggrQLimitTime',
                                '12': 'cbQosQueueingCfgPriorityLevel',
                                '13': 'cbQosQueueingCfgBandwidth64',
                                '14': 'cbQosQueueingCfgIndividualQSize64'}

cbQosTSCfgEntry_lookup = {'1': 'cbQosTSCfgRate',
                          '2': 'cbQosTSCfgBurstSize',
                          '3': 'cbQosTSCfgExtBurstSize',
                          '4': 'cbQosTSCfgAdaptiveEnabled',
                          '5': 'cbQosTSCfgAdaptiveRate',
                          '6': 'cbQosTSCfgLimitType',
                          '7': 'cbQosTSCfgRateType',
                          '8': 'cbQosTSCfgPercentRateValue',
                          '9': 'cbQosTSCfgBurstTime',
                          '10': 'cbQosTSCfgExtBurstTime',
                          '11': 'cbQosTSCfgRate64',
                          '12': 'cbQosTSCfgBurstSize64',
                          '13': 'cbQosTSCfgExtBurstSize64'}

cbQosPoliceCfgEntry_lookup = {'1': 'cbQosPoliceCfgRate',
                              '2': 'cbQosPoliceCfgBurstSize',
                              '3': 'cbQosPoliceCfgExtBurstSize',
                              '4': 'cbQosPoliceCfgConformAction',
                              '5': 'cbQosPoliceCfgConformSetValue',
                              '6': 'cbQosPoliceCfgExceedAction',
                              '7': 'cbQosPoliceCfgExceedSetValue',
                              '8': 'cbQosPoliceCfgViolateAction',
                              '9': 'cbQosPoliceCfgViolateSetValue',
                              '10': 'cbQosPoliceCfgPir',
                              '11': 'cbQosPoliceCfgRate64',
                              '12': 'cbQosPoliceCfgRateType',
                              '13': 'cbQosPoliceCfgPercentRateValue',
                              '14': 'cbQosPoliceCfgPercentPirValue',
                              '15': 'cbQosPoliceCfgCellRate',
                              '16': 'cbQosPoliceCfgCellPir',
                              '17': 'cbQosPoliceCfgBurstCell',
                              '18': 'cbQosPoliceCfgExtBurstCell',
                              '19': 'cbQosPoliceCfgBurstTime',
                              '20': 'cbQosPoliceCfgExtBurstTime',
                              '21': 'cbQosPoliceCfgCdvt',
                              '22': 'cbQosPoliceCfgConformColor',
                              '23': 'cbQosPoliceCfgExceedColor',
                              '24': 'cbQosPoliceCfgConditional',
                              '25': 'cbQosPoliceCfgBurstSize64',
                              '26': 'cbQosPoliceCfgExtBurstSize64',
                              '27': 'cbQosPoliceCfgPir64'}




# ---------------------------------------------------------------------------------------
def main():
# ---------------------------------------------------------------------------------------

    # logging
    # ---------------------------------------------------------------------------------------
    logfile = '/tmp/qos_parser.log'
    global logger
    logger = logging.getLogger('qos-discovery')
    hdlr = logging.FileHandler(logfile)
    # we have the PID in each log entry to differentiate parallel processes writing to the log
    formatter = logging.Formatter('%(asctime)s - %(process)d - %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    # avoid propagation to console
    logger.propagate = False
    logger.setLevel(logging.INFO)

    # default level is INFO, is overriden to DEBUG if -D passed
    logger.info("START")

    # get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--community", dest="community",    default='public',    help="read-only SNMP community")
    parser.add_argument("-d", "--device",    dest="device",       default='localhost', help="device name")
    parser.add_argument("-j", "--json",      dest="json_output",  default=None,        help="json output file")
    parser.add_argument("-p", "--port",      dest="port",         default=161,         help="UDP port for SNMP queries")
    parser.add_argument("-D", "--debug", action="store_true", dest="debug", default="",       help="debug mode")
    params = parser.parse_args()
    hostname = params.device
    port = params.port
    community = params.community
    json_output_file = params.json_output

    global debug
    debug = params.debug

    if hostname == '':
        logger.error("please pass a device as parameter using -d device")
        print("FATAL : please pass a device as parameter using -d device")
        sys.exit(1)
    elif community == '':
        logger.error("please pass a comunity as parameter using -c community")
        print("FATAL : please pass a community as parameter using -c community")
        sys.exit(1)
    else:
        logger.info("device to parse : %s:%s" % (hostname, port))

    if debug:
        logger.setLevel(logging.DEBUG)
        print('device %s' % (hostname))


    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    # start by collecting all relevant OID tables from the device.
    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    collection_start = timer()


    # get cbQosServicePolicyEntries and format it in cbQosServicePolicyTable
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosServicePolicyEntry')
    cbQosServicePolicyEntries = get_table(hostname, port, community, oids['cbQosServicePolicyEntry'])
    cbQosServicePolicyTable = get_cbQosServicePolicyTable(cbQosServicePolicyEntries)
    dump_table('cbQosServicePolicyTable', cbQosServicePolicyTable)


    # get ifDescr
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for ifDescr')
    ifEntries = get_table(hostname, port, community, oids['ifDescr'])
    ifEntriesTable = get_ifEntriesTable(ifEntries)
    dump_table('ifEntriesTable', ifEntriesTable)


    # get cbQosObjectsEntries
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosObjectsEntry')
    cbQosObjectsEntries = get_table(hostname, port, community, oids['cbQosObjectsEntry'])
    cbQosObjectsTable = get_cbQosObjectTable(cbQosObjectsEntries)
    dump_table('cbQosObjectsTable',cbQosObjectsTable)


    # get cbQosPolicyMapCfgEntry
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosPolicyMapCfgEntry')
    cbQosPolicyMapCfgEntries = get_table(hostname, port, community, oids['cbQosPolicyMapCfgEntry'])
    cbQosPolicyMapCfgTable = get_cbQosPolicyMapTable(cbQosPolicyMapCfgEntries)
    dump_table('cbQosPolicyMapCfgTable', cbQosPolicyMapCfgTable)


    # get cbQosCMCfgEntry
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosCMCfgEntry')
    cbQosCMCfgEntries = get_table(hostname, port, community, oids['cbQosCMCfgEntry'])
    cbQosCMCfgTable = get_cbQosCMCfgTable(cbQosCMCfgEntries)
    dump_table('cbQosCMCfgTable', cbQosCMCfgTable)


    # get cbQosQueueingCfgEntry
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosQueueingCfgEntry')
    cbQosQueueingCfgEntries = get_table(hostname, port, community, oids['cbQosQueueingCfgEntry'])
    cbQosQueueingCfgTable = get_cbQosQueueingCfgTable(cbQosQueueingCfgEntries)
    dump_table('cbQosQueueingCfgTable', cbQosQueueingCfgTable)


    # get cbQosTSCfgEntry (shaping config)
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosTSCfgEntry')
    cbQosTSCfgEntries = get_table(hostname, port, community, oids['cbQosTSCfgEntry'])
    cbQosTSCfgTable = get_cbQosTSCfgTable(cbQosTSCfgEntries)
    dump_table('cbQosTSCfgTable', cbQosTSCfgTable)


    # get cbQosPoliceCfgEntry
    # ---------------------------------------------------------------------------------------
    logger.info('get_table for cbQosPoliceCfgEntry')
    cbQosPoliceCfgEntries = get_table(hostname, port, community, oids['cbQosPoliceCfgEntry'])
    cbQosPoliceCfgTable = get_cbQosPoliceCfgTable(cbQosPoliceCfgEntries)
    dump_table('cbQosPoliceCfgTable', cbQosPoliceCfgTable)


    # ---------------------------------------------------------------------------------------
    # construct list of interfaces having QoS defined
    # use a dict so we get auto-unification
    # ---------------------------------------------------------------------------------------
    logger.info("get table of interfaces with QoS")
    interfaces = {}
    for cbQosPolicyIndex in list(cbQosServicePolicyTable.keys()):
        qos_interface_idx = cbQosServicePolicyTable[cbQosPolicyIndex]['cbQosIfIndex']
         # only for real interfaces, see InterfaceType in CISCO-CLASS-BASED-QOS-MIB for other values
        qos_interface_type = cbQosServicePolicyTable[cbQosPolicyIndex]['cbQosIfType']
        if  qos_interface_type == '1':
            interface_name = ifEntriesTable.get(qos_interface_idx, 'noNameInterface')
            interfaces[qos_interface_idx] = interface_name
        else:
            logger.info('skipped interface idx %s because its type is %s' % (qos_interface_idx, qos_interface_type))

    dump_table('interfaces', interfaces)

    collection_end = timer()
    collection_duration = round((collection_end - collection_start), 2)
    analysis_start = timer()

    # ---------------------------------------------------------------------------------------
    # prepare an interface table object to make later parsing easier
    #
    # each entry in InterfacesTable is built as:
    #    key   -> interface-name
    #    value -> array of service-policies indices
    #    eg    'GigabitEthernet0/0' -> [16, 18]
    #          'GigabitEthernet0/2' -> [50]
    #
    # two rounds to build the table, first the key->table, then fill each table
    # ---------------------------------------------------------------------------------------
    InterfacesTable = {}
    for idx in cbQosServicePolicyTable:
        (interface_idx, interface_name) = get_interface(idx, cbQosServicePolicyTable, interfaces)
        if interface_name:
            InterfacesTable[interface_name] = []
    for idx in cbQosServicePolicyTable:
        (interface_idx, interface_name) = get_interface(idx, cbQosServicePolicyTable, interfaces)
        if interface_name:
            InterfacesTable[interface_name].append(idx)


    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    # loop over the cbQosObjectsTable to build its hierarchy
    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    logger.info("build the hierarchy of cbQosObjectsTable in ObjectsTable")

    ObjectsTable = AutoVivification()

    for cbQosObjectsTable_top_idx in list(cbQosObjectsTable.keys()):

        # store the interface name
        (interface_idx, interface_name) = get_interface(cbQosObjectsTable_top_idx, cbQosServicePolicyTable, interfaces)
        ObjectsTable[cbQosObjectsTable_top_idx]['ifname'] = interface_name

        # first, find the top-level policy-maps attached to interfaces, aka service-policies
        indices_L1 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['policymap'], '0')
        for idx_L1 in indices_L1:
            cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L1, cbQosObjectsTable)
            policymapname = get_policymap_name(cbQosConfigIndex, cbQosPolicyMapCfgTable)
            policymapdirection = policy_traffic_direction_names[get_policymap_direction(cbQosObjectsTable_top_idx,cbQosServicePolicyTable)]
            ObjectsTable[cbQosObjectsTable_top_idx]['servicePolicyName']      = policymapname
            ObjectsTable[cbQosObjectsTable_top_idx]['servicePolicyDirection'] = policymapdirection
            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps']             = {}

            # second, find the class-maps within the current service-policy
            indices_L2 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['classmap'], idx_L1)
            for idx_L2 in indices_L2:
                cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2, cbQosObjectsTable)
                classmapname_L2 = get_classmap_name(cbQosConfigIndex, cbQosCMCfgTable)
                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2] = {}

                # find the bandwidth info for this class-map
                indices_L2b = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['queueing'], idx_L2)
                for idx_L2b in indices_L2b:
                    cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                    (bandwidth, units) = get_bandwidth(cbQosConfigIndex, cbQosQueueingCfgTable)
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx']       = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['idx_L2']       = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw']           = bandwidth
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw_unit']      = units
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw_unit_text'] = queueing_bandwidth_units[units]

                # find the police info for this class-map
                indices_L2b = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['police'], idx_L2)
                for idx_L2b in indices_L2b:
                    cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                    (police_rate, police_rate_type, police_percent_rate) = get_police(cbQosConfigIndex, cbQosPoliceCfgTable)
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx']                = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['idx_L2']                = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['police_rate']           = police_rate
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['police_rate_type']      = police_rate_type
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['police_rate_type_text'] = police_rate_types[police_rate_type]
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['police_percent_rate']   = police_percent_rate

                # find the shaping info for this class-map
                indices_L2b = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['trafficShaping'], idx_L2)
                for idx_L2b in indices_L2b:
                    cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                    (shape_rate, shape_type) = get_shaping(cbQosConfigIndex, cbQosTSCfgTable)
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx']          = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['shape_rate']      = shape_rate
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['shape_type']      = shape_type
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['shape_type_text'] = shaping_rate_types[shape_type]

                # find the random-detect info for this class-map
                indices_L2b = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['randomDetect'], idx_L2)
                for idx_L2b in indices_L2b:
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx']        = idx_L2
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['random_detect'] = True

                # third level : the policy-maps within the current class-map
                indices_L3 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['policymap'], idx_L2)
                for idx_L3 in indices_L3:
                    cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L3, cbQosObjectsTable)
                    policymapname_L3 = get_policymap_name(cbQosConfigIndex,cbQosPolicyMapCfgTable)
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['PolicyName']  = policymapname_L3
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps']  = {}

                    # fourth level : the class-maps within the current policy-map
                    indices_L4 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['classmap'], idx_L3)
                    for idx_L4 in indices_L4:
                        cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L4, cbQosObjectsTable)
                        classmapname_L4 = get_classmap_name(cbQosConfigIndex, cbQosCMCfgTable)
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4] = {}

                        # find the bandwidth info for this class-map
                        indices_L5 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['queueing'], idx_L4)
                        for idx_L5 in indices_L5:
                            cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5, cbQosObjectsTable)
                            (bandwidth, units) = get_bandwidth(cbQosConfigIndex, cbQosQueueingCfgTable)
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['cfgidx']       = idx_L4
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['bw']           = bandwidth
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['bw_unit']      = units
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['bw_unit_text'] = queueing_bandwidth_units[units]

                        # find the police info for this class-map
                        indices_L5 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['police'], idx_L4)
                        for idx_L5 in indices_L5:
                            cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5, cbQosObjectsTable)
                            (police_rate, police_rate_type, police_percent_rate) = get_police(cbQosConfigIndex, cbQosPoliceCfgTable)
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['cfgidx']                = idx_L4
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['police_rate']           = police_rate
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['police_rate_type']      = police_rate_type
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['police_rate_type_text'] = police_rate_types[police_rate_type]
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['police_percent_rate']   = police_percent_rate

                        # find the shaping info for this class-map
                        indices_L5 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['trafficShaping'], idx_L4)
                        for idx_L5 in indices_L5:
                            cbQosConfigIndex = get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5, cbQosObjectsTable)
                            (shape_rate, shape_type) = get_shaping(cbQosConfigIndex, cbQosTSCfgTable)
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['cfgidx']          = idx_L4
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['shape_rate']      = shape_rate
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['shape_type']      = shape_type
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['shape_type_text'] = shaping_rate_types[shape_type]

                        # find the random-detect info for this class-map
                        indices_L5 = get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, object_types['randomDetect'], idx_L4)
                        for idx_L5 in indices_L5:
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['cfgidx']        = idx_L4
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][classmapname_L4]['random_detect'] = True

                        # REMARK :
                        # we are now in double-nested classes :
                        # interface -> service-policy -> class-map -> policy-map -> class-map
                        # deeper recursion in QoS is indeed possible but improbable, so we stop recursing here.


    dump_table('ObjectsTable', ObjectsTable)
    dump_table('InterfacesTable', InterfacesTable)


    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    # present the results
    # for each interface, we show the attached service-policy, then dig-down to the sub-objects
    # ---------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------
    logger.info("consolidate the hierarchy to a JSON structure")

    # to collect everything related to QoS in a large JSON object
    qosinfo = AutoVivification()

    for interface_idx in sorted(interfaces):

        # each interface
        interface_name = interfaces[interface_idx]

        # for each service-policy bound to the current interface
        for ObjectsTable_idx in sorted(InterfacesTable[interface_name]):
            service_policy_name = ObjectsTable[ObjectsTable_idx]['servicePolicyName']
            qosinfo[interface_name]['service-policies'][service_policy_name]['direction'] = ObjectsTable[ObjectsTable_idx]['servicePolicyDirection']

            # second, find the class-maps within the current service-policy
            for class_map_L1 in sorted(ObjectsTable[ObjectsTable_idx]['class-maps']):

                # policing : either percentage or rate
                if 'police_rate_type' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    if ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type'] == '2':
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['police_rate'] = "%s %s" % (ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_percent_rate'], ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type_text'])
                    else:
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['police_rate'] = "%s %s" % (ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate'], ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type_text'])

                # bandwitdh
                if 'bw' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['bandwidth'] = "%s %s" % (ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['bw'], ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['bw_unit_text'])

                # the shaping
                if 'shape_rate' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['shape_rate'] = "%s %s" % (format_nr(ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['shape_rate']), ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['shape_type_text'])

                # in case someone wants to graph something, here is how you get the OIDs
                if 'cfgidx' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    obj_idx = ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['cfgidx']
                    cbQosCMPostPolicyByte64_oid = get_full_oid('cbQosCMPostPolicyByte64', ObjectsTable_idx, obj_idx)
                    cbQosCMDropPkt64_oid = get_full_oid('cbQosCMDropPkt64', ObjectsTable_idx, obj_idx)
                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['oids']['cbQosCMPostPolicyByte64'] = cbQosCMPostPolicyByte64_oid
                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['oids']['cbQosCMDropPkt64'] = cbQosCMDropPkt64_oid

                # third level : the policy-maps within the current L1-class-map
                if 'PolicyName' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    policy_map_name = ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['PolicyName']

                # each class-map
                if 'class-maps' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                    for class_map_L2 in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps']:

                        # bandwidth
                        if 'bw' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]:
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['bandwidth'] = "%s %s" % (ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['bw'], ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['bw_unit_text'])

                        # policing : either percentage or rate
                        if 'police_rate_type' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]:
                            if ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['police_rate_type'] == '2':
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][
                                    class_map_L2]['police_rate'] = "%s %s" % (
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                        class_map_L2][
                                        'police_percent_rate'],
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                        class_map_L2][
                                        'police_rate_type_text'])
                            else:
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['police_rate'] = "%s %s" % (
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['police_rate'],
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['police_rate_type_text'])

                        # shaping
                        if 'shape_rate' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]:
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['shape_rate'] = "%s %s" % (format_nr(ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['shape_rate']), ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['shape_type_text'])

                        # in case someone wants to graph something, here is how you get the OIDs
                        if 'cfgidx' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]:
                            obj_idx = ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2]['cfgidx']
                            cbQosCMPostPolicyByte64_oid = get_full_oid('cbQosCMPostPolicyByte64', ObjectsTable_idx, obj_idx)
                            cbQosCMDropPkt64_oid = get_full_oid('cbQosCMDropPkt64', ObjectsTable_idx, obj_idx)
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['oids']['cbQosCMPostPolicyByte64'] = cbQosCMPostPolicyByte64_oid
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['oids']['cbQosCMDropPkt64'] = cbQosCMDropPkt64_oid


    analysis_end = timer()
    analysis_duration = round((analysis_end - analysis_start), 2)

    # add all the stuff to a data structure and encode in JSON
    device_qos_info = {}
    device_qos_info['_meta'] = {}
    device_qos_info['_meta']['timestamp'] = datetime.datetime.now().isoformat()
    device_qos_info['_meta']['collection_duration'] = collection_duration
    device_qos_info['_meta']['analysis_duration'] = analysis_duration
    logger.info('collection_duration=%s, analysis_duration=%s' % (collection_duration, analysis_duration))
    device_qos_info['_meta']['devicename'] = hostname
    device_qos_info['_meta']['interfaces_count'] = len(qosinfo)
    device_qos_info['interfaces'] = qosinfo
    if json_output_file:
        with open(json_output_file, "w") as json_file:
            json_file.write(json.dumps(device_qos_info, sort_keys=True, indent=4))
            if debug:
                print('qosinfo written to %s' % json_output_file)
    else:
        logger.info('specify a JSON output file using -j filespec to save output')
        print('no JSON output file specified, use -D or check %s' % logfile)

    logger.info("END")


# a function to run a snmpbulkget on an OID, and get a dictionary back
# ---------------------------------------------------------------------------------------
def get_table(hostname, port, community, oid):
# ---------------------------------------------------------------------------------------

    start = timer()

    # some tuning that might need adjustements
    nonRepeaters = 0
    maxRepetitions = 50

    table = {}
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in bulkCmd(SnmpEngine(),
                              CommunityData(community, mpModel=1),
                              UdpTransportTarget((hostname, port)),
                              ContextData(),
                              nonRepeaters,
                              maxRepetitions,
                              ObjectType(ObjectIdentity(oid)),
                              lexicographicMode=False,
                              lookupMib=False):

        if errorIndication:
            logger.critical('error : %s', errorIndication)
            print("FATAL 1, exit")
            sys.exit(1)
        else:
            if errorStatus:
                logger.critical('%s at %s\n' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[-1][int(errorIndex)-1] or '?'
                    ))
                print("FATAL 2, exit")
                sys.exit(1)
            else:
                # sucessful walk. Store the index and values in a dictionary
                for varBind in varBinds:
                    table[varBind[0].prettyPrint()] = varBind[1].prettyPrint()

    end = timer()
    logger.debug('get_table : oid=%s, entries=%s, duration=%s' % ('.'.join(map(str, oid)), len(table), round((end - start), 2)))

    return table

# end def get_table
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
def get_cbQosServicePolicyTable(cbQosServicePolicyEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosServicePolicyTable")
    cbQosServicePolicyTable = AutoVivification()
    for cbQosServicePolicyEntry in list(cbQosServicePolicyEntries.keys()):
        array = cbQosServicePolicyEntry.split('.')
        pName = array[13]
        cbQosPolicyIndex = array[14]
        pVal = cbQosServicePolicyEntry_lookup.get(pName, pName)
        cbQosServicePolicyTable[cbQosPolicyIndex][pVal] = cbQosServicePolicyEntries[cbQosServicePolicyEntry]

    return cbQosServicePolicyTable


# ---------------------------------------------------------------------------------------
def get_ifEntriesTable(ifEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_ifEntriesTable")
    ifEntriesTable = {}
    for ifEntry in list(ifEntries.keys()):
        array = ifEntry.split('.')
        ifEntryIndex = array[10]
        ifEntriesTable[ifEntryIndex] = ifEntries[ifEntry]

    return ifEntriesTable


# ---------------------------------------------------------------------------------------
def get_cbQosObjectTable(cbQosObjectsEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosObjectTable")
    cbQosObjectTable = AutoVivification()
    for cbQosObjectsEntry in list(cbQosObjectsEntries.keys()):
        array = cbQosObjectsEntry.split('.')
        pName = array[13]
        cbQosPolicyIndex = array[14]
        cbQosObjectsIndex = array[15]
        pVal = cbQosObjectsEntry_lookup.get(pName, pName)
        cbQosObjectTable[cbQosPolicyIndex]["QosObjectsEntry"][cbQosObjectsIndex][pVal] = cbQosObjectsEntries[cbQosObjectsEntry]

    return cbQosObjectTable


# ---------------------------------------------------------------------------------------
def get_cbQosPolicyMapTable(cbQosPolicyMapCfgEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosPolicyMapTable")

    cbQosPolicyMapTable = AutoVivification()
    for cbQosPolicyMapEntry in list(cbQosPolicyMapCfgEntries.keys()):
        array = cbQosPolicyMapEntry.split('.')
        pName = array[13]
        cbQosConfigIndex = array[14]
        pVal = cbQosPolicyMapCfgEntry_lookup.get(pName, pName)
        cbQosPolicyMapTable[cbQosConfigIndex][pVal] = cbQosPolicyMapCfgEntries[cbQosPolicyMapEntry]

    return cbQosPolicyMapTable


# ---------------------------------------------------------------------------------------
def get_cbQosCMCfgTable(cbQosCMCfgEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosCMCfgTable")
    cbQosCMCfgTable = AutoVivification()

    for cbQosCMEntry in list(cbQosCMCfgEntries.keys()):
        array = cbQosCMEntry.split('.')
        pName = array[13]
        cbQosConfigIndex = array[14]
        pVal = cbQosCMCfgEntry_lookup.get(pName, pName)
        cbQosCMCfgTable[cbQosConfigIndex][pVal] = cbQosCMCfgEntries[cbQosCMEntry]

    return cbQosCMCfgTable


# ---------------------------------------------------------------------------------------
def get_cbQosQueueingCfgTable(cbQosQueueingCfgEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosQueueingCfgTable")
    cbQosQueueingCfgTable = AutoVivification()

    for cbQosQueueingCfgEntry in list(cbQosQueueingCfgEntries.keys()):
        array = cbQosQueueingCfgEntry.split('.')
        pName = array[13]
        cbQosConfigIndex = array[14]
        pVal = cbQosQueueingCfgEntry_lookup.get(pName, pName)
        cbQosQueueingCfgTable[cbQosConfigIndex][pVal] = cbQosQueueingCfgEntries[cbQosQueueingCfgEntry]

    return cbQosQueueingCfgTable


# ---------------------------------------------------------------------------------------
def get_cbQosTSCfgTable(cbQosTSCfgEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosTSCfgTable")
    cbQosTSCfgTable = AutoVivification()

    for cbQosTSCfgEntry in list(cbQosTSCfgEntries.keys()):
        array = cbQosTSCfgEntry.split('.')
        pName = array[13]
        cbQosConfigIndex = array[14]
        pVal = cbQosTSCfgEntry_lookup.get(pName, pName)
        cbQosTSCfgTable[cbQosConfigIndex][pVal] = cbQosTSCfgEntries[cbQosTSCfgEntry]

    return cbQosTSCfgTable


# ---------------------------------------------------------------------------------------
def get_cbQosPoliceCfgTable(cbQosPoliceCfgEntries):
# ---------------------------------------------------------------------------------------

    logger.debug("in get_cbQosPoliceCfgTable")
    cbQosPoliceCfgTable = AutoVivification()

    for cbQosPoliceCfgEntry in list(cbQosPoliceCfgEntries.keys()):
        array = cbQosPoliceCfgEntry.split('.')
        pName = array[13]
        cbQosConfigIndex = array[14]
        pVal = cbQosPoliceCfgEntry_lookup.get(pName, pName)
        cbQosPoliceCfgTable[cbQosConfigIndex][pVal] = cbQosPoliceCfgEntries[cbQosPoliceCfgEntry]

    return cbQosPoliceCfgTable


# ---------------------------------------------------------------------------------------
# parse cbQosObjectsTable to find the list of indices having a certain parent,
# type and top-index. Used to build the object hierarchy
#
def get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, objectType, parent):
    # ---------------------------------------------------------------------------------------

    indices = []
    for cbQosObjectsTable_idx in cbQosObjectsTable[cbQosObjectsTable_top_idx]['QosObjectsEntry']:
        if \
            cbQosObjectsTable[cbQosObjectsTable_top_idx]['QosObjectsEntry'][cbQosObjectsTable_idx]['cbQosObjectsType'] == str(objectType) \
        and \
            cbQosObjectsTable[cbQosObjectsTable_top_idx]['QosObjectsEntry'][cbQosObjectsTable_idx]['cbQosParentObjectsIndex'] == str(parent):
                indices.append(cbQosObjectsTable_idx)
    return indices


# ---------------------------------------------------------------------------------------
def get_cbQosConfigIndex(top_idx, obj_idx, cbQosObjectsTable):
# ---------------------------------------------------------------------------------------

    return cbQosObjectsTable[top_idx]['QosObjectsEntry'][obj_idx]['cbQosConfigIndex']


# ---------------------------------------------------------------------------------------
def get_policymap_name(idx, cbQosPolicyMapCfgTable):
# ---------------------------------------------------------------------------------------

    return cbQosPolicyMapCfgTable[idx]['cbQosPolicyMapName']


# ---------------------------------------------------------------------------------------
def get_classmap_name(idx, cbQosCMCfgTable):
# ---------------------------------------------------------------------------------------

    if 'cbQosCMName' in cbQosCMCfgTable[idx]:
        return cbQosCMCfgTable[idx]['cbQosCMName']
    else:
        return 'noNameClassMap'


# ---------------------------------------------------------------------------------------
def get_policymap_direction(idx, cbQosServicePolicyTable):
# ---------------------------------------------------------------------------------------

    return cbQosServicePolicyTable[idx]['cbQosPolicyDirection']


# ---------------------------------------------------------------------------------------
def get_bandwidth(idx, cbQosQueueingCfgTable):
# ---------------------------------------------------------------------------------------

    bandwidth = cbQosQueueingCfgTable[idx]['cbQosQueueingCfgBandwidth']
    unit = cbQosQueueingCfgTable[idx]['cbQosQueueingCfgBandwidthUnits']
    # we don't divide by 1'000, because the unit is already kbps.
    return (bandwidth, unit)


# ---------------------------------------------------------------------------------------
def get_police(idx, cbQosPoliceCfgTable):
# ---------------------------------------------------------------------------------------

    rate = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgRate64']
    unit = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgRateType']
    perc_rate = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgPercentRateValue']
    if unit == '1':   # bps to kbps
        rate = str(int(rate) / 1000)
    return (rate, unit, perc_rate)


# ---------------------------------------------------------------------------------------
def get_shaping(idx, cbQosTSCfgTable):
# ---------------------------------------------------------------------------------------

    rate = cbQosTSCfgTable[idx]['cbQosTSCfgRate']
    unit = cbQosTSCfgTable[idx]['cbQosTSCfgRateType']
    if unit == '1':   # bps
        rate = str(int(rate) / 1000)
    return (rate, unit)


# ---------------------------------------------------------------------------------------
def get_interface(idx, cbQosServicePolicyTable, interfaces):

    interface_idx = cbQosServicePolicyTable[idx]['cbQosIfIndex']
    interface_name = interfaces.get(interface_idx, None)
    return (interface_idx, interface_name)


# ---------------------------------------------------------------------------------------
def get_full_oid(base_oid, policy_idx, obj_idx):

    return qos_oids[base_oid] + '.' + str(policy_idx) + '.' + str(obj_idx)


# ---------------------------------------------------------------------------------------
def format_nr(number):
# 1000000000 --> 1'000'000'000
# Python 2.7 has formats, but we are still under 2.6
# ---------------------------------------------------------------------------------------

    try:
        number = int(number)
        s = '%d' % number
        groups = []
        while s and s[-1].isdigit():
            groups.append(s[-3:])
            s = s[:-3]
        return s + "'".join(reversed(groups))

    except:
        return number


# ---------------------------------------------------------------------------------------
def dump_table(tablename, tablevar):
    if debug:
        pp = pprint.PrettyPrinter(indent=4)
        print("====== %s ======\n" % tablename)
        pp.pprint(tablevar)
        print("\n\n")


# ---------------------------------------------------------------------------------------
class AutoVivification(dict):
# ---------------------------------------------------------------------------------------
    # Implementation of perl's autovivification feature
    # http://stackoverflow.com/questions/635483/what-is-the-best-way-to-implement-nested-dictionaries-in-python
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()
