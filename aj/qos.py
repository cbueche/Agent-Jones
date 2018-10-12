#!/usr/bin/env python
'''

qos.py - QoS polling for Agent-Jones

Author : Ch. Bueche

'''

import logging
from datetime import datetime
import autovivification
from snimpy import mib


# -----------------------------------------------------------------------------------
class QOScollector():
    '''
    QoS manager
    '''

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

    def __init__(self, app):

        self.logger = logging.getLogger('aj.qos')
        self.logger.info('fn=QOS/init : creating an instance of QOS')
        self.app = app

    def collect(self,
                m,
                devicename='localhost'):
        """Create a new QOS collector.

            :param devicename: The hostname or IP address of the agent to
                connect to. Optionally, the port can be specified
                separated with a double colon.
            :type host: str
        """

        # start by collecting all relevant OID tables from the device.
        collection_start = datetime.now()

        # get cbQosServicePolicyEntries and format it in cbQosServicePolicyTable
        self.logger.info('get_table for cbQosServicePolicyEntry')
        cbQosServicePolicyEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosServicePolicyEntry'))
        cbQosServicePolicyTable = self.get_cbQosServicePolicyTable(cbQosServicePolicyEntries)

        # get ifDescr
        self.logger.info('get_table for ifDescr')
        ifEntries = self.get_table(m, devicename, self.node_to_oid('IF-MIB', 'ifDescr'))
        ifEntriesTable = self.get_ifEntriesTable(ifEntries)

        # get cbQosObjectsEntries
        self.logger.info('get_table for cbQosObjectsEntry')
        cbQosObjectsEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosObjectsEntry'))
        cbQosObjectsTable = self.get_cbQosObjectTable(cbQosObjectsEntries)

        # get cbQosPolicyMapCfgEntry
        self.logger.info('get_table for cbQosPolicyMapCfgEntry')
        cbQosPolicyMapCfgEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosPolicyMapCfgEntry'))
        cbQosPolicyMapCfgTable = self.get_cbQosPolicyMapTable(cbQosPolicyMapCfgEntries)

        # get cbQosCMCfgEntry
        self.logger.info('get_table for cbQosCMCfgEntry')
        cbQosCMCfgEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosCMCfgEntry'))
        cbQosCMCfgTable = self.get_cbQosCMCfgTable(cbQosCMCfgEntries)

        # get cbQosQueueingCfgEntry
        self.logger.info('get_table for cbQosQueueingCfgEntry')
        cbQosQueueingCfgEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosQueueingCfgEntry'))
        cbQosQueueingCfgTable = self.get_cbQosQueueingCfgTable(cbQosQueueingCfgEntries)

        # get cbQosTSCfgEntry (shaping config)
        self.logger.info('get_table for cbQosTSCfgEntry')
        cbQosTSCfgEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosTSCfgEntry'))
        cbQosTSCfgTable = self.get_cbQosTSCfgTable(cbQosTSCfgEntries)

        # get cbQosPoliceCfgEntry
        self.logger.info('get_table for cbQosPoliceCfgEntry')
        cbQosPoliceCfgEntries = self.get_table(m, devicename, self.node_to_oid('CISCO-CLASS-BASED-QOS-MIB', 'cbQosPoliceCfgEntry'))
        cbQosPoliceCfgTable = self.get_cbQosPoliceCfgTable(cbQosPoliceCfgEntries)

        collection_end = datetime.now()
        tdiff = collection_end - collection_start
        collection_duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10 ** 6) / 1000
        analysis_start = datetime.now()

        # ---------------------------------------------------------------------------------------
        # construct list of interfaces having QoS defined
        # use a dict so we get auto-unification
        # ---------------------------------------------------------------------------------------
        self.logger.info("get table of interfaces with QoS")
        interfaces = {}
        for cbQosPolicyIndex in list(cbQosServicePolicyTable.keys()):
            qos_interface_idx = cbQosServicePolicyTable[cbQosPolicyIndex]['cbQosIfIndex']
            # only for real interfaces, see InterfaceType in CISCO-CLASS-BASED-QOS-MIB for other values
            qos_interface_type = cbQosServicePolicyTable[cbQosPolicyIndex]['cbQosIfType']
            if qos_interface_type == '1':
                interface_name = ifEntriesTable.get(qos_interface_idx, 'noNameInterface')
                interfaces[qos_interface_idx] = interface_name
            else:
                self.logger.info('skipped interface idx %s because its type is %s' % (qos_interface_idx, qos_interface_type))

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
            (interface_idx, interface_name) = self.get_interface(idx, cbQosServicePolicyTable, interfaces)
            if interface_name:
                InterfacesTable[interface_name] = []
        for idx in cbQosServicePolicyTable:
            (interface_idx, interface_name) = self.get_interface(idx, cbQosServicePolicyTable, interfaces)
            if interface_name:
                InterfacesTable[interface_name].append(idx)

        # loop over the cbQosObjectsTable to build its hierarchy
        # ---------------------------------------------------------------------------------------
        self.logger.info("build the hierarchy of cbQosObjectsTable in ObjectsTable")

        ObjectsTable = autovivification.AutoVivification()

        for cbQosObjectsTable_top_idx in list(cbQosObjectsTable.keys()):

            # store the interface name
            (interface_idx, interface_name) = self.get_interface(cbQosObjectsTable_top_idx, cbQosServicePolicyTable,
                                                            interfaces)
            ObjectsTable[cbQosObjectsTable_top_idx]['ifname'] = interface_name

            # first, find the top-level policy-maps attached to interfaces, aka service-policies
            indices_L1 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['policymap'], '0')
            for idx_L1 in indices_L1:
                cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L1, cbQosObjectsTable)
                policymapname = self.get_policymap_name(cbQosConfigIndex, cbQosPolicyMapCfgTable)
                policymapdirection = self.policy_traffic_direction_names[
                    self.get_policymap_direction(cbQosObjectsTable_top_idx, cbQosServicePolicyTable)]
                ObjectsTable[cbQosObjectsTable_top_idx]['servicePolicyName'] = policymapname
                ObjectsTable[cbQosObjectsTable_top_idx]['servicePolicyDirection'] = policymapdirection
                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'] = {}

                # second, find the class-maps within the current service-policy
                indices_L2 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['classmap'], idx_L1)
                for idx_L2 in indices_L2:
                    cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2, cbQosObjectsTable)
                    classmapname_L2 = self.get_classmap_name(cbQosConfigIndex, cbQosCMCfgTable)
                    ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2] = {}

                    # find the bandwidth info for this class-map
                    indices_L2b = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['queueing'],
                                              idx_L2)
                    for idx_L2b in indices_L2b:
                        cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                        (bandwidth, units) = self.get_bandwidth(cbQosConfigIndex, cbQosQueueingCfgTable)
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['idx_L2'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw'] = bandwidth
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw_unit'] = units
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['bw_unit_text'] = \
                        self.queueing_bandwidth_units[units]

                    # find the police info for this class-map
                    indices_L2b = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['police'],
                                              idx_L2)
                    for idx_L2b in indices_L2b:
                        cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                        (police_rate, police_rate_type, police_percent_rate) = self.get_police(cbQosConfigIndex, cbQosPoliceCfgTable)
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['idx_L2'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'police_rate'] = police_rate
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'police_rate_type'] = police_rate_type
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'police_rate_type_text'] = self.police_rate_types[police_rate_type]
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'police_percent_rate'] = police_percent_rate

                    # find the shaping info for this class-map
                    indices_L2b = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                   self.object_types['trafficShaping'], idx_L2)
                    for idx_L2b in indices_L2b:
                        cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L2b, cbQosObjectsTable)
                        (shape_rate, shape_type) = self.get_shaping(cbQosConfigIndex, cbQosTSCfgTable)
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'shape_rate'] = shape_rate
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'shape_type'] = shape_type
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['shape_type_text'] = \
                        self.shaping_rate_types[shape_type]

                    # find the random-detect info for this class-map
                    indices_L2b = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                   self.object_types['randomDetect'], idx_L2)
                    for idx_L2b in indices_L2b:
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['cfgidx'] = idx_L2
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['random_detect'] = True

                    # third level : the policy-maps within the current class-map
                    indices_L3 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['policymap'],
                                             idx_L2)
                    for idx_L3 in indices_L3:
                        cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L3, cbQosObjectsTable)
                        policymapname_L3 = self.get_policymap_name(cbQosConfigIndex, cbQosPolicyMapCfgTable)
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2][
                            'PolicyName'] = policymapname_L3
                        ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'] = {}

                        # fourth level : the class-maps within the current policy-map
                        indices_L4 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx, self.object_types['classmap'],
                                                 idx_L3)
                        for idx_L4 in indices_L4:
                            cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L4,
                                                                    cbQosObjectsTable)
                            classmapname_L4 = self.get_classmap_name(cbQosConfigIndex, cbQosCMCfgTable)
                            ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                classmapname_L4] = {}

                            # find the bandwidth info for this class-map
                            indices_L5 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                          self.object_types['queueing'], idx_L4)
                            for idx_L5 in indices_L5:
                                cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5,
                                                                        cbQosObjectsTable)
                                (bandwidth, units) = self.get_bandwidth(cbQosConfigIndex, cbQosQueueingCfgTable)
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['cfgidx'] = idx_L4
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['bw'] = bandwidth
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['bw_unit'] = units
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['bw_unit_text'] = self.queueing_bandwidth_units[units]

                            # find the police info for this class-map
                            indices_L5 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                          self.object_types['police'], idx_L4)
                            for idx_L5 in indices_L5:
                                cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5,
                                                                        cbQosObjectsTable)
                                (police_rate, police_rate_type, police_percent_rate) = self.get_police(cbQosConfigIndex, cbQosPoliceCfgTable)
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['cfgidx'] = idx_L4
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['police_rate'] = police_rate
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['police_rate_type'] = police_rate_type
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['police_rate_type_text'] = self.police_rate_types[police_rate_type]
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['police_percent_rate'] = police_percent_rate

                            # find the shaping info for this class-map
                            indices_L5 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                          self.object_types['trafficShaping'], idx_L4)
                            for idx_L5 in indices_L5:
                                cbQosConfigIndex = self.get_cbQosConfigIndex(cbQosObjectsTable_top_idx, idx_L5,
                                                                        cbQosObjectsTable)
                                (shape_rate, shape_type) = self.get_shaping(cbQosConfigIndex, cbQosTSCfgTable)
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['cfgidx'] = idx_L4
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['shape_rate'] = shape_rate
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['shape_type'] = shape_type
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['shape_type_text'] = self.shaping_rate_types[shape_type]

                            # find the random-detect info for this class-map
                            indices_L5 = self.get_indices(cbQosObjectsTable, cbQosObjectsTable_top_idx,
                                                          self.object_types['randomDetect'], idx_L4)
                            for idx_L5 in indices_L5:
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['cfgidx'] = idx_L4
                                ObjectsTable[cbQosObjectsTable_top_idx]['class-maps'][classmapname_L2]['class-maps'][
                                    classmapname_L4]['random_detect'] = True

                            # REMARK :
                            # we are now in double-nested classes :
                            # interface -> service-policy -> class-map -> policy-map -> class-map
                            # deeper recursion in QoS is indeed possible but improbable, so we stop recursing here.

        # ---------------------------------------------------------------------------------------
        # present the results
        # for each interface, we show the attached service-policy, then dig-down to the sub-objects
        # ---------------------------------------------------------------------------------------
        self.logger.info("consolidate the hierarchy to a JSON structure")

        # to collect everything related to QoS in a large JSON object
        qosinfo = autovivification.AutoVivification()

        for interface_idx in sorted(interfaces):

            # each interface
            interface_name = interfaces[interface_idx]

            # for each service-policy bound to the current interface
            for ObjectsTable_idx in sorted(InterfacesTable[interface_name]):
                service_policy_name = ObjectsTable[ObjectsTable_idx]['servicePolicyName']
                qosinfo[interface_name]['service-policies'][service_policy_name]['direction'] = \
                ObjectsTable[ObjectsTable_idx]['servicePolicyDirection']

                # second, find the class-maps within the current service-policy
                for class_map_L1 in sorted(ObjectsTable[ObjectsTable_idx]['class-maps']):

                    # policing : either percentage or rate
                    if 'police_rate_type' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        if ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type'] == '2':
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                class_map_L1]['police_rate'] = "%s %s" % (
                            ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_percent_rate'],
                            ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type_text'])
                        else:
                            qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                class_map_L1]['police_rate'] = "%s %s" % (
                            ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate'],
                            ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['police_rate_type_text'])

                    # bandwitdh
                    if 'bw' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1][
                            'bandwidth'] = "%s %s" % (ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['bw'],
                                                      ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1][
                                                          'bw_unit_text'])

                    # the shaping
                    if 'shape_rate' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1][
                            'shape_rate'] = "%s %s" % (
                        self.format_nr(ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['shape_rate']),
                        ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['shape_type_text'])

                    # in case someone wants to graph something, here is how you get the OIDs
                    if 'cfgidx' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        obj_idx = ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['cfgidx']
                        cbQosCMPostPolicyByte64_oid = self.get_full_oid('cbQosCMPostPolicyByte64', ObjectsTable_idx, obj_idx)
                        cbQosCMDropPkt64_oid = self.get_full_oid('cbQosCMDropPkt64', ObjectsTable_idx, obj_idx)
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1][
                            'oids']['cbQosCMPostPolicyByte64'] = cbQosCMPostPolicyByte64_oid
                        qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][class_map_L1][
                            'oids']['cbQosCMDropPkt64'] = cbQosCMDropPkt64_oid

                    # third level : the policy-maps within the current L1-class-map
                    if 'PolicyName' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        policy_map_name = ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['PolicyName']

                    # each class-map
                    if 'class-maps' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]:
                        for class_map_L2 in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps']:

                            # bandwidth
                            if 'bw' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                class_map_L2]:
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                    class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2][
                                    'bandwidth'] = "%s %s" % (
                                ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2][
                                    'bw'],
                                ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2][
                                    'bw_unit_text'])

                            # policing : either percentage or rate
                            if 'police_rate_type' in \
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                        class_map_L2]:
                                if \
                                ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2][
                                    'police_rate_type'] == '2':
                                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                        class_map_L1]['policy-maps'][policy_map_name]['class-maps'][
                                        class_map_L2]['police_rate'] = "%s %s" % (
                                        ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                            class_map_L2][
                                            'police_percent_rate'],
                                        ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                            class_map_L2][
                                            'police_rate_type_text'])
                                else:
                                    qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                        class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2][
                                        'police_rate'] = "%s %s" % (
                                        ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                            class_map_L2]['police_rate'],
                                        ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                            class_map_L2]['police_rate_type_text'])

                            # shaping
                            if 'shape_rate' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                class_map_L2]:
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                    class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2][
                                    'shape_rate'] = "%s %s" % (self.format_nr(
                                    ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                        class_map_L2]['shape_rate']), ObjectsTable[ObjectsTable_idx]['class-maps'][
                                                                   class_map_L1]['class-maps'][class_map_L2][
                                                                   'shape_type_text'])

                            # in case someone wants to graph something, here is how you get the OIDs
                            if 'cfgidx' in ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][
                                class_map_L2]:
                                obj_idx = \
                                ObjectsTable[ObjectsTable_idx]['class-maps'][class_map_L1]['class-maps'][class_map_L2][
                                    'cfgidx']
                                cbQosCMPostPolicyByte64_oid = self.get_full_oid('cbQosCMPostPolicyByte64', ObjectsTable_idx,
                                                                           obj_idx)
                                cbQosCMDropPkt64_oid = self.get_full_oid('cbQosCMDropPkt64', ObjectsTable_idx, obj_idx)
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                    class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['oids'][
                                    'cbQosCMPostPolicyByte64'] = cbQosCMPostPolicyByte64_oid
                                qosinfo[interface_name]['service-policies'][service_policy_name]['class-maps'][
                                    class_map_L1]['policy-maps'][policy_map_name]['class-maps'][class_map_L2]['oids'][
                                    'cbQosCMDropPkt64'] = cbQosCMDropPkt64_oid

        analysis_end = datetime.now()
        tdiff = analysis_end - analysis_start
        analysis_duration = (tdiff.microseconds + (tdiff.seconds + tdiff.days * 24 * 3600) * 10 ** 6) / 1000

        self.logger.info('collection_duration=%s, analysis_duration=%s' % (collection_duration, analysis_duration))

        # add all the stuff to a data structure and encode in JSON

        meta = {}
        meta['timestamp'] = datetime.now().isoformat()
        meta['collection_duration'] = collection_duration
        meta['devicename'] = devicename
        meta['interfaces_count'] = len(qosinfo)

        self.logger.debug('fn=QOS/collect : %s : returning qos info for %s interfaces' % (devicename, len(qosinfo)))
        return meta, qosinfo


    # ---------------------------------------------------------------------------------------
    def get_table(self, m, devicename, oid):

        #self.logger.debug('fn=qos/get_table : d=%s, oid=%s' % (devicename, oid))

        tstart = datetime.now()

        session = m._session._session

        try:
            self.logger.debug('fn=qos/get_table : %s : SNMP walk on %s' % (devicename, oid))
            data = session.walkmore(str(oid))
        except Exception as e:
            self.logger.error("fn=qos/get_table : %s : oid walk failed: %s" % (devicename, e))
            return errst.status('ERROR_SNMP_OP', 'oid walk failed: %s' % e), 200

        # try to unpack the Python tuples. Not sure it will work with all sorts of get/walk results
        entries = {}
        for entry in data:
            #self.logger.debug('entry=<%s>' % str(entry))
            oid = '.'.join(map(str, entry[0]))
            if type(entry[1]) == tuple:
                value = '.'.join(map(str, entry[1]))
            else:
                value = str(entry[1])
            entries[oid] = value

        tend = datetime.now()
        tdiff = tend - tstart
        duration = (tdiff.microseconds + (tdiff.seconds +
                                          tdiff.days * 24 * 3600) * 10 ** 6) / 1000

        self.logger.info('fn=qos/get_table : %s : count=%s, duration=%s' % (devicename, len(entries), duration))
        return entries


    # ---------------------------------------------------------------------------------------
    def get_cbQosServicePolicyTable(self, cbQosServicePolicyEntries):

        self.logger.debug("in get_cbQosServicePolicyTable")
        cbQosServicePolicyTable = autovivification.AutoVivification()
        for cbQosServicePolicyEntry in list(cbQosServicePolicyEntries.keys()):
            array = cbQosServicePolicyEntry.split('.')
            pName = array[13]
            cbQosPolicyIndex = array[14]
            pVal = self.cbQosServicePolicyEntry_lookup.get(pName, pName)
            cbQosServicePolicyTable[cbQosPolicyIndex][pVal] = cbQosServicePolicyEntries[cbQosServicePolicyEntry]

        return cbQosServicePolicyTable


    # ---------------------------------------------------------------------------------------
    def get_ifEntriesTable(self, ifEntries):

        self.logger.debug("in get_ifEntriesTable")
        ifEntriesTable = {}
        for ifEntry in list(ifEntries.keys()):
            array = ifEntry.split('.')
            ifEntryIndex = array[10]
            ifEntriesTable[ifEntryIndex] = ifEntries[ifEntry]

        return ifEntriesTable


    # ---------------------------------------------------------------------------------------
    def get_cbQosObjectTable(self, cbQosObjectsEntries):

        self.logger.debug("in get_cbQosObjectTable")
        cbQosObjectTable = autovivification.AutoVivification()
        for cbQosObjectsEntry in list(cbQosObjectsEntries.keys()):
            array = cbQosObjectsEntry.split('.')
            pName = array[13]
            cbQosPolicyIndex = array[14]
            cbQosObjectsIndex = array[15]
            pVal = self.cbQosObjectsEntry_lookup.get(pName, pName)
            cbQosObjectTable[cbQosPolicyIndex]["QosObjectsEntry"][cbQosObjectsIndex][pVal] = cbQosObjectsEntries[
                cbQosObjectsEntry]

        return cbQosObjectTable


    # ---------------------------------------------------------------------------------------
    def get_cbQosPolicyMapTable(self, cbQosPolicyMapCfgEntries):

        self.logger.debug("in get_cbQosPolicyMapTable")
        cbQosPolicyMapTable = autovivification.AutoVivification()
        for cbQosPolicyMapEntry in list(cbQosPolicyMapCfgEntries.keys()):
            array = cbQosPolicyMapEntry.split('.')
            pName = array[13]
            cbQosConfigIndex = array[14]
            pVal = self.cbQosPolicyMapCfgEntry_lookup.get(pName, pName)
            cbQosPolicyMapTable[cbQosConfigIndex][pVal] = cbQosPolicyMapCfgEntries[cbQosPolicyMapEntry]

        return cbQosPolicyMapTable


    # ---------------------------------------------------------------------------------------
    def get_cbQosCMCfgTable(self, cbQosCMCfgEntries):

        self.logger.debug("in get_cbQosCMCfgTable")
        cbQosCMCfgTable = autovivification.AutoVivification()
        for cbQosCMEntry in list(cbQosCMCfgEntries.keys()):
            array = cbQosCMEntry.split('.')
            pName = array[13]
            cbQosConfigIndex = array[14]
            pVal = self.cbQosCMCfgEntry_lookup.get(pName, pName)
            cbQosCMCfgTable[cbQosConfigIndex][pVal] = cbQosCMCfgEntries[cbQosCMEntry]

        return cbQosCMCfgTable


    # ---------------------------------------------------------------------------------------
    def get_cbQosQueueingCfgTable(self, cbQosQueueingCfgEntries):

        self.logger.debug("in get_cbQosQueueingCfgTable")
        cbQosQueueingCfgTable = autovivification.AutoVivification()
        for cbQosQueueingCfgEntry in list(cbQosQueueingCfgEntries.keys()):
            array = cbQosQueueingCfgEntry.split('.')
            pName = array[13]
            cbQosConfigIndex = array[14]
            pVal = self.cbQosQueueingCfgEntry_lookup.get(pName, pName)
            cbQosQueueingCfgTable[cbQosConfigIndex][pVal] = cbQosQueueingCfgEntries[cbQosQueueingCfgEntry]

        return cbQosQueueingCfgTable


    # ---------------------------------------------------------------------------------------
    def get_cbQosTSCfgTable(self, cbQosTSCfgEntries):

        self.logger.debug("in get_cbQosTSCfgTable")
        cbQosTSCfgTable = autovivification.AutoVivification()

        for cbQosTSCfgEntry in list(cbQosTSCfgEntries.keys()):
            array = cbQosTSCfgEntry.split('.')
            pName = array[13]
            cbQosConfigIndex = array[14]
            pVal = self.cbQosTSCfgEntry_lookup.get(pName, pName)
            cbQosTSCfgTable[cbQosConfigIndex][pVal] = cbQosTSCfgEntries[cbQosTSCfgEntry]

        return cbQosTSCfgTable

    # ---------------------------------------------------------------------------------------
    def get_cbQosPoliceCfgTable(self, cbQosPoliceCfgEntries):

        self.logger.debug("in get_cbQosPoliceCfgTable")
        cbQosPoliceCfgTable = autovivification.AutoVivification()
        for cbQosPoliceCfgEntry in list(cbQosPoliceCfgEntries.keys()):
            array = cbQosPoliceCfgEntry.split('.')
            pName = array[13]
            cbQosConfigIndex = array[14]
            pVal = self.cbQosPoliceCfgEntry_lookup.get(pName, pName)
            cbQosPoliceCfgTable[cbQosConfigIndex][pVal] = cbQosPoliceCfgEntries[cbQosPoliceCfgEntry]

        return cbQosPoliceCfgTable

    # ---------------------------------------------------------------------------------------
    def get_interface(self, idx, cbQosServicePolicyTable, interfaces):

        interface_idx = cbQosServicePolicyTable[idx]['cbQosIfIndex']
        interface_name = interfaces.get(interface_idx, None)
        return (interface_idx, interface_name)

    # ---------------------------------------------------------------------------------------
    # parse cbQosObjectsTable to find the list of indices having a certain parent,
    # type and top-index. Used to build the object hierarchy
    def get_indices(self, cbQosObjectsTable, cbQosObjectsTable_top_idx, objectType, parent):
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
    def get_cbQosConfigIndex(self, top_idx, obj_idx, cbQosObjectsTable):

        return cbQosObjectsTable[top_idx]['QosObjectsEntry'][obj_idx]['cbQosConfigIndex']


    # ---------------------------------------------------------------------------------------
    def get_police(self, idx, cbQosPoliceCfgTable):

        rate = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgRate64']
        unit = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgRateType']
        perc_rate = cbQosPoliceCfgTable[idx]['cbQosPoliceCfgPercentRateValue']
        if unit == '1':   # bps to kbps
            rate = str(int(rate) / 1000)
        return (rate, unit, perc_rate)

    # ---------------------------------------------------------------------------------------
    def get_classmap_name(self, idx, cbQosCMCfgTable):

        if 'cbQosCMName' in cbQosCMCfgTable[idx]:
            return cbQosCMCfgTable[idx]['cbQosCMName']
        else:
            return 'noNameClassMap'

    # ---------------------------------------------------------------------------------------
    def get_policymap_name(self, idx, cbQosPolicyMapCfgTable):

        return cbQosPolicyMapCfgTable[idx]['cbQosPolicyMapName']

    # ---------------------------------------------------------------------------------------
    def get_policymap_direction(self, idx, cbQosServicePolicyTable):

        return cbQosServicePolicyTable[idx]['cbQosPolicyDirection']

    # ---------------------------------------------------------------------------------------
    def get_shaping(self, idx, cbQosTSCfgTable):

        rate = cbQosTSCfgTable[idx]['cbQosTSCfgRate']
        unit = cbQosTSCfgTable[idx]['cbQosTSCfgRateType']
        if unit == '1':  # bps
            rate = str(int(rate) / 1000)
        return (rate, unit)


    # ---------------------------------------------------------------------------------------
    def get_bandwidth(self, idx, cbQosQueueingCfgTable):

        bandwidth = cbQosQueueingCfgTable[idx]['cbQosQueueingCfgBandwidth']
        unit = cbQosQueueingCfgTable[idx]['cbQosQueueingCfgBandwidthUnits']
        # we don't divide by 1'000, because the unit is already kbps.
        return (bandwidth, unit)

    # ---------------------------------------------------------------------------------------
    def get_full_oid(self, base_oid, policy_idx, obj_idx):

        return self.qos_oids[base_oid] + '.' + str(policy_idx) + '.' + str(obj_idx)

    # ---------------------------------------------------------------------------------------
    def format_nr(self, number):
    # 1000000000 --> 1'000'000'000
    # Python 2.7 has formats, but we are still under 2.6

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
    def node_to_oid(self, mibtosearch, node):

        # see https://github.com/vincentbernat/snimpy/issues/85
        oid_tuple = mib.get(mibtosearch, node).oid
        oid_str = '.'.join(map(str, oid_tuple))
        return oid_str

