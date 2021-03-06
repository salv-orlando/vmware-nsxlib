# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Admin statuses
ADMIN_STATE_UP = "UP"
ADMIN_STATE_DOWN = "DOWN"

# Replication modes
MTEP = "MTEP"

# Port attachment types
ATTACHMENT_VIF = "VIF"
ATTACHMENT_LR = "LOGICALROUTER"
ATTACHMENT_DHCP = "DHCP_SERVICE"
ATTACHMENT_MDPROXY = "METADATA_PROXY"

VIF_RESOURCE_TYPE = "VifAttachmentContext"

VIF_TYPE_PARENT = "PARENT"
VIF_TYPE_CHILD = "CHILD"

ALLOCATE_ADDRESS_NONE = "None"

# SegmentPort init_state types
INIT_STATE_UNBLOCKED_VLAN = 'UNBLOCKED_VLAN'
INIT_STATE_RESTORE_VIF = 'RESTORE_VIF'

# NSXv3 L2 Gateway constants
BRIDGE_ENDPOINT = "BRIDGEENDPOINT"
FAILOVER_MODE_PREEMPTIVE = "PREEMPTIVE"
FAILOVER_MODE_NONPREEMPTIVE = "NON_PREEMPTIVE"

# Router type
ROUTER_TYPE_TIER0 = "TIER0"
ROUTER_TYPE_TIER1 = "TIER1"
ROUTER_TYPE_TIER0_DR = "DISTRIBUTED_ROUTER_TIER0"
ROUTER_TYPE_TIER1_DR = "DISTRIBUTED_ROUTER_TIER1"

LROUTERPORT_UPLINK = "LogicalRouterUpLinkPort"
LROUTERPORT_DOWNLINK = "LogicalRouterDownLinkPort"
LROUTERPORT_CENTRALIZED = "LogicalRouterCentralizedServicePort"
LROUTERPORT_LINKONTIER0 = "LogicalRouterLinkPortOnTIER0"
LROUTERPORT_LINKONTIER1 = "LogicalRouterLinkPortOnTIER1"

# NSX service type
SERVICE_DHCP = "dhcp"

# NSX-V3 Distributed Firewall constants
IP_SET = 'IPSet'
NSGROUP = 'NSGroup'
NSGROUP_COMPLEX_EXP = 'NSGroupComplexExpression'
NSGROUP_SIMPLE_EXP = 'NSGroupSimpleExpression'
NSGROUP_TAG_EXP = 'NSGroupTagExpression'
EXCLUDE_PORT = 'Exclude-Port'

# Firewall rule position
FW_INSERT_BEFORE = 'insert_before'
FW_INSERT_AFTER = 'insert_after'
FW_INSERT_BOTTOM = 'insert_bottom'
FW_INSERT_TOP = 'insert_top'

# firewall rule actions
FW_ACTION_ALLOW = 'ALLOW'
FW_ACTION_DROP = 'DROP'
FW_ACTION_REJECT = 'REJECT'

# firewall disable/enable
FW_ENABLE = 'enable_firewall'
FW_DISABLE = 'disable_firewall'

# nsgroup members update actions
NSGROUP_ADD_MEMBERS = 'ADD_MEMBERS'
NSGROUP_REMOVE_MEMBERS = 'REMOVE_MEMBERS'

# NSServices resource types
L4_PORT_SET_NSSERVICE = 'L4PortSetNSService'
ICMP_TYPE_NSSERVICE = 'ICMPTypeNSService'
IP_PROTOCOL_NSSERVICE = 'IPProtocolNSService'

# firewall section types
FW_SECTION_LAYER3 = 'LAYER3'

TARGET_TYPE_LOGICAL_SWITCH = 'LogicalSwitch'
TARGET_TYPE_LOGICAL_PORT = 'LogicalPort'
TARGET_TYPE_IPV4ADDRESS = 'IPv4Address'
TARGET_TYPE_IPV6ADDRESS = 'IPv6Address'

# filtering operators and expressions
EQUALS = 'EQUALS'

IN = 'IN'
OUT = 'OUT'
IN_OUT = 'IN_OUT'

TCP = 'TCP'
UDP = 'UDP'
ICMPV4 = 'ICMPv4'
ICMPV6 = 'ICMPv6'
IPV4 = 'IPV4'
IPV6 = 'IPV6'
IPV4_IPV6 = 'IPV4_IPV6'

LOCAL_IP_PREFIX = 'local_ip_prefix'

# Allowed address pairs
NUM_ALLOWED_IP_ADDRESSES = 128
NUM_ALLOWED_IP_ADDRESSES_v4 = NUM_ALLOWED_IP_ADDRESSES
NUM_ALLOWED_IP_ADDRESSES_v6 = 15
MAX_STATIC_ROUTES = 26

# QoS directions egress/ingress
EGRESS = 'egress'
INGRESS = 'ingress'
EGRESS_SHAPING = 'EgressRateShaper'
INGRESS_SHAPING = 'IngressRateShaper'

# Transport zone constants
TRANSPORT_TYPE_VLAN = 'VLAN'
TRANSPORT_TYPE_OVERLAY = 'OVERLAY'
HOST_SWITCH_MODE_ENS = 'ENS'
HOST_SWITCH_MODE_STANDARD = 'STANDARD'

# Error codes returned by the backend
ERR_CODE_OBJECT_NOT_FOUND = 202
ERR_CODE_IPAM_POOL_EXHAUSTED = 5109
ERR_CODE_IPAM_SPECIFIC_IP = 5123
ERR_CODE_IPAM_IP_ALLOCATED = 5141
ERR_CODE_IPAM_IP_NOT_IN_POOL = 5110
ERR_CODE_IPAM_RANGE_MODIFY = 5602
ERR_CODE_IPAM_RANGE_DELETE = 5015
ERR_CODE_IPAM_RANGE_SHRUNK = 5016

# backend versions
NSX_VERSION_1_1_0 = '1.1.0'
NSX_VERSION_2_0_0 = '2.0.0'
NSX_VERSION_2_1_0 = '2.1.0'
NSX_VERSION_2_2_0 = '2.2.0'
NSX_VERSION_2_3_0 = '2.3.0'
NSX_VERSION_2_4_0 = '2.4.0'
NSX_VERSION_2_5_0 = '2.5.0'
NSX_VERSION_3_0_0 = '3.0.0'
NSX_VERSION_3_0_2 = '3.0.2'
NSX_VERSION_3_1_0 = '3.1.0'
NSX_VERSION_3_2_0 = '3.2.0'

# Features available depending on the NSX Manager backend version
FEATURE_MAC_LEARNING = 'MAC Learning'
FEATURE_DYNAMIC_CRITERIA = 'Dynamic criteria'
FEATURE_EXCLUDE_PORT_BY_TAG = 'Exclude Port by Tag'
FEATURE_ROUTER_FIREWALL = 'Router Firewall'
FEATURE_LOAD_BALANCER = 'Load Balancer'
FEATURE_LB_HM_RESPONSE_CODES = 'Load Balancer HM response codes'
FEATURE_DHCP_RELAY = 'DHCP Relay'
FEATURE_VLAN_ROUTER_INTERFACE = 'VLAN Router Interface'
FEATURE_RATE_LIMIT = 'Requests Rate Limit'
FEATURE_IPSEC_VPN = 'IPSec VPN'
FEATURE_ON_BEHALF_OF = 'On Behalf Of'
FEATURE_TRUNK_VLAN = 'Trunk Vlan'
FEATURE_ROUTER_TRANSPORT_ZONE = 'Router Transport Zone'
FEATURE_NO_DNAT_NO_SNAT = 'No DNAT/No SNAT'
FEATURE_ENS_WITH_SEC = 'ENS with security'
FEATURE_ENS_WITH_QOS = 'ENS with QoS'
FEATURE_ICMP_STRICT = 'Strict list of supported ICMP types and codes'
FEATURE_ROUTER_ALLOCATION_PROFILE = 'Router Allocation Profile'
FEATURE_ENABLE_STANDBY_RELOCATION = 'Router Enable standby relocation'
FEATURE_PARTIAL_UPDATES = 'Partial Update with PATCH'
FEATURE_RELAX_SCALE_VALIDATION = 'Relax Scale Validation for LbService'
FEATURE_SWITCH_HYPERBUS_MODE = 'Switch hyperbus mode with policy API'
FEATURE_GET_TZ_FROM_SWITCH = 'Get TZ endpoints from host switch'
FEATURE_ROUTE_REDISTRIBUTION_CONFIG = 'Tier0 route redistribution config'
FEATURE_CONTAINER_CLUSTER_INVENTORY = 'Container Cluster Inventory'
FEATURE_IPV6 = 'IPV6 Forwarding and Address Allocation'
FEATURE_MP2P_MIGRATION = 'MP to Policy Migration'
FEATURE_SPOOFGUARD_CIDR = 'Spoofguard IPv4 CIDR'

# Features available depending on the Policy Manager backend version
FEATURE_NSX_POLICY = 'NSX Policy'
FEATURE_NSX_POLICY_NETWORKING = 'NSX Policy Networking'
FEATURE_NSX_POLICY_MDPROXY = 'NSX Policy Metadata Proxy'
FEATURE_NSX_POLICY_DHCP = 'NSX Policy DHCP'
FEATURE_NSX_POLICY_GLOBAL_CONFIG = 'NSX Policy Global Config'
FEATURE_NSX_POLICY_ADMIN_STATE = 'NSX Policy Segment admin state'
FEATURE_NSX_POLICY_ORBAC = 'NSX Policy ORBAC'
