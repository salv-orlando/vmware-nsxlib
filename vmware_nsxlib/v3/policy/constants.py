# Copyright 2017 VMware, Inc.
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

TCP = 'TCP'
UDP = 'UDP'

POLICY_INFRA_TENANT = 'infra'
POLICY_AAA_TENANT = 'aaa'

ACTION_ALLOW = 'ALLOW'
ACTION_DENY = 'DROP'

ANY_GROUP = 'ANY'
ANY_SERVICE = 'ANY'

CONDITION_KEY_TAG = 'Tag'
CONDITION_KEY_NAME = 'Name'
CONDITION_MEMBER_IPSET = 'IPSet'
CONDITION_MEMBER_VM = 'VirtualMachine'
CONDITION_MEMBER_PORT = 'LogicalPort'
CONDITION_MEMBER_SWITCH = 'LogicalSwitch'
CONDITION_OP_EQUALS = 'EQUALS'
CONDITION_OP_NOTEQUALS = 'NOTEQUALS'
CONDITION_OP_CONTAINS = 'CONTAINS'
CONDITION_OP_STARTS_WITH = 'STARTSWITH'
CONDITION_OP_AND = 'AND'
CONDITION_OP_OR = 'OR'

DEFAULT_THUMBPRINT = 'abc'
DEFAULT_DOMAIN = 'default'
DEFAULT_ENFORCEMENT_POINT = 'default'

STATE_REALIZED = 'REALIZED'
STATE_UNREALIZED = 'UNREALIZED'
STATE_ERROR = 'ERROR'

CATEGORY_EMERGENCY = 'Emergency'
CATEGORY_INFRASTRUCTURE = 'Infrastructure'
CATEGORY_ENVIRONMENT = 'Environment'
CATEGORY_APPLICATION = 'Application'
CATEGORY_LOCAL_GW = 'LocalGatewayRules'

ACTIVE_STANDBY = 'ACTIVE_STANDBY'
ACTIVE_ACTIVE = 'ACTIVE_ACTIVE'

PREEMPTIVE = 'PREEMPTIVE'
NON_PREEMPTIVE = 'NON_PREEMPTIVE'

NAT_ACTION_SNAT = 'SNAT'
NAT_ACTION_DNAT = 'DNAT'
NAT_ACTION_NO_SNAT = 'NO_SNAT'
NAT_ACTION_NO_DNAT = 'NO_DNAT'
NAT_ACTION_REFLEXIVE = 'REFLEXIVE'
NAT_FIREWALL_MATCH_BYPASS = 'BYPASS'
NAT_FIREWALL_MATCH_EXTERNAL = 'MATCH_EXTERNAL_ADDRESS'
NAT_FIREWALL_MATCH_INTERNAL = 'MATCH_INTERNAL_ADDRESS'

# Segment ports attachment types
ATTACHMENT_PARENT = "PARENT"
ATTACHMENT_CHILD = "CHILD"
ATTACHMENT_INDEPENDENT = "INDEPENDENT"

IPV6_RA_MODE_DISABLED = "DISABLED"
IPV6_RA_MODE_SLAAC_RA = "SLAAC_DNS_THROUGH_RA"
IPV6_RA_MODE_SLAAC_DHCP = "SLAAC_DNS_THROUGH_DHCP"
IPV6_RA_MODE_DHCP = "DHCP_ADDRESS_AND_DNS_THROUGH_DHCP"

# WAF operational mode types
WAF_OPERATIONAL_MODE_DETECTION = 'DETECTION'
WAF_OPERATIONAL_MODE_PROTECTION = 'PROTECTION'
WAF_OPERATIONAL_MODE_DISABLED = 'DISABLED'

# WAF debug log level types
WAF_LOG_LEVEL_NO_LOG = 'NO_LOG'
WAF_LOG_LEVEL_ERROR = 'ERROR'
WAF_LOG_LEVEL_WARNING = 'WARNING'
WAF_LOG_LEVEL_NOTICE = 'NOTICE'
WAF_LOG_LEVEL_INFO = 'INFO'
WAF_LOG_LEVEL_DETAIL = 'DETAIL'
WAF_LOG_LEVEL_EVERYTHING = 'EVERYTHING'


# IpPool subnet type
IPPOOL_BLOCK_SUBNET = "IpAddressPoolBlockSubnet"
IPPOOL_STATIC_SUBNET = "IpAddressPoolStaticSubnet"

ADV_RULE_PERMIT = 'PERMIT'
ADV_RULE_DENY = 'DENY'

ADV_RULE_OPERATOR_GE = 'GE'
ADV_RULE_OPERATOR_EQ = 'EQ'

ADV_RULE_TYPE_TIER1_STATIC_ROUTES = 'TIER1_STATIC_ROUTES'
ADV_RULE_TIER1_CONNECTED = 'TIER1_CONNECTED'
ADV_RULE_TIER1_NAT = 'TIER1_NAT'
ADV_RULE_TIER1_LB_VIP = 'TIER1_LB_VIP'
ADV_RULE_TIER1_LB_SNAT = 'TIER1_LB_SNAT'
ADV_RULE_TIER1_DNS_FORWARDER_IP = 'TIER1_DNS_FORWARDER_IP'
ADV_RULE_TIER1_IPSEC_LOCAL_ENDPOINT = 'TIER1_IPSEC_LOCAL_ENDPOINT'

IPSEC_VPN_RULE_PROTECT = 'PROTECT'
IPSEC_VPN_RULE_BYPASS = 'BYPASS'
