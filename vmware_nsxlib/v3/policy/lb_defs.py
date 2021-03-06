# Copyright 2018 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
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
#

from oslo_log import log as logging
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy.core_defs import ResourceDef

LOG = logging.getLogger(__name__)

TENANTS_PATH_PATTERN = "%s/"
LB_VIRTUAL_SERVERS_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-virtual-servers/"
LB_SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-services/"
LB_POOL_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-pools/"
LB_APP_PROFILE_PATTERN = TENANTS_PATH_PATTERN + "lb-app-profiles/"
LB_MONITOR_PROFILE_PATTERN = TENANTS_PATH_PATTERN + "lb-monitor-profiles/"
LB_CLIENT_SSL_PROFILE_PATTERN = (TENANTS_PATH_PATTERN +
                                 "lb-client-ssl-profiles/")
LBSERVER_SSL_PROFILE_PATTERN = (TENANTS_PATH_PATTERN +
                                "lb-server-ssl-profiles/")
LB_PERSISTENCE_PROFILE_PATTERN = (TENANTS_PATH_PATTERN +
                                  "lb-persistence-profiles/")


class LBRuleDef(object):
    def __init__(self, actions, match_conditions=None, name=None,
                 match_strategy=None, phase=None):
        self.actions = actions
        self.name = name
        self.match_conditions = match_conditions
        self.match_strategy = match_strategy
        self.phase = phase

    def get_obj_dict(self):
        lb_rule = {
            'actions': self.actions
        }
        if self.match_conditions:
            lb_rule['match_conditions'] = self.match_conditions
        if self.name:
            lb_rule['display_name'] = self.name
        if self.match_strategy:
            lb_rule['match_strategy'] = self.match_strategy
        if self.phase:
            lb_rule['phase'] = self.phase
        return lb_rule


class LBPoolMemberDef(object):
    def __init__(self, ip_address, port=None, name=None,
                 weight=None, admin_state=None, backup_member=None):
        self.name = name
        self.ip_address = ip_address
        self.port = port
        self.weight = weight
        self.admin_state = admin_state
        self.backup_member = backup_member

    def get_obj_dict(self):
        body = {'ip_address': self.ip_address}
        if self.name:
            body['display_name'] = self.name
        if self.ip_address:
            body['port'] = self.port
        if self.weight:
            body['weight'] = self.weight
        if self.admin_state:
            body['admin_state'] = self.admin_state
        if self.backup_member is not None:
            body['backup_member'] = self.backup_member
        return body


class LBServerSslProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return LBSERVER_SSL_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'server_ssl_profile_id')

    @staticmethod
    def resource_type():
        return "LBServerSslProfile"

    def get_obj_dict(self):
        body = super(LBServerSslProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['cipher_group_label', 'ciphers',
                                            'protocols',
                                            'session_cache_enabled'])
        return body


class LBClientSslProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_CLIENT_SSL_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'client_ssl_profile_id')

    @staticmethod
    def resource_type():
        return "LBClientSslProfile"

    def get_obj_dict(self):
        body = super(LBClientSslProfileDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'protocols')
        return body


class LBPersistenceProfileBase(ResourceDef):

    @property
    def path_pattern(self):
        return LB_PERSISTENCE_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'persistence_profile_id')


class LBCookiePersistenceProfileDef(LBPersistenceProfileBase):

    @staticmethod
    def resource_type():
        return "LBCookiePersistenceProfile"

    def get_obj_dict(self):
        body = super(LBCookiePersistenceProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['cookie_garble', 'cookie_mode', 'cookie_name',
                   'cookie_path', 'cookie_time', 'persistence_shared'])
        return body


class LBSourceIpPersistenceProfileDef(LBPersistenceProfileBase):

    @staticmethod
    def resource_type():
        return "LBSourceIpPersistenceProfile"

    def get_obj_dict(self):
        body = super(LBSourceIpPersistenceProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['ha_persistence_mirroring_enabled', 'persistence_shared',
                   'purge', 'timeout'])
        return body


class LBAppProfileBaseDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_APP_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_app_profile_id')

    def get_obj_dict(self):
        body = super(LBAppProfileBaseDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['idle_timeout'])
        return body


class LBHttpProfileDef(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBHttpProfile"

    def get_obj_dict(self):
        body = super(LBHttpProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['http_redirect_to', 'http_redirect_to_https', 'ntlm',
                   'request_body_size', 'request_header_size',
                   'response_header_size', 'response_timeout',
                   'x_forwarded_for'])
        return body


class LBFastTcpProfile(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBFastTcpProfile"

    def get_obj_dict(self):
        body = super(LBFastTcpProfile, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['close_timeout', 'ha_flow_mirroring_enabled'])
        return body


class LBFastUdpProfile(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBFastUdpProfile"

    def get_obj_dict(self):
        body = super(LBFastUdpProfile, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['flow_mirroring_enabled'])
        return body


class LBPoolDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_POOL_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_pool_id')

    @staticmethod
    def resource_type():
        return 'LBPool'

    def get_obj_dict(self):
        body = super(LBPoolDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['active_monitor_paths',
                   'algorithm', 'member_group', 'snat_translation',
                   'tcp_multiplexing_enabled', 'tcp_multiplexing_number'])
        members = self.get_attr('members')
        if members is None:
            members = []
        if self.has_attr('members'):
            members = members if isinstance(members, list) else [members]
            body['members'] = []
            for member in members:
                # the list contains old json members and newly added member
                if isinstance(member, LBPoolMemberDef):
                    member = member.get_obj_dict()
                body['members'].append(member)
        return body


class LBVirtualServerDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_VIRTUAL_SERVERS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'virtual_server_id')

    @staticmethod
    def resource_type():
        return 'LBVirtualServer'

    def get_obj_dict(self):
        body = super(LBVirtualServerDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['ip_address', 'ports', 'max_concurrent_connections'])
        self._set_attrs_if_supported(
            body, ['access_log_enabled', 'log_significant_event_only'])
        client_ssl_binding = self.get_attr('client_ssl_profile_binding')
        if client_ssl_binding:
            self._set_attr_if_specified(
                body, 'client_ssl_profile_binding',
                value=client_ssl_binding)
        server_ssl_binding = self.get_attr('server_ssl_profile_binding')
        if server_ssl_binding:
            self._set_attr_if_specified(
                body, 'server_ssl_profile_binding',
                value=server_ssl_binding)
        waf_profile_binding = self.get_attr('waf_profile_binding')
        if waf_profile_binding:
            if isinstance(waf_profile_binding, WAFProfileBindingDef):
                waf_profile_binding = waf_profile_binding.get_obj_dict()
            self._set_attr_if_specified(
                body, 'waf_profile_binding',
                value=waf_profile_binding)
        rules = self.get_attr('rules')
        if self.has_attr('rules'):
            rules = rules if isinstance(rules, list) else [rules]
            body['rules'] = []
            for rule in rules:
                # the list contains old json rules and newly added ruledef rule
                if isinstance(rule, LBRuleDef):
                    rule = rule.get_obj_dict()
                body['rules'].append(rule)
        app_profile_id = self.get_attr('application_profile_id')
        if app_profile_id:
            app_profile_def = LBAppProfileBaseDef(
                lb_app_profile_id=app_profile_id, tenant=self.get_tenant())
            body['application_profile_path'] = (
                app_profile_def.get_resource_full_path())

        if self.has_attr('lb_persistence_profile_id'):
            path = ""
            lb_persistence_profile_id = self.get_attr(
                'lb_persistence_profile_id')
            if lb_persistence_profile_id:
                lb_persistence_profile_def = LBPersistenceProfileBase(
                    persistence_profile_id=lb_persistence_profile_id,
                    tenant=self.get_tenant())
                path = lb_persistence_profile_def.get_resource_full_path()
            body['lb_persistence_profile_path'] = path
        if self.has_attr('lb_service_id'):
            path = ""
            lb_service_id = self.get_attr('lb_service_id')
            if lb_service_id:
                lb_service_def = LBServiceDef(
                    lb_service_id=lb_service_id, tenant=self.get_tenant())
                path = lb_service_def.get_resource_full_path()
            body['lb_service_path'] = path
        if self.has_attr('pool_id'):
            path = ""
            lb_pool_id = self.get_attr('pool_id')
            if lb_pool_id:
                lb_pool_def = LBPoolDef(
                    lb_pool_id=lb_pool_id, tenant=self.get_tenant())
                path = lb_pool_def.get_resource_full_path()
            body['pool_path'] = path
        if self.has_attr('access_list_control'):
            lb_alc = self.get_attr('access_list_control')
            if isinstance(lb_alc, LBAccessListControlDef):
                self.attrs['access_list_control'] = lb_alc.get_obj_dict()
            self._set_attrs_if_supported(body, ['access_list_control'])
        return body

    @property
    def version_dependant_attr_map(self):
        return {'access_list_control': nsx_constants.NSX_VERSION_3_0_0,
                'access_log_enabled': nsx_constants.NSX_VERSION_3_0_0,
                'log_significant_event_only': nsx_constants.NSX_VERSION_3_0_0}


class ClientSSLProfileBindingDef(object):
    def __init__(self, default_certificate_path, sni_certificate_paths=None,
                 ssl_profile_path=None, client_auth_ca_paths=None,
                 client_auth=None):
        self.default_certificate_path = default_certificate_path
        self.sni_certificate_paths = sni_certificate_paths
        self.ssl_profile_path = ssl_profile_path
        self.client_auth_ca_paths = client_auth_ca_paths
        self.client_auth = client_auth

    def get_obj_dict(self):
        body = {
            'default_certificate_path': self.default_certificate_path
        }
        if self.sni_certificate_paths:
            body['sni_certificate_paths'] = self.sni_certificate_paths
        if self.ssl_profile_path:
            body['ssl_profile_path'] = self.ssl_profile_path
        if self.client_auth_ca_paths:
            body['client_auth_ca_paths'] = self.client_auth_ca_paths
        if self.client_auth:
            body['client_auth'] = self.client_auth
        return body


class ServerSSLProfileBindingDef(object):
    def __init__(self, client_certificate_path=None,
                 certificate_chain_depth=None,
                 server_auth=None, server_auth_ca_paths=None,
                 server_auth_crl_paths=None, ssl_profile_path=None):
        self.client_certificate_path = client_certificate_path
        self.certificate_chain_depth = certificate_chain_depth
        self.server_auth = server_auth
        self.server_auth_ca_paths = server_auth_ca_paths
        self.server_auth_crl_paths = server_auth_crl_paths
        self.ssl_profile_path = ssl_profile_path

    def get_obj_dict(self):
        body = {}
        if self.client_certificate_path:
            body['client_certificate_path'] = self.client_certificate_path
        if self.ssl_profile_path:
            body['certificate_chain_depth'] = self.certificate_chain_depth
        if self.server_auth:
            body['server_auth'] = self.server_auth
        if self.ssl_profile_path:
            body['server_auth_ca_paths'] = self.server_auth_ca_paths
        if self.server_auth_crl_paths:
            body['server_auth_crl_paths'] = self.server_auth_crl_paths
        if self.ssl_profile_path:
            body['ssl_profile_path'] = self.ssl_profile_path
        return body


class WAFProfileBindingDef(object):
    def __init__(self, waf_profile_path,
                 operational_mode=constants.WAF_OPERATIONAL_MODE_PROTECTION,
                 debug_log_level=constants.WAF_LOG_LEVEL_NO_LOG):
        self.waf_profile_path = waf_profile_path
        self.operational_mode = operational_mode
        self.debug_log_level = debug_log_level

    def get_obj_dict(self):
        body = {
            'waf_profile_path': self.waf_profile_path,
            'operational_mode': self.operational_mode,
            'debug_log_level': self.debug_log_level
        }
        return body


class LBServiceDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_SERVICES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id')

    @staticmethod
    def resource_type():
        return 'LBService'

    def get_obj_dict(self):
        body = super(LBServiceDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['size', 'connectivity_path'])
        self._set_attrs_if_supported(body, ['relax_scale_validation'])
        return body

    @property
    def version_dependant_attr_map(self):
        return {'relax_scale_validation': nsx_constants.NSX_VERSION_3_0_0}


class LBServiceStatisticsDef(ResourceDef):

    def __init__(self, **kwargs):
        self.realtime = kwargs.pop('realtime')
        super(LBServiceStatisticsDef, self).__init__(**kwargs)

    @property
    def path_pattern(self):
        if self.realtime:
            return (LB_SERVICES_PATH_PATTERN +
                    '%s/statistics?source=realtime')
        return LB_SERVICES_PATH_PATTERN + '%s/statistics/'

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id', '')


class LBServiceStatusDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_SERVICES_PATH_PATTERN + '%s/detailed-status/'

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id', '')


class LBServiceUsageDef(ResourceDef):

    def __init__(self, **kwargs):
        self.realtime = kwargs.pop('realtime')
        super(LBServiceUsageDef, self).__init__(**kwargs)

    @property
    def path_pattern(self):
        if self.realtime:
            return (LB_SERVICES_PATH_PATTERN +
                    '%s/service-usage?source=realtime')
        return LB_SERVICES_PATH_PATTERN + '%s/service-usage/'

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id', '')


class LBVirtualServerStatusDef(ResourceDef):

    @property
    def path_pattern(self):
        return (LB_SERVICES_PATH_PATTERN +
                '%s/lb-virtual-servers/%s/detailed-status/')

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id', 'lb_virtual_server_id', '')


class LBMonitorProfileBaseDef(ResourceDef):

    addl_attrs = ['interval', 'timeout', 'fall_count', 'rise_count']

    @property
    def path_pattern(self):
        return LB_MONITOR_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_monitor_profile_id')

    def get_obj_dict(self):
        body = super(LBMonitorProfileBaseDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, self.addl_attrs)
        return body


class LBHttpMonitorProfileDef(LBMonitorProfileBaseDef):

    addl_attrs = LBMonitorProfileBaseDef.addl_attrs + [
        'monitor_port', 'request_url', 'request_method', 'request_version',
        'request_headers', 'request_body', 'response_status_codes']

    @staticmethod
    def resource_type():
        return "LBHttpMonitorProfile"


class LBHttpsMonitorProfileDef(LBHttpMonitorProfileDef):

    @staticmethod
    def resource_type():
        return "LBHttpsMonitorProfile"


class LBUdpMonitorProfileDef(LBMonitorProfileBaseDef):

    addl_attrs = LBMonitorProfileBaseDef.addl_attrs + [
        'monitor_port', 'receive', 'send']

    @staticmethod
    def resource_type():
        return "LBUdpMonitorProfile"


class LBIcmpMonitorProfileDef(LBMonitorProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBIcmpMonitorProfile"


class LBTcpMonitorProfileDef(LBMonitorProfileBaseDef):

    addl_attrs = LBMonitorProfileBaseDef.addl_attrs + ['monitor_port']

    @staticmethod
    def resource_type():
        return "LBTcpMonitorProfile"


class LBAccessListControlDef(object):
    def __init__(self, action, group_path, enabled=None):
        self.action = action
        self.group_path = group_path
        self.enabled = enabled

    def get_obj_dict(self):
        access_list_control = {
            'action': self.action,
            'group_path': self.group_path
        }
        if self.enabled is not None:
            access_list_control['enabled'] = self.enabled
        return access_list_control
