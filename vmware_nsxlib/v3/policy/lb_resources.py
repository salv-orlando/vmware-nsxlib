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

import copy

from oslo_log import log as logging

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy.core_resources import IGNORE
from vmware_nsxlib.v3.policy.core_resources import NsxPolicyResourceBase
from vmware_nsxlib.v3.policy import lb_defs
from vmware_nsxlib.v3 import utils


LOG = logging.getLogger(__name__)


class NsxPolicyLBAppProfileBase(NsxPolicyResourceBase):
    """NSX Policy LB app profile"""

    def create_or_overwrite(self, name,
                            lb_app_profile_id=None,
                            description=IGNORE,
                            http_redirect_to_https=IGNORE,
                            http_redirect_to=IGNORE,
                            idle_timeout=IGNORE,
                            ntlm=IGNORE,
                            request_body_size=IGNORE,
                            request_header_size=IGNORE,
                            response_header_size=IGNORE,
                            response_timeout=IGNORE,
                            x_forwarded_for=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_id = self._init_obj_uuid(lb_app_profile_id)
        lb_app_profile_def = self._init_def(
            lb_app_profile_id=lb_app_profile_id,
            name=name,
            description=description,
            http_redirect_to_https=http_redirect_to_https,
            http_redirect_to=http_redirect_to,
            idle_timeout=idle_timeout,
            ntlm=ntlm,
            request_body_size=request_body_size,
            request_header_size=request_header_size,
            response_header_size=response_header_size,
            response_timeout=response_timeout,
            x_forwarded_for=x_forwarded_for,
            tags=tags,
            tenant=tenant)
        self._create_or_store(lb_app_profile_def)
        return lb_app_profile_id

    def delete(self, lb_app_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_def = self.entry_def(
            lb_app_profile_id=lb_app_profile_id,
            tenant=tenant)
        self._delete_with_retry(lb_app_profile_def)

    def get(self, lb_app_profile_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lb_app_profile_def = self.entry_def(
            lb_app_profile_id=lb_app_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_app_profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_app_profile_def)

    def update(self, lb_app_profile_id,
               name=IGNORE,
               description=IGNORE,
               http_redirect_to_https=IGNORE,
               http_redirect_to=IGNORE,
               idle_timeout=IGNORE,
               ntlm=IGNORE,
               request_body_size=IGNORE,
               request_header_size=IGNORE,
               response_header_size=IGNORE,
               response_timeout=IGNORE,
               x_forwarded_for=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            lb_app_profile_id=lb_app_profile_id,
            name=name,
            description=description,
            http_redirect_to_https=http_redirect_to_https,
            http_redirect_to=http_redirect_to,
            idle_timeout=idle_timeout,
            ntlm=ntlm,
            request_body_size=request_body_size,
            request_header_size=request_header_size,
            response_header_size=response_header_size,
            response_timeout=response_timeout,
            x_forwarded_for=x_forwarded_for,
            tags=tags,
            tenant=tenant)

    def get_path(self, lb_app_profile_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            lb_app_profile_id=lb_app_profile_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()


class NsxPolicyLBAppProfileHttpApi(NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBHttpProfileDef


class NsxPolicyLBAppProfileFastTcpApi(
    NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBFastTcpProfile


class NsxPolicyLBAppProfileFastUdpApi(
    NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBFastUdpProfile


class NsxPolicyLoadBalancerServerSSLProfileApi(NsxPolicyResourceBase):
    """NSX Policy LB server ssl profile"""

    @property
    def entry_def(self):
        return lb_defs.LBServerSslProfileDef

    def create_or_overwrite(self, name, server_ssl_profile_id=None,
                            description=IGNORE, tags=IGNORE,
                            cipher_group_label=IGNORE, ciphers=IGNORE,
                            protocols=IGNORE, session_cache_enabled=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        server_ssl_profile_id = self._init_obj_uuid(server_ssl_profile_id)
        lb_server_ssl_profile_def = self._init_def(
            server_ssl_profile_id=server_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)
        self._create_or_store(lb_server_ssl_profile_def)
        return server_ssl_profile_id

    def delete(self, server_ssl_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_server_ssl_profile_def = self.entry_def(
            server_ssl_profile_id=server_ssl_profile_id,
            tenant=tenant)
        self._delete_with_retry(lb_server_ssl_profile_def)

    def get(self, server_ssl_profile_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lb_server_ssl_profile_def = self.entry_def(
            server_ssl_profile_id=server_ssl_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_server_ssl_profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_server_ssl_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_server_ssl_profile_def)

    def update(self, server_ssl_profile_id,
               name=IGNORE, description=IGNORE, tags=IGNORE,
               cipher_group_label=IGNORE, ciphers=IGNORE,
               protocols=IGNORE, session_cache_enabled=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            server_ssl_profile_id=server_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)


class NsxPolicyLoadBalancerClientSSLProfileApi(NsxPolicyResourceBase):
    """NSX Policy LB client ssl profile"""

    @property
    def entry_def(self):
        return lb_defs.LBClientSslProfileDef

    def create_or_overwrite(self, name,
                            client_ssl_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            protocols=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        client_ssl_profile_id = self._init_obj_uuid(
            client_ssl_profile_id)
        lb_client_ssl_profile_def = self._init_def(
            client_ssl_profile_id=client_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)
        self._create_or_store(lb_client_ssl_profile_def)
        return client_ssl_profile_id

    def delete(self, client_ssl_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_client_ssl_profile_def = self.entry_def(
            client_ssl_profile_id=client_ssl_profile_id,
            tenant=tenant)
        self._delete_with_retry(lb_client_ssl_profile_def)

    def get(self, client_ssl_profile_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lb_client_ssl_profile_def = self.entry_def(
            client_ssl_profile_id=client_ssl_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_client_ssl_profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_client_ssl_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_client_ssl_profile_def)

    def update(self, client_ssl_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               protocols=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            client_ssl_profile_id=client_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)

    def get_path(self, profile_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            client_ssl_profile_id=profile_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()


class NsxPolicyLoadBalancerPersistenceProfileApi(
    NsxPolicyResourceBase):
    """LB generic api for all types of session persistence profiles"""

    @property
    def entry_def(self):
        return lb_defs.LBPersistenceProfileBase

    def create_or_overwrite(self, name,
                            persistence_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            ha_persistence_mirroring_enabled=IGNORE,
                            persistence_shared=IGNORE,
                            purge=IGNORE,
                            timeout=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        raise nsxlib_exc.NotImplemented(
            "Creating generic persistence profile")

    def delete(self, persistence_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        self._delete_with_retry(persistence_profile_def)

    def get(self, persistence_profile_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        return self.policy_api.get(persistence_profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_def = self.entry_def(tenant=tenant)
        return self._list(persistence_profile_def)

    def update(self, persistence_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               ha_persistence_mirroring_enabled=IGNORE,
               persistence_shared=IGNORE,
               purge=IGNORE,
               timeout=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        raise nsxlib_exc.NotImplemented(
            "Updating generic persistence profile")

    def get_path(self, profile_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            persistence_profile_id=profile_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()

    def wait_until_realized(self, pers_id,
                            entity_type='LbPersistenceProfileDto',
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        pers_def = self.entry_def(
            persistence_profile_id=pers_id, tenant=tenant)
        return self._wait_until_realized(
            pers_def, entity_type=entity_type,
            sleep=sleep, max_attempts=max_attempts)


class NsxPolicyLoadBalancerCookiePersistenceProfileApi(
    NsxPolicyLoadBalancerPersistenceProfileApi):
    """NSX Policy LB cookie persistence profile"""

    @property
    def entry_def(self):
        return lb_defs.LBCookiePersistenceProfileDef

    def create_or_overwrite(self, name,
                            persistence_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            cookie_garble=IGNORE,
                            cookie_name=IGNORE,
                            cookie_mode=IGNORE,
                            cookie_path=IGNORE,
                            cookie_time=IGNORE,
                            persistence_shared=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_id = self._init_obj_uuid(
            persistence_profile_id)
        lb_cookie_persistence_profile_def = self._init_def(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            cookie_name=cookie_name,
            cookie_garble=cookie_garble,
            cookie_mode=cookie_mode,
            cookie_path=cookie_path,
            cookie_time=cookie_time,
            persistence_shared=persistence_shared,
            tenant=tenant)
        self._create_or_store(lb_cookie_persistence_profile_def)
        return persistence_profile_id

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_cookie_persistence_profile_def = self.entry_def(tenant=tenant)
        results = self._list(lb_cookie_persistence_profile_def)
        # filter the results by resource type
        return [res for res in results
                if res.get('resource_type') == self.entry_def.resource_type()]

    def update(self, persistence_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               cookie_garble=IGNORE,
               cookie_name=IGNORE,
               cookie_mode=IGNORE,
               cookie_path=IGNORE,
               cookie_time=IGNORE,
               persistence_shared=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            cookie_garble=cookie_garble,
            cookie_mode=cookie_mode,
            cookie_name=cookie_name,
            cookie_path=cookie_path,
            cookie_time=cookie_time,
            persistence_shared=persistence_shared,
            tenant=tenant)


class NsxPolicyLoadBalancerSourceIpPersistenceProfileApi(
    NsxPolicyLoadBalancerPersistenceProfileApi):
    """NSX Policy LB source ip persistence profile"""

    @property
    def entry_def(self):
        return lb_defs.LBSourceIpPersistenceProfileDef

    def create_or_overwrite(self, name,
                            persistence_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            ha_persistence_mirroring_enabled=IGNORE,
                            persistence_shared=IGNORE,
                            purge=IGNORE,
                            timeout=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_id = self._init_obj_uuid(
            persistence_profile_id)
        lb_source_ip_persistence_profile_def = self._init_def(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            ha_persistence_mirroring_enabled=ha_persistence_mirroring_enabled,
            persistence_shared=persistence_shared,
            purge=purge,
            timeout=timeout,
            tenant=tenant)
        self._create_or_store(lb_source_ip_persistence_profile_def)
        return persistence_profile_id

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_source_ip_persistence_profile_def = self.entry_def(tenant=tenant)
        results = self._list(lb_source_ip_persistence_profile_def)
        # filter the results by resource type
        return [res for res in results
                if res.get('resource_type') == self.entry_def.resource_type()]

    def update(self, persistence_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               ha_persistence_mirroring_enabled=IGNORE,
               persistence_shared=IGNORE,
               purge=IGNORE,
               timeout=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            ha_persistence_mirroring_enabled=ha_persistence_mirroring_enabled,
            persistence_shared=persistence_shared,
            purge=purge,
            timeout=timeout,
            tenant=tenant)


class NsxPolicyLoadBalancerPoolApi(NsxPolicyResourceBase):
    """NSX Policy LBService."""
    @property
    def entry_def(self):
        return lb_defs.LBPoolDef

    def create_or_overwrite(self, name, lb_pool_id=None, description=IGNORE,
                            tags=IGNORE, members=IGNORE, algorithm=IGNORE,
                            active_monitor_paths=IGNORE, member_group=IGNORE,
                            snat_translation=IGNORE,
                            tcp_multiplexing_enabled=IGNORE,
                            tcp_multiplexing_number=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_id = self._init_obj_uuid(lb_pool_id)
        lb_pool_def = self._init_def(
            lb_pool_id=lb_pool_id,
            name=name,
            description=description,
            tags=tags,
            members=members,
            active_monitor_paths=active_monitor_paths,
            algorithm=algorithm,
            member_group=member_group,
            snat_translation=snat_translation,
            tcp_multiplexing_enabled=tcp_multiplexing_enabled,
            tcp_multiplexing_number=tcp_multiplexing_number,
            tenant=tenant)

        self._create_or_store(lb_pool_def)
        return lb_pool_id

    def delete(self, lb_pool_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        self._delete_with_retry(lb_pool_def)

    def get(self, lb_pool_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        return self.policy_api.get(lb_pool_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(tenant=tenant)
        return self.policy_api.list(lb_pool_def)['results']

    def update(self, lb_pool_id, name=IGNORE, description=IGNORE,
               tags=IGNORE, members=IGNORE, algorithm=IGNORE,
               active_monitor_paths=IGNORE, member_group=IGNORE,
               snat_translation=IGNORE, tcp_multiplexing_enabled=IGNORE,
               tcp_multiplexing_number=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               allow_partial_updates=True):
        self._update(
            lb_pool_id=lb_pool_id,
            name=name,
            description=description,
            tags=tags,
            members=members,
            active_monitor_paths=active_monitor_paths,
            algorithm=algorithm,
            member_group=member_group,
            snat_translation=snat_translation,
            tcp_multiplexing_enabled=tcp_multiplexing_enabled,
            tcp_multiplexing_number=tcp_multiplexing_number,
            tenant=tenant, allow_partial_updates=allow_partial_updates)

    def add_monitor_to_pool(self, lb_pool_id, active_monitor_paths,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        monitor_paths = lb_pool.get('active_monitor_paths', [])
        monitor_paths.extend(active_monitor_paths)
        self._update(
            lb_pool_id=lb_pool_id, active_monitor_paths=monitor_paths,
            tenant=tenant)

    def remove_monitor_from_pool(self, lb_pool_id, monitor_path,
                                 tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        monitor_paths = lb_pool.get('active_monitor_paths', [])
        if monitor_path in monitor_paths:
            monitor_paths.remove(monitor_path)
            self._update(lb_pool_id=lb_pool_id,
                         active_monitor_paths=monitor_paths,
                         tenant=tenant)

    def create_pool_member_and_add_to_pool(
            self, lb_pool_id, ip_address, port=None,
            display_name=None, weight=None, admin_state=None,
            backup_member=None,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_member = lb_defs.LBPoolMemberDef(
            ip_address, port=port,
            name=display_name,
            weight=weight, admin_state=admin_state,
            backup_member=backup_member)
        lb_pool_def = lb_defs.LBPoolDef(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        lb_pool_members = lb_pool.get('members', [])
        lb_pool_members.append(lb_pool_member)
        self._update(lb_pool_id=lb_pool_id, members=lb_pool_members,
                     tenant=tenant)
        return lb_pool_member

    def update_pool_member(
            self, lb_pool_id, ip_address, port=None,
            display_name=None, weight=None, admin_state=None,
            backup_member=None,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = lb_defs.LBPoolDef(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        lb_pool_members = lb_pool.get('members', [])
        member_to_update = [x for x in lb_pool_members if (
            x.get('ip_address') == ip_address and x.get('port') == str(port))]
        if member_to_update:
            if display_name:
                member_to_update[0]['display_name'] = display_name
            if weight:
                member_to_update[0]['weight'] = weight
            if admin_state:
                member_to_update[0]['admin_state'] = admin_state
            if backup_member is not None:
                member_to_update[0]['backup_member'] = backup_member
            self._update(lb_pool_id=lb_pool_id, members=lb_pool_members,
                         tenant=tenant)
        else:
            ops = ('Updating member %(address)s:%(port)d failed, not found in '
                   'pool %(pool)s', {'address': ip_address,
                                     'port': port,
                                     'pool': lb_pool_id})
            raise nsxlib_exc.ResourceNotFound(manager=lb_pool_def,
                                              operation=ops)

    def remove_pool_member(self, lb_pool_id, ip_address, port=None,
                           tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = lb_defs.LBPoolDef(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        lb_pool_members = lb_pool.get('members', [])
        lb_pool_members = [x for x in lb_pool_members if (
            x.get('ip_address') != ip_address or x.get('port') != str(port))]
        self._update(lb_pool_id=lb_pool_id, members=lb_pool_members,
                     tenant=tenant)

    def get_path(self, lb_pool_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            lb_pool_id=lb_pool_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()

    def wait_until_realized(self, lb_pool_id, entity_type='LbPoolDto',
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        return self._wait_until_realized(
            lb_pool_def, entity_type=entity_type,
            sleep=sleep, max_attempts=max_attempts)


class NsxPolicyLoadBalancerServiceApi(NsxPolicyResourceBase):
    """NSX Policy LBService."""

    @property
    def entry_def(self):
        return lb_defs.LBServiceDef

    def create_or_overwrite(self, name, lb_service_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            size=IGNORE,
                            connectivity_path=IGNORE,
                            relax_scale_validation=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_service_id = self._init_obj_uuid(lb_service_id)
        lb_service_def = self._init_def(
            lb_service_id=lb_service_id,
            name=name,
            description=description,
            tags=tags,
            size=size,
            connectivity_path=connectivity_path,
            relax_scale_validation=relax_scale_validation,
            tenant=tenant)

        self._create_or_store(lb_service_def)
        return lb_service_id

    def delete(self, lb_service_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        self._delete_with_retry(lb_service_def)

    def get(self, lb_service_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        return self.policy_api.get(lb_service_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT, silent=False,
             silent_if_empty=False):
        if not silent and silent_if_empty:
            # Log only non-empty results
            silent = True
        lb_service_def = lb_defs.LBServiceDef(tenant=tenant)
        list_results = self.policy_api.list(lb_service_def, silent=silent)
        if silent_if_empty and list_results.get('results'):
            LOG.debug("REST call: GET %s. Response: %s",
                      lb_service_def.get_section_path(), list_results)

        return list_results['results']

    def update(self, lb_service_id, name=IGNORE,
               description=IGNORE, tags=IGNORE,
               size=IGNORE, connectivity_path=IGNORE,
               relax_scale_validation=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(
            lb_service_id=lb_service_id,
            name=name,
            description=description,
            tags=tags,
            size=size,
            connectivity_path=connectivity_path,
            relax_scale_validation=relax_scale_validation,
            tenant=tenant)

    def update_customized(self, lb_service_id, update_payload_cbk,
                          tenant=constants.POLICY_INFRA_TENANT):
        """Update the LB service using GET & PUT

        Changing the body with a customized callback
        """

        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        lb_service_path = lb_service_def.get_resource_path()

        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.policy_api.client.max_attempts)
        def _update():
            # Get the current data of service
            lb_service_body = self.policy_api.get(lb_service_def)
            # Update the body with the supplied callback
            update_payload_cbk(lb_service_body)
            # Update the backend using PUT
            self.policy_api.client.update(lb_service_path, lb_service_body)

        _update()

    def get_statistics(self, lb_service_id, realtime=False,
                       tenant=constants.POLICY_INFRA_TENANT,
                       silent=False):
        lb_service_stats_def = (
            lb_defs.LBServiceStatisticsDef(
                lb_service_id=lb_service_id,
                realtime=realtime,
                tenant=tenant))
        return self.policy_api.get(lb_service_stats_def, silent=silent)

    def get_status(self, lb_service_id,
                   tenant=constants.POLICY_INFRA_TENANT,
                   silent=False):
        lb_service_status_def = (
            lb_defs.LBServiceStatusDef(
                lb_service_id=lb_service_id,
                tenant=tenant))
        return self.policy_api.get(lb_service_status_def, silent=silent)

    def get_virtual_server_status(self, lb_service_id, lb_virtual_server_id,
                                  tenant=constants.POLICY_INFRA_TENANT):
        lb_vs_status_def = (
            lb_defs.LBVirtualServerStatusDef(
                lb_service_id=lb_service_id,
                lb_virtual_server_id=lb_virtual_server_id,
                tenant=tenant))
        return self.policy_api.get(lb_vs_status_def)

    def get_usage(self, lb_service_id, realtime=False,
                  tenant=constants.POLICY_INFRA_TENANT):
        lb_service_status_def = lb_defs.LBServiceUsageDef(
            lb_service_id=lb_service_id, realtime=realtime, tenant=tenant)
        return self.policy_api.get(lb_service_status_def)

    def get_path(self, lb_service_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            lb_service_id=lb_service_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()

    def wait_until_realized(self, lb_service_id, entity_type='LbServiceDto',
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        return self._wait_until_realized(
            lb_service_def, entity_type=entity_type,
            sleep=sleep, max_attempts=max_attempts)


class NsxPolicyLoadBalancerVirtualServerAPI(NsxPolicyResourceBase):
    """NSX Policy LoadBalancerVirtualServers"""

    @property
    def entry_def(self):
        return lb_defs.LBVirtualServerDef

    def create_or_overwrite(self, name, virtual_server_id=None,
                            description=IGNORE,
                            rules=IGNORE, application_profile_id=IGNORE,
                            ip_address=IGNORE, lb_service_id=IGNORE,
                            client_ssl_profile_binding=IGNORE,
                            pool_id=IGNORE,
                            lb_persistence_profile_id=IGNORE,
                            ports=IGNORE,
                            server_ssl_profile_binding=IGNORE,
                            waf_profile_binding=IGNORE,
                            max_concurrent_connections=IGNORE,
                            access_list_control=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            tags=IGNORE, access_log_enabled=IGNORE,
                            log_significant_event_only=IGNORE):
        virtual_server_id = self._init_obj_uuid(virtual_server_id)
        lbvs_def = self._init_def(
            virtual_server_id=virtual_server_id,
            name=name,
            description=description,
            tenant=tenant,
            rules=rules,
            application_profile_id=application_profile_id,
            ip_address=ip_address,
            lb_service_id=lb_service_id,
            client_ssl_profile_binding=client_ssl_profile_binding,
            pool_id=pool_id,
            lb_persistence_profile_id=lb_persistence_profile_id,
            ports=ports,
            server_ssl_profile_binding=server_ssl_profile_binding,
            waf_profile_binding=waf_profile_binding,
            max_concurrent_connections=max_concurrent_connections,
            access_list_control=access_list_control,
            tags=tags,
            access_log_enabled=access_log_enabled,
            log_significant_event_only=log_significant_event_only
        )
        self._create_or_store(lbvs_def)
        return virtual_server_id

    def delete(self, virtual_server_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        self._delete_with_retry(lbvs_def)

    def get(self, virtual_server_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        return self.policy_api.get(lbvs_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(tenant=tenant)
        return self.policy_api.list(lbvs_def)['results']

    def update(self, virtual_server_id, name=IGNORE, description=IGNORE,
               rules=IGNORE, application_profile_id=IGNORE,
               ip_address=IGNORE, lb_service_id=IGNORE,
               client_ssl_profile_binding=IGNORE,
               pool_id=IGNORE,
               lb_persistence_profile_id=IGNORE,
               ports=IGNORE,
               server_ssl_profile_binding=IGNORE,
               waf_profile_binding=IGNORE,
               max_concurrent_connections=IGNORE,
               access_list_control=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               allow_partial_updates=True, access_log_enabled=IGNORE,
               log_significant_event_only=IGNORE):

        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.policy_api.client.max_attempts)
        def _update():
            self._update(
                virtual_server_id=virtual_server_id,
                name=name,
                description=description,
                tenant=tenant,
                rules=rules,
                application_profile_id=application_profile_id,
                ip_address=ip_address,
                lb_service_id=lb_service_id,
                client_ssl_profile_binding=client_ssl_profile_binding,
                pool_id=pool_id,
                lb_persistence_profile_id=lb_persistence_profile_id,
                ports=ports,
                server_ssl_profile_binding=server_ssl_profile_binding,
                waf_profile_binding=waf_profile_binding,
                max_concurrent_connections=max_concurrent_connections,
                access_list_control=access_list_control,
                tags=tags,
                allow_partial_updates=allow_partial_updates,
                access_log_enabled=access_log_enabled,
                log_significant_event_only=log_significant_event_only)

        _update()

    def update_virtual_server_with_pool(
            self, virtual_server_id, pool_id=IGNORE,
            tenant=constants.POLICY_INFRA_TENANT):
        return self.update(
            virtual_server_id, pool_id=pool_id, tenant=tenant)

    def update_virtual_server_application_profile(
            self, virtual_server_id, application_profile_id=IGNORE,
            tenant=constants.POLICY_INFRA_TENANT):
        return self.update(
            virtual_server_id, application_profile_id=application_profile_id,
            tenant=tenant)

    def update_virtual_server_persistence_profile(
            self, virtual_server_id, lb_persistence_profile_id=IGNORE,
            tenant=constants.POLICY_INFRA_TENANT):
        return self.update(
            virtual_server_id,
            lb_persistence_profile_id=lb_persistence_profile_id,
            tenant=tenant)

    def update_virtual_server_client_ssl_profile_binding(
            self, virtual_server_id, client_ssl_profile_binding=IGNORE,
            tenant=constants.POLICY_INFRA_TENANT):
        return self.update(
            virtual_server_id,
            client_ssl_profile_binding=client_ssl_profile_binding,
            tenant=tenant)

    def remove_virtual_server_client_ssl_profile_binding(
            self, virtual_server_id, tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self._get_and_update_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        body = lbvs_def.body if lbvs_def.body else {}
        body.pop('client_ssl_profile_binding', None)
        # Server ssl profile binding can not exist without client ssl profile
        # binding
        body.pop('server_ssl_profile_binding', None)
        if body:
            lbvs_def.set_obj_dict(body)
        self.policy_api.create_or_update(
            lbvs_def, partial_updates=False)

    def remove_dlb_virtual_server_persistence_profile(
            self, virtual_server_id, tenant=constants.POLICY_INFRA_TENANT):
        dlb_vs_def = self._get_and_update_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        body = dlb_vs_def.body if dlb_vs_def.body else {}
        body.pop('lb_persistence_profile_path', None)
        if body:
            dlb_vs_def.set_obj_dict(body)
        self.policy_api.create_or_update(
            dlb_vs_def, partial_updates=False)

    def update_virtual_server_with_vip(self, virtual_server_id, vip,
                                       tenant=constants.POLICY_INFRA_TENANT):
        return self.update(
            virtual_server_id, ip_address=vip, tenant=tenant)

    def build_client_ssl_profile_binding(self, default_certificate_path,
                                         sni_certificate_paths=None,
                                         ssl_profile_path=None,
                                         client_auth_ca_paths=None,
                                         client_auth=None):
        return lb_defs.ClientSSLProfileBindingDef(
            default_certificate_path,
            sni_certificate_paths=sni_certificate_paths,
            ssl_profile_path=ssl_profile_path,
            client_auth_ca_paths=client_auth_ca_paths, client_auth=client_auth)

    def update_client_ssl_profile_binding(
            self, virtual_server_id, default_certificate_path,
            sni_certificate_paths=None, ssl_profile_path=None,
            client_auth_ca_paths=None, client_auth=None,
            tenant=constants.POLICY_INFRA_TENANT):
        client_ssl_def = lb_defs.ClientSSLProfileBindingDef(
            default_certificate_path,
            sni_certificate_paths=sni_certificate_paths,
            ssl_profile_path=ssl_profile_path,
            client_auth_ca_paths=client_auth_ca_paths, client_auth=client_auth)

        return self.update(
            virtual_server_id, client_ssl_profile_binding=client_ssl_def,
            tenant=tenant)

    def build_lb_rule(self, actions=None, display_name=None,
                      match_conditions=None, match_strategy=None, phase=None):
        return lb_defs.LBRuleDef(
            actions, match_conditions, display_name, match_strategy, phase)

    def _add_rule_in_position(self, body, lb_rule, position):
        lb_rules = body.get('rules', [])
        if position < 0 or position > len(lb_rules):
            # Add as the last one
            lb_rules.append(lb_rule)
        elif position <= len(lb_rules):
            lb_rules.insert(position, lb_rule)

        return lb_rules

    def add_lb_rule(self, virtual_server_id, actions=None,
                    name=None, match_conditions=None,
                    match_strategy=None, phase=None, position=-1,
                    tenant=constants.POLICY_INFRA_TENANT):
        lb_rule = lb_defs.LBRuleDef(
            actions, match_conditions, name, match_strategy, phase)
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        lb_rules = self._add_rule_in_position(body, lb_rule, position)
        return self._update(virtual_server_id=virtual_server_id,
                            vs_data=body,
                            rules=lb_rules, tenant=tenant)

    def update_lb_rules(self, virtual_server_id, rules,
                        tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        lbvs_path = lbvs_def.get_resource_path()

        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.policy_api.client.max_attempts)
        def _update():
            # Get the current data of vs
            lbvs_body = self.policy_api.get(lbvs_def)
            lbvs_body['rules'] = copy.deepcopy(rules)
            # Update the backend using PUT
            self.policy_api.client.update(lbvs_path, lbvs_body)

        _update()

    def update_lb_rule(self, virtual_server_id, lb_rule_name,
                       actions=None, match_conditions=None,
                       match_strategy=None, phase=None, position=-1,
                       compare_name_suffix=None,
                       tenant=constants.POLICY_INFRA_TENANT):
        lb_rule = lb_defs.LBRuleDef(
            actions, match_conditions, lb_rule_name, match_strategy, phase)
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        lb_rules = body.get('rules', [])

        # Remove existing rule
        try:
            if compare_name_suffix:
                rule_index = next(lb_rules.index(r) for r in lb_rules
                                  if r.get('display_name',
                                           '').endswith(compare_name_suffix))
            else:
                rule_index = next(lb_rules.index(r) for r in lb_rules
                                  if r.get('display_name') == lb_rule_name)
        except Exception:
            err_msg = (_("No resource in rules matched for values: "
                         "%(values)s") % {'values': lb_rule_name})
            raise nsxlib_exc.ResourceNotFound(
                manager=self,
                operation=err_msg)
        if position < 0:
            position = rule_index

        del(lb_rules[rule_index])

        # Insert new rule
        lb_rules = self._add_rule_in_position(body, lb_rule, position)
        return self._update(
            virtual_server_id=virtual_server_id,
            rules=lb_rules, vs_data=body, tenant=tenant)

    def remove_lb_rule(self, virtual_server_id, lb_rule_name,
                       check_name_suffix=False,
                       tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(virtual_server_id=virtual_server_id,
                                  tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        lb_rules = body.get('rules', [])
        if check_name_suffix:
            lb_rules = [r for r in lb_rules
                        if not r.get('display_name', '').endswith(
                            lb_rule_name)]
        else:
            lb_rules = [r for r in lb_rules
                        if r.get('display_name') != lb_rule_name]
        return self._update(
            virtual_server_id=virtual_server_id, vs_data=body,
            rules=lb_rules, tenant=tenant)

    def build_access_list_control(self, action, group_path, enabled=None):
        return lb_defs.LBAccessListControlDef(action, group_path, enabled)

    def get_path(self, virtual_server_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        return profile_def.get_resource_full_path()

    def wait_until_realized(self, virtual_server_id, entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        return self._wait_until_realized(
            lbvs_def, entity_type=entity_type,
            sleep=sleep, max_attempts=max_attempts)


class NsxPolicyLBMonitorProfileBase(NsxPolicyResourceBase):
    """NSX Policy LB monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            **kwargs):
        lb_monitor_profile_id = self._init_obj_uuid(lb_monitor_profile_id)
        lb_monitor_profile_def = self._init_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            tenant=tenant,
            **kwargs)
        self._create_or_store(lb_monitor_profile_def)
        return lb_monitor_profile_id

    def delete(self, lb_monitor_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_monitor_profile_def = self.entry_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tenant=tenant)
        self._delete_with_retry(lb_monitor_profile_def)

    def get(self, lb_monitor_profile_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        lb_monitor_profile_def = self.entry_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_monitor_profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_monitor_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_monitor_profile_def)

    def update(self,
               lb_monitor_profile_id,
               name=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               **kwargs):
        self._update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            name=name,
            tags=tags,
            tenant=tenant,
            **kwargs)

    def get_path(self, lb_monitor_profile_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        mon_def = self.entry_def(lb_monitor_profile_id=lb_monitor_profile_id,
                                 tenant=tenant)
        return mon_def.get_resource_full_path()


class NsxPolicyLBMonitorProfileHttpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB HTTP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            request_url=IGNORE,
                            request_method=IGNORE,
                            request_version=IGNORE,
                            request_headers=IGNORE,
                            request_body=IGNORE,
                            response_status_codes=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileHttpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            request_url=request_url,
            request_method=request_method,
            request_version=request_version,
            request_headers=request_headers,
            request_body=request_body,
            response_status_codes=response_status_codes,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               request_url=IGNORE,
               request_method=IGNORE,
               request_version=IGNORE,
               request_headers=IGNORE,
               request_body=IGNORE,
               response_status_codes=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileHttpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            request_url=request_url,
            request_method=request_method,
            request_version=request_version,
            request_headers=request_headers,
            request_body=request_body,
            response_status_codes=response_status_codes,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBHttpMonitorProfileDef


class NsxPolicyLBMonitorProfileHttpsApi(NsxPolicyLBMonitorProfileHttpApi):
    """NSX Policy LB HTTPS monitor profile"""

    @property
    def entry_def(self):
        return lb_defs.LBHttpsMonitorProfileDef


class NsxPolicyLBMonitorProfileUdpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB UDP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            receive=IGNORE,
                            send=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileUdpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            receive=receive,
            send=send,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               receive=IGNORE,
               send=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileUdpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            receive=receive,
            send=send,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBUdpMonitorProfileDef


class NsxPolicyLBMonitorProfileIcmpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB ICMP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileIcmpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileIcmpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBIcmpMonitorProfileDef


class NsxPolicyLBMonitorProfileTcpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB TCP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileTcpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileTcpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            name=name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBTcpMonitorProfileDef


class NsxPolicyLoadBalancerApi(object):
    """This is the class that have all load balancer policy apis"""
    def __init__(self, *args):
        self.lb_http_profile = NsxPolicyLBAppProfileHttpApi(*args)
        self.lb_fast_tcp_profile = NsxPolicyLBAppProfileFastTcpApi(*args)
        self.lb_fast_udp_profile = NsxPolicyLBAppProfileFastUdpApi(*args)
        self.client_ssl_profile = (
            NsxPolicyLoadBalancerClientSSLProfileApi(*args))
        self.server_ssl_profile = (
            NsxPolicyLoadBalancerServerSSLProfileApi(*args))
        self.lb_persistence_profile = (
            NsxPolicyLoadBalancerPersistenceProfileApi(*args))
        self.lb_cookie_persistence_profile = (
            NsxPolicyLoadBalancerCookiePersistenceProfileApi(*args))
        self.lb_source_ip_persistence_profile = (
            NsxPolicyLoadBalancerSourceIpPersistenceProfileApi(*args))
        self.lb_service = NsxPolicyLoadBalancerServiceApi(*args)
        self.virtual_server = NsxPolicyLoadBalancerVirtualServerAPI(*args)
        self.lb_pool = NsxPolicyLoadBalancerPoolApi(*args)
        self.lb_monitor_profile_http = NsxPolicyLBMonitorProfileHttpApi(*args)
        self.lb_monitor_profile_https = (
            NsxPolicyLBMonitorProfileHttpsApi(*args))
        self.lb_monitor_profile_udp = NsxPolicyLBMonitorProfileUdpApi(*args)
        self.lb_monitor_profile_icmp = NsxPolicyLBMonitorProfileIcmpApi(*args)
        self.lb_monitor_profile_tcp = NsxPolicyLBMonitorProfileTcpApi(*args)
