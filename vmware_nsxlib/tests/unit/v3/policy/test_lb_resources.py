# Copyright 2017 VMware, Inc.
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

import mock

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3.policy import test_resources
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy import lb_defs

TEST_TENANT = 'test'


class TestPolicyLBClientSSLProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBClientSSLProfileApi, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.client_ssl_profile

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        protocols = ['TLS_V1_1']
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                client_ssl_profile_id=obj_id,
                description=description,
                protocols=protocols,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                name=name,
                description=description,
                protocols=protocols,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=mock.ANY,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = lb_defs.LBClientSslProfileDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBPersistenceProfile(
    test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBPersistenceProfile, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_persistence_profile)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                self.resourceApi.entry_def(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                self.resourceApi.entry_def(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                self.resourceApi.entry_def(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                self.resourceApi.entry_def(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)


class TestPolicyLBCookiePersistenceProfile(
    test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBCookiePersistenceProfile, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_cookie_persistence_profile)

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        cookie_garble = 'test_garble'
        cookie_name = 'test_name'
        cookie_mode = 'INSERT'
        cookie_path = 'path'
        cookie_time = 'time'
        persistence_shared = False
        with self.mock_create_update() as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                persistence_profile_id=obj_id,
                description=description,
                cookie_name=cookie_name,
                cookie_garble=cookie_garble,
                cookie_mode=cookie_mode,
                cookie_path=cookie_path,
                cookie_time=cookie_time,
                persistence_shared=persistence_shared,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    cookie_name=cookie_name,
                    cookie_garble=cookie_garble,
                    cookie_mode=cookie_mode,
                    cookie_path=cookie_path,
                    cookie_time=cookie_time,
                    persistence_shared=persistence_shared,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with self.mock_create_update() as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [
                {'resource_type': self.resourceApi.entry_def.resource_type,
                 'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [
                {'resource_type': self.resourceApi.entry_def.resource_type,
                 'display_name': 'profile1'},
                {'resource_type': 'wrong_type',
                 'display_name': 'profile2'}]}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(1, len(result))

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        cookie_garble = 'test_garble'
        cookie_name = 'test_name'
        cookie_mode = 'INSERT'
        cookie_path = 'path'
        cookie_time = 'time'
        persistence_shared = False
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    cookie_name=cookie_name,
                                    cookie_garble=cookie_garble,
                                    cookie_mode=cookie_mode,
                                    cookie_path=cookie_path,
                                    cookie_time=cookie_time,
                                    persistence_shared=persistence_shared,
                                    tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    cookie_name=cookie_name,
                    cookie_garble=cookie_garble,
                    cookie_mode=cookie_mode,
                    cookie_path=cookie_path,
                    cookie_time=cookie_time,
                    persistence_shared=persistence_shared,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBSourceIpProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBSourceIpProfileApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_source_ip_persistence_profile)

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        ha = 'ha'
        persistence_shared = True
        purge = 'purge'
        timeout = 100
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                persistence_profile_id=obj_id,
                description=description,
                ha_persistence_mirroring_enabled=ha,
                persistence_shared=persistence_shared,
                purge=purge,
                timeout=timeout,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    ha_persistence_mirroring_enabled=ha,
                    persistence_shared=persistence_shared,
                    purge=purge,
                    timeout=timeout,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [
                {'resource_type': self.resourceApi.entry_def.resource_type,
                 'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        ha = False
        persistence_shared = False
        purge = 'no purge'
        timeout = 101
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:

            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    ha_persistence_mirroring_enabled=ha,
                                    persistence_shared=persistence_shared,
                                    purge=purge,
                                    timeout=timeout,
                                    tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    ha_persistence_mirroring_enabled=ha,
                    persistence_shared=persistence_shared,
                    purge=purge,
                    timeout=timeout,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBApplicationProfile(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBApplicationProfile, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_http_profile

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        http_redirect_to_https = False
        http_redirect_to = "sample-url"
        idle_timeout = 100
        ntlm = False
        request_body_size = 1025
        request_header_size = 10
        response_header_size = 10
        response_timeout = 10
        x_forwarded_for = 'INSERT'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_app_profile_id=obj_id,
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
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
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
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBHttpProfileDef(tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBService(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBService, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_service

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        size = 'SMALL'
        connectivity_path = 'path'
        relax_scale_validation = True
        with self.mock_create_update() as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_service_id=obj_id,
                description=description,
                size=size,
                connectivity_path=connectivity_path,
                relax_scale_validation=relax_scale_validation,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBServiceDef(
                    nsx_version=self.policy_lib.get_version(),
                    lb_service_id=obj_id,
                    name=name,
                    description=description,
                    size=size,
                    connectivity_path=connectivity_path,
                    relax_scale_validation=relax_scale_validation,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with self.mock_create_update() as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBServiceDef(lb_service_id=mock.ANY,
                                     name=name,
                                     description=description,
                                     tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_unsupported_attribute(self):
        name = 'd1'
        description = 'desc'
        relax_scale_validation = True

        with self.mock_create_update() as api_call, \
                mock.patch.object(self.resourceApi, 'version', '0.0.0'):
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                relax_scale_validation=relax_scale_validation,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBServiceDef(lb_service_id=mock.ANY,
                                     name=name,
                                     description=description,
                                     tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = lb_defs.LBServiceDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        size = 'SMALL'
        connectivity_path = 'path'
        relax_scale_validation = True
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:
            self.resourceApi.update(
                obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT,
                size=size,
                connectivity_path=connectivity_path,
                relax_scale_validation=relax_scale_validation)
            expected_def = lb_defs.LBServiceDef(
                nsx_version=self.policy_lib.get_version(),
                lb_service_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT,
                size=size,
                connectivity_path=connectivity_path,
                relax_scale_validation=relax_scale_validation)
            self.assert_called_with_def(update_call, expected_def)

    def test_update_customized(self):
        obj_id = '111'
        name = 'name'
        tags = [{'tag': '1', 'scope': '2'}]

        def update_callback(body):
            body['tags'] = tags

        with self.mock_get(obj_id, name), \
            mock.patch.object(self.policy_api.client, "update") as update_call:
            self.resourceApi.update_customized(
                obj_id, update_callback)

            update_call.assert_called_once_with(
                'infra/lb-services/%s' % obj_id,
                {'id': obj_id, 'display_name': name,
                 'resource_type': 'LBService',
                 'tags': tags})

    def test_get_status(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get_status(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceStatusDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_statistics(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get_statistics(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceStatisticsDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_virtual_server_status(self):
        obj_id = '111'
        vs_id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get_virtual_server_status(
                obj_id, vs_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerStatusDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_wait_until_realized_fail(self):
        lbs_id = 'test_lbs'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': lbs_id,
                'entity_type': 'LbServiceDto'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.RealizationTimeoutError,
                              self.resourceApi.wait_until_realized,
                              lbs_id, max_attempts=5, sleep=0.1,
                              tenant=TEST_TENANT)

    def test_wait_until_realized_error(self):
        lbs_id = 'test_lbs'
        error_code = 23500
        related_error_code = 23707
        error_msg = 'Found errors in the request.'
        related_error_msg = 'Exceed maximum number of load balancer.'
        info = {'state': constants.STATE_ERROR,
                'realization_specific_identifier': lbs_id,
                'entity_type': 'LbServiceDto',
                'alarms': [{
                    'message': error_msg,
                    'error_details': {
                        'related_errors': [{
                            'error_code': related_error_code,
                            'module_name': 'LOAD-BALANCER',
                            'error_message': related_error_msg
                        }],
                        'error_code': error_code,
                        'module_name': 'LOAD-BALANCER',
                        'error_message': error_msg
                    }
                }]}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            with self.assertRaises(nsxlib_exc.RealizationErrorStateError) as e:
                self.resourceApi.wait_until_realized(
                    lbs_id, tenant=TEST_TENANT)
            error_msg_tail = "%s: %s" % (error_msg, related_error_msg)
            self.assertTrue(e.exception.msg.endswith(error_msg_tail))
            self.assertEqual(e.exception.error_code, error_code)
            self.assertEqual(e.exception.related_error_codes,
                             [related_error_code])

    def test_wait_until_realized_succeed(self):
        lbs_id = 'test_lbs'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': lbs_id,
                'entity_type': 'LbServiceDto'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                lbs_id, max_attempts=5, sleep=0.1, tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)


class TestPolicyLBVirtualServer(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBVirtualServer, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.virtual_server

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        waf_profile_id = 'waf'
        waf_profile_path = self.policy_lib.waf_profile.get_path(
            profile_id=waf_profile_id, tenant=TEST_TENANT)
        waf_profile_binding = lb_defs.WAFProfileBindingDef(
            waf_profile_path=waf_profile_path)
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                virtual_server_id=obj_id,
                waf_profile_binding=waf_profile_binding,
                description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id, name=name, description=description,
                waf_profile_binding=waf_profile_binding,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=mock.ANY, name=name, description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = lb_defs.LBVirtualServerDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        vs_name = 'name-name'
        with self.mock_get(obj_id, vs_name), \
            self.mock_create_update() as update_call:

            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id, name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_add_lb_rule(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        rule_actions = 'test1'
        rule_match_conditions = 'test2'
        rule_name = 'dummy_rule'
        rule_match_strategy = 'test3'
        rule_phase = 'test4'
        with self.mock_get(vs_obj_id, vs_name), \
            self.mock_create_update() as update_call:
            self.resourceApi.add_lb_rule(
                vs_obj_id, actions=rule_actions, name=rule_name,
                match_conditions=rule_match_conditions,
                match_strategy=rule_match_strategy, phase=rule_phase)
            lb_rule = lb_defs.LBRuleDef(
                rule_actions, rule_match_conditions, rule_name,
                rule_match_strategy, rule_phase)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[lb_rule])
            self.assert_called_with_def(update_call, expected_def)

    def test_add_lb_rule_first(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        rule_actions = 'test1'
        rule_match_conditions = 'test2'
        rule_name = 'dummy_rule'
        rule_match_strategy = 'test3'
        rule_phase = 'test4'
        with self.mock_get(vs_obj_id, vs_name,
                           rules=[{'display_name': 'xx'},
                                  {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:

            self.resourceApi.add_lb_rule(
                vs_obj_id, actions=rule_actions, name=rule_name,
                match_conditions=rule_match_conditions,
                match_strategy=rule_match_strategy, phase=rule_phase,
                position=0)
            lb_rule = lb_defs.LBRuleDef(
                rule_actions, rule_match_conditions, rule_name,
                rule_match_strategy, rule_phase)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[lb_rule,
                       {'display_name': 'xx'},
                       {'display_name': 'yy'}])
            self.assert_called_with_def(update_call, expected_def)

    def test_add_lb_rule_last(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        rule_actions = 'test1'
        rule_match_conditions = 'test2'
        rule_name = 'dummy_rule'
        rule_match_strategy = 'test3'
        rule_phase = 'test4'
        with self.mock_get(vs_obj_id, vs_name,
                           rules=[{'display_name': 'xx'},
                                  {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:
            self.resourceApi.add_lb_rule(
                vs_obj_id, actions=rule_actions, name=rule_name,
                match_conditions=rule_match_conditions,
                match_strategy=rule_match_strategy, phase=rule_phase)
            lb_rule = lb_defs.LBRuleDef(
                rule_actions, rule_match_conditions, rule_name,
                rule_match_strategy, rule_phase)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'xx'},
                       {'display_name': 'yy'},
                       lb_rule])
            self.assert_called_with_def(update_call, expected_def)

    def test_add_lb_rule_last_over(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        rule_actions = 'test1'
        rule_match_conditions = 'test2'
        rule_name = 'dummy_rule'
        rule_match_strategy = 'test3'
        rule_phase = 'test4'
        with self.mock_get(vs_obj_id, vs_name,
                           rules=[{'display_name': 'xx'},
                                  {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:

            self.resourceApi.add_lb_rule(
                vs_obj_id, actions=rule_actions, name=rule_name,
                match_conditions=rule_match_conditions,
                match_strategy=rule_match_strategy, phase=rule_phase,
                position=999)
            lb_rule = lb_defs.LBRuleDef(
                rule_actions, rule_match_conditions, rule_name,
                rule_match_strategy, rule_phase)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'xx'},
                       {'display_name': 'yy'},
                       lb_rule])
            self.assert_called_with_def(update_call, expected_def)

    def test_add_lb_rule_mid(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        rule_actions = 'test1'
        rule_match_conditions = 'test2'
        rule_name = 'dummy_rule'
        rule_match_strategy = 'test3'
        rule_phase = 'test4'
        with self.mock_get(vs_obj_id, vs_name,
                           rules=[{'display_name': 'xx'},
                                  {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:
            self.resourceApi.add_lb_rule(
                vs_obj_id, actions=rule_actions, name=rule_name,
                match_conditions=rule_match_conditions,
                match_strategy=rule_match_strategy, phase=rule_phase,
                position=1)
            lb_rule = lb_defs.LBRuleDef(
                rule_actions, rule_match_conditions, rule_name,
                rule_match_strategy, rule_phase)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'xx'},
                       lb_rule,
                       {'display_name': 'yy'}])
            self.assert_called_with_def(update_call, expected_def)

    def test_update_lb_rule(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        with self.mock_get(
                vs_obj_id, vs_name,
                rules=[{'display_name': 'xx', 'actions': '11'},
                       {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:
            self.resourceApi.update_lb_rule(vs_obj_id, 'xx', actions='22')

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'xx', 'actions': '22'},
                       {'display_name': 'yy'}])
            self.assert_called_with_def(update_call, expected_def)

    def test_update_lb_rule_position(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        with self.mock_get(
                vs_obj_id, vs_name,
                rules=[{'display_name': 'xx', 'actions': '11'},
                       {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:
            self.resourceApi.update_lb_rule(vs_obj_id, 'xx', actions='22',
                                            position=1)

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'yy'},
                       {'display_name': 'xx', 'actions': '22'}])
            self.assert_called_with_def(update_call, expected_def)

    def test_remove_lb_rule(self):
        vs_obj_id = '111'
        vs_name = 'name-name'
        with self.mock_get(vs_obj_id, vs_name,
                           rules=[{'display_name': 'xx'},
                                  {'display_name': 'yy'}]), \
            self.mock_create_update() as update_call:
            self.resourceApi.remove_lb_rule(vs_obj_id, 'xx')

            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=vs_obj_id,
                rules=[{'display_name': 'yy'}])
            self.assert_called_with_def(update_call, expected_def)

    def test_wait_until_realized_fail(self):
        vs_id = 'test_vs'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': vs_id}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.RealizationTimeoutError,
                              self.resourceApi.wait_until_realized,
                              vs_id, max_attempts=5, sleep=0.1,
                              tenant=TEST_TENANT)

    def test_wait_until_realized_succeed(self):
        vs_id = 'test_vs'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': vs_id,
                'entity_type': 'LbVirtualServerDto'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                vs_id, entity_type='LbVirtualServerDto', max_attempts=5,
                sleep=0.1, tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)


class TestPolicyLBPoolApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBPoolApi, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_pool

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        members = [
            lb_defs.LBPoolMemberDef(ip_address='10.0.0.1')]
        algorithm = 'algo'
        active_monitor_paths = 'path1'
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_pool_id=obj_id,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                name=name,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=mock.ANY,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_retry_stale_revision(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        members = [
            lb_defs.LBPoolMemberDef(ip_address='10.0.0.1')]
        algorithm = 'algo'
        active_monitor_paths = 'path1'
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api, "create_or_update",
                               side_effect=nsxlib_exc.StaleRevision
                               ) as api_call:
            with self.assertRaises(nsxlib_exc.StaleRevision):
                self.resourceApi.create_or_overwrite(
                    name,
                    lb_pool_id=obj_id,
                    description=description,
                    members=members,
                    active_monitor_paths=active_monitor_paths,
                    algorithm=algorithm,
                    member_group=member_group,
                    snat_translation=snat_translation,
                    tenant=TEST_TENANT)
                self.assertEqual(nsxlib_testcase.NSX_MAX_ATTEMPTS,
                                 api_call.call_count)

    def test_create_with_retry_pending_delete(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        members = [
            lb_defs.LBPoolMemberDef(ip_address='10.0.0.1')]
        algorithm = 'algo'
        active_monitor_paths = 'path1'
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api, "create_or_update",
                               side_effect=nsxlib_exc.NsxPendingDelete
                               ) as api_call:
            with self.assertRaises(nsxlib_exc.NsxPendingDelete):
                self.resourceApi.create_or_overwrite(
                    name,
                    lb_pool_id=obj_id,
                    description=description,
                    members=members,
                    active_monitor_paths=active_monitor_paths,
                    algorithm=algorithm,
                    member_group=member_group,
                    snat_translation=snat_translation,
                    tenant=TEST_TENANT)
                self.assertEqual(nsxlib_testcase.NSX_MAX_ATTEMPTS,
                                 api_call.call_count)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = lb_defs.LBPoolDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        members = [{'ip_address': '10.0.0.1'}]
        algorithm = 'algo'
        active_monitor_paths = ['path1']
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}), \
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    members=members,
                                    active_monitor_paths=active_monitor_paths,
                                    algorithm=algorithm,
                                    member_group=member_group,
                                    snat_translation=snat_translation,
                                    tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                name=name,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_add_monitor_to_pool(self):
        obj_id = '111'
        active_monitor_paths = ['path1']
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}), \
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.add_monitor_to_pool(
                obj_id,
                active_monitor_paths,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                active_monitor_paths=active_monitor_paths,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_remove_monitor_from_pool(self):
        obj_id = '111'
        removed_monitor_path = 'path1'
        stay_monitor_path = 'path2'
        active_monitors = [removed_monitor_path, stay_monitor_path]
        with mock.patch.object(
            self.policy_api, "get", return_value={
                'id': obj_id, 'active_monitor_paths': active_monitors}), \
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.remove_monitor_from_pool(
                obj_id,
                removed_monitor_path,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                active_monitor_paths=[stay_monitor_path],
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_create_pool_member_and_add_to_pool(self):
        obj_id = '111'
        ip_address = '1.1.1.1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}), \
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.create_pool_member_and_add_to_pool(
                obj_id, ip_address,
                tenant=TEST_TENANT)
            mem_def = lb_defs.LBPoolMemberDef(ip_address)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                members=[mem_def],
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_update_pool_member(self):
        obj_id = '111'
        ip_address = '1.1.1.1'
        port = '80'
        new_name = 'mem1'
        member = {'ip_address': ip_address, 'port': port}
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id,
                                             'members': [member]}), \
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_pool_member(
                obj_id, ip_address, port=port, display_name=new_name,
                tenant=TEST_TENANT)
            member['display_name'] = new_name
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                members=[member],
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBMonitorProfileHttpApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBMonitorProfileHttpApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_monitor_profile_http)
        self.obj_def = lb_defs.LBHttpMonitorProfileDef

    def test_create_with_id(self):
        name = 'd1'
        obj_id = '111'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                lb_monitor_profile_id=obj_id,
                name=name,
                tenant=TEST_TENANT)
            expected_def = self.obj_def(
                lb_monitor_profile_id=obj_id,
                name=name,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name=name,
                tenant=TEST_TENANT)
            expected_def = self.obj_def(
                lb_monitor_profile_id=mock.ANY,
                name=name,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = self.obj_def(
                lb_monitor_profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = self.obj_def(
                lb_monitor_profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.obj_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = self.obj_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        with self.mock_get(obj_id, name), \
            self.mock_create_update() as update_call:

            self.resourceApi.update(obj_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = self.obj_def(
                lb_monitor_profile_id=obj_id,
                name=name,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBMonitorProfileHttpsApi(TestPolicyLBMonitorProfileHttpApi):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBMonitorProfileHttpsApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_monitor_profile_https)
        self.obj_def = lb_defs.LBHttpsMonitorProfileDef


class TestPolicyLBMonitorProfileUdpApi(TestPolicyLBMonitorProfileHttpApi):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBMonitorProfileUdpApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_monitor_profile_udp)
        self.obj_def = lb_defs.LBUdpMonitorProfileDef


class TestPolicyLBMonitorProfileIcmpApi(TestPolicyLBMonitorProfileHttpApi):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBMonitorProfileIcmpApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_monitor_profile_icmp)
        self.obj_def = lb_defs.LBIcmpMonitorProfileDef


class TestPolicyLBMonitorProfileTcpApi(TestPolicyLBMonitorProfileHttpApi):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBMonitorProfileTcpApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_monitor_profile_tcp)
        self.obj_def = lb_defs.LBTcpMonitorProfileDef
