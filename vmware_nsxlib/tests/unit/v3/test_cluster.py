# Copyright 2015 VMware, Inc.
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
import unittest
from unittest import mock
from urllib import parse as urlparse

from requests import codes
from requests import exceptions as requests_exceptions
from requests import models

from oslo_serialization import jsonutils

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import cluster
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc


def _validate_conn_up(*args, **kwargs):
    return True


def _validate_conn_down(*args, **kwargs):
    raise requests_exceptions.ConnectionError()


def _validate_server_busy(*args, **kwargs):
    raise nsxlib_exc.ServerBusy(details="Test")


def get_sess_create_resp():
    sess_create_response = models.Response()
    sess_create_response.status_code = 200
    sess_create_response.headers = {'Set-Cookie': 'JSESSIONID=abc;'}
    return sess_create_response


class RequestsHTTPProviderTestCase(unittest.TestCase):

    def test_new_connection(self):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.username = 'nsxuser'
        mock_api.nsxlib_config.password = 'nsxpassword'
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = True
        mock_api.nsxlib_config.token_provider = None
        mock_api.nsxlib_config.ca_file = None
        mock_api.nsxlib_config.http_timeout = 99
        mock_api.nsxlib_config.conn_idle_timeout = 39
        mock_api.nsxlib_config.client_cert_provider = None
        provider = cluster.NSXRequestsHTTPProvider()
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            session = provider.new_connection(
                mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                           'nsxuser', 'nsxpassword', None))

            self.assertEqual(('nsxuser', 'nsxpassword'), session.auth)
            self.assertFalse(session.verify)
            self.assertIsNone(session.cert)
            self.assertEqual(100,
                             session.adapters['https://'].max_retries.total)
            self.assertEqual(99, session.timeout)

    def test_new_connection_with_client_auth(self):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = True
        mock_api.nsxlib_config.ca_file = None
        mock_api.nsxlib_config.http_timeout = 99
        mock_api.nsxlib_config.conn_idle_timeout = 39
        cert_provider_inst = client_cert.ClientCertProvider(
            '/etc/cert.pem')
        mock_api.nsxlib_config.client_cert_provider = cert_provider_inst
        provider = cluster.NSXRequestsHTTPProvider()
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            session = provider.new_connection(
                mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                           None, None, None))

            self.assertIsNone(session.auth)
            self.assertFalse(session.verify)
            self.assertEqual(cert_provider_inst, session.cert_provider)
            self.assertEqual(99, session.timeout)

    @mock.patch("vmware_nsxlib.v3.cluster.NSXRequestsHTTPProvider."
                "get_default_headers")
    def test_new_connection_with_token_provider(self, mock_get_def_headers):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = True
        mock_api.nsxlib_config.ca_file = None
        mock_api.nsxlib_config.http_timeout = 99
        mock_api.nsxlib_config.conn_idle_timeout = 39
        mock_api.nsxlib_config.client_cert_provider = None
        token_provider_inst = mock.Mock()
        mock_api.nsxlib_config.token_provider = token_provider_inst
        mock_api.nsxlib_config.allow_overwrite_header = False
        provider = cluster.NSXRequestsHTTPProvider()
        cluster_provider = cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                            'nsxuser', 'nsxpassword', None)
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            session = provider.new_connection(mock_api, cluster_provider)

            self.assertIsNone(session.auth)
            self.assertFalse(session.verify)
            self.assertIsNone(session.cert)
            self.assertEqual(100,
                             session.adapters['https://'].max_retries.total)
            self.assertEqual(99, session.timeout)
            mock_get_def_headers.assert_called_once_with(
                mock.ANY, cluster_provider, False, token_provider_inst)

    @mock.patch("vmware_nsxlib.v3.debug_retry.RetryDebug.from_int")
    @mock.patch("vmware_nsxlib.v3.cluster.NSXHTTPAdapter.__init__")
    def test_new_connection_with_ca_file(self, mock_adaptor_init, mock_retry):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = False
        mock_adaptor_init.return_value = None
        mock_retry.return_value = 100
        provider = cluster.NSXRequestsHTTPProvider()
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            session = provider.new_connection(
                mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                           None, None, "ca_file"))

            self.assertEqual("ca_file", session.verify)
            mock_adaptor_init.assert_called_once_with(
                pool_connections=1, pool_maxsize=1,
                max_retries=100, pool_block=False,
                thumbprint=None)

    @mock.patch("vmware_nsxlib.v3.debug_retry.RetryDebug.from_int")
    @mock.patch("vmware_nsxlib.v3.cluster.NSXHTTPAdapter.__init__")
    def test_new_connection_with_thumbprint(self, mock_adaptor_init,
                                            mock_retry):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = False
        mock_adaptor_init.return_value = None
        mock_retry.return_value = 100
        provider = cluster.NSXRequestsHTTPProvider()
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            session = provider.new_connection(
                mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                           None, None, None, "thumbprint"))

            self.assertIsNone(session.verify)
            mock_adaptor_init.assert_called_once_with(
                pool_connections=1, pool_maxsize=1,
                max_retries=100, pool_block=False,
                thumbprint="thumbprint")

    def test_validate_connection_keep_alive(self):
        mock_conn = mocks.MockRequestSessionApi()
        mock_conn.default_headers = {}
        mock_ep = mock.Mock()
        mock_ep.provider.url = 'https://1.2.3.4'
        mock_cluster = mock.Mock()
        mock_cluster.nsxlib_config = mock.Mock()
        mock_cluster.nsxlib_config.url_base = 'abc'
        provider = cluster.NSXRequestsHTTPProvider()

        with mock.patch.object(client.JSONRESTClient, "get",
                               return_value={'result_count': 0}):
            self.assertRaises(nsxlib_exc.ResourceNotFound,
                              provider.validate_connection,
                              mock_cluster, mock_ep, mock_conn)

        with mock.patch.object(client.JSONRESTClient, "get",
                               return_value={'healthy': True}):
            provider.validate_connection(mock_cluster, mock_ep, mock_conn)

    def _validate_con_mocks(self, nsx_version):
        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        nsxlib = v3.NsxLib(nsxlib_config)
        nsxlib.nsx_version = nsx_version
        mock_conn = mocks.MockRequestSessionApi()
        mock_conn.default_headers = {}
        mock_ep = mock.Mock()
        mock_ep.provider.url = 'https://1.2.3.4'
        conf = mock.Mock()
        conf.url_base = 'abc'
        mock_cluster = mock.Mock()
        mock_cluster.nsxlib_config = conf
        return (mock_cluster, mock_ep, mock_conn)

    def test_validate_connection_method(self):
        mock_cluster, mock_ep, mock_conn = self._validate_con_mocks('2.4.0')
        provider = cluster.NSXRequestsHTTPProvider()
        with mock.patch.object(client.JSONRESTClient, "get",
                               return_value={'healthy': False}):
            self.assertRaises(nsxlib_exc.ResourceNotFound,
                              provider.validate_connection,
                              mock_cluster, mock_ep, mock_conn)

        with mock.patch.object(client.JSONRESTClient, "get",
                               return_value={'healthy': True}):
            provider.validate_connection(mock_cluster, mock_ep, mock_conn)


class NSXHTTPAdapterTestCase(nsxlib_testcase.NsxClientTestCase):

    @mock.patch("requests.adapters.HTTPAdapter.init_poolmanager")
    def test_init_poolmanager(self, mock_init_poolmanager):
        cluster.NSXHTTPAdapter(thumbprint="thumbprint")
        mock_init_poolmanager.assert_called_once_with(
            mock.ANY, mock.ANY, block=mock.ANY,
            assert_fingerprint="thumbprint")


class NsxV3ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _assert_providers(self, cluster_api, provider_tuples):
        self.assertEqual(len(cluster_api.providers), len(provider_tuples))

        def _assert_provider(pid, purl):
            for provider in cluster_api.providers:
                if provider.id == pid and provider.url == purl:
                    return
            self.fail("Provider: %s not found" % pid)

        for provider_tuple in provider_tuples:
            _assert_provider(provider_tuple[0], provider_tuple[1])

    def test_conf_providers_no_scheme(self):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_up)

        self._assert_providers(
            api, [(p, "https://%s" % p) for p in conf_managers])

    def test_conf_providers_with_scheme(self):
        conf_managers = ['http://8.9.10.11:8080', 'https://9.10.11.12:4433']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_up)

        self._assert_providers(
            api, [(urlparse.urlparse(p).netloc, p) for p in conf_managers])

    def test_http_retries(self):
        api = self.mock_nsx_clustered_api(retries=9)
        with api.endpoints['1.2.3.4'].pool.item() as session:
            self.assertEqual(
                session.adapters['https://'].max_retries.total, 9)

    def test_conns_per_pool(self):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        api = self.new_mocked_cluster(
            conf_managers, _validate_conn_up,
            concurrent_connections=11)

        for ep_id, ep in api.endpoints.items():
            self.assertEqual(ep.pool.max_size, 11)

    def test_timeouts(self):
        api = self.mock_nsx_clustered_api(http_read_timeout=37, http_timeout=7)
        api.get('logical-ports')
        mock_call = api.recorded_calls.method_calls[0]
        name, args, kwargs = mock_call
        self.assertEqual(kwargs['timeout'], (7, 37))


# Repeat the above tests with client cert present
# in NsxLib initialization
class NsxV3ClusteredAPIWithClientCertTestCase(NsxV3ClusteredAPITestCase):

    def use_client_cert_auth(self):
        return True


class ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _test_health(self, validate_fn, expected_health, exceptions=None):
        conf_managers = ['8.9.10.11', '9.10.11.12']
        api = self.new_mocked_cluster(conf_managers, validate_fn,
                                      exceptions=exceptions)

        self.assertEqual(expected_health, api.health)

    def test_orange_health(self):

        def _validate(cluster_api, endpoint, conn):
            if endpoint.provider.id == '8.9.10.11':
                raise Exception()

            return True

        self._test_health(_validate, cluster.ClusterHealth.ORANGE)

    def test_green_health(self):
        self._test_health(_validate_conn_up, cluster.ClusterHealth.GREEN)

    def test_red_health(self):
        self._test_health(_validate_conn_down, cluster.ClusterHealth.RED)

    def test_cluster_validate_with_exception(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_down)

        self.assertEqual(3, len(api.endpoints))
        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_validate_with_exception_retry(self):
        self._test_health(_validate_server_busy, cluster.ClusterHealth.GREEN)

    def test_cluster_validate_with_exception_no_retry(self):
        exceptions = config.ExceptionConfig()
        exceptions.retriables = []
        self._test_health(_validate_server_busy,
                          cluster.ClusterHealth.RED,
                          exceptions)

    def test_cluster_proxy_stale_revision(self):

        def stale_revision():
            raise nsxlib_exc.StaleRevision(manager='1.1.1.1',
                                           operation='whatever')

        api = self.mock_nsx_clustered_api(session_response=stale_revision)
        self.assertRaises(nsxlib_exc.StaleRevision,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_down_and_retry_on_server_error(self):

        def server_error():
            return mocks.MockRequestsResponse(
                codes.INTERNAL_SERVER_ERROR,
                jsonutils.dumps({'error_message': 'test', 'error_code': 98}))

        def all_well():
            return mocks.MockRequestsResponse(
                codes.OK,
                jsonutils.dumps({'id': 'test'}))

        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        exceptions = config.ExceptionConfig()
        exceptions.ground_triggers.append(nsxlib_exc.CannotConnectToServer)
        api = self.mock_nsx_clustered_api(
            nsx_api_managers=conf_managers,
            session_response=[server_error, all_well])
        api.nsxlib_config.exception_config = exceptions

        api.get('api/v1/transport-zones')
        # first manager should go down, second one is confirmed as UP
        # after retry
        self.assertEqual(cluster.ClusterHealth.ORANGE, api.health)

    def test_max_retry_attempts_on_server_error(self):

        def server_error():
            return mocks.MockRequestsResponse(
                codes.INTERNAL_SERVER_ERROR,
                jsonutils.dumps({'error_message': 'test', 'error_code': 98}))

        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        exceptions = config.ExceptionConfig()
        exceptions.ground_triggers.append(nsxlib_exc.CannotConnectToServer)
        max_attempts = 4
        api = self.mock_nsx_clustered_api(
            nsx_api_managers=conf_managers,
            max_attempts=max_attempts,
            session_response=[server_error for i in range(0, max_attempts)])
        api.nsxlib_config.cluster_unavailable_retry = False
        api.nsxlib_config.exception_config = exceptions

        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')
        self.assertEqual(cluster.ClusterHealth.RED, api.health)

    def test_max_retry_attempts_on_retriable_error(self):

        def server_error():
            return mocks.MockRequestsResponse(
                codes.INTERNAL_SERVER_ERROR,
                jsonutils.dumps({'error_message': 'test', 'error_code': 98}))

        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        exceptions = config.ExceptionConfig()
        max_attempts = 2
        api = self.mock_nsx_clustered_api(
            nsx_api_managers=conf_managers,
            max_attempts=max_attempts,
            session_response=[server_error for i in range(0, max_attempts)])
        api.nsxlib_config.exception_config = exceptions

        self.assertRaises(nsxlib_exc.CannotConnectToServer,
                          api.get, 'api/v1/transport-zones')
        # This exception does not ground endpoint
        self.assertEqual(cluster.ClusterHealth.GREEN, api.health)

    def test_regenerate_error(self):

        def server_error():
            return mocks.MockRequestsResponse(
                codes.INTERNAL_SERVER_ERROR,
                jsonutils.dumps({'error_message': 'test', 'error_code': 99}))

        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        exceptions = config.ExceptionConfig()
        max_attempts = 2
        api = self.mock_nsx_clustered_api(
            nsx_api_managers=conf_managers,
            max_attempts=max_attempts,
            session_response=[server_error for i in range(0, max_attempts)])
        api.nsxlib_config.exception_config = exceptions

        self.assertRaises(nsxlib_exc.ClientCertificateNotTrusted,
                          api.get, 'api/v1/transport-zones')
        self.assertEqual(cluster.ClusterHealth.GREEN, api.health)

    def test_exception_translation_on_ground_error(self):

        def server_error():
            raise requests_exceptions.ConnectionError()

        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        exceptions = config.ExceptionConfig()
        max_attempts = 4
        api = self.mock_nsx_clustered_api(
            nsx_api_managers=conf_managers,
            max_attempts=max_attempts,
            session_response=[server_error for i in range(0, max_attempts)])
        api.nsxlib_config.exception_config = exceptions

        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')
        self.assertEqual(cluster.ClusterHealth.RED, api.health)

    def test_cluster_proxy_connection_establish_error(self):

        def connect_timeout():
            raise requests_exceptions.ConnectTimeout()

        api = self.mock_nsx_clustered_api(session_response=connect_timeout)
        api._validate = mock.Mock()
        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_proxy_connection_aborted(self):

        def connect_timeout():
            raise requests_exceptions.ConnectionError("Connection Aborted")

        def all_good():
            pass

        # First call will cause connection aborted error, but next one
        # should work
        api = self.mock_nsx_clustered_api(session_response=[connect_timeout,
                                                            all_good])
        api._validate = mock.Mock()
        self.assertEqual(cluster.ClusterHealth.GREEN, api.health)

    def test_cluster_round_robin_servicing(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        api = self.mock_nsx_clustered_api(nsx_api_managers=conf_managers)
        api._validate = mock.Mock()

        eps = list(api._endpoints.values())

        def _get_schedule(num_eps):
            return [api._select_endpoint() for i in range(num_eps)]

        self.assertEqual(_get_schedule(3), eps)

        self.assertEqual(_get_schedule(6), [eps[0], eps[1], eps[2],
                                            eps[0], eps[1], eps[2]])

        eps[0]._state = cluster.EndpointState.DOWN
        self.assertEqual(_get_schedule(4), [eps[1], eps[2], eps[1], eps[2]])

        eps[1]._state = cluster.EndpointState.DOWN
        self.assertEqual(_get_schedule(2), [eps[2], eps[2]])

        eps[0]._state = cluster.EndpointState.UP
        self.assertEqual(_get_schedule(4), [eps[0], eps[2], eps[0], eps[2]])

    def test_cluster_select_endpoint(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        max_attempts = 3
        api = self.mock_nsx_clustered_api(nsx_api_managers=conf_managers,
                                          max_attempts=max_attempts)
        api.nsxlib_config.cluster_unavailable_retry = False
        api._validate = mock.Mock()
        eps = list(api._endpoints.values())

        # all up - select the first one
        self.assertEqual(api._select_endpoint(), eps[0])

        # run again - select the 2nd
        self.assertEqual(api._select_endpoint(), eps[1])

        # all down - return None
        eps[0]._state = cluster.EndpointState.DOWN
        eps[1]._state = cluster.EndpointState.DOWN
        eps[2]._state = cluster.EndpointState.DOWN
        self.assertEqual(api._select_endpoint(), None)

        # up till now the validate method should not have been called
        self.assertEqual(api._validate.call_count, 0)

        # set up the retries flag, and check that validate was called
        # until retries have been exhausted
        api.nsxlib_config.cluster_unavailable_retry = True
        self.assertEqual(api._select_endpoint(), None)
        self.assertEqual(api._validate.call_count, len(eps))

        # simulate the case where 1 endpoint finally goes up
        self.validate_count = 0
        self.max_validate = max_attempts - 1

        def _mock_validate(ep):
            if self.validate_count >= self.max_validate:
                ep._state = cluster.EndpointState.UP
            self.validate_count += 1

        api._validate = _mock_validate
        self.assertEqual(api._select_endpoint(),
                         eps[(self.max_validate - 1) % len(eps)])
        self.assertEqual(self.validate_count, self.max_validate + 1)

    def test_reinitialize_cluster(self):
        with mock.patch.object(cluster.TimeoutSession, 'request',
                               return_value=get_sess_create_resp()):
            api = self.mock_nsx_clustered_api()
            # just make sure this api is defined, and does not crash
            api._reinit_cluster()

    def test_initialize_cluster_without_health_check(self):
        conf_managers = ['8.9.10.11', '9.10.11.12']
        validate_fn = mock.MagicMock()
        api = self.new_mocked_cluster(conf_managers, validate_fn,
                                      enable_health_check=False)
        self.assertEqual(cluster.ClusterHealth.GREEN, api.health)
        validate_fn.assert_not_called()
