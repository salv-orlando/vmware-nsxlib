# Copyright 2016 VMware, Inc.
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

from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

BASE_SECTION = 'trust-management'
CERT_SECTION = BASE_SECTION + '/certificates'
ID_SECTION = BASE_SECTION + '/principal-identities'
ID_WITH_CERT_SECTION = BASE_SECTION + '/principal-identities/with-certificate'
USER_GROUP_TYPES = [
    'read_only_api_users',
    'read_write_api_users',
    'superusers']


class NsxLibTrustManagement(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return CERT_SECTION

    def create_cert_list(self, cert_pem, private_key=None, passphrase=None,
                         tags=None):
        resource = CERT_SECTION + '?action=import'
        body = {'pem_encoded': cert_pem}
        if private_key:
            body.update(
                {'private_key': private_key})
        if passphrase:
            body.update({'passphrase': passphrase})
        if tags:
            body.update({'tags': tags})
        return self.client.create(resource, body)['results']

    def create_cert(self, cert_pem, private_key=None, passphrase=None,
                    tags=None):
        results = self.create_cert_list(cert_pem, private_key, passphrase,
                                        tags)
        # note: the assumption of only one result is wrong. It returns the
        # chained certs
        if len(results) > 0:
            # should be only one result
            return results[0]['id']

    def get_cert(self, cert_id):
        resource = CERT_SECTION + '/' + cert_id
        return self.client.get(resource)

    def get_certs(self):
        return self.client.get(CERT_SECTION)['results']

    def delete_cert(self, cert_id):
        resource = CERT_SECTION + '/' + cert_id
        self._delete_by_path_with_retry(resource)

    def find_cert_with_pem(self, cert_pem):
        """Find NSX certificates with specific pem and return their IDs"""
        # First fix Dos to unix possible issues, as the NSX backed also does
        nsx_style_pem = cert_pem.replace('\r\n', '\n')
        certs = self.get_certs()
        cert_ids = [cert['id'] for cert in certs
                    if cert['pem_encoded'] == nsx_style_pem]
        return cert_ids

    def create_identity(self, name, cert_id,
                        node_id, permission_group):
        # Validate permission group before sending to server
        if permission_group not in USER_GROUP_TYPES:
            raise nsxlib_exc.InvalidInput(
                operation='create_identity',
                arg_val=permission_group,
                arg_name='permission_group')
        body = {'name': name, 'certificate_id': cert_id,
                'node_id': node_id, 'role': permission_group,
                'is_protected': True}
        self.client.create(ID_SECTION, body)

    def get_identities(self, name):
        ids = self.client.get(ID_SECTION)['results']
        return [identity for identity in ids if identity['name'] == name]

    def delete_identity(self, identity_id):
        resource = ID_SECTION + '/' + identity_id
        self._delete_by_path_with_retry(resource)

    def find_cert_and_identity(self, name, cert_pem):
        certs = self.get_certs()

        if not isinstance(cert_pem, str):
            cert_pem = cert_pem.decode('ascii')
        cert_ids = [cert['id'] for cert in certs
                    if cert['pem_encoded'] == cert_pem]
        if not cert_ids:
            raise nsxlib_exc.ResourceNotFound(
                manager=getattr(self.client, 'nsx_api_managers'),
                operation="find_certificate")

        identities = self.get_identities(name)
        # should be zero or one matching identities
        results = [identity for identity in identities
                   if identity['certificate_id'] in cert_ids]

        if not results:
            raise nsxlib_exc.ResourceNotFound(
                manager=self.client.nsx_api_managers,
                operation="delete_identity")

        return results[0]['certificate_id'], results[0]['id']

    def delete_cert_and_identity(self, name, cert_pem):
        cert_id, identity_id = self.find_cert_and_identity(name, cert_pem)
        self.delete_identity(identity_id)
        self.delete_cert(cert_id)

    def create_cert_and_identity(self, name, cert_pem,
                                 node_id,
                                 permission_group='read_write_api_users'):
        nsx_cert_id = self.create_cert(cert_pem)
        try:
            self.create_identity(name, nsx_cert_id, node_id, permission_group)
        except nsxlib_exc.ManagerError as e:
            self.delete_cert(nsx_cert_id)
            raise e

    def create_identity_with_cert(self, name, cert_pem,
                                  node_id, role,
                                  is_protected=True):
        body = {'name': name, 'certificate_pem': cert_pem,
                'node_id': node_id, 'role': role,
                'is_protected': is_protected}
        self.client.create(ID_WITH_CERT_SECTION, body)
