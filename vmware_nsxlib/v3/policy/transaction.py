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

import threading

from oslo_log import log

from vmware_nsxlib._i18n import _

from vmware_nsxlib.v3 import exceptions

from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy import core_defs
from vmware_nsxlib.v3 import utils


LOG = log.getLogger(__name__)


class NsxPolicyTransactionException(exceptions.NsxLibException):
    message = _("Policy Transaction Error: %(msg)s")


class NsxPolicyTransaction(object):
    # stores current transaction per thread
    # nested transactions not supported

    data = threading.local()

    def __init__(self):
        # For now only infra tenant is supported
        self.defs = [core_defs.TenantDef(
            tenant=constants.POLICY_INFRA_TENANT)]
        self.client = None

    def __enter__(self):
        if self.get_current():
            raise NsxPolicyTransactionException(
                "Nested transactions not supported")

        self.data.instance = self
        return self

    def __exit__(self, e_type, e_value, e_traceback):
        # Always reset transaction regardless of exceptions
        self.data.instance = None

        if e_type:
            # If exception occured in the "with" block, raise it
            # without applying to backend
            return False

        # exception might happen here and will be raised
        self.apply_defs()

    def store_def(self, resource_def, client):
        if self.client and client != self.client:
            raise NsxPolicyTransactionException(
                "All operations under transaction must have same client")

        self.client = client
        # TODO(annak): raise exception for different tenants
        if isinstance(resource_def, list):
            self.defs.extend(resource_def)
        else:
            self.defs.append(resource_def)

    def _sort_defs(self):
        sorted_defs = []

        while len(self.defs):
            for resource_def in self.defs:
                if resource_def in sorted_defs:
                    continue

                # We want all parents to appear before the child
                if not resource_def.path_defs():
                    # top level resource
                    sorted_defs.append(resource_def)
                    continue

                parent_type = resource_def.path_defs()[-1]
                parents = [d for d in self.defs if isinstance(d, parent_type)]
                missing_parents = [d for d in parents if d not in sorted_defs]

                if not missing_parents:
                    # All parents are appended to sorted list, child can go in
                    sorted_defs.append(resource_def)

            unsorted = [d for d in self.defs if d not in sorted_defs]
            self.defs = unsorted

        self.defs = sorted_defs

    def _build_wrapper_dict(self, resource_class, node, delete=False,
                            child_resource_ref=False):
        if child_resource_ref:
            wrapper_dict = {'resource_type': 'ChildResourceReference',
                            'target_type': resource_class,
                            'id': node['id'],
                            'children': []}
        else:
            wrapper_dict = {'resource_type': 'Child%s' % resource_class,
                            resource_class: node}
        if delete:
            wrapper_dict.update({'marked_for_delete': True})
        LOG.debug("### WRAPPER DICT:%s", wrapper_dict)
        return wrapper_dict

    def _find_parent_in_dict(self, d, resource_def, level=1):

        res_path_defs = resource_def.path_defs()
        if not res_path_defs or len(res_path_defs) <= level:
            return

        parent_type = resource_def.path_defs()[level]

        is_leaf = (level + 1 == len(res_path_defs))
        resource_type = parent_type.resource_type()
        resource_class = parent_type.resource_class()
        parent_id = resource_def.get_attr(resource_def.path_ids[level])

        def create_missing_node():
            node = {'resource_type': resource_type,
                    'id': parent_id,
                    'children': []}
            LOG.debug("#### UNEXPECTED: %s", resource_type)
            return self._build_wrapper_dict(resource_class, node), node

        # iterate over all objects in d, and look for resource type
        for child in d:
            parent = None
            if (child.get('target_type') == resource_type and
                child['resource_type'] == 'ChildResourceReference'):
                parent = child
            if resource_type in child and child[resource_type]:
                parent = child[resource_type]
            # If resource type matches, check for id
            if parent and parent['id'] == parent_id:
                if is_leaf:
                    return parent
                if 'children' not in parent:
                    parent['children'] = []

                return self._find_parent_in_dict(
                    parent['children'], resource_def, level + 1)

        # Parent not found - create a node for missing parent
        wrapper, node = create_missing_node()
        d.append(wrapper)
        if is_leaf:
            # This is the last parent that needs creation
            return node
        return self._find_parent_in_dict(node['children'], resource_def,
                                         level + 1)

    def apply_defs(self):
        # TODO(annak): find longest common URL, for now always
        # applying on tenant level
        if not self.defs or not self.client:
            # Empty transaction
            return

        self._sort_defs()

        top_def = self.defs[0]
        url = top_def.get_resource_path()
        body = {'resource_type': top_def.resource_type(),
                'children': []}

        # iterate over defs (except top level def)
        for resource_def in self.defs[1:]:
            parent_dict = None
            if 'children' in body:
                parent_dict = self._find_parent_in_dict(body['children'],
                                                        resource_def)

            if not parent_dict:
                # Top level resource
                parent_dict = body

            if 'children' not in parent_dict:
                parent_dict['children'] = []

            resource_class = resource_def.resource_class()
            node = resource_def.get_obj_dict()
            if resource_def.mandatory_child_def:
                # This is a workaround for policy issue that involves required
                # children (see comment on definition of mandatory_child_def)
                # TODO(annak): remove when policy solves the issue
                child_def = resource_def.mandatory_child_def
                child_dict_key = child_def.get_last_section_dict_key
                node[child_dict_key] = [child_def.get_obj_dict()]
            child_resource_ref = (
                resource_def.has_attr('child_resource_ref') and
                resource_def.get_attr('child_resource_ref'))
            LOG.debug("#### BEFORE WRAP CALL")
            LOG.debug("#### NODE XXX: %s", node)
            LOG.debug("#### CHILD REF:%s", child_resource_ref)
            meh = self._build_wrapper_dict(resource_class,
                                           node,
                                           resource_def.get_delete(),
                                           child_resource_ref)
            parent_dict['children'].append(meh)

        if body:
            headers = {'nsx-enable-partial-patch': 'true'}

            @utils.retry_upon_exception(
                (exceptions.NsxPendingDelete, exceptions.StaleRevision),
                max_attempts=self.client.max_attempts)
            def _do_patch_with_retry():
                self.client.patch(url, body, headers=headers)

            _do_patch_with_retry()

    @staticmethod
    def get_current():
        if hasattr(NsxPolicyTransaction.data, 'instance'):
            return NsxPolicyTransaction.data.instance
