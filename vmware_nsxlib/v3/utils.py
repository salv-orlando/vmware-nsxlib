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

import abc
import collections
import inspect
import re
from threading import Lock
import time

from oslo_log import log
import tenacity
from tenacity import _utils as tenacity_utils

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import constants
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants

LOG = log.getLogger(__name__)

TagLimits = collections.namedtuple('TagLimits',
                                   ['scope_length', 'tag_length', 'max_tags'])

# These defaults reflect latest tag & scope limits on the backend. As of 2.5,
# backend no longer returns tag limit via API.
MAX_RESOURCE_TYPE_LEN = 128
MAX_TAG_LEN = 256
MAX_TAGS = 15
MAX_NSGROUPS_CRITERIA_TAGS = 10

DEFAULT_MAX_ATTEMPTS = 10
DEFAULT_CACHE_AGE_SEC = 600
INJECT_HEADERS_CALLBACK = None
IS_ATTR_SET_CALLBACK = None


def set_is_attr_callback(callback):
    global IS_ATTR_SET_CALLBACK
    IS_ATTR_SET_CALLBACK = callback


def is_attr_set(attr):
    if IS_ATTR_SET_CALLBACK:
        return IS_ATTR_SET_CALLBACK(attr)
    return attr is not None


def set_inject_headers_callback(callback):
    global INJECT_HEADERS_CALLBACK
    INJECT_HEADERS_CALLBACK = callback


def censor_headers(headers):
    censored_headers = ['authorization', 'x-xsrf-token', 'cookie']
    result = {}
    for name, value in headers.items():
        if name.lower() in censored_headers:
            result[name] = '--- CENSORED ---'
        else:
            result[name] = value

    return result


def _update_resource_length(length):
    global MAX_RESOURCE_TYPE_LEN
    MAX_RESOURCE_TYPE_LEN = length


def _update_tag_length(length):
    global MAX_TAG_LEN
    MAX_TAG_LEN = length


def _update_max_tags(max_tags):
    global MAX_TAGS
    MAX_TAGS = max_tags


def _update_max_nsgroups_criteria_tags(max_tags):
    global MAX_NSGROUPS_CRITERIA_TAGS
    MAX_NSGROUPS_CRITERIA_TAGS = max(10, max_tags - 5)


def update_tag_limits(limits):
    _update_resource_length(limits.scope_length)
    _update_tag_length(limits.tag_length)
    _update_max_tags(limits.max_tags)
    _update_max_nsgroups_criteria_tags(limits.max_tags)


def _validate_resource_type_length(resource_type):
    # Add in a validation to ensure that we catch this at build time
    if len(resource_type) > MAX_RESOURCE_TYPE_LEN:
        raise nsxlib_exc.NsxLibInvalidInput(
            error_message=(_('Resource type cannot exceed %(max_len)s '
                             'characters: %(resource_type)s') %
                           {'max_len': MAX_RESOURCE_TYPE_LEN,
                            'resource_type': resource_type}))


def add_v3_tag(tags, resource_type, tag):
    _validate_resource_type_length(resource_type)
    tags.append({'scope': resource_type, 'tag': tag[:MAX_TAG_LEN]})
    return tags


def update_v3_tags(current_tags, tags_update):
    current_scopes = set([tag['scope'] for tag in current_tags])
    updated_scopes = set([tag['scope'] for tag in tags_update])

    # All tags scopes which are either completely new or already defined on the
    # resource are left in place, unless the tag value is empty, in that case
    # it is ignored.
    tags = [{'scope': tag['scope'], 'tag': tag['tag']}
            for tag in (current_tags + tags_update)
            if tag['tag'] and
            tag['scope'] in (current_scopes ^ updated_scopes)]

    modified_scopes = current_scopes & updated_scopes
    for tag in tags_update:
        if tag['scope'] in modified_scopes:
            # If the tag value is empty or None, then remove the tag completely
            if tag['tag']:
                tag['tag'] = tag['tag'][:MAX_TAG_LEN]
                tags.append(tag)

    return tags


def _log_before_retry(retry_state):
    """Before call strategy that logs to some logger the attempt."""
    if retry_state.attempt_number > 1:
        LOG.warning("Retrying call to '%(func)s' for the %(num)s time",
                    {'func': tenacity_utils.get_callback_name(
                        retry_state.fn),
                     'num': tenacity_utils.to_ordinal(
                        retry_state.attempt_number)})


def _get_args_from_frame(frames, frame_num):
    if len(frames) > frame_num and frames[frame_num] and frames[frame_num][0]:
        argvalues = inspect.getargvalues(frames[frame_num][0])
        formated_args = inspect.formatargvalues(*argvalues)
        # remove the first 'self' arg from the log as it adds no information
        formated_args = re.sub(r'\(self=.*?, ', "(", formated_args)
        return formated_args


def _log_after_retry(retry_state):
    """After call strategy that logs to some logger the finished attempt."""
    # Using inspect to get arguments of the relevant call
    frames = inspect.trace()
    # Look at frame #2 first because of the internal functions _do_X
    formated_args = _get_args_from_frame(frames, 2)
    if not formated_args:
        formated_args = _get_args_from_frame(frames, 1)
    if not formated_args:
        formated_args = "Unknown"

    LOG.warning("Finished retry of %(func)s for the %(num)s time after "
                "%(time)0.3f(s) with args: %(args)s",
                {'func': tenacity_utils.get_callback_name(retry_state.fn),
                 'num': tenacity_utils.to_ordinal(retry_state.attempt_number),
                 'time': retry_state.seconds_since_start,
                 'args': formated_args})


def retry_upon_exception(exc, delay=0.5, max_delay=2,
                         max_attempts=DEFAULT_MAX_ATTEMPTS):
    # exc can be a single exception or a tuple of exceptions
    return tenacity.retry(reraise=True,
                          retry=tenacity.retry_if_exception_type(exc),
                          wait=tenacity.wait_exponential(
                              multiplier=delay, max=max_delay),
                          stop=tenacity.stop_after_attempt(max_attempts),
                          before=_log_before_retry, after=_log_after_retry)


def retry_random_upon_exception(exc, delay=0.5, max_delay=5,
                                max_attempts=DEFAULT_MAX_ATTEMPTS):
    return tenacity.retry(reraise=True,
                          retry=tenacity.retry_if_exception_type(exc),
                          wait=tenacity.wait_random_exponential(
                              multiplier=delay, max=max_delay),
                          stop=tenacity.stop_after_attempt(max_attempts),
                          before=_log_before_retry, after=_log_after_retry)


def retry_upon_none_result(max_attempts, delay=0.5, max_delay=10,
                           random=False):
    if random:
        wait_func = tenacity.wait_random_exponential(
            multiplier=delay, max=max_delay)
    else:
        wait_func = tenacity.wait_exponential(
            multiplier=delay, max=max_delay)
    return tenacity.retry(reraise=True,
                          retry=tenacity.retry_if_result(lambda x: x is None),
                          wait=wait_func,
                          stop=tenacity.stop_after_attempt(max_attempts),
                          before=_log_before_retry, after=_log_after_retry)


class RetryAttemptsExceeded(tenacity.RetryError):
    def reraise(self):
        raise self.last_attempt.result()


# Retry when exception is returned by decorated function.
# If retry attempts are exceeded, reraise the last exception.
# This is achieved by overriding reraise method of RetryAttemptsExceeded
def retry_random_upon_exception_result(max_attempts, delay=0.5, max_delay=10):
    wait_func = tenacity.wait_random_exponential(
        multiplier=delay, max=max_delay)
    return tenacity.retry(reraise=True,
                          retry_error_cls=RetryAttemptsExceeded,
                          retry=tenacity.retry_if_result(
                              lambda x: isinstance(x, Exception)),
                          wait=wait_func,
                          stop=tenacity.stop_after_attempt(max_attempts),
                          before=_log_before_retry, after=_log_after_retry)


def list_match(list1, list2):
    # Check if list1 and list2 have identical elements, but relaxed on
    # dict elements where list1's dict element can be a subset of list2's
    # corresponding element.
    if (not isinstance(list1, list) or not isinstance(list2, list) or
        len(list1) != len(list2)):
        return False
    list1 = sorted(list1)
    list2 = sorted(list2)
    for (v1, v2) in zip(list1, list2):
        if isinstance(v1, dict):
            if not dict_match(v1, v2):
                return False
        elif isinstance(v1, list):
            if not list_match(v1, v2):
                return False
        elif v1 != v2:
            return False
    return True


def dict_match(dict1, dict2):
    # Check if dict1 is a subset of dict2.
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        return False
    for k1, v1 in dict1.items():
        if k1 not in dict2:
            return False
        v2 = dict2[k1]
        if isinstance(v1, dict):
            if not dict_match(v1, v2):
                return False
        elif isinstance(v1, list):
            if not list_match(v1, v2):
                return False
        elif v1 != v2:
            return False
    return True


def get_name_short_uuid(uuid):
    return '_' + uuid[:5] + '...' + uuid[-5:]


def get_name_and_uuid(name, uuid, tag=None, maxlen=80):
    short_uuid = get_name_short_uuid(uuid)
    maxlen = maxlen - len(short_uuid)
    if tag:
        maxlen = maxlen - len(tag) - 1
        return name[:maxlen] + '_' + tag + short_uuid
    else:
        return name[:maxlen] + short_uuid


def build_extra_args(body, extra_args, **kwargs):
    for arg in extra_args:
        if arg in kwargs:
            body[arg] = kwargs[arg]
    return body


def escape_tag_data(data):
    # ElasticSearch query_string requires slashes and dashes to
    # be escaped. We assume no other reserved characters will be
    # used in tag scopes or values
    return data.replace('/', '\\/').replace('-', '\\-').replace(':', '\\:')


def escape_display_name(display_name):
    # Illegal characters for the display names are  ;|=,~@
    rx = re.compile('([;|=,~@])')
    return rx.sub('.', display_name)


class NsxLibCache(object):
    def __init__(self, timeout):
        self.timeout = timeout
        self._cache = {}
        super(NsxLibCache, self).__init__()

    def expired(self, entry):
        return (time.time() - entry['time']) > self.timeout

    def get(self, key):
        if key in self._cache:
            # check that the value is still valid
            if self.expired(self._cache[key]):
                # this entry has expired
                self.remove(key)
            else:
                return self._cache[key]['value']

    def update(self, key, value):
        self._cache[key] = {'time': time.time(),
                            'value': value}

    def remove(self, key):
        if key in self._cache:
            del self._cache[key]


class NsxLibApiBase(object):
    """Base class for nsxlib api """
    def __init__(self, client, nsxlib_config=None, nsxlib=None):
        self.client = client
        self.nsxlib_config = nsxlib_config
        self.nsxlib = nsxlib
        super(NsxLibApiBase, self).__init__()
        self.cache = NsxLibCache(self.cache_timeout)
        self.max_attempts = (self.client.max_attempts
                             if hasattr(self.client, 'max_attempts') else 1)

    @abc.abstractproperty
    def uri_segment(self):
        pass

    @abc.abstractproperty
    def resource_type(self):
        pass

    @property
    def use_cache_for_get(self):
        """By default no caching is used"""
        return False

    @property
    def cache_timeout(self):
        """the default cache aging time in seconds"""
        return DEFAULT_CACHE_AGE_SEC

    def get_path(self, resource=None):
        if resource:
            return '%s/%s' % (self.uri_segment, resource)
        return self.uri_segment

    def list(self):
        return self.client.list(self.uri_segment)

    def get(self, uuid, silent=False):
        if self.use_cache_for_get:
            # try to get it from the cache
            result = self.cache.get(uuid)
            if result:
                if not silent:
                    LOG.debug("Getting %s from cache.", self.get_path(uuid))
                return result
        # call the client
        result = self.client.get(self.get_path(uuid), silent=silent)
        if result and self.use_cache_for_get:
            # add the result to the cache
            self.cache.update(uuid, result)
        return result

    def read(self, uuid, silent=False):
        """The same as get"""
        return self.get(uuid, silent=silent)

    def delete(self, uuid):
        if self.use_cache_for_get:
            self.cache.remove(uuid)
        return self._delete_with_retry(uuid)

    def find_by_display_name(self, display_name):
        found = []
        for resource in self.list()['results']:
            if resource['display_name'] == display_name:
                found.append(resource)
        return found

    def _update_with_retry(self, uuid, payload):
        if self.use_cache_for_get:
            self.cache.remove(uuid)
        return self._update_resource(self.get_path(uuid), payload, retry=True)

    def _internal_update_resource(self, resource, payload, headers=None,
                                  create_action=False,
                                  get_params=None,
                                  action_params=None,
                                  update_payload_cbk=None):
        get_path = action_path = resource
        if get_params:
            get_path = get_path + get_params
        if action_params:
            action_path = action_path + action_params
        revised_payload = self.client.get(get_path)
        # custom resource callback for updating the payload
        if update_payload_cbk:
            update_payload_cbk(revised_payload, payload)
        # special treatment for tags (merge old and new)
        if 'tags_update' in payload.keys():
            revised_payload['tags'] = update_v3_tags(
                revised_payload.get('tags', []),
                payload['tags_update'])
            del payload['tags_update']
        # update all the rest of the parameters
        for key_name in payload.keys():
            # handle 2 levels of dictionary:
            if isinstance(payload[key_name], dict):
                if key_name not in revised_payload:
                    revised_payload[key_name] = payload[key_name]
                else:
                    # copy each key
                    revised_payload[key_name].update(payload[key_name])
            else:
                revised_payload[key_name] = payload[key_name]
        if create_action:
            return self.client.create(action_path, revised_payload,
                                      headers=headers)
        else:
            return self.client.update(action_path, revised_payload,
                                      headers=headers)

    def _update_resource(self, resource, payload, headers=None,
                         create_action=False, get_params=None,
                         action_params=None, update_payload_cbk=None,
                         retry=False):
        if retry:
            # If revision_id of the payload that we send is older than what
            # NSX has, we will get a 412: Precondition Failed.
            # In that case we need to re-fetch, patch the response and send
            # it again with the new revision_id
            @retry_upon_exception(nsxlib_exc.StaleRevision,
                                  max_attempts=self.max_attempts)
            def do_update():
                return self._internal_update_resource(
                    resource, payload,
                    headers=headers,
                    create_action=create_action,
                    get_params=get_params,
                    action_params=action_params,
                    update_payload_cbk=update_payload_cbk)

            return do_update()
        else:
            return self._internal_update_resource(
                resource, payload,
                headers=headers,
                create_action=create_action,
                get_params=get_params,
                action_params=action_params,
                update_payload_cbk=update_payload_cbk)

    def _delete_with_retry(self, resource, headers=None):
        self._delete_by_path_with_retry(self.get_path(resource), headers)

    def _delete_by_path_with_retry(self, path, headers=None):
        # Using internal method so we can access max_attempts in the decorator
        @retry_upon_exception(nsxlib_exc.StaleRevision,
                              max_attempts=self.max_attempts)
        def _do_delete():
            self.client.delete(path, headers=headers)

        _do_delete()

    def _create_with_retry(self, resource, body=None, headers=None):
        # Using internal method so we can access max_attempts in the decorator
        @retry_upon_exception(nsxlib_exc.StaleRevision,
                              max_attempts=self.max_attempts)
        def _do_create():
            return self.client.create(resource, body, headers=headers)

        return _do_create()

    def _get_resource_by_name_or_id(self, name_or_id, resource):
        all_results = self.client.list(resource)['results']
        matched_results = []
        for rs in all_results:
            if rs.get('id') == name_or_id:
                # Matched by id - must be unique
                return name_or_id

            if rs.get('display_name') == name_or_id:
                # Matched by name - add to the list to verify it is unique
                matched_results.append(rs)

        if len(matched_results) == 0:
            err_msg = (_("Could not find %(resource)s %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            raise nsxlib_exc.ResourceNotFound(details=err_msg)
        elif len(matched_results) > 1:
            err_msg = (_("Found multiple %(resource)s named %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            raise nsxlib_exc.MultipleResourcesFound(details=err_msg)

        return matched_results[0].get('id')

    def get_id_by_name_or_id(self, name_or_id):
        """Get a resource by it's display name or uuid

        Return the resource data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                self.get_path())

    def build_v3_api_version_tag(self):
        """Some resources are created on the manager

        that do not have a corresponding plugin resource.

        """
        return [{'scope': self.nsxlib_config.plugin_scope,
                 'tag': self.nsxlib_config.plugin_tag},
                {'scope': "os-api-version",
                 'tag': self.nsxlib_config.plugin_ver}]

    def build_v3_api_version_project_tag(self, project_name, project_id=None):
        if not project_name:
            project_name = self.nsxlib_config.plugin_tag
        tags = [{'scope': self.nsxlib_config.plugin_scope,
                 'tag': self.nsxlib_config.plugin_tag},
                {'scope': "os-api-version",
                 'tag': self.nsxlib_config.plugin_ver},
                {'scope': 'os-project-name',
                 'tag': project_name[:MAX_TAG_LEN]}]
        if project_id:
            tags.append({'scope': 'os-project-id',
                         'tag': project_id[:MAX_TAG_LEN]})
        return tags

    def is_internal_resource(self, nsx_resource):
        """Indicates whether the passed nsx-resource is internal

        owned by the plugin for internal use.

        """
        for tag in nsx_resource.get('tags', []):
            if tag['scope'] == self.nsxlib_config.plugin_scope:
                return tag['tag'] == self.nsxlib_config.plugin_tag
        return False

    def build_v3_tags_payload(self, resource, resource_type, project_name):
        """Construct the tags payload that will be pushed to NSX-v3

        Add <resource_type>:<resource-id>, os-project-id:<project-id>,
        os-project-name:<project_name> os-api-version:<plugin-api-version>

        """
        _validate_resource_type_length(resource_type)
        # There may be cases when the plugin creates the port, for example DHCP
        if not project_name:
            project_name = self.nsxlib_config.plugin_tag
        project_id = (resource.get('project_id', '') or
                      resource.get('tenant_id', ''))
        # If project_id is present in resource and set to None, explicitly set
        # the project_id in tags as ''.
        if project_id is None:
            project_id = ''
        return [{'scope': resource_type,
                 'tag': resource.get('id', '')[:MAX_TAG_LEN]},
                {'scope': 'os-project-id',
                 'tag': project_id[:MAX_TAG_LEN]},
                {'scope': 'os-project-name',
                 'tag': project_name[:MAX_TAG_LEN]},
                {'scope': 'os-api-version',
                 'tag': self.nsxlib_config.plugin_ver}]


# Some utilities for services translations & validations
# both for the nsx manager & policy manager
def validate_icmp_params(icmp_type, icmp_code, icmp_version=4, strict=False):
    if icmp_version != 4:
        # ICMPv6 is currently not supported
        return
    if icmp_type is not None:
        if (strict and icmp_type not in
                constants.IPV4_ICMP_STRICT_TYPES):
            raise nsxlib_exc.InvalidInput(
                operation='create_rule',
                arg_val=icmp_type,
                arg_name='icmp_type')
        if icmp_type not in constants.IPV4_ICMP_TYPES:
            raise nsxlib_exc.InvalidInput(
                operation='create_rule',
                arg_val=icmp_type,
                arg_name='icmp_type')
        if (icmp_code and strict and icmp_code not in
                constants.IPV4_ICMP_STRICT_TYPES[icmp_type]):
            raise nsxlib_exc.InvalidInput(
                operation='create_rule',
                arg_val=icmp_code,
                arg_name='icmp_code for this icmp_type')
        if (icmp_code and icmp_code not in
                constants.IPV4_ICMP_TYPES[icmp_type]):
            raise nsxlib_exc.InvalidInput(
                operation='create_rule',
                arg_val=icmp_code,
                arg_name='icmp_code for this icmp_type')


def get_l4_protocol_name(protocol_number):
    if protocol_number is None:
        return
    protocol_number = constants.IP_PROTOCOL_MAP.get(protocol_number,
                                                    protocol_number)
    try:
        protocol_number = int(protocol_number)
    except ValueError:
        raise nsxlib_exc.InvalidInput(
            operation='create_rule',
            arg_val=protocol_number,
            arg_name='protocol')
    if protocol_number == 6:
        return nsx_constants.TCP
    elif protocol_number == 17:
        return nsx_constants.UDP
    elif protocol_number == 1:
        return nsx_constants.ICMPV4
    else:
        return protocol_number


def get_dhcp_opt_code(name):
    _supported_options = {
        'subnet-mask': 1,
        'time-offset': 2,
        'router': 3,
        'dns-name': 6,
        'host-name': 12,
        'boot-file-size': 13,
        'domain-name': 15,
        'ip-forwarding': 19,
        'interface-mtu': 26,
        'broadcast-address': 28,
        'arp-cache-timeout': 35,
        'nis-domain': 40,
        'nis-servers': 41,
        'ntp-servers': 42,
        'netbios-name-servers': 44,
        'netbios-dd-server': 45,
        'netbios-node-type': 46,
        'netbios-scope': 47,
        'dhcp-renewal-time': 58,
        'dhcp-rebinding-time': 59,
        'class-id': 60,
        'dhcp-client-identifier': 61,
        'nisplus-domain': 64,
        'nisplus-servers': 65,
        'tftp-server': 66,
        'tftp-server-name': 66,
        'bootfile-name': 67,
        'system-architecture': 93,
        'interface-id': 94,
        'machine-id': 97,
        'name-search': 117,
        'subnet-selection': 118,
        'domain-search': 119,
        'classless-static-route': 121,
        'tftp-server-address': 150,
        'server-ip-address': 150,
        'etherboot': 175,
        'config-file': 209,
        'path-prefix': 210,
        'reboot-time': 211,
    }
    return _supported_options.get(name)


def params_to_url_query(**kwargs):
    queries = []
    for key, val in kwargs.items():
        if key not in ("", None) and val not in ("", None):
            queries.append("%s=%s" % (key, val))
    return "&".join(queries)


class APIRateLimiter(object):
    def __init__(self, max_calls, period=1.0):
        self._enabled = max_calls is not None
        if not self._enabled:
            return
        if period <= 0 or int(max_calls) <= 0:
            raise ValueError('period and max_calls should be positive')
        self._period = period
        self._max_calls = min(int(max_calls),
                              constants.API_DEFAULT_MAX_RATE)
        self._call_time = collections.deque()
        self._lock = Lock()

    def __enter__(self):
        if not self._enabled:
            return 0
        pre_wait_ts = time.time()
        with self._lock:
            wait_time = self._calc_wait_time()
            if wait_time:
                time.sleep(wait_time)
            # assume api call happens immediately after entering context
            post_wait_ts = time.time()
            self._call_time.append(post_wait_ts)
            return post_wait_ts - pre_wait_ts

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def adjust_rate(self, **kwargs):
        pass

    def _calc_wait_time(self):
        now = time.time()
        # remove timestamps out of current window
        while self._call_time and now - self._period > self._call_time[0]:
            self._call_time.popleft()
        current_rate = len(self._call_time)
        if current_rate < self._max_calls:
            return 0
        # call_time contains at least #max_rate timestamps.
        # earliest possible time to get below rate limit is at
        # T = self.call_time[-self.max_calls] + self.period
        # Thus need to wait T - now
        return self._call_time[-self._max_calls] + self._period - now


class APIRateLimiterAIMD(APIRateLimiter):
    def __init__(self, max_calls, period=1.0):
        super(APIRateLimiterAIMD, self).__init__(max_calls, period=period)
        if self._enabled:
            self._top_rate = self._max_calls
            self._max_calls = 1
            self._pos_sig = 0
            self._neg_sig = 0
            self._last_adjust_rate = time.time()

    def adjust_rate(self, wait_time=0.0, status_code=200, **kwargs):
        if not self._enabled:
            return
        with self._lock:
            if status_code in constants.API_REDUCE_RATE_CODES:
                self._neg_sig += 1
            elif wait_time >= constants.API_WAIT_MIN_THRESHOLD:
                self._pos_sig += 1

            now = time.time()
            if now - self._last_adjust_rate >= self._period:
                if self._neg_sig > 0:
                    self._max_calls = max(self._max_calls // 2, 1)
                    LOG.debug("Decreasing API rate limit to %d due to HTTP "
                              "status code %d", self._max_calls, status_code)
                elif self._pos_sig > 0:
                    self._max_calls = min(self._max_calls + 1, self._top_rate)
                    LOG.debug("Increasing API rate limit to %d with HTTP "
                              "status code %d", self._max_calls, status_code)
                self._pos_sig = 0
                self._neg_sig = 0
                self._last_adjust_rate = now


class APICallRecord(object):
    def __init__(self, verb, uri, status, provider=None, timestamp=None):
        self.timestamp = timestamp or time.time()
        self.verb = verb
        self.uri = uri
        self.status = status
        self.provider = provider


class APICallCollector(object):
    def __init__(self, provider, max_entry=50000):
        self._api_log_store = collections.deque(maxlen=max_entry)
        self.provider = provider

    def add_record(self, record):
        self._api_log_store.append(record)

    def pop_record(self):
        return self._api_log_store.popleft()

    def pop_all_records(self):
        records = []
        while len(self._api_log_store) > 0:
            records.append(self.pop_record())
        return records
