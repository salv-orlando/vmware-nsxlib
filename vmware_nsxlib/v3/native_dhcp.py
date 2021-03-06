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

import netaddr

from oslo_log import log
from vmware_nsxlib.v3 import constants
from vmware_nsxlib.v3 import utils


LOG = log.getLogger(__name__)


class NsxLibNativeDhcp(utils.NsxLibApiBase):

    def build_static_routes(self, gateway_ip, cidr, host_routes):
        # The following code is based on _generate_opts_per_subnet() in
        # neutron/agent/linux/dhcp.py. It prepares DHCP options for a subnet.

        # Add route for directly connected network.
        static_routes = [{'network': cidr, 'next_hop': '0.0.0.0'}]
        # Copy routes from subnet host_routes attribute.
        if host_routes:
            for hr in host_routes:
                if hr['destination'] == constants.IPv4_ANY:
                    if not gateway_ip:
                        gateway_ip = hr['nexthop']
                else:
                    static_routes.append({'network': hr['destination'],
                                          'next_hop': hr['nexthop']})

        # If gateway_ip is defined, add default route via this gateway.
        if gateway_ip:
            static_routes.append({'network': constants.IPv4_ANY,
                                  'next_hop': gateway_ip})
        return static_routes, gateway_ip

    def build_server_name(self, net_name, net_id):
        return utils.get_name_and_uuid(net_name or 'dhcpserver', net_id)

    def build_server(self, name, ip_address, cidr, gateway_ip,
                     dns_domain=None, dns_nameservers=None,
                     host_routes=None,
                     dhcp_profile_id=None,
                     tags=None):

        # Prepare the configuration for a new logical DHCP server.
        server_ip = "%s/%u" % (ip_address,
                               netaddr.IPNetwork(cidr).prefixlen)

        if not dns_domain:
            dns_domain = self.nsxlib_config.dns_domain

        if not dns_nameservers:
            dns_nameservers = self.nsxlib_config.dns_nameservers

        if not utils.is_attr_set(gateway_ip):
            gateway_ip = None

        static_routes, gateway_ip = self.build_static_routes(
            gateway_ip, cidr, host_routes)

        options = {'option121': {'static_routes': static_routes}}

        body = {'name': name,
                'server_ip': server_ip,
                'dns_nameservers': dns_nameservers,
                'domain_name': dns_domain,
                'gateway_ip': gateway_ip,
                'options': options,
                'tags': tags}

        if dhcp_profile_id:
            body['dhcp_profile_id'] = dhcp_profile_id

        return body
