#!/usr/bin/env python3
#
#  Copyright (c) 2024, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

import unittest
import ipaddress

import config
import thread_cert

from node import OtbrNode

IPV4_CIDR_ADDR_CMD = f'ip addr show {config.BACKBONE_IFNAME} | grep -w inet | grep -Eo "[0-9.]+/[0-9]+"'


class SevenBRs_ThreePartitions_ThreeInfra(thread_cert.TestCase):
    """
    Topology:
        ****************(backbone0.0)******************
                |                |              |
              BR2_0            BR0_0          BR1_0
                |                               |
              BR2_1 ---- BR2_2 ---- BR2_3     BR1_1
                |          |         |          |
        *****(backbone0.1)****   *****(backbone0.2)****
    """
    USE_MESSAGE_FACTORY = False
    BR0_0, BR1_0, BR1_1, BR2_0, BR2_1, BR2_2, BR2_3 = range(1, 8)

    TOPOLOGY = {
        BR0_0: {
            'name': 'BR0_0',
            'backbone_network_id': 0,
            'allowlist': [],
            'is_otbr': True,
            'version': '1.3',
        },
        BR1_0: {
            'name': 'BR1_1',
            'backbone_network_id': 0,
            'allowlist': [BR1_1],
            'is_otbr': True,
            'version': '1.3',
        },
        BR1_1: {
            'name': 'BR1_2',
            'backbone_network_id': 2,
            'allowlist': [BR1_0],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_0: {
            'name': 'BR2_0',
            'backbone_network_id': 0,
            'allowlist': [BR2_1],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_1: {
            'name': 'BR2_1',
            'backbone_network_id': 1,
            'allowlist': [BR2_0, BR2_2],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_2: {
            'name': 'BR2_2',
            'backbone_network_id': 1,
            'allowlist': [BR2_1, BR2_3],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_3: {
            'name': 'BR2_4',
            'backbone_network_id': 2,
            'allowlist': [BR2_2],
            'is_otbr': True,
            'version': '1.3',
        }
    }

    def test(self):
        br0_0: OtbrNode = self.nodes[self.BR0_0]
        br1_0: OtbrNode = self.nodes[self.BR1_0]
        br1_1: OtbrNode = self.nodes[self.BR1_1]
        br2_0: OtbrNode = self.nodes[self.BR2_0]
        br2_1: OtbrNode = self.nodes[self.BR2_1]
        br2_2: OtbrNode = self.nodes[self.BR2_2]
        br2_3: OtbrNode = self.nodes[self.BR2_3]

        border_routers = [br0_0, br1_0, br1_1, br2_0, br2_1, br2_2, br2_3]

        # start nodes
        for br in border_routers:
            br.start()

        # sleep some time more to ensure every BR gets the network data, otherwise the test can fail sometimes.
        self.simulator.go(config.BORDER_ROUTER_STARTUP_DELAY)

        # ---------------------------------------
        # br peers
        _, br1_0_rloc16, br1_1_rloc16, br2_0_rloc16, br2_1_rloc16, br2_2_rloc16, br2_3_rloc16 = [
            br.get_addr16() for br in border_routers
        ]

        self.assertCountEqual(br0_0.get_br_peers_rloc16s(), [])
        self.assertCountEqual(br1_0.get_br_peers_rloc16s(), [br1_1_rloc16])
        self.assertCountEqual(br1_1.get_br_peers_rloc16s(), [br1_0_rloc16])
        self.assertCountEqual(br2_0.get_br_peers_rloc16s(), [br2_1_rloc16, br2_2_rloc16, br2_3_rloc16])
        self.assertCountEqual(br2_1.get_br_peers_rloc16s(), [br2_0_rloc16, br2_2_rloc16, br2_3_rloc16])
        self.assertCountEqual(br2_2.get_br_peers_rloc16s(), [br2_0_rloc16, br2_1_rloc16, br2_3_rloc16])
        self.assertCountEqual(br2_3.get_br_peers_rloc16s(), [br2_0_rloc16, br2_1_rloc16, br2_2_rloc16])

        # ---------------------------------------
        # br routers
        br0_0_addr = ipaddress.IPv6Address(br0_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br1_0_addr = ipaddress.IPv6Address(br1_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br1_1_addr = ipaddress.IPv6Address(br1_1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_0_addr = ipaddress.IPv6Address(br2_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_1_addr = ipaddress.IPv6Address(br2_1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_2_addr = ipaddress.IPv6Address(br2_2.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_3_addr = ipaddress.IPv6Address(br2_3.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))

        self.assertCountEqual(br0_0.get_br_routers_ip_addresses(), [br2_0_addr, br1_0_addr])
        self.assertCountEqual(br1_0.get_br_routers_ip_addresses(), [br2_0_addr, br0_0_addr])
        self.assertCountEqual(br1_1.get_br_routers_ip_addresses(), [br2_3_addr])
        self.assertCountEqual(br2_0.get_br_routers_ip_addresses(), [br0_0_addr, br1_0_addr])
        self.assertCountEqual(br2_1.get_br_routers_ip_addresses(), [br2_2_addr])
        self.assertCountEqual(br2_2.get_br_routers_ip_addresses(), [br2_1_addr])
        self.assertCountEqual(br2_3.get_br_routers_ip_addresses(), [br1_1_addr])


@unittest.skip("Skipping")
class TenBRs_ThreePartitions_ThreeInfra(thread_cert.TestCase):
    """
    Topology:
        ***********************(backbone0.0)************************
              |           |          |           |         |
            BR2_0 ----- BR2_1      BR0_0       BR1_0 --- BR1_1
              |           |                                |
            BR2_2 ----- BR2_3 ---- BR2_4 ----- BR2_5     BR1_2
              |           |          |           |         |
        ***********(backbone0.1)*********    *****(backbone0.2)*****
    """
    USE_MESSAGE_FACTORY = False

    BR0_0 = 1
    BR1_0, BR1_1, BR1_2 = (2, 3, 4)
    BR2_0, BR2_1, BR2_2, BR2_3, BR2_4, BR2_5 = (5, 6, 7, 8, 9, 10)

    TOPOLOGY = {
        BR0_0: {
            'name': 'BR0_0',
            'backbone_network_id': 0,
            'allowlist': [],
            'is_otbr': True,
            'version': '1.3',
        },
        BR1_0: {
            'name': 'BR1_0',
            'backbone_network_id': 0,
            'allowlist': [BR1_1],
            'is_otbr': True,
            'version': '1.3',
        },
        BR1_1: {
            'name': 'BR1_1',
            'backbone_network_id': 0,
            'allowlist': [BR1_0, BR1_2],
            'is_otbr': True,
            'version': '1.3',
        },
        BR1_2: {
            'name': 'BR1_2',
            'backbone_network_id': 2,
            'allowlist': [BR1_1],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_0: {
            'name': 'BR2_0',
            'backbone_network_id': 0,
            'allowlist': [BR2_1, BR2_2],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_1: {
            'name': 'BR2_1',
            'backbone_network_id': 0,
            'allowlist': [BR2_0, BR2_3],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_2: {
            'name': 'BR2_2',
            'backbone_network_id': 1,
            'allowlist': [BR2_0, BR2_3],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_3: {
            'name': 'BR2_3',
            'backbone_network_id': 1,
            'allowlist': [BR2_1, BR2_2, BR2_4],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_4: {
            'name': 'BR2_4',
            'backbone_network_id': 1,
            'allowlist': [BR2_3, BR2_5],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2_5: {
            'name': 'BR2_5',
            'backbone_network_id': 2,
            'allowlist': [BR2_4],
            'is_otbr': True,
            'version': '1.3',
        }
    }

    def test(self):
        br0_0: OtbrNode = self.nodes[self.BR0_0]

        br1_0: OtbrNode = self.nodes[self.BR1_0]
        br1_1: OtbrNode = self.nodes[self.BR1_1]
        br1_2: OtbrNode = self.nodes[self.BR1_2]

        br2_0: OtbrNode = self.nodes[self.BR2_0]
        br2_1: OtbrNode = self.nodes[self.BR2_1]
        br2_2: OtbrNode = self.nodes[self.BR2_2]
        br2_3: OtbrNode = self.nodes[self.BR2_3]
        br2_4: OtbrNode = self.nodes[self.BR2_4]
        br2_5: OtbrNode = self.nodes[self.BR2_5]

        # start nodes
        for br in [br0_0, br1_0, br1_1, br1_2, br2_0, br2_1, br2_2, br2_3, br2_4, br2_5]:
            br.start()

        # sleep some time more to ensure every BR gets the network data, otherwise the test can fail sometimes.
        self.simulator.go(config.BORDER_ROUTER_STARTUP_DELAY)

        # ---------------------------------------
        # br peers
        br1_0_rloc16, br1_1_rloc16, br1_2_rloc16 = \
            [br.get_addr16() for br in [br1_0, br1_1, br1_2]]
        br2_0_rloc16, br2_1_rloc16, br2_2_rloc16, br2_3_rloc16, br2_4_rloc16, br2_5_rloc16 = \
            [br.get_addr16() for br in [br2_0, br2_1, br2_2, br2_3, br2_4, br2_5]]

        self.assertCountEqual(br0_0.get_br_peers_rloc16s(), [])

        self.assertCountEqual(br1_0.get_br_peers_rloc16s(), [br1_1_rloc16, br1_2_rloc16])
        self.assertCountEqual(br1_1.get_br_peers_rloc16s(), [br1_0_rloc16, br1_2_rloc16])
        self.assertCountEqual(br1_2.get_br_peers_rloc16s(), [br1_0_rloc16, br1_1_rloc16])

        self.assertCountEqual(br2_0.get_br_peers_rloc16s(),
                              [br2_1_rloc16, br2_2_rloc16, br2_3_rloc16, br2_4_rloc16, br2_5_rloc16])
        self.assertCountEqual(br2_1.get_br_peers_rloc16s(),
                              [br2_0_rloc16, br2_2_rloc16, br2_3_rloc16, br2_4_rloc16, br2_5_rloc16])
        self.assertCountEqual(br2_2.get_br_peers_rloc16s(),
                              [br2_0_rloc16, br2_1_rloc16, br2_3_rloc16, br2_4_rloc16, br2_5_rloc16])
        self.assertCountEqual(br2_3.get_br_peers_rloc16s(),
                              [br2_0_rloc16, br2_1_rloc16, br2_2_rloc16, br2_4_rloc16, br2_5_rloc16])
        self.assertCountEqual(br2_4.get_br_peers_rloc16s(),
                              [br2_0_rloc16, br2_1_rloc16, br2_2_rloc16, br2_3_rloc16, br2_5_rloc16])
        self.assertCountEqual(br2_5.get_br_peers_rloc16s(),
                              [br2_0_rloc16, br2_1_rloc16, br2_2_rloc16, br2_3_rloc16, br2_4_rloc16])

        # ---------------------------------------
        # br routers
        br0_0_addr = ipaddress.IPv6Address(br0_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br1_0_addr = ipaddress.IPv6Address(br1_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br1_1_addr = ipaddress.IPv6Address(br1_1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br1_2_addr = ipaddress.IPv6Address(br1_2.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_0_addr = ipaddress.IPv6Address(br2_0.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_1_addr = ipaddress.IPv6Address(br2_1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_2_addr = ipaddress.IPv6Address(br2_2.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_3_addr = ipaddress.IPv6Address(br2_3.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_4_addr = ipaddress.IPv6Address(br2_4.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_5_addr = ipaddress.IPv6Address(br2_5.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))

        # infra #0
        self.assertCountEqual(br0_0.get_br_routers_ip_addresses(), [br2_0_addr, br2_1_addr, br1_0_addr, br1_1_addr])
        self.assertCountEqual(br1_0.get_br_routers_ip_addresses(), [br2_0_addr, br2_1_addr, br0_0_addr, br1_1_addr])
        self.assertCountEqual(br1_1.get_br_routers_ip_addresses(), [br2_0_addr, br2_1_addr, br0_0_addr, br1_0_addr])
        self.assertCountEqual(br2_0.get_br_routers_ip_addresses(), [br2_1_addr, br0_0_addr, br1_0_addr, br1_1_addr])
        self.assertCountEqual(br2_1.get_br_routers_ip_addresses(), [br2_0_addr, br0_0_addr, br1_0_addr, br1_1_addr])

        # infra #1
        self.assertCountEqual(br2_2.get_br_routers_ip_addresses(), [br2_3_addr, br2_4_addr])
        self.assertCountEqual(br2_3.get_br_routers_ip_addresses(), [br2_2_addr, br2_4_addr])
        self.assertCountEqual(br2_4.get_br_routers_ip_addresses(), [br2_2_addr, br2_3_addr])

        # infra #2
        self.assertCountEqual(br2_5.get_br_routers_ip_addresses(), [br1_2_addr])
        self.assertCountEqual(br1_2.get_br_routers_ip_addresses(), [br2_5_addr])


@unittest.skip("Skipping")
class FiveBorderRoutersOnTwoInfrastructures(thread_cert.TestCase):
    """
    Topology:

        ***********(backbone0.0)*************
              |         |         |
             BR1 ------BR2       BR6
              |         |
             BR3 ----- BR4 ----- BR5
              |         |         |
        ***********(backbone0.1)*************
    """
    USE_MESSAGE_FACTORY = False
    BR1, BR2, BR3, BR4, BR5, BR6 = range(1, 7)

    TOPOLOGY = {
        BR1: {
            'name': 'BR_1',
            'backbone_network_id': 0,
            'allowlist': [BR2, BR3],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2: {
            'name': 'BR_2',
            'backbone_network_id': 0,
            'allowlist': [BR1, BR4],
            'is_otbr': True,
            'version': '1.3',
        },
        BR3: {
            'name': 'BR_3',
            'backbone_network_id': 1,
            'allowlist': [BR1, BR4],
            'is_otbr': True,
            'version': '1.3',
        },
        BR4: {
            'name': 'BR_4',
            'backbone_network_id': 1,
            'allowlist': [BR2, BR3, BR5],
            'is_otbr': True,
            'version': '1.3',
        },
        BR5: {
            'name': 'BR_5',
            'backbone_network_id': 1,
            'allowlist': [BR4],
            'is_otbr': True,
            'version': '1.3',
        },
        BR6: {
            'name': 'BR_6',
            'backbone_network_id': 0,
            'allowlist': [],
            'is_otbr': True,
            'version': '1.3',
        }
    }

    def test(self):
        br1: OtbrNode = self.nodes[self.BR1]
        br2: OtbrNode = self.nodes[self.BR2]
        br3: OtbrNode = self.nodes[self.BR3]
        br4: OtbrNode = self.nodes[self.BR4]
        br5: OtbrNode = self.nodes[self.BR5]
        br6: OtbrNode = self.nodes[self.BR6]

        border_routers = [br1, br2, br3, br4, br5, br6]

        # start nodes
        for br in border_routers:
            br.start()

        # sleep some time more to ensure every BR has get the network data and RA messages correctly,
        # otherwise the test can fail sometimes.
        self.simulator.go(config.BORDER_ROUTER_STARTUP_DELAY + 3)

        # br peers
        br1_rloc16, br2_rloc16, br3_rloc16, br4_rloc16, br5_rloc16, _ = [br.get_addr16() for br in border_routers]

        self.assertCountEqual(br1.get_br_peers_rloc16s(), [br2_rloc16, br3_rloc16, br4_rloc16, br5_rloc16])
        self.assertCountEqual(br2.get_br_peers_rloc16s(), [br1_rloc16, br3_rloc16, br4_rloc16, br5_rloc16])
        self.assertCountEqual(br3.get_br_peers_rloc16s(), [br1_rloc16, br2_rloc16, br4_rloc16, br5_rloc16])
        self.assertCountEqual(br4.get_br_peers_rloc16s(), [br1_rloc16, br2_rloc16, br3_rloc16, br5_rloc16])
        self.assertCountEqual(br5.get_br_peers_rloc16s(), [br1_rloc16, br2_rloc16, br3_rloc16, br4_rloc16])
        self.assertCountEqual(br6.get_br_peers_rloc16s(), [])

        # br routers
        br1_infra_link_local = ipaddress.IPv6Address(br1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br2_infra_link_local = ipaddress.IPv6Address(br2.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br3_infra_link_local = ipaddress.IPv6Address(br3.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br4_infra_link_local = ipaddress.IPv6Address(br4.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br5_infra_link_local = ipaddress.IPv6Address(br5.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))
        br6_infra_link_local = ipaddress.IPv6Address(br6.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL))

        self.assertCountEqual(br1.get_br_routers_ip_addresses(), [br2_infra_link_local, br6_infra_link_local])
        self.assertCountEqual(br2.get_br_routers_ip_addresses(), [br1_infra_link_local, br6_infra_link_local])
        self.assertCountEqual(br3.get_br_routers_ip_addresses(), [br4_infra_link_local, br5_infra_link_local])
        self.assertCountEqual(br4.get_br_routers_ip_addresses(), [br3_infra_link_local, br5_infra_link_local])
        self.assertCountEqual(br5.get_br_routers_ip_addresses(), [br3_infra_link_local, br4_infra_link_local])
        self.assertCountEqual(br6.get_br_routers_ip_addresses(), [br1_infra_link_local, br2_infra_link_local])


@unittest.skip("This is just an example")
class TwoBorderRoutersOnTwoInfrastructures(thread_cert.TestCase):
    """
    Test that two border routers on different infrastructures can ping each other via Thread interface.

    Topology:

    -------(backbone0.0)-------- | ---------(backbone0.1)-------
              |                             |
           BR1 (Leader)  ..............  BR2 (Router)

    """
    USE_MESSAGE_FACTORY = False

    BR1 = 1
    BR2 = 2

    TOPOLOGY = {
        BR1: {
            'name': 'BR_1',
            'backbone_network_id': 0,
            'allowlist': [BR2],
            'is_otbr': True,
            'version': '1.3',
        },
        BR2: {
            'name': 'BR_2',
            'backbone_network_id': 1,
            'allowlist': [BR1],
            'is_otbr': True,
            'version': '1.3',
        }
    }

    def test(self):
        br1: OtbrNode = self.nodes[self.BR1]
        br2: OtbrNode = self.nodes[self.BR2]

        # start nodes
        br1.start()
        self.simulator.go(2)
        br2.start()
        self.simulator.go(config.BORDER_ROUTER_STARTUP_DELAY)

        # check roles
        self.assertEqual('leader', br1.get_state())
        self.assertEqual('router', br2.get_state())

        # check two BRs AIL are in different subnets
        br1_infra_ip_addr = br1.bash(IPV4_CIDR_ADDR_CMD)
        br2_infra_ip_addr = br2.bash(IPV4_CIDR_ADDR_CMD)

        self.assertEqual(len(br1_infra_ip_addr), 1)
        self.assertEqual(len(br2_infra_ip_addr), 1)
        self.assertNotEqual(ipaddress.ip_network(br1_infra_ip_addr[0].strip(), strict=False),
                            ipaddress.ip_network(br2_infra_ip_addr[0].strip(), strict=False))

        # Ping test
        br1_thread_link_local = br1.get_ip6_address(config.ADDRESS_TYPE.LINK_LOCAL)
        br2_thread_link_local = br2.get_ip6_address(config.ADDRESS_TYPE.LINK_LOCAL)
        br1_infra_link_local = br1.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL)
        br2_infra_link_local = br2.get_ip6_address(config.ADDRESS_TYPE.BACKBONE_LINK_LOCAL)

        # ping each other using Thread link-local address
        self.assertTrue(br1.ping(br2_thread_link_local))
        self.assertTrue(br2.ping(br1_thread_link_local))

        # ping each other using Infra link-local address
        self.assertFalse(br1.ping(br2_infra_link_local, interface=br1_infra_link_local))
        self.assertFalse(br2.ping(br1_infra_link_local, interface=br2_infra_link_local))

        # br peers
        self.assertEqual(br1.get_br_peers_rloc16s(), [br2.get_addr16()])
        self.assertEqual(br2.get_br_peers_rloc16s(), [br1.get_addr16()])

        # br routers
        self.assertEqual(br1.get_br_routers_ip_addresses(), [])
        self.assertEqual(br2.get_br_routers_ip_addresses(), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
