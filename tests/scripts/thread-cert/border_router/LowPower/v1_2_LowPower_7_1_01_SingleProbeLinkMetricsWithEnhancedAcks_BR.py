#!/usr/bin/env python3
#
#  Copyright (c) 2022, The OpenThread Authors.
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
import traceback
import copy

from v1_2_LowPower_7_1_01_SingleProbeLinkMetricsWithEnhancedAcks import LowPower_7_1_01
from v1_2_LowPower_7_1_01_SingleProbeLinkMetricsWithEnhancedAcks import LEADER

from config import ADDRESS_TYPE, INTERFACE_TYPE
from node import OtbrNode

# LowPower_7_1_01.TOPOLOGY[LEADER]['is_otbr'] = True

# def get_thread_link_local_address(self, node: OtbrNode) -> str:
#     print(f"======node: {node}")
#     traceback.print_stack()
#     print(f"================")
#     return node.get_ip6_address(ADDRESS_TYPE.LINK_LOCAL, INTERFACE_TYPE.THREAD_WPAN)

# LowPower_7_1_01.get_thread_link_local_address = get_thread_link_local_address


class LowPower_7_1_01_BR(LowPower_7_1_01):
    TOPOLOGY = copy.deepcopy(LowPower_7_1_01.TOPOLOGY)
    TOPOLOGY[LEADER]['is_otbr'] = True

    # def __init__(self, *args, **kwargs):
    #     #print("=========init LowPower_7_1_01_BR=============")
    #     self.TOPOLOGY[LEADER]['is_otbr'] = True
    #     super().__init__(*args, **kwargs)

    def get_thread_link_local_address(self, node: OtbrNode) -> str:
        return node.get_ip6_address(ADDRESS_TYPE.LINK_LOCAL, INTERFACE_TYPE.THREAD_WPAN)

    #@unittest.skip("Skip")
    def test(self):
        super().test()

if __name__ == '__main__':
    #unittest.main(verbosity=2, defaultTest='LowPower_7_1_01_BR')
    unittest.main(verbosity=2)
