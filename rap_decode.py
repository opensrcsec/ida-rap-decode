# BSD 3-Clause License
#
# Copyright (c) 2021, Open Source Security, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Pawel Wieczorkiewicz <wipawel@grsecurity.net>
#
from ida_allins import NN_jmp, NN_jmpshort, NN_jmpni, NN_jmpfi
from idautils import Functions, DecodePreviousInstruction
from ida_bytes import is_code, get_flags, del_items, get_item_size
from ida_auto import auto_wait
from ida_funcs import get_func
from ida_ua import create_insn
from idaapi import *

def is_jmp(insn):
  return insn and insn.itype in [NN_jmp, NN_jmpshort, NN_jmpni, NN_jmpfi]


class rap_decode_t(plugin_t):
    flags = PLUGIN_KEEP
    comment = ""
    help = "Run this plugin once and wait for it to finish"
    wanted_name = "RAP Decode"
    wanted_hotkey = "Alt-F8"

    MAX_ALIGN_LENGTH = 15

    def init(self):
        return PLUGIN_OK

    def run(self, arg):
        print("Running RAP Decode plugin...")
        self.rap_decode()

    def term(self):
        pass

    def rap_decode(self):
        for func_ea in Functions():
            func = get_func(func_ea)
            flowchart = FlowChart(func)

            for bb in flowchart:
                data_ea = bb.end_ea
                if is_code(get_flags(data_ea)):
                    continue

                last_insn = DecodePreviousInstruction(data_ea)
                if not is_jmp(last_insn):
                    continue

                # Delete all items from current EA up to maximal alignment length
                for ea in range(data_ea, data_ea + self.MAX_ALIGN_LENGTH):
                    del_items(ea)

                ea = data_ea
                while ea < data_ea + self.MAX_ALIGN_LENGTH:
                    size = create_insn(ea)
                    # Skip item if unable to create instruction for it
                    ea += size if size > 0 else get_item_size(ea)

        auto_wait()


def PLUGIN_ENTRY():
    return rap_decode_t()

