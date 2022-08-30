import idaapi
import idautils
from idautils import ida_segment, ida_bytes

import struct
from keystone import *
from capstone import *
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *


BIT = 64


CAPSTONE = 0
KEYSTONE = 1
UNICORN = 2

WORD = int(BIT / 8)
PAGE_SIZE = 0x1000
ALIGN = ((2 ** BIT - 1) ^ (PAGE_SIZE - 1))
DUMMY_IMPORT = 0xFFF80000
STACK = 0xF7770000
if BIT == 64:
    DUMMY_IMPORT += 0xFF00000000
    STACK += 0xFF00000000

def pack(address):
    ps = ""
    if idaapi.get_inf_structure().is_be() == True:
        ps = ">"
    else:
        ps = "<"

    if BIT == 64: ps += "Q"
    else: ps += "I"
    
    return struct.pack(ps, address)

class Emulator():
    def __init__(self):
        arch, mode = self.get_arch(UNICORN)
        self.uc = Uc(arch, mode)
        self.uc.mem_map(STACK, PAGE_SIZE * 0x100)
        self.uc.mem_map(DUMMY_IMPORT, PAGE_SIZE)
        self.uc.mem_write(DUMMY_IMPORT, self.get_retcode(WORD))

        prev_end_ea = 0
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if seg.type == ida_segment.SEG_XTRN:
                size = seg.end_ea - seg.start_ea
                size = size + (WORD - size % WORD)

                # heuristic
                if arch == UC_ARCH_ARM or arch == UC_ARCH_ARM64:
                    data = (self.get_retcode(WORD)) * int(size / WORD)
                else:
                    data = pack(DUMMY_IMPORT) * int(size / WORD)

            start_ea = seg.start_ea & ALIGN
            end_ea = seg.end_ea
            if start_ea < prev_end_ea: start_ea += PAGE_SIZE
            if end_ea & (PAGE_SIZE - 1) != 0:
                end_ea = (end_ea & ALIGN) + PAGE_SIZE
            prev_end_ea = end_ea

            if end_ea - start_ea > 0:
                self.uc.mem_map(start_ea, end_ea - start_ea)
            self.uc.mem_write(seg.start_ea, data) 

    def get_arch(self, libtype):
        be_types = [CS_MODE_BIG_ENDIAN, KS_MODE_BIG_ENDIAN, UC_MODE_BIG_ENDIAN]
        le_types = [CS_MODE_LITTLE_ENDIAN, KS_MODE_LITTLE_ENDIAN, UC_MODE_LITTLE_ENDIAN]
        bit64_types = [CS_MODE_64, KS_MODE_64, UC_MODE_64]
        bit32_types = [CS_MODE_32, KS_MODE_32, UC_MODE_32]
        arm64_types = [CS_ARCH_ARM64, KS_ARCH_ARM64, UC_ARCH_ARM64]
        arm_types = [CS_ARCH_ARM, KS_ARCH_ARM, UC_ARCH_ARM]
        x86_types = [CS_ARCH_X86, KS_ARCH_X86, UC_ARCH_X86]
        arch = None
        mode = None
        info = idaapi.get_inf_structure()

        if info.is_be() == True:
            mode = be_types[libtype]
        else:
            mode = le_types[libtype]

        if info.procname == "ARM":
            if BIT == 64: arch = arm64_types[libtype]
            else: arch = arm_types[libtype]
        elif info.procname == "metapc":
            arch = x86_types[libtype]
            if BIT == 64: mode = bit64_types[libtype]
            else: mode = bit32_types[libtype]
        return (arch, mode)

    def get_retcode(self, word):
        arch, mode = self.get_arch(KEYSTONE)

        code = b"nop"
        try:
            ks = Ks(arch, mode)
            nop, cnt = ks.asm(code)
        except KsError as e:
            print("Keystone Error: %s" % e)

        code = b"ret"
        try:
            ks = Ks(arch, mode)
            ret, cnt = ks.asm(code)
        except KsError as e:
            print("Keystone Error: %s" % e)

        data = bytes(ret)
        while True:
            data = bytes(nop) + data
            if len(data) >= word: break

        if len(data) != word:
            print("retcode Error")
            data = data[:word]

        return data

    def reg_init(self):
        arch, mode = self.get_arch(UNICORN)
        if arch == UC_ARCH_ARM64:
            self.uc.reg_write(UC_ARM64_REG_X28, STACK + 0xC0000);
            self.uc.reg_write(UC_ARM64_REG_FP, STACK + 0x80000);
            self.uc.reg_write(UC_ARM64_REG_SP, STACK + 0x40000);
        elif arch == UC_ARCH_ARM:
            self.uc.reg_write(UC_ARM_REG_FP, STACK + 0x80000);
            self.uc.reg_write(UC_ARM_REG_SP, STACK + 0x40000);
        elif arch == UC_ARCH_X86:
            if mode == UC_MODE_64:
                self.uc.reg_write(UC_X86_REG_RBP, STACK + 0x80000);
                self.uc.reg_write(UC_X86_REG_RSP, STACK + 0x40000);
            else:
                self.uc.reg_write(UC_X86_REG_EBP, STACK + 0x80000);
                self.uc.reg_write(UC_X86_REG_ESP, STACK + 0x40000);

    def run(self, ctx):
        self.reg_init()

        start_ea = ctx.cur_func.start_ea
        end_ea = ctx.cur_func.end_ea

#        data = self.uc.mem_read(0xF558, 0x10)
#        arch, mode = self.get_arch(CAPSTONE)
#        cs = Cs(arch, mode)
#        for i in cs.disasm(data, 0xF558):
#            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        try:
            self.uc.emu_start(start_ea, end_ea)
        except UcError as e:
            print("Unicorn Error: %s" % e)


class PluginHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctx.cur_func == None:
            idaapi.warning("not function!")
            return 1

        emu = Emulator()
        emu.run(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PopupHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self) 

    def finish_populating_widget_popup(self, form, popup):
        formtype = idaapi.get_widget_type(form)
        if formtype == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "act:emulate", None)

class PluginEntry(idaapi.plugin_t):
    def init(self):
        self.popupHook = PopupHook()

        action_desc = idaapi.action_desc_t("act:emulate", "Emulate Me •_•", PluginHandler(), None, None, -1)
        idaapi.register_action(action_desc)
#        idaapi.attach_action_to_menu("Edit/Plugins/", "act:emulate", idaapi.SETMENU_FIRST)
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action("act:emulate")
#        idaapi.detach_action_from_menu("Edit/Plugins/", "act:emulate")

    def run(self):
        self.popupHook.hook()

def PLUGIN_ENTRY():
        return PluginEntry()

if __name__ == '__main__':
    entry = PluginEntry()
    entry.init()
    entry.run()
