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

PLUGIN_NAME = "•_•"

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


def hexdump(address, data):
    word = 8
    if address + len(data) > 0x100000000:
        word = 16

    result = ""
    size = len(data)
    line = int(size / 0x10) + 1 - int(not (size % 0x10))
    for i in range(line):
        fmt = "%0" + str(word) + "X  "
        result += fmt % (address + (i * 0x10))
        col_len = (size - (i * 0x10))
        for j in range(min(col_len, 0x10)):
            if j == 8: result += " "
            result += "%02X " % data[i * 0x10 + j]
        if col_len < 0x10:
            result += "   " * (0x10 - col_len)
        result += " |"
        for j in range(min(col_len, 0x10)):
            b = data[i * 0x10 + j]
            s = chr(b) if 32 <= b < 127 else "."
            result += s
        if col_len < 0x10:
            result += " " * (0x10 - col_len)
        result += "|\n"
    return result

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
        self.prev_ea = 0
        self.patched = {}
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

    def __del__(self):
        self.restore_patch()

    def add_patch(self, address, size):
        self.patched[(address, size)] = 1

    def restore_patch(self):
        for address, size in self.patched:
            for p in range(address, address + size):
                ida_bytes.patch_byte(p, ida_bytes.get_original_byte(p))
        self.patched = {}

    def get_prev_ea(self):
        return self.prev_ea

    def set_prev_ea(self, ea):
        self.prev_ea = ea

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

    def read(self, address, size):
        return self.uc.mem_read(address, size)

    def write(self, address, data):
        self.uc.mem_write(address, data)
        return

    def run(self, start_ea, end_ea):
        self.reg_init()

        try:
            self.uc.emu_start(start_ea, end_ea)
        except UcError as e:
            print("Unicorn Error: %s" % e)



emu = Emulator()

class EmulateFuncHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        if ctx.cur_func == None:
            idaapi.warning("not function!")
            return 1

        emu.run(ctx.cur_func.start_ea, ctx.cur_func.end_ea)
        print("End emulation.")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class EmulateHereHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        prev_ea = emu.get_prev_ea()
        end_ea = idaapi.ask_addr(prev_ea, "What is the end address of the routine you want to emulate?")
        if end_ea == None or end_ea - ctx.cur_ea <= 0 or end_ea - ctx.cur_ea > 0x1000:
            print("Wrong address! (Only current address + (0x1 ~ 0x1000) is allowed)")
            return 1
        emu.set_prev_ea(end_ea)
        emu.run(ctx.cur_ea, end_ea)
        print("End emulation.")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ConvertHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ida_bytes.create_strlit(ctx.cur_ea, 0, ida_nalt.STRTYPE_C)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PrintHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        if ctx.cur_value == 0xffffffffffffffff:
            print("Not address symbol!")
            return 1

        size = idaapi.ask_long(0x1000, "How many bytes do you want to print?")
        if size == None or size <= 0 or size > 0x1000:
            print("Wrong size! (Only 0x1 ~ 0x1000 is allowed)")
            return 1
        address = ctx.cur_value
        data = emu.read(address, size)
        print(hexdump(address, data))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ApplyHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        if ctx.cur_value == 0xffffffffffffffff:
            print("Not address symbol!")
            return 1

        size = idaapi.ask_long(0x1000, "How many bytes do you want to patch?")
        if size == None or size <= 0 or size > 0x1000:
            print("Wrong size! (Only 0x1 ~ 0x1000 is allowed)")
            return 1

        address = ctx.cur_value
        data = emu.read(address, size)
        ida_bytes.patch_bytes(address, bytes(data))
        emu.add_patch(address, size)
        print("Patching to memory after emulation succeeded!")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ResetEmuHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        print("Reset emulator successful!")
        del emu
        emu = Emulator()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RestoreBytesHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global emu

        emu.restore_patch()
        print("Restore bytes successful!")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class UnloadHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.unregister_action("act:emulate_func")
        idaapi.unregister_action("act:emulate_here")
        idaapi.unregister_action("act:convert")
        idaapi.unregister_action("act:print")
        idaapi.unregister_action("act:apply")
        idaapi.unregister_action("act:reset_emu")
        idaapi.unregister_action("act:restore_bytes")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PopupHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self) 

    def finish_populating_widget_popup(self, form, popup, ctx):
        formtype = idaapi.get_widget_type(form)
        if formtype == idaapi.BWN_DISASM: # or formtype == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, "act:emulate_func", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:emulate_here", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:convert", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:print", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:apply", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:reset_emu", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:restore_bytes", PLUGIN_NAME + "/")
            idaapi.attach_action_to_popup(form, popup, "act:unload", PLUGIN_NAME + "/")

class PluginEntry(idaapi.plugin_t):
    def init(self):
        self.popupHook = PopupHook()

        action_emulate_func_desc = idaapi.action_desc_t("act:emulate_func", "Emulate Function •_•", EmulateFuncHandler(), "Ctrl+Shift+E", None, -1)
        action_emulate_here_desc = idaapi.action_desc_t("act:emulate_here", "Emulate Here •_•", EmulateHereHandler(), "Ctrl+Shift+H", None, -1)
        action_convert_desc = idaapi.action_desc_t("act:convert", "Convert Me •_•", ConvertHandler(), None, None, -1)
        action_print_desc = idaapi.action_desc_t("act:print", "Print Me •_•", PrintHandler(), None, None, -1)
        action_apply_desc = idaapi.action_desc_t("act:apply", "Apply Me •_•", ApplyHandler(), "Ctrl+Shift+A", None, -1)
        action_reset_emu_desc = idaapi.action_desc_t("act:reset_emu", "Reset Emulator •_•", ResetEmuHandler(), None, None, -1)
        action_restore_bytes_desc = idaapi.action_desc_t("act:restore_bytes", "Restore Patched Bytes •_•", RestoreBytesHandler(), None, None, -1)
        action_unload_desc = idaapi.action_desc_t("act:unload", "Unload Me •_•", UnloadHandler(), None, None, -1)
        idaapi.register_action(action_emulate_func_desc)
        idaapi.register_action(action_emulate_here_desc)
        idaapi.register_action(action_convert_desc)
        idaapi.register_action(action_print_desc)
        idaapi.register_action(action_apply_desc)
        idaapi.register_action(action_reset_emu_desc)
        idaapi.register_action(action_restore_bytes_desc)
        idaapi.register_action(action_unload_desc)
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action("act:emulate_func")
        idaapi.unregister_action("act:emulate_here")
        idaapi.unregister_action("act:convert")
        idaapi.unregister_action("act:print")
        idaapi.unregister_action("act:apply")
        idaapi.unregister_action("act:reset_emu")
        idaapi.unregister_action("act:restore_bytes")
        idaapi.unregister_action("act:unload")

    def run(self):
        self.popupHook.hook()

def PLUGIN_ENTRY():
        return PluginEntry()

if __name__ == '__main__':
    entry = PluginEntry()
    entry.init()
    entry.run()
