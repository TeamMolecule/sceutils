# check README.md for how to install

import struct
from collections import defaultdict

import idaapi
import idc


NORETURN_NIDS = [0xB997493D, 0x391B5B74, 0x00CCE39C, 0x37691BF8, 0x2F2C6046, 0x39AD080B, 0x83A4F46F, 0xB1CD7AC2, 0xEC287338]


class p_type:
    PT_LOAD = 1


def _make_unpacker(tag, size):
    def f(data, off=0):
        return struct.unpack("<{}".format(tag), data[off:off+size])[0]
    return f


u8 = _make_unpacker("B", 1)
u16 = _make_unpacker("H", 2)
u32 = _make_unpacker("I", 4)


def c_str(data):
    return data[:data.find("\x00")]


class ELFHeader:

    def __init__(self, data):
        self.e_entry = u32(data, 0x18)
        self.e_phoff = u32(data, 0x1C)
        self.e_phentsize = u16(data, 0x2A)
        self.e_phnum = u16(data, 0x2C)


class ELFphdr:

    def __init__(self, data):
        self.p_type = u32(data, 0)
        self.p_offset = u32(data, 0x4)
        self.p_vaddr = u32(data, 0x8)
        self.p_filesz = u32(data, 0x10)
        self.p_memsz = u32(data, 0x14)
        self.p_flags = u32(data, 0x18)
        self.x = bool(self.p_flags & 1)


class Modinfo:

    def __init__(self, data):
        self.sz = u32(data, 0)
        self.export_top = u32(data, 0x24)
        self.export_end = u32(data, 0x28)
        self.import_top = u32(data, 0x2C)
        self.import_end = u32(data, 0x30)


class Modexport:

    required_reading = 0x20

    def __init__(self, data):
        self.sz = u8(data, 0)
        assert(self.sz == 0x20)
        self.num_funcs = u16(data, 0x6)
        self.libnid = u32(data, 16)
        self.libname_ptr = u32(data, 20)
        self.libname = "noname"
        self.nid_table = u32(data, 24)
        self.entry_table = u32(data, 28)


class Modimport:

    required_reading = 0x24

    def __init__(self, data):
        self.sz = u16(data, 0)
        assert(self.sz == 0x24)
        self.num_funcs = u16(data, 6)
        self.libnid = u32(data, 12)
        self.libname_ptr = u32(data, 16)
        self.libname = "noname"
        self.nid_table = u32(data, 20)
        self.entry_table = u32(data, 24)


def make_func(func, name):
    t_reg = func & 1  # 0 = ARM, 1 = THUMB
    func -= t_reg
    for i in range(4):
        idc.SetReg(func + i, "T", t_reg)
    idc.MakeFunction(func)
    if name:
        idc.MakeName(func, name)


def add_xrefs():
    """
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to things that look like addresses
    """
    addr = 0
    while addr != idc.BADADDR:
        addr = idc.NextHead(addr)
        if idc.GetMnem(addr) in ["MOV", "MOVW"]:
            reg = idc.GetOpnd(addr, 0)
            if idc.GetOpnd(addr, 1)[0] != "#":
                continue
            val = idc.GetOperandValue(addr, 1)
            found = False
            next_addr = addr
            for x in range(16):
                next_addr = idc.NextHead(next_addr)
                if idc.GetMnem(next_addr) in ["B", "BX"]:
                    break
                # TODO: we could handle a lot more situations if we follow branches, but it's getting complicated
                # if there's a function call and our register is scratch, it will probably get corrupted, bail out
                if idc.GetMnem(next_addr) in ["BL", "BLX"] and reg in ["R0", "R1", "R2", "R3"]:
                    break
                # if we see a MOVT, do the match!
                if idc.GetMnem(next_addr) in ["MOVT", "MOVT.W"] and idc.GetOpnd(next_addr, 0) == reg:
                    if idc.GetOpnd(next_addr, 1)[0] == "#":
                        found = True
                        val += idc.GetOperandValue(next_addr, 1) * (2 ** 16)
                    break
                # if we see something other than MOVT doing something to the register, bail out
                if idc.GetOpnd(next_addr, 0) == reg or idc.GetOpnd(next_addr, 1) == reg:
                    break
            if val & 0xFFFF0000 == 0:
                continue
            if found:
                # pair of MOV/MOVT
                idc.OpOffEx(next_addr, 1, idc.REF_HIGH16, val, 0, 0)
            else:
                # a single MOV instruction
                idc.OpOff(addr, 1, 0)


class VitaElf:

    def __init__(self, fin):
        self.fin = fin
        self.nid_to_name = dict()
        self.seg0_off = None
        self.seg0_va = None
        self.comments = defaultdict(list)

    def load_nids(self):
        try:
            with open("db.yml", "r") as fin:
                data = fin.read().split("\n")
        except IOError:
            raise Exception("Please place db.yml into the directory with your elfs!")
        for line in data:
            if "0x" in line and "nid: " not in line:
                name, nid = line.strip().split(":")
                name = name.strip()
                nid = int(nid.strip(), 16)
                self.nid_to_name[nid] = name

    def add_nid_cmt(self, func, cmt):
        func = func & ~1
        self.comments[func].append(cmt)
        idc.set_func_cmt(func, " aka ".join(self.comments[func]), 0)

    def parse_impexp(self, top, end, cls, callback):
        arr = []
        cur = top
        while cur < end:
            self.fin.seek(self.seg0_off + cur)
            impexp = cls(self.fin.read(cls.required_reading))
            if impexp.libname_ptr:
                self.fin.seek(self.seg0_off + impexp.libname_ptr - self.seg0_va)
                data = self.fin.read(256)
                impexp.libname = c_str(data)

            arr.append(impexp)
            cur += impexp.sz

        for impexp in arr:
            for x in xrange(impexp.num_funcs):
                self.fin.seek(self.seg0_off + impexp.nid_table - self.seg0_va + x * 4)
                nid = u32(self.fin.read(4))
                self.fin.seek(self.seg0_off + impexp.entry_table - self.seg0_va + x * 4)
                func = u32(self.fin.read(4))

                callback(impexp, func, nid)

    def func_get_name(self, prefix, libname, nid):
        if nid in self.nid_to_name:
            suffix = self.nid_to_name[nid]
        else:
            suffix = "0x{:08X}".format(nid)
        return "{}.{}.{}".format(prefix, libname, suffix)

    def cb_noret(self, _, func, nid):
        if nid in NORETURN_NIDS:
            make_func(func, None)
            idc.SetFunctionFlags(func, idc.GetFunctionFlags(func) | idaapi.FUNC_NORET)

    def cb_exp(self, exp, func, nid):
        name = self.func_get_name("exp", exp.libname, nid)

        make_func(func, name)

        self.add_nid_cmt(func, "[Export libnid: 0x{:08X} ({}), NID: 0x{:08X}]".format(exp.libnid, exp.libname, nid))

    def cb_imp(self, imp, func, nid):
        name = self.func_get_name("imp", imp.libname, nid)

        make_func(func, name)
        idc.SetFunctionFlags(func, idc.GetFunctionFlags(func) | idaapi.FUNC_THUNK | idaapi.FUNC_LIB)

        self.add_nid_cmt(func, "[Import libnid: 0x{:08X} ({}), NID: 0x{:08X}]".format(imp.libnid, imp.libname, nid))

    def go(self):
        print "0) Building NID cache..."
        self.load_nids()

        # Vita is ARM
        idaapi.set_processor_type("arm", idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)

        print "1) Loading ELF segments"
        self.fin.seek(0)
        header = ELFHeader(self.fin.read(0x34))

        self.fin.seek(header.e_phoff)
        phdrs = [ELFphdr(self.fin.read(header.e_phentsize)) for _ in xrange(header.e_phnum)]

        for phdr in phdrs:
            if phdr.p_type == p_type.PT_LOAD:
                idaapi.add_segm(0, phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz,
                                ".text" if phdr.x else ".data",
                                "CODE" if phdr.x else "DATA")
                self.fin.file2base(phdr.p_offset, phdr.p_vaddr, phdr.p_vaddr + phdr.p_filesz, 1)

        self.seg0_off = phdrs[0].p_offset
        self.seg0_va = phdrs[0].p_vaddr

        self.fin.seek(self.seg0_off + header.e_entry)
        modinfo = Modinfo(self.fin.read(0x34))

        print "2) Doing noreturn functions first"
        self.parse_impexp(modinfo.export_top, modinfo.export_end, Modexport, self.cb_noret)
        self.parse_impexp(modinfo.import_top, modinfo.import_end, Modimport, self.cb_noret)

        print "3) Parsing export tables"
        self.parse_impexp(modinfo.export_top, modinfo.export_end, Modexport, self.cb_exp)

        print "4) Parsing import tables"
        self.parse_impexp(modinfo.import_top, modinfo.import_end, Modimport, self.cb_imp)

        print "5) Waiting for IDA to analyze the program"
        idc.Wait()

        print "6) Analyzing system instructions"
        from highlight_arm_system_insn import run_script
        run_script()

        print "6) Adding MOVT/MOVW pair xrefs"
        add_xrefs()


def load_file(fin, *args, **kwargs):
    e = VitaElf(fin)
    e.go()

    return 1


def accept_file(fin, *args, **kwargs):
    fin.seek(0)
    header = fin.read(0x34)
    if header.startswith("\x7fELF") and u16(header, 0x10) == 0xFE04:
        return "PS Vita ELF"

    return 0
