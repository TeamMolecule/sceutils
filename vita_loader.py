# place this script into your IDA/loaders/ directory
# place a db.yml into the directory with your elfs

import struct
from collections import defaultdict

import idaapi
import idc
import ida_bytes


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


g_names = dict()

def load_nids():
    print "0) Building NID cache..."
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
            g_names[nid] = name


class ELFHeader():

    def __init__(self, data):
        self.e_entry = u32(data, 0x18)
        self.e_phoff = u32(data, 0x1C)
        self.e_phentsize = u16(data, 0x2A)
        self.e_phnum = u16(data, 0x2C)


class ELFphdr():

    def __init__(self, data):
        self.p_type = u32(data, 0)
        self.p_offset = u32(data, 0x4)
        self.p_vaddr = u32(data, 0x8)
        self.p_filesz = u32(data, 0x10)
        self.p_memsz = u32(data, 0x14)
        self.p_flags = u32(data, 0x18)
        self.x = bool(self.p_flags & 1)


class Modinfo():

    def __init__(self, data):
        self.sz = u32(data, 0)
        self.export_top = u32(data, 0x24)
        self.export_end = u32(data, 0x28)
        self.import_top = u32(data, 0x2C)
        self.import_end = u32(data, 0x30)


class Modexport():

    def __init__(self, data):
        self.sz = u8(data, 0)
        assert(self.sz == 0x20)
        self.num_funcs = u16(data, 0x6)
        self.libnid = u32(data, 16)
        self.libname_ptr = u32(data, 20)
        self.libname = "noname"
        self.nid_table = u32(data, 24)
        self.entry_table = u32(data, 28)


class Modimport():

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
    idc.MakeName(func, name)


def func_flags(func, nid):
    if nid in NORETURN_NIDS:
        idc.SetFunctionFlags(func, idc.GetFunctionFlags(func) | FUNC_NORET)


g_comments = defaultdict(list)
def add_nid_cmt(func, cmt):
    func = func & ~1
    g_comments[func].append(cmt)
    idc.set_func_cmt(func, " aka ".join(g_comments[func]), 0)


def load_file(fin, neflags, format):
    load_nids()

    # Vita is ARM
    idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)

    print "1) Load ELF segments"

    fin.seek(0)
    header = ELFHeader(fin.read(0x34))

    fin.seek(header.e_phoff)
    phdrs = [ELFphdr(fin.read(header.e_phentsize)) for x in xrange(header.e_phnum)]

    for phdr in phdrs:
        if phdr.p_type == p_type.PT_LOAD:
            idaapi.add_segm(0, phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz, ".text" if phdr.x else ".data", "CODE" if phdr.x else "DATA")
            fin.file2base(phdr.p_offset, phdr.p_vaddr, phdr.p_vaddr + phdr.p_filesz, 1)

    base = phdrs[0].p_offset
    va_base = phdrs[0].p_vaddr

    fin.seek(base + header.e_entry)
    modinfo = Modinfo(fin.read(0x34))

    print "2) Parse export tables"
    exports = []
    cur = modinfo.export_top
    while cur < modinfo.export_end:
        fin.seek(base + cur)
        exp = Modexport(fin.read(0x20))
        if exp.libname_ptr:
            fin.seek(base + exp.libname_ptr - va_base)
            data = fin.read(256)
            exp.libname = c_str(data)

        exports.append(exp)
        cur += 0x20

    for export in exports:
        for x in xrange(export.num_funcs):
            fin.seek(base + export.nid_table - va_base + x * 4)
            nid = u32(fin.read(4))
            fin.seek(base + export.entry_table - va_base + x * 4)
            func = u32(fin.read(4))

            if nid in g_names:
                name = "exp.{}.{}".format(export.libname, g_names[nid])
            else:
                name = "exp.{}.0x{:08X}".format(export.libname, nid)

            make_func(func, name)
            func_flags(func, nid)

            add_nid_cmt(func, "[Export libnid: 0x{:08X} ({}) NID: 0x{:08X}]".format(export.libnid, export.libname, nid))


    print "3) Parse import tables"
    imports = []
    cur = modinfo.import_top
    while cur < modinfo.import_end:
        fin.seek(base + cur)
        imp = Modimport(fin.read(0x80))
        if imp.libname_ptr:
            fin.seek(base + imp.libname_ptr - va_base)
            data = fin.read(256)
            imp.libname = c_str(data)

        imports.append(imp)
        cur += imp.sz

    for imp in imports:
        for x in xrange(imp.num_funcs):
            fin.seek(base + imp.nid_table - va_base + x * 4)
            nid = u32(fin.read(4))
            fin.seek(base + imp.entry_table - va_base + x * 4)
            func = u32(fin.read(4))

            if nid in g_names:
                name = "imp.{}.{}".format(imp.libname, g_names[nid])
            else:
                name = "imp.{}.0x{:08X}".format(imp.libname, nid)

            make_func(func, name)
            idc.SetFunctionFlags(func, FUNC_THUNK | FUNC_LIB)
            func_flags(func, nid)

            add_nid_cmt(func, "[Import libnid: 0x{:08X} ({}), NID: 0x{:08X}]".format(imp.libnid, imp.libname, nid))

    return 1


def accept_file(fin, name):
    fin.seek(0)
    header = fin.read(0x34)
    if header.startswith("\x7fELF") and u16(header, 0x12) == 0x28:
        return "PS Vita ELF"

    return 0
