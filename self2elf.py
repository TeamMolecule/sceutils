#!/usr/bin/python

import sys
import zlib
import sceutils
from scetypes import DevNull, SecureBool, SceHeader, SelfHeader, AppInfoHeader, ElfHeader, ElfPhdr, SegmentInfo
from Crypto.Cipher import AES
from Crypto.Util import Counter

def self2elf(inf, outf=DevNull(), silent=False):
    sce = SceHeader(inf.read(SceHeader.Size))
    if not silent:
        print sce
    self_hdr = SelfHeader(inf.read(SelfHeader.Size))
    inf.seek(self_hdr.appinfo_offset)
    appinfo_hdr = AppInfoHeader(inf.read(AppInfoHeader.Size))
    if not silent:
        print appinfo_hdr
    # copy elf header
    inf.seek(self_hdr.elf_offset)
    dat = inf.read(ElfHeader.Size)
    outf.write(dat)
    elf_hdr = ElfHeader(dat)
    if not silent:
        print elf_hdr
    # get segments
    elf_phdrs = []
    segment_infos = []
    encrypted = False
    at = ElfHeader.Size
    for i in range(elf_hdr.e_phnum):
        # phdr
        inf.seek(self_hdr.phdr_offset + i*ElfPhdr.Size)
        dat = inf.read(ElfPhdr.Size)
        phdr = ElfPhdr(dat)
        if not silent:
            print phdr
        elf_phdrs.append(phdr)
        # write phdr
        outf.write(dat)
        at += ElfPhdr.Size
        # seg info
        inf.seek(self_hdr.segment_info_offset + i*SegmentInfo.Size)
        segment_info = SegmentInfo(inf.read(SegmentInfo.Size))
        if not silent:
            print segment_info
        segment_infos.append(segment_info)
        if segment_info.plaintext == SecureBool.NO:
            encrypted = True
    # get keys
    if encrypted:
        keys = sceutils.get_keys(inf, sce, appinfo_hdr.sys_version, appinfo_hdr.self_type, silent)
    else:
        keys = {}
    # generate ELF
    for i in range(elf_hdr.e_phnum):
        if elf_phdrs[i].p_filesz == 0:
            continue
        if not silent:
            print 'Dumping segment {0}...'.format(i)
        # padding
        pad_len = elf_phdrs[i].p_offset - at
        if pad_len < 0:
            raise RuntimeError("ELF p_offset invalid!")
        outf.write(b"\x00" * pad_len)
        at += pad_len
        # data
        inf.seek(segment_infos[i].offset)
        dat = inf.read(segment_infos[i].size)
        # encryption
        if segment_infos[i].plaintext == SecureBool.NO:
            (key, iv) = keys[i]
            ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
            section_aes = AES.new(key, AES.MODE_CTR, counter=ctr)
            dat = section_aes.decrypt(dat)
        # compression
        if segment_infos[i].compressed == SecureBool.YES:
            z = zlib.decompressobj()
            dat = z.decompress(dat)
        # write-back
        outf.write(dat)
        at += len(dat)

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as inf:
        with open(sys.argv[2], "wb") as outf:
            self2elf(inf, outf)
