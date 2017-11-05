#!/usr/bin/python

import os
import sys
import zlib
import argparse
import sceutils
from scetypes import SecureBool, SceHeader, SelfHeader, AppInfoHeader, ElfHeader, ElfPhdr, SegmentInfo, SceVersionInfo, SceControlInfo, SceControlInfoDigest256, ControlType, SceControlInfoDRM, SceRIF
from Crypto.Cipher import AES
from Crypto.Util import Counter

def self2elf(inf, outf=open(os.devnull, "w"), klictxt='0', silent=False):
    npdrmtype=0
    sce = SceHeader(inf.read(SceHeader.Size))
    if not silent:
        print sce
    self_hdr = SelfHeader(inf.read(SelfHeader.Size))
    inf.seek(self_hdr.appinfo_offset)
    appinfo_hdr = AppInfoHeader(inf.read(AppInfoHeader.Size))
    if not silent:
        print appinfo_hdr
    inf.seek(self_hdr.sceversion_offset)
    verinfo_hdr = SceVersionInfo(inf.read(SceVersionInfo.Size))
    if not silent:
        print verinfo_hdr
    inf.seek(self_hdr.controlinfo_offset)
    controlinfo_hdr = SceControlInfo(inf.read(SceControlInfo.Size))
    ci_off = SceControlInfo.Size
    if not silent:
        print controlinfo_hdr
    if controlinfo_hdr.type == ControlType.DIGEST_SHA256: 
        inf.seek(self_hdr.controlinfo_offset+ci_off)
        ci_off += SceControlInfoDigest256.Size
        controldigest256 = SceControlInfoDigest256(inf.read(SceControlInfoDigest256.Size))
        if not silent:
            print controldigest256
    inf.seek(self_hdr.controlinfo_offset+ci_off)
    controlinfo_hdr = SceControlInfo(inf.read(SceControlInfo.Size))
    if not silent:
        print controlinfo_hdr    
    ci_off += SceControlInfo.Size
    if controlinfo_hdr.type == ControlType.NPDRM_VITA:
        inf.seek(self_hdr.controlinfo_offset+ci_off)
        ci_off += SceControlInfoDRM.Size
        controlnpdrm = SceControlInfoDRM(inf.read(SceControlInfoDRM.Size))
        npdrmtype=controlnpdrm.npdrm_type
        if not silent:
            print controlnpdrm

    # copy elf header
    inf.seek(self_hdr.elf_offset)
    dat = inf.read(ElfHeader.Size)
    outf.write(dat)
    elf_hdr = ElfHeader(dat)
    if not silent:
        print elf_hdr
    # get segments
    elf_phdrs = {}
    segment_infos = {}
    encrypted = False
    at = ElfHeader.Size
    for i in range(elf_hdr.e_phnum):
        # phdr
        inf.seek(self_hdr.phdr_offset + i*ElfPhdr.Size)
        dat = inf.read(ElfPhdr.Size)
        phdr = ElfPhdr(dat)
        if not silent:
            print phdr
        #elf_phdrs.append(phdr)
        elf_phdrs[i] = phdr
        # write phdr
        outf.write(dat)
        at += ElfPhdr.Size
        # seg info
        inf.seek(self_hdr.segment_info_offset + i*SegmentInfo.Size)
        segment_info = SegmentInfo(inf.read(SegmentInfo.Size))
        if not silent:
            print segment_info
        #segment_infos.append(segment_info)
        segment_infos[i] = segment_info
        if segment_info.plaintext == SecureBool.NO:
            encrypted = True
    # get keys
    if encrypted:
        scesegs = sceutils.get_segments(inf, sce, appinfo_hdr.sys_version, appinfo_hdr.self_type, npdrmtype, klictxt, silent)
    else:
        scesegs = {}
    # generate ELF
    for i in range(elf_hdr.e_phnum):
        if scesegs:
            idx = scesegs[i].idx
        else:
            idx=i
                
        if elf_phdrs[idx].p_filesz == 0:
            continue
        if not silent:
            print 'Dumping segment {0}...'.format(idx)
        # padding
        #print elf_phdrs[i].p_offset
        pad_len = elf_phdrs[idx].p_offset - at
        if pad_len < 0:
            print pad_len
            raise RuntimeError("ELF p_offset invalid!")
        outf.write(b"\x00" * pad_len)
        at += pad_len
        # data
        inf.seek(segment_infos[idx].offset)
        dat = inf.read(segment_infos[idx].size)
        # encryption
        if segment_infos[idx].plaintext == SecureBool.NO:
            ctr = Counter.new(128, initial_value=long(scesegs[i].iv.encode("hex"), 16))
            section_aes = AES.new(scesegs[i].key, AES.MODE_CTR, counter=ctr)
            dat = section_aes.decrypt(dat)
        # compression
        if segment_infos[idx].compressed == SecureBool.YES:
            z = zlib.decompressobj()
            dat = z.decompress(dat)
        # write-back
        outf.write(dat)
        at += len(dat)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inputfile", help="input file name", type=str)
    parser.add_argument("-o", "--outputfile", help="output file name", type=str)
    parser.add_argument("-k", "--keyriffile", help="NoNpdrm RIF file name", type=str)
    args=parser.parse_args()
    with open(args.inputfile, "rb") as inf:
        with open(args.outputfile, "wb") as outf:
            if args.keyriffile:
                with open(args.keyriffile, "rb") as rif:
                    lic = SceRIF(rif.read(SceRIF.Size))
                    self2elf(inf, outf, lic.klicense)
            else:
                self2elf(inf, outf, 0)
                        
                    
