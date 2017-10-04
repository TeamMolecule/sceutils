#!/usr/bin/python

import os
import sys
import zlib
import sceutils
from scetypes import SecureBool, SceHeader, SelfHeader, AppInfoHeader, ElfHeader, ElfPhdr, SegmentInfo
from Crypto.Cipher import AES
from Crypto.Util import Counter

def scedecrypt(inf, outdir, decompress=True, silent=False):
    sce = SceHeader(inf.read(SceHeader.Size))
    if not silent:
        print sce
    (sysver, selftype) = sceutils.get_key_type(inf, sce, silent)
    scesegs = sceutils.get_segments(inf, sce, sysver, selftype, silent)
    for i, sceseg in scesegs.iteritems():
        if not silent:
            print 'Decrypting segment {0}...'.format(i)
        outf = open(os.path.join(outdir, "{}.seg{:02}".format(os.path.basename(inf.name), i)), "wb")
        inf.seek(sceseg.offset)
        dat = inf.read(sceseg.size)
        ctr = Counter.new(128, initial_value=long(sceseg.iv.encode("hex"), 16))
        section_aes = AES.new(sceseg.key, AES.MODE_CTR, counter=ctr)
        dat = section_aes.decrypt(dat)
        if sceseg.compressed:
            if not silent:
                print 'Decompressing segment {0}...'.format(i)
            z = zlib.decompressobj()
            dat = z.decompress(dat)
        outf.write(dat)
        

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as inf:
        scedecrypt(inf, sys.argv[2])
