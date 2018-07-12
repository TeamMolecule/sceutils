#!/usr/bin/env python2

from sys import argv
import struct
from collections import defaultdict
import os.path
import glob

from util import u32, u8, c_str
from scedecrypt import scedecrypt


SCEUF_HEADER_SIZE = 0x80
SCEUF_FILEREC_SIZE = 0x20

pup_types = {
    0x100: "version.txt",
    0x101: "license.xml",
    0x200: "psp2swu.self",
    0x204: "cui_setupper.self",
    0x400: "package_scewm.wm",
    0x401: "package_sceas.as",
    0x2005: "UpdaterES1.CpUp",
    0x2006: "UpdaterES2.CpUp",
}

FSTYPE = [
    "unknown0",
    "os0",
    "unknown2",
    "unknown3",
    "vs0_chmod",
    "unknown5",
    "unknown6",
    "unknown7",
    "pervasive8",
    "boot_slb2",
    "vs0",
    "devkit_cp",
    "motionC",
    "bbmc",
    "unknownE",
    "motionF",
    "touch10",
    "touch11",
    "syscon12",
    "syscon13",
    "pervasive14",
    "unknown15",
    "vs0_tarpatch",
    "sa0",
    "pd0",
    "pervasive19",
    "unknown1A",
    "psp_emulist",
]

g_typecount = defaultdict(int)

def make_filename(hdr, filetype):
    magic, version, flags, moffs, metaoffs = struct.unpack("<IIIIQ", hdr[0:24])
    if magic == 0x454353 and version == 3 and flags == 0x30040:
        meta = hdr[metaoffs:]
        t = u8(meta, 4)
        if t < 0x1C:
            name = "{}-{:02}.pkg".format(FSTYPE[t], g_typecount[t])
            g_typecount[t] += 1
            return name
    return "unknown-0x{:x}.pkg".format(filetype)


def pup_extract_files(pup, output):
    with open(pup, "rb") as fin:
        header = fin.read(SCEUF_HEADER_SIZE)
        if header[0:5] != "SCEUF":
            print "Invalid PUP"
            return -1

        cnt = u32(header, 0x18)

        print "-" * 80
        print "PUP Version: 0x{:x}".format(u32(header, 8))
        print "Firmware Version: 0x{:08X}".format(u32(header, 0x10))
        print "Build Number: {}".format(u32(header, 0x14))
        print "Number of Files: {}".format(cnt)
        print "-" * 80

        for x in range(cnt):
            fin.seek(SCEUF_HEADER_SIZE + x * SCEUF_FILEREC_SIZE)
            rec = fin.read(SCEUF_FILEREC_SIZE)
            filetype, offset, length, flags = struct.unpack("<QQQQ", rec)

            filename = pup_types.get(filetype)
            if not filename:
                fin.seek(offset)
                hdr = fin.read(0x1000)
                filename = make_filename(hdr, filetype)
            # print "filename {} type {} offset {:x} length {:x} flags {:x}".format(filename, filetype, offset, length, flags)

            with open(os.path.join(output, filename), "wb") as fout:
                fin.seek(offset)
                fout.write(fin.read(length))
            print "- {}".format(filename)

        print "-" * 80


def pup_decrypt_packages(src, dst):
    files = [os.path.basename(x) for x in glob.glob(os.path.join(src, "*.pkg"))]
    files.extend(["cui_setupper.self"])

    for filename in files:
        filepath = os.path.join(src, filename)
        with open(filepath, "rb") as fin:
            try:
                scedecrypt(fin, dst, silent=True)
                print "Decrypted {}".format(filename)
            except KeyError:
                print "[!] Couldn't decrypt {}".format(filename)

    print "-" * 80


def slb2_extract(src, dst):
    with open(src, "rb") as fin:
        hdr = fin.read(0x200)
        magic, version, flags, file_count, total_blocks = struct.unpack("<IIIII", hdr[0:20])
        if magic != 0x32424C53:
            raise RuntimeError("Invalid SLB2 file")
        print "SLB2 version: {}, flags: 0x{:X}, file_count: {}, total_blocks: 0x{:X}".format(version, flags, file_count, total_blocks)

        for x in range(file_count):
            entry_start = 0x20 + x * 0x30
            entry = hdr[entry_start:entry_start + 0x30]
            filename = c_str(entry[0x10:])

            block_offset, filesize = struct.unpack("<II", entry[0:8])

            with open(os.path.join(dst, filename), "wb") as fout:
                fin.seek(block_offset * 0x200)
                fout.write(fin.read(filesize))
                print "- {}".format(filename)

    print "-" * 80


def enc_decrypt(src, dst):
    with open(src, "rb") as fin:
        data = fin.read()

    magic, offset, plaintext_size, unk, data_size = struct.unpack("<IIIII", data[0:20])

    if magic != 0x64B2C8E5:
        raise RuntimeError("enc format invalid")

    data = data[offset:offset+data_size]
    # TODO




def slb2_decrypt(src, dst):
    for filename in ["second_loader.enc", "secure_kernel.enc"]:
        enc_decrypt(os.path.join(src, filename), os.path.join(dst, filename.replace(".enc", ".bin")))


def extract_pup(pup, output):
    if os.path.exists(output):
        print "{} already exists, remove it first".format(output)
        return

    print "Extracting {} to {}".format(pup, output)

    os.mkdir(output)

    pup_dst = os.path.join(output, "PUP")
    os.mkdir(pup_dst)

    pup_extract_files(pup, pup_dst)

    pup_dec = os.path.join(output, "PUP_dec")
    os.mkdir(pup_dec)

    pup_decrypt_packages(pup_dst, pup_dec)

    slb2_dst = os.path.join(output, "SLB2")
    os.mkdir(slb2_dst)

    slb2_extract(os.path.join(pup_dec, "boot_slb2-00.pkg.seg02"), slb2_dst)

    slb2_dec = os.path.join(output, "SLB2_dec")
    os.mkdir(slb2_dec)
    slb2_decrypt(slb2_dst, slb2_dec)


def main():
    if len(argv) != 3:
        print "Usage: ./pup_fiction.py FILE.PUP output-dir/"
        return 1
    extract_pup(argv[1], argv[2])


if __name__ == "__main__":
    main()
