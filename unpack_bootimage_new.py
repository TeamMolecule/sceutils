from sys import argv

import struct
import os


def _make_unpacker(tag, size):
    def f(data, off=0):
        return struct.unpack("<{}".format(tag), data[off:off+size])[0]
    return f


u8 = _make_unpacker("B", 1)
u16 = _make_unpacker("H", 2)
u32 = _make_unpacker("I", 4)


def c_str(data):
    return data[:data.find("\x00")]


def main():
    if len(argv) != 3:
        print "Usage: unpack_bootimage_new.py bootimage.skprx output-dir/"
        return

    with open(argv[1], "rb") as fin:
        data = fin.read()

    data = data[data.find("SceKernelBootimage")-4:]
    base_va = 0x81000000
    off = u32(data, 0xCC) - base_va
    num = u32(data, off)

    for x in xrange(num):
        entry_off = off + 8 + 12 * x

        name_off = u32(data, entry_off) - base_va
        name = c_str(data[name_off:name_off+0x100])
        basename = name[name.rfind("/")+1:]
        start = u32(data, entry_off + 4) - base_va
        size = u32(data, entry_off + 8)

        print "Writing {}...".format(name)
        mod = data[start:start+size]
        with open(os.path.join(argv[2], basename), "wb") as fout:
            fout.write(mod)


if __name__ == "__main__":
    main()
