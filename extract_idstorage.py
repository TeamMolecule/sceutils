#!/usr/bin/env python2

from sys import argv

import os

from util import u16


def main():
    if len(argv) != 3:
        print "Usage: extract_idstorage.py idstorage-partition.bin output-directory/"
        return

    with open(argv[1], "rb") as fin:
        data = fin.read()

    index_table = data[0:512]
    for index in range(256):
        leaf = u16(index_table, index * 2)
        if leaf not in [0xFFFF, 0xFFF5]:
            with open(os.path.join(argv[2], "leaf_{:04X}.bin".format(leaf)), "wb") as fout:
                fout.write(data[512 * index:512 * (index + 1)])
            print "Leaf 0x{:04X}".format(leaf)


if __name__ == "__main__":
    main()
