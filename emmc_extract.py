#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct, sys, itertools
from enum import Enum

EMMC_BLOCK_SIZE = 512

class EmmcPartitionCode(Enum):
    EMPTY = 0
    IDSTORAGE = 1
    SLB2 = 2
    OS0 = 3
    VS0 = 4
    VD0 = 5
    TM0 = 6
    UR0 = 7
    UX0 = 8
    GRO0 = 9
    GRW0 = 0xA
    UD0 = 0xB
    SA0 = 0xC
    UNKOWN_MC = 0xD
    PD0 = 0xE

class EmmcPartitionType(Enum):
    UNKNOWN_0 = 0
    FAT16 = 0x6
    EXFAT = 0x7
    UNKNOWN = 0xB
    RAW = 0xDA

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

class EmmcPartition:
    Size = 0x11

    def __init__(self, data):
        (
            offset,
            size,
            code,
            type,
            self.active,
            self.flags,
        ) = struct.unpack('<IIBB?I2x', data)

        self.offset = offset*EMMC_BLOCK_SIZE
        self.size = size*EMMC_BLOCK_SIZE
        self.code = EmmcPartitionCode(code)
        self.type = EmmcPartitionType(type)

    def __str__(self):
        str = ''
        str += 'EmmcPartition:\n'
        str += 'Offset (bytes):   0x{:X}\n'.format(self.offset)
        str += 'Size (bytes):     0x{:X} ({})\n'.format(self.size, sizeof_fmt(self.size))
        str += 'Code:             {}\n'.format(self.code)
        str += 'Type:             {}\n'.format(self.type)
        str += 'Active:           {}\n'.format(self.active)
        str += 'Flags:            0x{:08X}\n'.format(self.flags)
        return str

class EmmcMasterBlock:
    Size = 0x200

    def __init__(self, data):
        (
            self.magic,
            self.version,
            size,
            signature
        ) = struct.unpack('<32sII40x272x94x16x16x16x16xH', data)

        if signature != 0xAA55:
            raise TypeError('Invalid boot signature')

        if self.version != 3:
            raise TypeError('Unknown version')

        self.size = size*EMMC_BLOCK_SIZE

        partitions = data[0x50:0x160]
        partitions = [EmmcPartition(partitions[x:x+EmmcPartition.Size]) for x in range(0, len(partitions), EmmcPartition.Size)]
        self.partitions = [p for p in itertools.takewhile(lambda x: x.offset != 0, partitions)]

    def __str__(self):
        str = ''
        str += 'EmmcMasterBlock:\n'
        str += 'Magic:          {}\n'.format(self.magic)
        str += 'Version:        {}\n'.format(self.version)
        str += 'Size (bytes):   0x{:X} ({})\n'.format(self.size, sizeof_fmt(self.size))
        str += 'Partitions:\n'

        for p in self.partitions:
            str += '{}\n'.format(p)

        return str

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as emmc:
        master = EmmcMasterBlock(emmc.read(EmmcMasterBlock.Size))
        print(master)

        for p in master.partitions:
            if len([x for x in master.partitions if x.code == p.code]) > 1:
                name = '{}_{}.bin'.format(str(p.code).split('.', 1)[-1], 'active' if p.active else 'inactive').lower()
            else:
                name = '{}.bin'.format(str(p.code).split('.', 1)[-1]).lower()

            print('extracting {}... '.format(name))

            with open(name, 'wb') as f:
                emmc.seek(p.offset)
                length = 0

                while length != p.size:
                    data = emmc.read(p.size - length)
                    if len(data) == 0 or data == None:
                      break

                    f.write(data)
                    length += len(data)
                    print('{:.2f}%... '.format(100*length/p.size))

            if length != p.size:
                print('output {} is truncated ({:.2f}% dumped)'.format(name, 100*length/p.size))

