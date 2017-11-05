import binascii
import struct
from collections import defaultdict, namedtuple
from enum import Enum

SCE_MAGIC = 0x00454353

KeyEntry = namedtuple('KeyEntry', ['minver', 'maxver', 'keyrev', 'key', 'iv'])
SceSegment = namedtuple('SceSegment', ['offset', 'idx', 'size', 'compressed', 'key', 'iv'])

class SceType(Enum):
    SELF = 1
    SRVK = 2
    SPKG = 3
    DEV = 0xC0

class SceSigType(Enum):
    ECDSA160 = 1
    RSA2048 = 5

class SelfType(Enum):
    NONE = 0
    KERNEL = 0x07
    APP = 0x08
    BOOT = 0x09
    SECURE = 0x0B
    USER = 0x0D

class KeyType(Enum):
    METADATA = 0
    NPDRM = 1
    
class SelfPlatform(Enum):
    PS3 = 0
    VITA = 0x40

class SkpgType(Enum):
    TYPE_0 = 0x0
    OS0 = 0x1
    TYPE_2 = 0x2
    TYPE_3 = 0x3
    PERMISSIONS_4 = 0x4
    TYPE_5 = 0x5
    TYPE_6 = 0x6
    TYPE_7 = 0x7
    SYSCON_8 = 0x8
    BOOT = 0x9
    VS0 = 0xA
    CPFW = 0xB
    MOTION_C = 0xC
    BBMC_D = 0xD
    TYPE_E = 0xE
    MOTION_F = 0xF
    TOUCH_10 = 0x10
    TOUCH_11 = 0x11
    SYSCON_12 = 0x12
    SYSCON_13 = 0x13
    SYSCON_14 = 0x14
    TYPE_15 = 0x15
    VS0_TAR_PATCH = 0x16
    SA0 = 0x17
    PD0 = 0x18
    SYSCON_19 = 0x19
    TYPE_1A = 0x1A
    PSPEMU_LIST = 0x1B

class ControlType(Enum):
    CONTROL_FLAGS = 1
    DIGEST_SHA1 = 2
    NPDRM_PS3 = 3
    DIGEST_SHA256 = 4
    NPDRM_VITA = 5
    UNK_SIG1 = 6
    UNK_HASH1 = 7

class SecureBool(Enum):
    UNUSED = 0
    NO = 1
    YES = 2

class EncryptionType(Enum):
    NONE = 1
    AES128CTR = 3

class HashType(Enum):
    NONE = 1
    HMACSHA1 = 2
    HMACSHA256 = 6

class CompressionType(Enum):
    NONE = 1
    DEFLATE = 2

class KeyStore:
    def __init__(self):
        self._store = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    def register(self, keytype, scetype, keyrev, key, iv, minver=0, maxver=0xffffffffffffffff, selftype=SelfType.NONE):
        self._store[keytype][scetype][selftype].append(KeyEntry(minver, maxver, keyrev, binascii.a2b_hex(key), binascii.a2b_hex(iv)))

    def get(self, keytype, scetype, sysver=-1, keyrev=-1, selftype=SelfType.NONE):
        if keytype not in self._store:
            raise KeyError("Cannot find any keys for this key type")
        if scetype not in self._store[keytype]:
            raise KeyError("Cannot find any keys for this SCE type")
        if selftype not in self._store[keytype][scetype]:
            raise KeyError("Cannot find any keys for this SELF type")
        for item in self._store[keytype][scetype][selftype]:
            if (sysver < 0 or (sysver >= item.minver and sysver <= item.maxver)) and (keyrev < 0 or keyrev == item.keyrev):
                return (item.key, item.iv)
        raise KeyError("Cannot find key/iv for this SCE file")

class SceHeader:
    Size = 32
    def __init__(self, data):
        (
            self.magic, 
            self.version, 
            platform, 
            self.key_revision, 
            sce_type, 
            self.metadata_offset, 
            self.header_length, 
            self.data_length
        ) = struct.unpack('<IIBBHIQQ', data)
        if self.magic != SCE_MAGIC:
            raise TypeError('Invalid SCE magic')
        if self.version != 3:
            raise TypeError('Unknown SCE version')
        self.sce_type = SceType(sce_type)
        self.platform = SelfPlatform(platform)

    def __str__(self):
        ret = ''
        ret += 'SCE Header:\n'
        ret += ' Version:          {0}\n'.format(self.version)
        ret += ' Platform:         {0}\n'.format(self.platform)
        ret += ' Key Revision:     0x{0:X}\n'.format(self.key_revision)
        ret += ' SCE Type:         {0}\n'.format(self.sce_type)
        ret += ' Metadata Offset:  0x{0:X}\n'.format(self.metadata_offset)
        ret += ' Header Length:    0x{0:X}\n'.format(self.header_length)
        ret += ' Data Length:      0x{0:X}'.format(self.data_length)
        return ret

class SelfHeader:
    Size = 88
    def __init__(self, data):
        (
            self.file_length, 
            self.field_8, 
            self.self_offset, 
            self.appinfo_offset, 
            self.elf_offset, 
            self.phdr_offset, 
            self.shdr_offset, 
            self.segment_info_offset, 
            self.sceversion_offset, 
            self.controlinfo_offset, 
            self.controlinfo_length
        ) = struct.unpack('<QQQQQQQQQQQ', data)

class AppInfoHeader:
    Size = 32
    def __init__(self, data):
        (
            self.auth_id, 
            self.vendor_id, 
            self_type, 
            self.sys_version, 
            self.field_18
        ) = struct.unpack('<QIIQQ', data)
        self.self_type = SelfType(self_type)

    def __str__(self):
        ret = ''
        ret += 'App Info Header:\n'
        ret += ' Auth ID:          0x{0:X}\n'.format(self.auth_id)
        ret += ' Vendor ID:        0x{0:X}\n'.format(self.vendor_id)
        ret += ' SELF Type:        {0}\n'.format(self.self_type)
        ret += ' Sys Version:      0x{0:X}'.format(self.sys_version)
        return ret

class ElfHeader:
    Size = 52
    def __init__(self, data):
        (
            e_ident_1,
            e_ident_2,
            self.e_type, 
            self.e_machine, 
            self.e_version, 
            self.e_entry, 
            self.e_phoff, 
            self.e_shoff, 
            self.e_flags, 
            self.e_ehsize, 
            self.e_phentsize, 
            self.e_phnum, 
            self.e_shentsize, 
            self.e_shnum, 
            self.e_shstrndx
        ) = struct.unpack('<QQHHIIIIIHHHHHH', data)
        if e_ident_1 != 0x10101464C457F:
            raise TypeError('Unknown ELF e_ident')
        if self.e_machine != 0x28 and self.e_machine != 0xF00D:
            raise TypeError('Unknown ELF e_machine')
        if self.e_version != 0x1:
            raise TypeError('Unknown ELF e_version')

    def __str__(self):
        ret = ''
        ret += 'ELF Header:\n'
        ret += ' e_machine:        {0}\n'.format("ARM" if self.e_machine == 0x28 else "MeP")
        ret += ' e_entry:          0x{0:X}\n'.format(self.e_entry)
        ret += ' e_phnum:          {0}'.format(self.e_phnum)
        return ret

class ElfPhdr:
    Size = 32
    def __init__(self, data):
        (
            self.p_type, 
            self.p_offset, 
            self.p_vaddr, 
            self.p_paddr, 
            self.p_filesz, 
            self.p_memsz, 
            self.p_flags, 
            self.p_align
        ) = struct.unpack('<IIIIIIII', data)

    def __str__(self):
        ret = ''
        ret += ' ELF Segment:\n'
        ret += '  p_type:          0x{0:X}\n'.format(self.p_type)
        ret += '  p_offset:        0x{0:X}\n'.format(self.p_offset)
        ret += '  p_vaddr:         0x{0:X}\n'.format(self.p_vaddr)
        ret += '  p_paddr:         0x{0:X}\n'.format(self.p_paddr)
        ret += '  p_filesz:        0x{0:X}\n'.format(self.p_filesz)
        ret += '  p_memsz:         0x{0:X}\n'.format(self.p_memsz)
        ret += '  p_flags:         0x{0:X}\n'.format(self.p_flags)
        ret += '  p_align:         0x{0:X}'.format(self.p_align)
        return ret

class SegmentInfo:
    Size = 32
    def __init__(self, data):
        (
            self.offset, 
            self.size, 
            compressed, 
            self.field_14, 
            plaintext, 
            self.field_1C
        ) = struct.unpack('<QQIIII', data)
        self.compressed = SecureBool(compressed)
        self.plaintext = SecureBool(plaintext)

    def __str__(self):
        ret = ''
        ret += ' Segment Info:\n'
        ret += '  offset:          0x{0:X}\n'.format(self.offset)
        ret += '  size:            0x{0:X}\n'.format(self.size)
        ret += '  compressed:      {0}\n'.format(self.compressed)
        ret += '  plaintext:       {0}'.format(self.plaintext)
        return ret

class MetadataInfo:
    Size = 64
    def __init__(self, data):
        self.key = data[0:16]
        self.iv = data[32:48]
        (pad0, pad1) = struct.unpack('<QQ', data[16:32])
        (pad2, pad3) = struct.unpack('<QQ', data[48:64])
        if pad0 != 0 or pad1 != 0 or pad2 != 0 or pad3 != 0:
            raise TypeError('Invalid metadata info padding (decryption likely failed)')

    def __str__(self):
        ret = ''
        ret += 'Metadata Info:\n'
        ret += ' Key:              {0}\n'.format(self.key.encode("hex"))
        ret += ' IV:               {0}'.format(self.iv.encode("hex"))
        return ret

class MetadataHeader:
    Size = 32
    def __init__(self, data):
        (
            self.signature_input_length, 
            self.signature_type, 
            self.section_count, 
            self.key_count, 
            self.opt_header_size, 
            self.field_18, 
            self.field_1C
        ) = struct.unpack('<QIIIIII', data)

    def __str__(self):
        ret = ''
        ret += ' Metadata Header:\n'
        ret += '  sig_input_len:   0x{0:X}\n'.format(self.signature_input_length)
        ret += '  sig_type:        {0}\n'.format(SceSigType(self.signature_type))
        ret += '  section_count    0x{0:X}\n'.format(self.section_count)
        ret += '  key_count:       0x{0:X}\n'.format(self.key_count)
        ret += '  opt_header_size: 0x{0:X}\n'.format(self.opt_header_size)
        ret += '  field_18:        {0}\n'.format(self.field_18)
        ret += '  field_1C:        {0}'.format(self.field_1C)
        return ret

class MetadataSection:
    Size = 48
    def __init__(self, data):
        (
            self.offset, 
            self.size, 
            self.type, 
            self.seg_idx, 
            hashtype, 
            self.hash_idx, 
            encryption, 
            self.key_idx, 
            self.iv_idx, 
            compression
        ) = struct.unpack('<QQIiIiIiiI', data)
        self.hash = HashType(hashtype)
        self.encryption = EncryptionType(encryption)
        self.compression = CompressionType(compression)

    def __str__(self):
        ret = ''
        ret += '  Metadata Section:\n'
        ret += '   offset:         0x{0:X}\n'.format(self.offset)
        ret += '   size:           0x{0:X}\n'.format(self.size)
        ret += '   type:           0x{0:X}\n'.format(self.type)
        ret += '   seg_idx:        0x{0:X}\n'.format(self.seg_idx)
        ret += '   hash:           {0}\n'.format(self.hash)
        ret += '   hash_idx:       0x{0:X}\n'.format(self.hash_idx)
        ret += '   encryption:     {0}\n'.format(self.encryption)
        ret += '   key_idx:        0x{0:X}\n'.format(self.key_idx)
        ret += '   iv_idx:         0x{0:X}\n'.format(self.iv_idx)
        ret += '   compression:    {0}'.format(self.compression)
        return ret

class SrvkHeader:
    Size = 32
    def __init__(self, data):
        (
            self.field_0, 
            self.field_4, 
            self.sys_version, 
            self.field_10, 
            self.field_14, 
            self.field_18, 
            self.field_1C
        ) = struct.unpack('<IIQIIII', data)

    def __str__(self):
        ret = ''
        ret += 'SRVK Header:\n'
        ret += ' field_0:          0x{0:X}\n'.format(self.field_0)
        ret += ' field_4:          0x{0:X}\n'.format(self.field_4)
        ret += ' sys_version:      0x{0:X}\n'.format(self.sys_version)
        ret += ' field_10:         0x{0:X}\n'.format(self.field_10)
        ret += ' field_14:         0x{0:X}\n'.format(self.field_14)
        ret += ' field_18:         0x{0:X}\n'.format(self.field_18)
        ret += ' field_1C:         0x{0:X}\n'.format(self.field_1C)
        return ret

class SpkgHeader:
    Size = 128
    def __init__(self, data):
        (
            self.field_0, 
            pkg_type, 
            self.flags, 
            self.field_C, 
            self.update_version, 
            self.final_size, 
            self.decrypted_size, 
            self.field_28, 
            self.field_30, 
            self.field_34, 
            self.field_38, 
            self.field_3C, 
            self.field_40, 
            self.field_48, 
            self.offset, 
            self.size, 
            self.part_idx, 
            self.total_parts, 
            self.field_70, 
            self.field_78
        ) = struct.unpack('<IIIIQQQQIIIIQQQQQQQQ', data)
        self.type = SkpgType(pkg_type)

    def __str__(self):
        ret = ''
        ret += 'SPKG Header:\n'
        ret += ' field_0:          0x{0:X}\n'.format(self.field_0)
        ret += ' type:             {0}\n'.format(self.type)
        ret += ' flags:            0x{0:X}\n'.format(self.flags)
        ret += ' field_C:          0x{0:X}\n'.format(self.field_C)
        ret += ' update_version:   0x{0:X}\n'.format(self.update_version)
        ret += ' final_size:       0x{0:X}\n'.format(self.final_size)
        ret += ' decrypted_size:   0x{0:X}\n'.format(self.decrypted_size)
        ret += ' field_28:         0x{0:X}\n'.format(self.field_28)
        ret += ' field_30:         0x{0:X}\n'.format(self.field_30)
        ret += ' field_34:         0x{0:X}\n'.format(self.field_34)
        ret += ' field_38:         0x{0:X}\n'.format(self.field_38)
        ret += ' field_3C:         0x{0:X}\n'.format(self.field_3C)
        ret += ' field_40:         0x{0:X}\n'.format(self.field_40)
        ret += ' field_48:         0x{0:X}\n'.format(self.field_48)
        ret += ' offset:           0x{0:X}\n'.format(self.offset)
        ret += ' size:             0x{0:X}\n'.format(self.size)
        ret += ' part_idx:         0x{0:X}\n'.format(self.part_idx)
        ret += ' total_parts:      0x{0:X}\n'.format(self.total_parts)
        ret += ' field_70:         0x{0:X}\n'.format(self.field_70)
        ret += ' field_78:         0x{0:X}\n'.format(self.field_78)
        return ret

class SceVersionInfo:
    Size = 16
    def __init__(self, data):
        (
            self.subtype, 
            self.isPresent, 
            self.size
        ) = struct.unpack('<IIQ', data)    

    def __str__(self):
        ret = 'SCE Version Info Header:\n'
        ret += ' subtype:          0x{0:X}\n'.format(self.subtype)
        ret += ' isPresent:        0x{0:X}\n'.format(self.isPresent)
        ret += ' size:             0x{0:X}\n'.format(self.size)
        return ret

class SceControlInfo:
    Size = 16
    def __init__(self, data):
        (
            control_type, 
            self.size, 
            self.more
        ) = struct.unpack('<IIQ', data)
        self.type = ControlType(control_type)        

    def __str__(self):
        ret = 'SCE Control Info Header:\n'
        ret += ' type:          {0}\n'.format(self.type)
        ret += ' size:          0x{0:X}\n'.format(self.size)
        ret += ' more:          0x{0:X}\n'.format(self.more)
        return ret        
        
class SceControlInfoDigest256:
    Size = 64
    def __init__(self, data):
        self.sce_hash = data[0:20]
        self.file_hash = data[20:52]
        (
            self.filler1,
            self.filler2,
            self.sdk_version
        ) = struct.unpack("<III",data[52:64])
          
      
    def __str__(self):
        ret = 'SCE Control Info Digest256:\n'
        ret += ' SCE Hash:         {0}\n'.format(self.sce_hash.encode("hex"))
        ret += ' File Hash:        {0}\n'.format(self.file_hash.encode("hex"))
        ret += ' SDK version:      0x{0:X}\n'.format(self.sdk_version)
        return ret         


class SceControlInfoDRM:
    Size = 0x100
    def __init__(self,data):
        self.content_id = data[0x10:0x40]
        self.digest1 = data[0x40:0x50]
        self.hash1 = data[0x50:0x70]
        self.hash2 = data[0x70:0x90]
        self.sig1r = data[0x90:0xAC]
        self.sig1s = data[0xAC:0xC8]
        self.sig2r = data[0xC8:0xE4]
        self.sig2s = data[0xE4:0x100]
        (
            self.magic, 
            self.sig_offset,
            self.size, 
            self.npdrm_type, 
            self.field_C,
        ) =  struct.unpack("<IHHII",data[0:0x10])


    def __str__(self):
        ret = 'SCE DRM Info:\n'
        ret += ' Magic:             0x{0:X}\n'.format(self.magic)
        ret += ' Sig Offset:        0x{0:X}\n'.format(self.sig_offset)
        ret += ' Size:              0x{0:X}\n'.format(self.size)
        ret += ' NPDRM Type:        0x{0:X}\n'.format(self.npdrm_type)
        ret += ' Content ID:        {0}\n'.format(self.content_id)
        ret += ' Type Digest:       {0}\n'.format(self.digest1.encode("hex"))
        ret += ' ECDSA224 Sig R:    {0}\n'.format(self.sig2r.encode("hex"))
        ret += ' ECDSA224 Sig S:    {0}\n'.format(self.sig2s.encode("hex"))
        return ret                   
        
class SceRIF:
    Size = 0x98
    def __init__(self,data):
        self.content_id = data[0x10:0x40]
        self.actidx = data[0x40:0x50]
        self.klicense = data[0x50:0x60]
        self.dates = data[0x60:0x70]
        self.filler = data[0x70:0x78]
        self.sig1r = data[0x78:0x8C]
        self.sig1s = data[0x8C:0x98]
        (
            self.majver, 
            self.minver,
            self.style, 
            self.riftype, 
            self.cid,
        ) =  struct.unpack(">HHHHQ",data[0:0x10])


    def __str__(self):
        ret = 'SCE RIF Info:\n'
        ret += ' Maj Ver:           0x{0:X}\n'.format(self.majver)
        ret += ' Min Ver:           0x{0:X}\n'.format(self.minver)
        ret += ' Style:             0x{0:X}\n'.format(self.style)
        ret += ' RifType:           0x{0:X}\n'.format(self.riftype)
        ret += ' CID:               0x{0:X}\n'.format(self.cid)
        ret += ' Content ID:        {0}\n'.format(self.content_id)
        ret += ' KLicensee:         {0}\n'.format(self.klicense.encode("hex"))
        ret += ' ECDSA160 Sig R:    {0}\n'.format(self.sig1r.encode("hex"))
        ret += ' ECDSA160 Sig S:    {0}\n'.format(self.sig1s.encode("hex"))
        return ret                           