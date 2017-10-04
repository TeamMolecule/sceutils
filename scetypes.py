import struct
from enum import Enum

SCE_MAGIC = 0x00454353

class SceType(Enum):
  SELF = 1
  SRVK = 2
  SPKG = 3
  DEV = 0xC0

class SelfType(Enum):
  NONE = 0
  KERNEL = 0x07
  FSELF = 0x08
  SECURE = 0x0B
  BOOT = 0x0C
  USER = 0x0D

class SelfPlatform(Enum):
  PS3 = 0
  VITA = 0x40

class SecureBool(Enum):
  NO = 1
  YES = 2

class KeyStore:
  _store = {}

  def register(self, scetype, key, iv, minver=0, maxver=0xffffffffffffffff, selftype=SelfType.NONE):
    if scetype not in self._store:
      self._store[scetype] = {}
    if selftype not in self._store[scetype]:
      self._store[scetype][selftype] = []
    self._store[scetype][selftype].append((minver, maxver, key, iv))

  def get(self, scetype, sysver, selftype=SelfType.NONE):
    if scetype not in self._store:
      raise KeyError("Cannot any keys for this SCE type")
    if selftype not in self._store[scetype]:
      raise KeyError("Cannot any keys for this SELF type")
    for item in self._store[scetype][selftype]:
      if sysver >= item[0] and sysver <= item[1]:
        return (item[2], item[3])
    raise KeyError("Cannot find key/iv for this SCE file")

class SceHeader:
  Size = 32
  def __init__(self, data):
    (
      self.magic, 
      self.version, 
      platform, 
      self.key_version, 
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
    ret += ' Key Version:      0x{0:X}\n'.format(self.key_version)
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
      self.field_8, 
      self.section_count, 
      self.key_count, 
      self.opt_header_size, 
      self.field_18, 
      self.field_1C
    ) = struct.unpack('<QIIIIII', data)

  def __str__(self):
    ret = ''
    ret += ' Metadata Header:\n'
    ret += '  sig_input_len:   {0}\n'.format(self.signature_input_length)
    ret += '  field_8:         {0}\n'.format(self.field_8)
    ret += '  section_count    {0}\n'.format(self.section_count)
    ret += '  key_count:       {0}\n'.format(self.key_count)
    ret += '  opt_header_size: {0}\n'.format(self.opt_header_size)
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
      self.hashed, 
      self.hash_idx, 
      self.encrypted, 
      self.key_idx, 
      self.iv_idx, 
      self.compressed
    ) = struct.unpack('<QQIIIIIIII', data)

  def __str__(self):
    ret = ''
    ret += '  Metadata Section:\n'
    ret += '   offset:         0x{0:X}\n'.format(self.offset)
    ret += '   size:           0x{0:X}\n'.format(self.size)
    ret += '   type:           0x{0:X}\n'.format(self.type)
    ret += '   seg_idx:        0x{0:X}\n'.format(self.seg_idx)
    ret += '   hashed:         0x{0:X}\n'.format(self.hashed)
    ret += '   hash_idx:       0x{0:X}\n'.format(self.hash_idx)
    ret += '   encrypted:      0x{0:X}\n'.format(self.encrypted)
    ret += '   key_idx:        0x{0:X}\n'.format(self.key_idx)
    ret += '   iv_idx:         0x{0:X}\n'.format(self.iv_idx)
    ret += '   compressed:     0x{0:X}'.format(self.compressed)
    return ret

class DevNull: 
  def write(self, str): 
    pass
