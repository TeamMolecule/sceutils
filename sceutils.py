from Crypto.Cipher import AES
from Crypto.Util import Counter
from scetypes import *

def print_metadata_keyvault(keys):
    print 'Metadata Vault:'
    for k in keys:
        print ' {0}:              0x{1:X}'.format(''.join('{:02X}'.format(x) for x in k))

def get_keys(inf, sce_hdr, sysver, self_type=SelfType.NONE, silent=False):
    from keys import SCE_KEYS
    inf.seek(sce_hdr.metadata_offset + 48)
    dat = inf.read(sce_hdr.header_length - sce_hdr.metadata_offset - 48)
    (key, iv) = SCE_KEYS.get(sce_hdr.sce_type, sysver, self_type)
    hdr_dec = AES.new(key, AES.MODE_CBC, iv)
    dec = hdr_dec.decrypt(dat[0:MetadataInfo.Size])
    metadata_info = MetadataInfo(dec)
    if not silent:
        print metadata_info
    contents_dec = AES.new(metadata_info.key, AES.MODE_CBC, metadata_info.iv)
    dec = contents_dec.decrypt(dat[MetadataInfo.Size:])
    metadata_hdr = MetadataHeader(dec[0:MetadataHeader.Size])
    if not silent:
        print metadata_hdr
    keymap = {}
    vault = [dec[MetadataHeader.Size + metadata_hdr.section_count*MetadataSection.Size + 16*i:MetadataHeader.Size + metadata_hdr.section_count*MetadataSection.Size + 16*i + 16] for i in range(metadata_hdr.key_count)]
    for i in range(metadata_hdr.section_count):
        metsec = MetadataSection(dec[MetadataHeader.Size + i*MetadataSection.Size:MetadataHeader.Size + i*MetadataSection.Size + MetadataSection.Size])
        if not silent:
            print metsec
        keymap[metsec.seg_idx] = (vault[metsec.key_idx], vault[metsec.iv_idx])
    return keymap
