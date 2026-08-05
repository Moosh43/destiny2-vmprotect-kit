#!/usr/bin/env python3
"""Rewrite the PE section table of a MEMORY-IMAGE dump so it loads as a real PE.

The dump is laid out by VIRTUAL address (VA = ImageBase + file offset), but it carries the
ORIGINAL on-disk header, whose PointerToRawData describes the file layout. 0/11 sections match,
so loading it as a PE reads the wrong bytes -- which is why it has to be imported as a raw binary.

Raw-binary import means Ghidra never parses .pdata, so it guesses function boundaries. That is the
source of the "no function at the real entry" problem (0x140527380, 0x1413E84A0, 0x140508800,
0x14053DE20, 0x14054F000 all had to be created by hand this session, and three were fall-through
continuations that read as standalone functions).

Fix: PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize (page-rounded),
FileAlignment = SectionAlignment. Then Ghidra's PE loader parses .pdata, .idata and .reloc.

  pe_memalign.py <in.bin> <out.bin>
"""
import struct,sys
src,dst=sys.argv[1],sys.argv[2]
d=bytearray(open(src,"rb").read())
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
opt=pe+24
secalign=struct.unpack_from('<I',d,opt+0x20)[0]
print(f"  sections={nsec} SectionAlignment={secalign:#x} FileAlignment={struct.unpack_from('<I',d,opt+0x24)[0]:#x}")
struct.pack_into('<I',d,opt+0x24,secalign)          # FileAlignment = SectionAlignment
t=opt+optsz
for i in range(nsec):
    e=t+i*40
    nm=d[e:e+8].rstrip(b'\0').decode(errors='replace')
    vs,va,rs,ro=struct.unpack_from('<IIII',d,e+8)
    nrs=(vs+secalign-1)&~(secalign-1)
    if va+nrs>len(d): nrs=len(d)-va
    struct.pack_into('<II',d,e+16,nrs,va)           # SizeOfRawData, PointerToRawData
    print(f"    {nm:<10} RawPtr {ro:#010x} -> {va:#010x}   RawSize {rs:#010x} -> {nrs:#010x}")
open(dst,"wb").write(bytes(d))
print(f"  wrote {dst}")
