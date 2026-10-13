#!/usr/bin/env bash
# 45-mine-crc.sh — mine real kernel symbol CRCs from .ko files' __versions tables
# usage: 45-mine-crc.sh [more.ko ...]
set -u

parse_ko() {
python3 - "$1" <<'PYEOF'
import struct, sys, json
data = open(sys.argv[1], 'rb').read()
e_shoff, = struct.unpack_from('<Q', data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', data, off)
    secs.append(dict(name=name, offset=offset, size=size))
strtab_off = secs[e_shstrndx]['offset']
def sname(n):
    end = data.index(b'\0', strtab_off + n)
    return data[strtab_off + n:end].decode()
for s in secs:
    if sname(s['name']) == '__versions':
        blob = data[s['offset']:s['offset'] + s['size']]
        # struct modversion_info: unsigned long crc (8 bytes) + char name[56]
        for i in range(len(blob) // 64):
            crc, = struct.unpack_from('<Q', blob, i * 64)
            nm = blob[i*64+8:i*64+64].split(b'\0')[0].decode(errors='replace')
            if nm:
                print(f'{nm}\t0x{crc & 0xffffffff:08x}')
        break
PYEOF
}

echo "== per-file dump =="
for ko in "$@"; do
  echo "-- $(basename $ko)"
  parse_ko "$ko"
done
echo MINE-DONE
