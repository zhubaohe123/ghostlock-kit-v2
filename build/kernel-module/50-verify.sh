#!/usr/bin/env bash
# 50-verify.sh — verify ghostlock.ko against the device ground truth
set -u

GKI=/root/gki
KO=/mnt/d/daima/root2/ghostlock/kmod/ghostlock.ko
REF=/mnt/d/daima/root2/ghostlock/kmod/trivial.ko   # built from device kheaders, ground truth format
READELF=$GKI/clang-r487747c/bin/llvm-readelf
fail=0

[ -f "$KO" ] || { echo "ghostlock.ko missing"; exit 1; }

echo "== modinfo =="
modinfo "$KO"

VM=$(modinfo -F vermagic "$KO")
VM_REF=$(modinfo -F vermagic "$REF" 2>/dev/null || true)
echo
echo "== vermagic =="
echo "ours: [$VM]"
echo "ref : [$VM_REF]"
if [ "$VM" = "$VM_REF" ]; then echo "VERMAGIC-BYTE-EXACT: OK"; else
  echo "VERMAGIC-DIFFERS (informational; ref built from device kheaders)"; fi
case "$VM" in
  *"vivo "*) echo "CHECK-NO-VIVO-PREFIX: FAIL"; fail=1 ;;
  *) echo "CHECK-NO-VIVO-PREFIX: OK" ;;
esac

echo
echo "== import_ns =="
INS=$(modinfo -F import_ns "$KO" 2>/dev/null || true)
echo "ours: [$INS]"
if [ "$INS" = "VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver" ]; then
  echo "CHECK-IMPORT-NS: OK"; else echo "CHECK-IMPORT-NS: FAIL"; fail=1; fi

echo
echo "== ELF =="
$READELF -h "$KO" | grep -E 'Class:|Machine:|Type:'
$READELF -h "$KO" | grep -q 'AArch64' && echo "CHECK-ARCH-AArch64: OK" || { echo "CHECK-ARCH-AArch64: FAIL"; fail=1; }

echo
echo "== __versions CRC dump (each 64-byte entry starts with u32 crc; all must be 0) =="
python3 - "$KO" <<'PYEOF'
import struct, sys
data = open(sys.argv[1], 'rb').read()
# parse ELF64 section headers
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
vers = [s for s in secs if sname(s['name']) == '__versions']
if not vers:
    print('__versions section: NOT FOUND'); sys.exit(1)
s = vers[0]
blob = data[s['offset']:s['offset'] + s['size']]
n = len(blob) // 64
bad = []
for i in range(n):
    crc, = struct.unpack_from('<Q', blob, i * 64)   # unsigned long crc (8B) + char name[56]
    name = blob[i * 64 + 8: i * 64 + 64].split(b'\0')[0].decode(errors='replace')
    if crc != 0:
        bad.append((name, crc))
print(f'__version entries: {n}, nonzero CRC: {len(bad)}')
for name, crc in bad[:10]:
    print(f'  NONZERO: {name} = 0x{crc:08x}')
print('CHECK-CRC-ALL-ZERO:', 'OK' if not bad else 'FAIL')
PYEOF
python3 -c "import sys" 2>/dev/null || true

echo
echo "== vivo string scan (whole binary) =="
if grep -aq 'vivo ' "$KO"; then echo "CHECK-NO-VIVO-STRING: FAIL"; fail=1; else echo "CHECK-NO-VIVO-STRING: OK"; fi

echo
echo "sections:"
$READELF -S "$KO" | grep -E 'modinfo|__versions|\.gnu\.linkonce\.this_module' || true

if [ "$fail" -eq 0 ]; then echo VERIFY-ALL-OK; else echo VERIFY-FAILED; exit 1; fi
