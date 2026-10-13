#!/usr/bin/env bash
# 83-prepare-rebuild.sh — after syncconfig the device config also needs
# include/generated/asm-offsets.h (CONFIG_STACKPROTECTOR_PER_TASK pulls
# -mstack-protector-guard-offset from it). syncconfig alone leaves it stale/
# empty -> "invalid value '' in 'mstack-protector-guard-offset='". `make prepare`
# generates it. Then rebuild and gate on the section size.
set -u
KSRC=/root/gki/android14-6.1
OUT=/root/gki/out-6.1.145
BUILD=/root/gki/ghostlock-build
CLANGBIN=/root/gki/clang-r487747c/bin
DEST=/mnt/d/daima/root2/ghostlock/kmod/ghostlock.ko

echo "== asm-offsets.h BEFORE =="
ls -la --time-style=+%H:%M:%S "$OUT/include/generated/asm-offsets.h" 2>/dev/null || echo "  absent"

echo
echo "== make prepare (generates asm-offsets.h etc.) =="
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  PATH="$CLANGBIN:$PATH" prepare -j"$(nproc)" 2>&1 | tail -8

echo
echo "== asm-offsets.h AFTER =="
ls -la --time-style=+%H:%M:%S "$OUT/include/generated/asm-offsets.h" 2>/dev/null || echo "  STILL ABSENT"
grep -E 'thread_info' "$OUT/include/generated/asm-offsets.h" 2>/dev/null | head -3

echo
echo "== rebuild module =="
rm -f "$BUILD"/*.o "$BUILD"/*.mod.c "$BUILD"/*.mod.o "$BUILD"/*.ko
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  PATH="$CLANGBIN:$PATH" KBUILD_MODPOST_WARN=1 \
  KBUILD_EXTRA_SYMBOLS=/root/gki/real.symvers \
  M="$BUILD" -j"$(nproc)" modules 2>&1 \
  | grep -viE '^\s*(CC |LD |MODPOST|Building|WARNING: Module)' | tail -20

echo
echo "== VERDICT =="
python3 - "$BUILD/ghostlock.ko" <<'PYEOF'
import struct, sys, os
p = sys.argv[1]
if not os.path.exists(p):
    print("  ghostlock.ko NOT BUILT"); raise SystemExit(1)
d = open(p,'rb').read()
e_shoff, = struct.unpack_from('<Q', d, 0x28)
es, en, si = struct.unpack_from('<HHH', d, 0x3A)
st = struct.unpack_from('<IIQQQQIIQQ', d, e_shoff+si*es)[4]
tm = None
for i in range(en):
    s = struct.unpack_from('<IIQQQQIIQQ', d, e_shoff+i*es)
    e = d.index(b'\x00', st+s[0]); nm = d[st+s[0]:e].decode()
    if nm == '.gnu.linkonce.this_module':
        tm = s[5]
print(f"  __this_module = 0x{tm:x}   device target = 0x440")
print("  ==> MATCH — SAFE TO INSMOD" if tm == 0x440 else "  ==> MISMATCH — do not load")
PYEOF

echo
echo "== pahole =="
pahole -C module "$BUILD/ghostlock.o" 2>/dev/null | grep -E 'btf_data|/\* size:'

cp -f "$BUILD/ghostlock.ko" "$DEST" 2>/dev/null && echo "copied -> $DEST"
echo PREPARE-REBUILD-DONE
