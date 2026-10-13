#!/usr/bin/env bash
# 81-sync-rebuild.sh (v2) — THE FIX, with make invoked inline.
#
# Root cause of the 0x400-vs-0x440 struct module mismatch:
#   .config was updated (01:27) but include/generated/autoconf.h was STALE (00:43),
#   because `make M=... modules` does NOT re-run syncconfig for external modules.
#   The compiler kept seeing the old config -> struct module lacked
#   btf_data_size/btf_data (CONFIG_DEBUG_INFO_BTF_MODULES) -> 16 bytes short.
#
# IMPORTANT: do NOT put the make command in a shell variable — the ':' in
# PATH makes make treat "PATH=..." as a target list ("multiple target patterns").
set -u
KSRC=/root/gki/android14-6.1
OUT=/root/gki/out-6.1.145
BUILD=/root/gki/ghostlock-build
CLANGBIN=/root/gki/clang-r487747c/bin
DEST=/mnt/d/daima/root2/ghostlock/kmod/ghostlock.ko

echo "== timestamps BEFORE =="
ls -la --time-style=+%H:%M:%S "$OUT/.config" "$OUT/include/generated/autoconf.h" 2>/dev/null

echo
echo "== syncconfig =="
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  PATH="$CLANGBIN:$PATH" syncconfig 2>&1 | tail -4

echo
echo "== timestamps AFTER =="
ls -la --time-style=+%H:%M:%S "$OUT/.config" "$OUT/include/generated/autoconf.h" 2>/dev/null

echo
echo "== decisive symbol in the generated header =="
grep -E 'CONFIG_DEBUG_INFO_BTF_MODULES' "$OUT/include/generated/autoconf.h" || echo "  STILL ABSENT"

echo
echo "== rebuild module =="
rm -f "$BUILD"/*.o "$BUILD"/*.mod.c "$BUILD"/*.mod.o "$BUILD"/*.ko
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  PATH="$CLANGBIN:$PATH" KBUILD_MODPOST_WARN=1 \
  KBUILD_EXTRA_SYMBOLS=/root/gki/real.symvers \
  M="$BUILD" -j"$(nproc)" modules 2>&1 | tail -5

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
print(f"  ghostlock.ko __this_module = 0x{tm:x}")
print(f"  device target              = 0x440")
print("  ==> MATCH — SAFE TO INSMOD" if tm == 0x440 else "  ==> STILL MISMATCH — do not load")
PYEOF

echo
echo "== pahole confirmation (btf_data + total size) =="
pahole -C module "$BUILD/ghostlock.o" 2>/dev/null | grep -E 'btf_data|/\* size:'

cp -f "$BUILD/ghostlock.ko" "$DEST" && echo "copied -> $DEST"
echo SYNCREBUILD-DONE
