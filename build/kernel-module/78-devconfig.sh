#!/usr/bin/env bash
# 78-devconfig.sh — use the DEVICE'S OWN complete .config (kconfig.txt) as the
# build config, so every struct layout matches byte-for-byte.
#
# This supersedes the lossy autoconf.h derivation: autoconf.h only lists what
# is ENABLED, so the old derivation silently lost options (KASAN, BTF, BTF_MODULES,
# ...) that change nested struct sizes -> struct module came out 0x400 instead
# of the device's 0x440 -> mod_sysfs_setup read garbage -> kernel panic.
set -u
KSRC=/root/gki/android14-6.1
OUT=/root/gki/out-6.1.145
BUILD=/root/gki/ghostlock-build
DEVCFG=/mnt/d/daima/root/../daima/root/build/kernel-extract/kconfig.txt
DEVCFG=/mnt/d/daima/root/build/kernel-extract/kconfig.txt
DEST=/mnt/d/daima/root2/ghostlock/kmod/ghostlock.ko
CLANGBIN=/root/gki/clang-r487747c/bin

[ -f "$DEVCFG" ] || { echo "FATAL: device kconfig not found at $DEVCFG"; exit 1; }
echo "device config: $(wc -l < "$DEVCFG") lines"

cp -f "$OUT/.config" "$OUT/.config.forcecfg" 2>/dev/null || true
cp -f "$DEVCFG" "$OUT/.config"
echo "installed device .config"

# UTS_RELEASE must still come out as 6.1.145-android14-11-maybe-dirty.
# The device's own CONFIG_LOCALVERSION is "" because Android's build system
# injects the localversion; we set it explicitly here.
if [ -x "$KSRC/scripts/config" ]; then
  "$KSRC/scripts/config" --file "$OUT/.config" --set-str LOCALVERSION "-android14-11-maybe-dirty"
  echo "LOCALVERSION forced to -android14-11-maybe-dirty"
fi

echo
echo "== olddefconfig (drops symbols the GKI tree doesn't know) =="
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 PATH="$CLANGBIN:$PATH" \
  olddefconfig 2>&1 | tail -2

echo
echo "== key configs after resolution =="
grep -E '^CONFIG_(KASAN|DEBUG_INFO_BTF|DEBUG_INFO_BTF_MODULES|ANDROID_KABI_RESERVE|CFI_CLANG|SHADOW_CALL_STACK|MODVERSIONS|LOCALVERSION)=' "$OUT/.config" | sed 's/^/  /'

echo
echo "== rebuild =="
cp -f /mnt/d/daima/root2/ghostlock/kmod/ghostlock-src/*.c "$BUILD"/ 2>/dev/null
cp -f /mnt/d/daima/root2/ghostlock/kmod/ghostlock-src/Makefile "$BUILD"/ 2>/dev/null
rm -f "$BUILD"/*.o "$BUILD"/*.mod.c "$BUILD"/*.mod.o "$BUILD"/*.ko
make -C "$KSRC" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 PATH="$CLANGBIN:$PATH" \
  KBUILD_MODPOST_WARN=1 KBUILD_EXTRA_SYMBOLS=/root/gki/real.symvers \
  M="$BUILD" -j"$(nproc)" modules 2>&1 | tail -6

echo
echo "== VERDICT =="
python3 - "$BUILD/ghostlock.ko" <<'PYEOF'
import struct, sys, subprocess
p = sys.argv[1]
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
print(f"  __this_module = 0x{tm:x}   (device target 0x440)")
print("  ==> MATCH — safe to insmod" if tm == 0x440 else "  ==> MISMATCH — do NOT load")
PYEOF
echo
modinfo "$BUILD/ghostlock.ko" 2>/dev/null | grep -E 'vermagic|import_ns' | sed 's/^/  /'
cp -f "$BUILD/ghostlock.ko" "$DEST" && echo "copied -> $DEST"
echo DEVCONFIG-DONE
