#!/system/bin/sh
# deploy-launcher.sh (v2) — install the ksud launcher into the manager's
# nativeLibraryDir and make sure /data/adb/ksud is a usable ksud.
#
# Idempotent; called from post-root.sh.
LOG=/data/local/tmp/deploy_launcher.log
: > "$LOG"
exec >> "$LOG" 2>&1

LAUNCHER=/data/local/tmp/ksud-exec
ORIG=/data/local/tmp/ksud          # pristine official ksud (never overwritten)

echo "== deploy-launcher $(date +%H:%M:%S) =="
[ -f "$LAUNCHER" ] || { echo "[!] $LAUNCHER missing"; exit 1; }
chmod 755 "$LAUNCHER" 2>/dev/null

# ---- 1. nativeLibraryDir ------------------------------------------------
LIBDIR=""
for D in /data/app/*/me.weishu.kernelsu*/lib/arm64; do
  [ -d "$D" ] && LIBDIR="$D"
done
echo "[*] LIBDIR=${LIBDIR:-none}"

if [ -n "$LIBDIR" ]; then
  if cmp -s "$LAUNCHER" "$LIBDIR/libksud.so"; then
    echo "[=] launcher already deployed"
  else
    [ -f "$LIBDIR/libksud.so" ] && [ ! -f /data/local/tmp/libksud.so.orig ] && \
      cp -a "$LIBDIR/libksud.so" /data/local/tmp/libksud.so.orig
    cat "$LAUNCHER" > "$LIBDIR/libksud.so"     # in-place: keeps inode + context
    chmod 755 "$LIBDIR/libksud.so"
    echo "[+] deployed launcher -> $LIBDIR/libksud.so ($(stat -c %s "$LIBDIR/libksud.so") bytes)"
  fi
  echo "[*] context: $(ls -Z "$LIBDIR/libksud.so" 2>/dev/null | awk '{print $1}')"
else
  echo "[!] manager nativeLibraryDir not found (app not installed?)"
fi

# ---- 2. /data/adb/ksud --------------------------------------------------
# NOTE: with the launcher deployed, the app's own KsuCli.install() now runs
#       through the launcher -> the real ksud -> /proc/self/exe IS the real
#       ksud, so it self-heals. We only fix a stale/patched copy here.
if [ -f "$ORIG" ]; then
  if cmp -s "$ORIG" /data/adb/ksud; then
    echo "[=] /data/adb/ksud already the original"
  else
    cp -f "$ORIG" /data/adb/ksud
    chmod 755 /data/adb/ksud
    echo "[+] restored original /data/adb/ksud"
  fi
else
  echo "[i] no pristine ksud at $ORIG (skipped)"
fi

echo "[*] verify: $(/data/adb/ksud debug info 2>&1 | head -3 | tr '\n' ' ')"
echo "== deploy-launcher done =="
exit 0
