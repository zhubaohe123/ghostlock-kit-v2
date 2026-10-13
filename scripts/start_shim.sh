#!/system/bin/sh
# Start ksushimd: root daemon holding the KernelSU driver fd.
#
# It listens on several candidate paths because /data/adb is 0700(root):
# an untrusted_app cannot traverse it, so the original single path was
# unreachable by the very client it was meant to serve. It can also hand
# out a *real* driver fd over SCM_RIGHTS, so the app needs no symbol hooks.
#
# Safe to re-run; used by the root script and manually after rooting.

HOME_DIR=/data/local/tmp
SHIM="$HOME_DIR/ksushimd"
LOG="$HOME_DIR/ksushimd.log"
UID_FILE=/data/adb/ksu_shim_uid

APP_SOCK=/data/data/me.weishu.kernelsu/ksu_shim.sock
TMP_SOCK=/data/local/tmp/ksu_shim.sock
ADB_SOCK=/data/adb/ksu_shim.sock

if [ ! -f "$SHIM" ]; then
  echo "[!] ksushimd not found at $SHIM"
  exit 1
fi
# adb push does not set the executable bit; fix it here.
chmod 755 "$SHIM" 2>/dev/null
if [ ! -x "$SHIM" ]; then
  echo "[!] $SHIM is not executable"
  exit 1
fi

# SO_PEERCRED reports the appId form (e.g. 10398), which is what pm prints
# FIRST in "uid:10398,1010398" - so take the first field. (The second field
# is the multi-user-mapped id and never matches SO_PEERCRED.)
MGR_UID=$(cat "$UID_FILE" 2>/dev/null | tr -dc '0-9')
if [ -z "$MGR_UID" ]; then
  MGR_UID=$(pm list packages -U 2>/dev/null | grep -E 'me\.weishu\.kernelsu|resukisu|supermanager' | grep -oE 'uid:[0-9]+' | head -1 | cut -d: -f2)
  [ -n "$MGR_UID" ] && echo "$MGR_UID" > "$UID_FILE" 2>/dev/null
fi

ENF_BEFORE=$(getenforce)
setenforce 0 2>/dev/null

# Must use pkill -x (exact process name). `pkill -f ksushimd` also matches the
# invoking `su -c '...ksushimd...'` command line and kills su itself, leaving
# the script half-executed and stray daemons behind.
pkill -x ksushimd 2>/dev/null
sleep 0.3
rm -f "$ADB_SOCK" /data/adb/ksu_shim.ready "$TMP_SOCK" "$APP_SOCK" 2>/dev/null

if [ -n "$MGR_UID" ]; then
  setsid "$SHIM" --allow-uid "$MGR_UID" </dev/null >"$LOG" 2>&1 &
else
  setsid "$SHIM" </dev/null >"$LOG" 2>&1 &
fi

i=0
while [ "$i" -lt 50 ]; do
  [ -S "$APP_SOCK" ] && [ -S "$TMP_SOCK" ] && break
  sleep 0.1
  i=$((i + 1))
done

[ "$ENF_BEFORE" = "Enforcing" ] && setenforce 1 2>/dev/null
chmod 644 "$LOG" 2>/dev/null

echo "manager uid: ${MGR_UID:-none}"
echo "--- ps ---"
ps -A -o PID,USER,NAME 2>/dev/null | grep -i ksushim
echo "--- sockets ---"
ls -l "$APP_SOCK" "$TMP_SOCK" "$ADB_SOCK" /data/adb/ksu_shim.ready 2>&1
echo "--- ksushimd log ---"
cat "$LOG" 2>&1
echo "--- selinux ---"
getenforce
exit 0
