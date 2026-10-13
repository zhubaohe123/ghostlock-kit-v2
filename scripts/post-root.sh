#!/system/bin/sh
# post-root.sh — everything that must happen AFTER GhostLock hands us root,
# to bring up the self-built kernel module and register the manager.
#
# This is the payoff of the whole kmod line:
#   1. insmod ghostlock.ko  (ABI-correct: struct module == 0x440, matching the
#      device's BTF layout; built from the device's own kconfig.txt)
#   2. read ksu_manager_appid's runtime address from kallsyms
#   3. write the manager app's appId into it  -> the manager becomes the manager
#   4. restart the shim so the app can obtain a real driver fd
#
# Idempotent: safe to re-run.
LOG=/data/local/tmp/post_root.log
: > "$LOG"
exec >> "$LOG" 2>&1

echo "== post-root $(date +%H:%M:%S) uid=$(id -u) =="

KO=/data/local/tmp/ghostlock.ko
POKE=/proc/ghostlock
MGRPKG=me.weishu.kernelsu

# ---- 1. module -----------------------------------------------------------
if grep -q '^ghostlock ' /proc/modules 2>/dev/null; then
  echo "[=] ghostlock.ko already loaded"
else
  if [ ! -f "$KO" ]; then echo "[!] $KO missing"; exit 1; fi
  insmod "$KO"
  rc=$?
  echo "[*] insmod rc=$rc"
  [ $rc -ne 0 ] && { echo "[!] insmod failed"; exit 1; }
fi

if [ ! -e "$POKE" ]; then echo "[!] $POKE missing"; exit 1; fi
echo "[+] poke interface ready: $(cat $POKE)"

# ---- 2. target symbol ----------------------------------------------------
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
ADDR=$(grep -w ksu_manager_appid /proc/kallsyms 2>/dev/null | awk '{print $1}' | head -1)
if [ -z "$ADDR" ]; then echo "[!] ksu_manager_appid not in kallsyms"; exit 1; fi
echo "[*] ksu_manager_appid @ 0x$ADDR"

# ---- 3. manager uid ------------------------------------------------------
MGR_UID=$(pm list packages -U 2>/dev/null | grep "$MGRPKG" | head -1 | sed 's/.*uid://' | cut -d, -f1 | tr -dc '0-9')
[ -z "$MGR_UID" ] && MGR_UID=$(cat /data/adb/ksu_shim_uid 2>/dev/null | tr -dc '0-9')
if [ -z "$MGR_UID" ]; then echo "[!] cannot determine manager uid"; exit 1; fi
echo "[*] manager appId = $MGR_UID"

# ---- 4. patch ------------------------------------------------------------
CUR=$(/data/local/tmp/ksu-grant manager-appid 2>/dev/null | grep -oE 'manager_appid=[0-9]+' | cut -d= -f2)
if [ "$CUR" = "$MGR_UID" ]; then
  echo "[=] already registered (manager_appid=$CUR)"
else
  echo "0x$ADDR $MGR_UID" > "$POKE"
  echo "[*] write rc=$? -> $(cat $POKE)"
fi

echo "[*] verify: $(/data/local/tmp/ksu-grant manager-appid 2>/dev/null | tail -1)"
echo "[*] info  : $(/data/local/tmp/ksu-grant info 2>/dev/null | tail -1)"

# ---- 5. shim -------------------------------------------------------------
echo "$MGR_UID" > /data/adb/ksu_shim_uid 2>/dev/null
if [ -f /data/local/tmp/start_shim.sh ]; then
  sh /data/local/tmp/start_shim.sh 2>&1 | grep -E 'manager uid|listeners|ksushimd' | head -5
else
  echo "[i] start_shim.sh missing"
fi

# ---- 6. manager privileged-command launcher ------------------------------
# The app runs every privileged command as
#     <nativeLibraryDir>/libksud.so <args>
# inside a libsu root shell. That child inherits the app's seccomp filter
# (which blocks ksud's reboot handshake, syscall 142) and does NOT inherit
# the app's driver fd. Consequence: ksud reports kernel uapi = 0, so
#   * soft reboot silently skips ("UAPI version mismatch: kernel=0, ksud=2")
#   * module install / update fails
# Fix: replace that file with ksud-exec, a launcher that fetches a REAL driver
# fd from ksushimd (root is explicitly allowed there) and then execs the real
# ksud. ksud's scan_driver_fd() then finds anon_inode:[ksu_driver] in
# /proc/self/fd and never needs the handshake.
if [ -f /data/local/tmp/deploy-launcher.sh ]; then
  sh /data/local/tmp/deploy-launcher.sh >/dev/null 2>&1
  cat /data/local/tmp/deploy_launcher.log 2>/dev/null | tail -7
else
  echo "[i] deploy-launcher.sh missing"
fi

echo "== post-root done =="
exit 0
