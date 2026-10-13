#!/system/bin/sh
# sr-test.sh — clear logcat, wait for the tap, then dump what ksud did.
# Run this in the background; tap 软重启 from the GUI afterwards.
OUT=/data/local/tmp/sr_test.txt
: > "$OUT"
exec >> "$OUT" 2>&1

logcat -c 2>/dev/null
echo "== logcat cleared $(date +%H:%M:%S) =="

# wait up to 60s for a ksud soft-reboot attempt
for i in $(seq 1 60); do
  sleep 1
  if logcat -d 2>/dev/null | grep -qiE 'soft.reboot|soft_reboot'; then
    echo "[!] saw soft_reboot mention after ${i}s"
    break
  fi
done

echo
echo "== full logcat snapshot (filtered) =="
logcat -d 2>/dev/null | grep -iE 'ksud|KernelSU|soft|UAPI|reboot' | tail -40

echo
echo "== any live ksud/soft processes =="
ps -A -o PID,USER,NAME 2>/dev/null | grep -iE 'ksud|soft' || echo "  none"

echo
echo "== boot state =="
echo "uptime=$(cut -d' ' -f1 /proc/uptime) boot=$(getprop sys.boot_completed)"
echo SR-TEST-DONE
exit 0
