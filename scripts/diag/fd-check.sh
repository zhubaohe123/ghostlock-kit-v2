#!/system/bin/sh
# fd-check.sh — verify the CLOEXEC fix landed in the running app.
OUT=/data/local/tmp/fd_check.txt
: > "$OUT"
exec >> "$OUT" 2>&1

echo "== manager processes =="
ps -A -o PID,USER,NAME 2>/dev/null | grep -i kernelsu

echo
echo "== driver fds and their flags =="
for P in $(ps -A -o PID,NAME 2>/dev/null | grep kernelsu | awk '{print $1}'); do
  for F in /proc/$P/fd/*; do
    L=$(readlink "$F" 2>/dev/null)
    case "$L" in
      *ksu_driver*)
        N=$(basename "$F")
        FL=$(grep -E '^flags:' /proc/$P/fdinfo/$N 2>/dev/null | awk '{print $2}')
        # O_CLOEXEC = 02000000 octal
        case "$FL" in
          02*|0[0-9][0-9]*) : ;;
        esac
        HEX=$(printf '%o' "0$FL" 2>/dev/null)
        echo "  pid $P  fd $N -> $L"
        echo "      flags(octal) = $FL"
        # does it contain the CLOEXEC bit (02000000 octal)?
        if [ "$(( 0$FL & 02000000 ))" -ne 0 ]; then
          echo "      CLOEXEC: SET     <-- children will NOT inherit"
        else
          echo "      CLOEXEC: CLEARED <-- children WILL inherit (fix active)"
        fi
        ;;
    esac
  done
done

echo
echo "== /data/adb/ksud current state =="
md5sum /data/adb/ksud 2>/dev/null
dd if=/data/adb/ksud bs=1 skip=$((0x338be0)) count=4 2>/dev/null | od -An -tx1 | sed 's/^/  site1: /'

echo
echo "== simulate the app's chain: does a root shell see the driver fd? =="
echo " (spawning 'su -c sleep' FROM the app is not directly possible;"
echo "  instead check whether any ksud child of the app holds one)"
for P in $(ps -A -o PID,NAME 2>/dev/null | grep -E 'ksud|^ *[0-9]+ sh$' | awk '{print $1}'); do
  echo "  pid $P: $(cat /proc/$P/cmdline 2>/dev/null | tr '\0' ' ')"
done
echo FD-CHECK-DONE
exit 0
