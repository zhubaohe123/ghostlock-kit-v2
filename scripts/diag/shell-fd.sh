#!/system/bin/sh
# shell-fd.sh — do the libsu root-shell processes inherit the driver fd?
OUT=/data/local/tmp/shell_fd.txt
: > "$OUT"
exec >> "$OUT" 2>&1

echo "== all libksud.so processes =="
for P in $(ps -A -o PID,USER,NAME 2>/dev/null | grep -E 'libksud|ksud|kernelsu' | awk '{print $1}'); do
  U=$(awk '/^Uid:/{print $2}' /proc/$P/status 2>/dev/null)
  C=$(cat /proc/$P/cmdline 2>/dev/null | tr '\0' ' ')
  echo "--- pid $P uid=$U"
  echo "    cmd: $C"
  echo "    driver fds:"
  FOUND=0
  for F in /proc/$P/fd/*; do
    L=$(readlink "$F" 2>/dev/null)
    case "$L" in
      *ksu_driver*)
        N=$(basename "$F")
        FL=$(grep -E '^flags:' /proc/$P/fdinfo/$N 2>/dev/null | awk '{print $2}')
        echo "      fd $N -> $L  flags=$FL"
        FOUND=1
        ;;
    esac
  done
  [ $FOUND -eq 0 ] && echo "      (none)"
  echo "    fd count: $(ls /proc/$P/fd 2>/dev/null | wc -l)"
done

echo
echo "== parent-child tree of the app =="
ps -A -o PID,PPID,USER,NAME 2>/dev/null | grep -E 'kernelsu|libksud|ksud' 

echo
echo "== seccomp status of the shell processes =="
for P in $(ps -A -o PID,NAME 2>/dev/null | grep -E 'libksud' | awk '{print $1}'); do
  echo "  pid $P: $(grep -E '^(Seccomp|Seccomp_filters):' /proc/$P/status 2>/dev/null | tr '\n' ' ')"
done
echo SHELL-FD-DONE
exit 0
