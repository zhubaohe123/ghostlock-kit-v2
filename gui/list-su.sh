#!/system/bin/sh
# list-su.sh — 列出已获 root 授权的第三方应用（被 ksu 驱动 allowlist 认可的 uid）
#
# 为什么要这么写：驱动没有可用的「列出 allowlist」ioctl
# （GET_ALLOW_LIST 返回 ENOTTY），只能对每个 uid 调 UID_GRANTED_ROOT。
# 放在设备端一次跑完，避免每个 App 一次 adb 往返。
pm list packages -U -3 2>/dev/null | while read -r line; do
  case "$line" in
    package:*) ;;
    *) continue ;;
  esac
  pkg=${line#package:}
  pkg=${pkg%% *}
  uid=$(printf '%s' "$line" | sed -n 's/.*uid:\([0-9][0-9]*\).*/\1/p')
  [ -z "$uid" ] && continue
  g=$(/data/local/tmp/ksu-grant granted-root "$uid" 2>/dev/null \
      | sed -n 's/.*granted=\([0-9]\).*/\1/p')
  [ "$g" = "1" ] && printf '%s\n' "$pkg"
done
exit 0
