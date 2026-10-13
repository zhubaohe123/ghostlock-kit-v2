#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rootweb.py — 一键 ROOT 工具（Web GUI）

为 vivo iQOO Neo9S Pro (PD2339) / GhostLock 方案设计的本地 Web 控制台。
只依赖 Python 标准库，无需 pip 安装任何东西。

启动：
    python rootweb.py            # 默认 http://127.0.0.1:8770
    python rootweb.py --port 9000 --open

原理（与 retry_run.ps1 / post-root.sh 完全一致）：
    1. 等待设备上线并稳定（uptime > SETTLE_SECONDS）
    2. 后台启动 GhostLock exploit（mcast 路由）
    3. 监视 /proc/modules 出现 kernelsu —— 出现即取得临时 root
    4. 执行 post-root.sh：
         insmod ghostlock.ko           → 内核任意 4 字节写
         写 ksu_manager_appid          → 让管理器成为驱动认可的 manager
         重启 ksushimd                 → 给 App 交付真驱动 fd
         部署 ksud-exec 启动器          → 修复模块安装 / 软重启
    5. 校验并报告
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# 路径与常量
# --------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
GL = os.path.dirname(HERE)                                    # ...\ghostlock
KIT = os.path.normpath(os.path.join(HERE, "..", "..", "..", "root", "ghostlock-kit"))

DEFAULT_SERIAL = "10AE8G1QXL0016B"
SETTLE_SECONDS = 240          # exploit 在开机后需要一点时间才稳定
MAX_ATTEMPTS = 13             # 与 retry_run.ps1 的 run 100..112 对应
WATCH_SECONDS = 200           # 单次 exploit 的最长观察时间
HTTP_PORT = 8770


# --------------------------------------------------------------------------
# 资源定位：打包成单文件 EXE 后资源在 sys._MEIPASS\assets 下；
# 从源码运行时则在 webui\assets\，再回退到各产物的原始位置。
# --------------------------------------------------------------------------
def resource_dir():
    if getattr(sys, "frozen", False):
        return os.path.join(getattr(sys, "_MEIPASS", HERE), "assets")
    return os.path.join(HERE, "assets")


def find_asset(names):
    """按 内嵌 assets → 产物原目录 → ghostlock-kit → 绝对路径 的顺序查找。"""
    if isinstance(names, str):
        names = [names]
    base = resource_dir()
    for n in names:
        p = os.path.join(base, n)
        if os.path.isfile(p):
            return p
    for n in names:
        for root in (GL, os.path.join(GL, "shim-build"), os.path.join(GL, "kmod"),
                     os.path.join(KIT, "files")):
            p = os.path.join(root, n)
            if os.path.isfile(p):
                return p
        if os.path.isabs(n) and os.path.isfile(n):
            return n
    return None


_ADB = None


def adb_exe():
    """优先用内嵌的 adb（免安装 platform-tools），否则回退到 PATH。"""
    global _ADB
    if _ADB:
        return _ADB
    p = find_asset([os.path.join("adb", "adb.exe"), "adb.exe"])
    _ADB = p if p else "adb"
    return _ADB


# (候选文件名, 设备路径) —— 逐个按 find_asset 解析
PUSH_LIST = [
    (["ghostlock.ko"],                      "/data/local/tmp/ghostlock.ko"),
    (["ksushimd"],                          "/data/local/tmp/ksushimd"),
    (["ksu-grant"],                         "/data/local/tmp/ksu-grant"),
    (["ksud-exec"],                         "/data/local/tmp/ksud-exec"),
    (["deploy-launcher.sh"],                "/data/local/tmp/deploy-launcher.sh"),
    (["list-su.sh"],                        "/data/local/tmp/list-su.sh"),
    (["start_shim.sh", "start-shim.sh"],    "/data/local/tmp/start_shim.sh"),
    (["post-root.sh"],                      "/data/local/tmp/post-root.sh"),
    (["ksud"],                              "/data/local/tmp/ksud"),
    (["ghostlock"],                         "/data/local/tmp/ghostlock"),
    (["offsets.json"],                      "/data/local/tmp/offsets.json"),
]

# --------------------------------------------------------------------------
# KernelSU 管理器
#
# 为什么必须由本工具自带并在跑 exploit 之前装好：
# exploit 本体（ghostlock）内嵌的 root 脚本是这样加载内核模块的 ——
#     KSUD=$(find /data/app -path '*/me.weishu.kernelsu-*/lib/arm64/libksud.so' \
#            -o -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' | head -1)
#     "$KSUD" late-load --kmi "$KMI" --allow-shell --package-name none
# 也就是说它把「管理器 APK 里的 libksud.so」当作加载器。全新设备上如果没装
# 管理器，$KSUD 为空 → late-load 根本不执行 → kernelsu.ko 永远加载不上。
# 所以顺序必须是：先 pm install 管理器，再跑 exploit。
# （--allow-shell 保证 adb shell 拿到 root，后续 su 才可用。）
# --------------------------------------------------------------------------
MANAGER_PKG = "me.weishu.kernelsu"
MANAGER_APK_ASSET = "KernelSU-manager.apk"


def manager_installed():
    rc, t = sh(f"pm list packages {MANAGER_PKG}", timeout=25)
    return MANAGER_PKG in t


def manager_uid():
    t = out(f"pm list packages -U {MANAGER_PKG}", timeout=25)
    m = re.search(r"uid:(\d+)", t)
    return int(m.group(1)) if m else None


def ensure_manager():
    """没装就装。返回 (ok, 说明)。"""
    if manager_installed():
        u = manager_uid()
        log(f"[=] 管理器已安装（{MANAGER_PKG}" + (f"，uid {u}" if u else "") + "）")
        return True, "already"

    apk = find_asset([MANAGER_APK_ASSET, "KernelSU-ghostlock-full.apk"])
    if not apk:
        log("[!] 内嵌资源里找不到管理器 APK —— 无法在全新设备上工作")
        return False, "missing-asset"

    log(f"[*] 安装 KernelSU 管理器（{os.path.getsize(apk):,} B）…")
    rc, t = adb("push", apk, "/data/local/tmp/manager.apk", timeout=600)
    if rc != 0:
        log("    [!] 推送 APK 失败")
        return False, "push-failed"

    for label, cmd in (("", "pm install -r -g /data/local/tmp/manager.apk"),
                       ("root 身份", "su -c 'pm install -r -g /data/local/tmp/manager.apk'")):
        rc, t = sh(cmd, timeout=600)
        txt = (t or "").strip()
        if "Success" in txt:
            log(f"    [+] 安装成功{('（' + label + '）') if label else ''}")
            # 让 PackageManager 把 native 库解出来，否则 nativeLibraryDir 还不存在
            sh(f"pm list packages {MANAGER_PKG}", timeout=25)
            time.sleep(3)
            u = manager_uid()
            log(f"    [*] 管理器 uid = {u}")
            return True, "installed"
        log(f"    [!] {label or 'shell'} 安装输出: {txt[:160]}")
    return False, "install-failed"

STATE_LOCK = threading.Lock()
STATE = {
    "running": False,
    "phase": "idle",          # idle | running | done | error | cancelled
    "attempt": 0,
    "message": "",
    "started_at": None,
    "finished_at": None,
    "cancel": False,
}
LOG = []                      # list[str]
LOG_LOCK = threading.Lock()

SERIAL = DEFAULT_SERIAL


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def log(msg):
    line = time.strftime("%H:%M:%S ") + str(msg)
    with LOG_LOCK:
        LOG.append(line)
        if len(LOG) > 4000:
            del LOG[:1000]
    print(line, flush=True)


def adb(*args, timeout=30, serial=True):
    """执行 adb，返回 (returncode, text)。失败时 returncode 为 124/127/1。"""
    cmd = [adb_exe()]
    if serial and SERIAL:
        cmd += ["-s", SERIAL]
    cmd += [str(a) for a in args]
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "(timeout)"
    except FileNotFoundError:
        return 127, f"adb not found ({adb_exe()})"
    except Exception as e:                                  # noqa: BLE001
        return 1, str(e)


def sh(cmd, timeout=30):
    """在设备上跑一条 shell 命令。"""
    return adb("shell", cmd, timeout=timeout)


def out(cmd, timeout=30):
    """跑 shell 命令并返回去空白输出。"""
    return sh(cmd, timeout=timeout)[1].strip()


def device_online():
    rc, t = adb("devices", serial=False, timeout=15)
    if rc != 0:
        return False
    for line in t.splitlines():
        if line.startswith(SERIAL) and "\tdevice" in line:
            return True
    return False


def autodetect_serial():
    """没显式指定时：若只有一台设备在线，就用它。"""
    global SERIAL
    rc, t = adb("devices", serial=False, timeout=15)
    if rc != 0:
        return
    devs = [l.split("\t")[0] for l in t.splitlines() if "\tdevice" in l]
    if len(devs) == 1:
        SERIAL = devs[0]


def uptime():
    t = out("cut -d' ' -f1 /proc/uptime", timeout=15)
    m = re.match(r"([\d.]+)", t)
    return float(m.group(1)) if m else -1.0


def boot_completed():
    return out("getprop sys.boot_completed", timeout=15).strip() == "1"


def wait_device(timeout, label="等待设备"):
    t0 = time.time()
    announced = False
    while time.time() - t0 < timeout:
        if STATE["cancel"]:
            raise FlowCancelled()
        if device_online() and boot_completed():
            if announced:
                log("[+] 设备已上线")
            return True
        if not announced:
            log(f"[*] {label}…（请连接 USB）")
            announced = True
        time.sleep(2)
    return False


def wait_settle():
    """等 uptime 超过稳定阈值。已经超过则立刻返回。"""
    u = uptime()
    if u < 0:
        return
    if u >= SETTLE_SECONDS:
        log(f"[*] 设备已稳定（uptime={u:.0f}s），直接开始")
        return
    need = SETTLE_SECONDS - u
    log(f"[*] 等待系统稳定：还差约 {need:.0f} 秒（当前 uptime={u:.0f}s）")
    t0 = time.time()
    while time.time() - t0 < need + 30:
        if STATE["cancel"]:
            raise FlowCancelled()
        if not device_online():
            time.sleep(3)
            continue
        u = uptime()
        if u >= SETTLE_SECONDS:
            log(f"[*] 已稳定（uptime={u:.0f}s）")
            return
        time.sleep(5)


# --------------------------------------------------------------------------
# 状态查询
# --------------------------------------------------------------------------
def get_status():
    st = {
        "serial": SERIAL,
        "online": False,
        "boot_completed": False,
        "uptime": None,
        "model": "",
        "kernel": "",
        "su": "",
        "rooted": False,
        "modules": {},
        "manager_appid": None,
        "manager_uid": None,
        "manager_installed": False,
        "manager_apk_bundled": bool(find_asset([MANAGER_APK_ASSET,
                                                "KernelSU-ghostlock-full.apk"])),
        "superuser": [],
        "shim": False,
        "launcher": False,
        "flow": dict(STATE),
    }
    if not device_online():
        return st
    st["online"] = True
    st["boot_completed"] = boot_completed()
    u = uptime()
    st["uptime"] = round(u, 1) if u >= 0 else None
    st["model"] = out("getprop ro.product.model", timeout=10)
    st["kernel"] = out("uname -r", timeout=10)
    st["manager_installed"] = manager_installed()
    st["manager_apk_bundled"] = bool(find_asset([MANAGER_APK_ASSET,
                                                 "KernelSU-ghostlock-full.apk"]))

    mods = out("grep -E 'ghostlock|kernelsu' /proc/modules", timeout=10)
    st["modules"] = {
        "kernelsu": "kernelsu" in mods,
        "ghostlock": "ghostlock" in mods,
    }

    su = out("su -c id", timeout=15)
    st["su"] = su
    st["rooted"] = "uid=0" in su

    if st["rooted"]:
        m = out("su -c '/data/local/tmp/ksu-grant manager-appid' 2>&1", timeout=15)
        mm = re.search(r"manager_appid=(\d+)", m)
        if mm:
            v = int(mm.group(1))
            st["manager_appid"] = v if v != 0xFFFFFFFF else -1
        mgr = out("pm list packages -U | grep me.weishu.kernelsu", timeout=15)
        mu = re.search(r"uid:(\d+)", mgr)
        if mu:
            st["manager_uid"] = int(mu.group(1))
        st["superuser"] = superuser_cached()

    shim = out("pidof ksushimd 2>/dev/null", timeout=10)
    st["shim"] = bool(shim.strip())
    # 启动器是否已部署：ksud-exec ≈ 2.1 MB，原版 libksud.so ≈ 4.9 MB。
    # 注意必须用 root —— /data/app 对 shell 不可读，glob 会失败。
    lib = out("su -c 'stat -c %s /data/app/*/me.weishu.kernelsu*/lib/arm64/libksud.so 2>/dev/null | head -1'",
              timeout=15).strip()
    st["launcher_raw"] = lib
    st["launcher"] = lib.isdigit() and int(lib) < 3_000_000
    return st


_SU_CACHE = {"at": 0.0, "list": [], "refreshing": False}
_SU_LOCK = threading.Lock()


def _refresh_superuser():
    try:
        rc, t = sh("su -c 'sh /data/local/tmp/list-su.sh'", timeout=90)
        lst = [l.strip() for l in t.splitlines()
               if l.strip() and not l.startswith("[") and " " not in l.strip()]
        with _SU_LOCK:
            _SU_CACHE["list"] = lst
            _SU_CACHE["at"] = time.time()
    except Exception:                                        # noqa: BLE001
        with _SU_LOCK:
            _SU_CACHE["at"] = time.time()
    finally:
        with _SU_LOCK:
            _SU_CACHE["refreshing"] = False


def superuser_cached(ttl=30):
    """枚举已授权 App。驱动没有「列出 allowlist」的 ioctl（GET_ALLOW_LIST 返回
    ENOTTY），只能逐 uid 调 UID_GRANTED_ROOT，较慢；因此缓存结果并在后台刷新，
    状态接口始终立即返回。"""
    with _SU_LOCK:
        stale = time.time() - _SU_CACHE["at"] > ttl
        if stale and not _SU_CACHE["refreshing"]:
            _SU_CACHE["refreshing"] = True
            threading.Thread(target=_refresh_superuser, daemon=True).start()
        return list(_SU_CACHE["list"])


# --------------------------------------------------------------------------
# 一键 ROOT 流程
# --------------------------------------------------------------------------
class FlowCancelled(Exception):
    pass


class FlowError(Exception):
    pass


def set_phase(phase, msg=""):
    with STATE_LOCK:
        STATE["phase"] = phase
        if msg:
            STATE["message"] = msg


def push_assets():
    log("[*] 推送必要文件…")
    missing = []
    for candidates, remote in PUSH_LIST:
        local = find_asset(candidates)
        if not local:
            log(f"    [!] 找不到 {candidates[0]}，跳过")
            missing.append(candidates[0])
            continue
        rc, t = adb("push", local, remote, timeout=180)
        size = os.path.getsize(local)
        if rc == 0:
            log(f"    [+] {os.path.basename(local)} → {remote}  ({size:,} B)")
        else:
            log(f"    [!] 推送失败 {os.path.basename(local)}: {t.strip()[:120]}")
            missing.append(candidates[0])
    sh("chmod 755 /data/local/tmp/ghostlock /data/local/tmp/ksushimd "
       "/data/local/tmp/ksu-grant /data/local/tmp/ksud /data/local/tmp/ksud-exec "
       "/data/local/tmp/post-root.sh /data/local/tmp/start_shim.sh "
       "/data/local/tmp/deploy-launcher.sh /data/local/tmp/list-su.sh 2>/dev/null", timeout=20)
    if missing:
        log(f"    [!] 缺少 {len(missing)} 个文件：{', '.join(missing)}")
        log("        （打包版应自带全部资源；从源码运行请确认 webui\\assets\\ 完整）")
    return not missing


def launch_exploit(attempt):
    cmd = (
        "cd /data/local/tmp && nohup sh -c "
        "'GHOSTLOCK_ROUTE=mcast GHOSTLOCK_CORE=4 GHOSTLOCK_CONSUMER_CORE=5 ./ghostlock' "
        f"> run_mcast{attempt}.log 2>&1 & echo started"
    )
    rc, t = sh(cmd, timeout=25)
    return "started" in t


def watch_exploit():
    """观察 WATCH_SECONDS 秒。返回 True 表示 kernelsu 已加载。"""
    t0 = time.time()
    offline_since = None
    while time.time() - t0 < WATCH_SECONDS:
        if STATE["cancel"]:
            raise FlowCancelled()
        time.sleep(5)
        if not device_online():
            if offline_since is None:
                offline_since = time.time()
                log("    [~] 设备掉线（exploit 触发重启，正常现象）")
            elif time.time() - offline_since > 90:
                log("    [~] 设备持续离线，等待重新上线")
                return False
            continue
        offline_since = None
        n = out("grep -c kernelsu /proc/modules 2>/dev/null", timeout=15)
        if n.isdigit() and int(n) > 0:
            return True
    return False


def run_post_root():
    log("[*] 执行后置步骤 post-root.sh …")
    rc, t = sh("su -c 'sh /data/local/tmp/post-root.sh'", timeout=180)
    time.sleep(2)
    body = out("cat /data/local/tmp/post_root.log", timeout=20)
    for line in body.splitlines():
        log("    " + line)
    return "post-root done" in body


def flow_root():
    with STATE_LOCK:
        STATE.update(running=True, phase="running", attempt=0,
                     message="", started_at=time.time(),
                     finished_at=None, cancel=False)
    try:
        log("=" * 58)
        log("一键 ROOT 启动")
        if not wait_device(180):
            raise FlowError("设备未连接（请插入 USB 并确认已授权调试）")

        push_assets()

        # 管理器必须先装好：exploit 靠它 APK 里的 libksud.so 当加载器来
        # late-load kernelsu.ko（见上方 MANAGER_PKG 处的说明）。
        mok, mwhy = ensure_manager()
        if not mok:
            raise FlowError(f"KernelSU 管理器不可用（{mwhy}），"
                            "exploit 将无法加载内核模块")

        if "uid=0" in out("su -c id", timeout=15):
            log("[=] 设备已有 root，跳过 exploit，直接做后置步骤")
        else:
            ok = False
            for attempt in range(100, 100 + MAX_ATTEMPTS):
                if STATE["cancel"]:
                    raise FlowCancelled()
                with STATE_LOCK:
                    STATE["attempt"] = attempt - 99
                log(f"[*] 第 {attempt - 99}/{MAX_ATTEMPTS} 次尝试…")
                if not wait_device(300, "等待设备重新上线"):
                    raise FlowError("设备长时间未上线")
                wait_settle()
                launch_exploit(attempt)
                if watch_exploit():
                    log("[+] *** KernelSU 已加载，取得临时 root ***")
                    ok = True
                    break
                log("    [~] 本次未成功，重试")
            if not ok:
                raise FlowError(f"{MAX_ATTEMPTS} 次尝试均未取得 root")
            time.sleep(8)

        run_post_root()

        st = get_status()
        log("")
        log("=" * 58)
        log("最终状态：")
        log(f"    root            : {'✅ 可用' if st['rooted'] else '❌ 不可用'}")
        log(f"    kernelsu 模块   : {'✅ 已加载' if st['modules'].get('kernelsu') else '❌ 未加载'}")
        log(f"    ghostlock 模块  : {'✅ 已加载' if st['modules'].get('ghostlock') else '❌ 未加载'}")
        log(f"    manager appid   : {st['manager_appid']}")
        log(f"    shim 守护进程   : {'✅ 运行中' if st['shim'] else '❌ 未运行'}")
        log(f"    已授权 App      : {len(st['superuser'])} 个")
        for a in st["superuser"]:
            log(f"        · {a}")
        good = st["rooted"] and st["modules"].get("kernelsu")
        set_phase("done" if good else "error",
                  "ROOT 成功" if good else "流程结束但状态异常")
        log("=" * 58)
    except FlowCancelled:
        log("[!] 已取消")
        set_phase("idle", "已取消")
    except FlowError as e:
        log(f"[!] 失败：{e}")
        set_phase("error", str(e))
    except Exception as e:                                   # noqa: BLE001
        log(f"[!] 异常：{e!r}")
        set_phase("error", repr(e))
    finally:
        with STATE_LOCK:
            STATE["running"] = False
            STATE["finished_at"] = time.time()


def start_flow():
    with STATE_LOCK:
        if STATE["running"]:
            return False
        STATE["cancel"] = False
    threading.Thread(target=flow_root, daemon=True).start()
    return True


# --------------------------------------------------------------------------
# 其他动作
# --------------------------------------------------------------------------
def do_softreboot():
    log("[*] 触发软重启…")
    rc, t = sh("su -c 'nohup /data/local/tmp/ksud-exec soft-reboot >/dev/null 2>&1 &'", timeout=30)
    log("    已下发，Android 框架将在数秒后重启")
    return True


def do_open_manager():
    sh("am start -n me.weishu.kernelsu/.ui.MainActivity", timeout=20)
    time.sleep(1)
    sh("monkey -p me.weishu.kernelsu -c android.intent.category.LAUNCHER 1", timeout=20)
    log("[*] 已尝试打开 KernelSU 管理器")
    return True


def do_install_manager():
    """安装/重装管理器 APK。装在 /data/app，重装会还原 libksud.so，
    所以随后要重新部署启动器。"""
    ok, why = ensure_manager()
    if ok and why == "installed":
        log("[*] 管理器已安装，重新部署 ksud 启动器（重装会还原 libksud.so）…")
        sh("su -c 'sh /data/local/tmp/deploy-launcher.sh'", timeout=120)
        body = out("cat /data/local/tmp/deploy_launcher.log", timeout=20)
        for line in body.splitlines()[-7:]:
            log("    " + line)
    return ok


def do_verify():
    st = get_status()
    log("[*] 状态复核：")
    log(f"    root={st['rooted']} kernelsu={st['modules'].get('kernelsu')} "
        f"ghostlock={st['modules'].get('ghostlock')} manager_appid={st['manager_appid']} "
        f"shim={st['shim']} 已授权={len(st['superuser'])}")
    return st


def do_su_command(cmd):
    log(f"[*] su -c {cmd}")
    rc, t = sh(f"su -c {json.dumps(cmd)}", timeout=60)
    for line in t.splitlines():
        log("    " + line)
    return t


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "GhostLockRootWeb/1.0"

    def log_message(self, fmt, *args):                       # 静音访问日志
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def do_GET(self):                                        # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            p = find_asset(["index.html"]) or os.path.join(HERE, "index.html")
            if p and os.path.isfile(p):
                with open(p, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            return self._send(404, "index.html missing", "text/plain; charset=utf-8")

        if path == "/api/status":
            return self._send(200, get_status())

        if path == "/api/log":
            since = 0
            q = self.path.split("?", 1)
            if len(q) > 1:
                m = re.search(r"since=(\d+)", q[1])
                if m:
                    since = int(m.group(1))
            with LOG_LOCK:
                lines = LOG[since:]
                total = len(LOG)
            return self._send(200, {"since": total, "lines": lines})

        if path == "/api/ping":
            return self._send(200, {"ok": True})

        return self._send(404, {"error": "not found"})

    def do_POST(self):                                       # noqa: N802
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:                                    # noqa: BLE001
            body = {}

        if path == "/api/root":
            started = start_flow()
            return self._send(200, {"started": started,
                                    "msg": "" if started else "已有任务在运行"})

        if path == "/api/cancel":
            with STATE_LOCK:
                STATE["cancel"] = True
            log("[*] 收到取消请求…")
            return self._send(200, {"ok": True})

        if path == "/api/softreboot":
            return self._send(200, {"ok": do_softreboot()})

        if path == "/api/openmanager":
            return self._send(200, {"ok": do_open_manager()})

        if path == "/api/verify":
            return self._send(200, do_verify())

        if path == "/api/installmanager":
            return self._send(200, {"ok": do_install_manager()})

        if path == "/api/su":
            cmd = (body.get("cmd") or "").strip()
            if not cmd:
                return self._send(400, {"error": "cmd required"})
            return self._send(200, {"out": do_su_command(cmd)})

        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="GhostLock 一键 ROOT Web GUI")
    ap.add_argument("--port", type=int, default=HTTP_PORT)
    ap.add_argument("--serial", default=None, help="adb 序列号（默认自动探测）")
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    args = ap.parse_args()

    global SERIAL
    if args.serial:
        SERIAL = args.serial
    else:
        autodetect_serial()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"

    frozen = getattr(sys, "frozen", False)
    res = resource_dir()
    ok, miss = 0, []
    for cands, _ in PUSH_LIST:
        if find_asset(cands):
            ok += 1
        else:
            miss.append(cands[0])

    lines = [
        "=" * 62,
        "  GhostLock 一键 ROOT 控制台",
        f"  运行方式   : {'独立 EXE（免环境）' if frozen else 'Python 源码'}",
        f"  资源目录   : {res}",
        f"  资源检查   : {ok}/{len(PUSH_LIST)} 就绪" +
        (f"   缺少: {', '.join(miss)}" if miss else ""),
        f"  管理器 APK : {'已内置' if find_asset([MANAGER_APK_ASSET]) else '缺失!'}",
        f"  adb        : {adb_exe()}",
        f"  设备序列号 : {SERIAL}",
        f"  打开       : {url}",
        "=" * 62,
    ]
    if miss:
        lines.append("  [!] 资源不完整，一键 ROOT 可能失败。")
    print("\n".join(lines), flush=True)
    if args.open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止", flush=True)


if __name__ == "__main__":
    main()
