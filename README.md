# GhostLock Kit v2 — iQOO Neo9S Pro 一键 Root

适用于 **vivo iQOO Neo9S Pro（V2339FA / PD2339，MediaTek MT6989）** 的临时 Root 套件。
第二代，**修复了上一代「进入 Root 管理器卡死 → 触发看门狗复位」的致命缺陷**，
并提供带 Web 图形界面的免环境一键 Root 工具。

> **Device** vivo iQOO Neo9S Pro (V2339FA / PD2339, MT6989 / Dimensity 9300+)
> **Firmware** `vivo/PD2339M/PD2339:16/BP2A.250605.031.A3/compiler260716172950:user/release-keys`
> **Kernel** `6.1.145-android14-11-maybe-dirty` · `CONFIG_CFI_CLANG=y` · BL 锁定
> **Vulnerability** CVE-2026-43499（futex PI requeue UAF → 任意内核读写 → cred patch）
> **仅供设备所有者与安全研究使用，请只在自己的设备上运行。**

---

## 这一代解决了什么

### 上一代的问题

上一代（[ghostlock-kit](https://github.com/zhubaohe123/ghostlock-kit)）的 README 里写着：

> 实测 ReSukiSU 4.2.0-rc1 管理器在本机会**打开即内核卡死**，已弃用。

现象是：Root 成功了，`adb shell su` 也能用，但**一打开 Root 管理器 App 就整机卡死**，
最终被 MTK 的 `aee_hangdet` 判定 CPU 失联，**硬件看门狗直接复位**。

### 根因：`libksud.so` 有两处驱动 fd 握手，Android 16 都会 SIGSYS 击杀

KernelSU 靠一个「reboot 魔数握手」把驱动 fd 装进调用进程（内核 hook `__NR_reboot`）。
而 Android 16 的 `/system/etc/seccomp_policy/app.policy` **对 app 封锁了 syscall 142**。

`libksud.so` 里这样的握手有 **两处**，只补一处不够：

| 站点 | 文件偏移 | 形态 | 后果 |
|---|---|---|---|
| 1 | `0x338be0` | 函数 `su` 内的**内联 `svc #0`** | 内联指令，用户态 hook 拦不到 |
| 2 | `0x34c364` | 走 **libc `syscall@plt`** | 管理器 fork 出的子进程命中这里 |

只补站点 1 时，tombstone 抓到铁证：

```
Cmdline: .../lib/arm64/libksud.so feature check adb_root
uid: 10402
signal 31 (SIGSYS), code 1 (SYS_SECCOMP)
Cause: seccomp prevented call to disallowed arm64 system call 142
    x0 00000000deadbeef  x1 00000000cafebabe  x8 000000000000008e
backtrace:
  #00 libc.so (syscall+32)        ← 走的是 libc syscall，不是内联 svc
  #01 libksud.so 0x34c364
```

**致死链**：

```
svc / syscall(142) → SIGSYS(31) → 进程被杀 → 内核侧 fd 随进程死亡
   → AMS/zygote 重启风暴 → 与 exploit 的 CPU 绑核争用叠加 → RCU stall
   → MTK aee_hangdet 判定 CPU 失联 → 硬件看门狗复位
```

**放大器**：管理器注册了 `.magica.BootCompletedReceiver`，
所以**每次开机都会自动重演一遍**这个死亡循环。

**决定性反证**：同一次利用从 adb/shell 跑时打印
`[+] no app seccomp filter (adb/shell flow); skipping W3` —— shell 没有该过滤器所以稳定；
`ksushimd`（root）执行**同一个** syscall 142 握手**成功**。
同一个系统调用，root 过、app 死，差异全在 seccomp。

### 本代的两处修复

#### 修复一：握手补丁（治「卡死」）

`libksud.so` 三处、每处 4 字节：

| 偏移 | 原字节 | 补丁后 | 作用 |
|---|---|---|---|
| `0x338be0` | `01 00 00 d4` (`svc #0`) | `1f 20 03 d5` (`nop`) | 不执行 svc，`status` 保持 -1，走失败分支 |
| `0x34c364` | `43 14 05 94` (`bl syscall`) | `1f 20 03 d5` (`nop`) | 不调用 syscall |
| `0x34c370` | `00 7d 1f 53` (`lsr w0,w8,#31`) | `20 00 80 52` (`mov w0,#1`) | 明确返回「失败」，而非「成功但 fd = -1」 |

> 字节序陷阱：`llvm-objdump` 显示的是指令字（大端书写），文件里是小端字节序。
> `531f7d00` → 文件字节是 `00 7d 1f 53`。

补完之后，管理器不再自杀，**卡死与看门狗复位彻底消失**。

#### 修复二：ksud 启动器（治「模块装不上 / 软重启没反应」）

补丁让 App 不再崩，但引出了新问题：管理器执行特权命令的真实路径是

```
app → libsu su(root shell) → <nativeLibraryDir>/libksud.so <命令>
```

这个子进程①**继承 app 的 seccomp 过滤器**（seccomp 不因 setuid 而移除），
②**拿不到 app 的驱动 fd**（libsu 跨 fork/exec 关闭 fd）。
结果 ksud 报 `kernel=0`，于是：

```
E KernelSU: ksud::init_event: UAPI version mismatch: kernel=0, ksud=2.
                             Please update KernelSU!, skip soft_reboot
```

而 ksud 源码里这个分支是**静默 `return Ok(())`** —— 点「软重启」毫无反应。

**解法**：`src/launcher/ksud-exec.c`，一个 20 KB 的启动器，做三件事：

1. 连接 `ksushimd` 的 socket，用 `SCM_RIGHTS` 取一份**真驱动 fd**
   （shim 鉴权里 `peer_uid == 0` 直接放行，而启动器跑在 root shell 里就是 uid 0）
2. **清掉该 fd 的 `O_CLOEXEC`**，让它穿过 `execve`
3. `execv()` 真 ksud —— ksud 的 `scan_driver_fd()` 在 `/proc/self/fd` 里
   直接扫到内核原生的 `anon_inode:[ksu_driver]`，**完全不需要握手**

部署方式是把 `<nativeLibraryDir>/libksud.so` **原地替换**为启动器
（`cat > 文件` 保留 inode 与 SELinux 上下文 `apk_data_file`）。
启动器带自保护：exec 前检查目标是否为自身（inode 比对 + 内容标记扫描），
避免管理器的 `KsuCli.install()` 把它复制到 `/data/adb/ksud` 后形成无限 exec 循环。

### 成果

| 项 | 上一代 | 本代 |
|---|---|---|
| 打开 Root 管理器 | ❌ 卡死 → 看门狗复位 | ✅ 正常工作 |
| 模块安装 / 更新 | ❌ 失败 | ✅ 正常 |
| 软重启 | ❌ 无反应 | ✅ 生效（`boot_completed` 1→0→1，内核不重启） |
| 超级用户授权页 | — | ✅ 正常读写驱动 allowlist |
| 一键 Root | PowerShell 脚本 | ✅ **Web GUI，免环境单文件 EXE** |

---

## 快速开始

### 方式 A：图形界面（推荐）

1. 到 [Releases](../../releases) 下载 **`GhostLock一键ROOT.zip`**（28 MB）
2. 解压，手机 USB 连电脑、打开「USB 调试」并授权本机
3. **双击 `GhostLock一键ROOT.exe`** → 浏览器自动打开界面 → 点「⚡ 一键 ROOT」

> 免环境：**不需要装 Python，也不需要装 platform-tools**（adb 已内置）。
> 管理器 APK 也已内置，全新手机可直接用。

### 方式 B：命令行

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\retry_run.ps1
```

### 验证

```bash
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

### 重要提示

- Root 是**临时的**（KernelSU late-load 模式）：手机重启后需要重新执行一次。
  已安装的模块、已授权的 App、管理器设置**不会**丢失。
- 设备**重启后停留在锁屏、不要解锁**时成功率最高（此时用户态服务最少，几乎一次成功）。
- 失败可能触发内核 panic 自动重启，属正常现象，一键工具会自动等待并重试（最多 13 次）。

---

## 架构

```
┌─────────────────────────── Windows ───────────────────────────┐
│  GhostLock一键ROOT.exe  (PyInstaller 单文件, 内嵌 25.6 MB 资源) │
│    ├── Web GUI   rootweb.py + index.html  (127.0.0.1:8770)     │
│    └── 内嵌 adb + 全部设备侧二进制                              │
└───────────────────────────────┬───────────────────────────────┘
                                │ adb
┌───────────────────────────────▼───────────────────────────────┐
│                        Android 设备                            │
│                                                                │
│  ① ghostlock (exploit, CVE-2026-43499)                         │
│       └─ 用管理器 APK 里的 libksud.so 当加载器：                │
│          libksud.so late-load --kmi <kmi> --allow-shell         │
│                                                                │
│  ② kernelsu.ko   (KernelSU 驱动, late-load 模式)               │
│  ③ ghostlock.ko  (本仓库, /proc/ghostlock → 任意 4 字节内核写) │
│       └─ post-root.sh 用它写 ksu_manager_appid                  │
│                                                                │
│  ④ ksushimd (root)  ── SCM_RIGHTS ──▶  App 进程真驱动 fd        │
│       监听三条 socket 路径，按「目录属主」鉴权                   │
│                                                                │
│  ⑤ ksud-exec  启动器                                            │
│       取真 fd → 清 CLOEXEC → exec 真 ksud                       │
│       （绕过 app seccomp 对 reboot 握手的封锁）                  │
└────────────────────────────────────────────────────────────────┘
```

**注意**：exploit 本体把「管理器 APK 里的 `libksud.so`」当作 `late-load` 加载器，
所以**必须先装管理器，再跑 exploit**。一键工具已按此顺序编排。

---

## 仓库结构

```
src/
  kmod/ghostlock.c            内核模块：/proc/ghostlock 任意 4 字节内核写
  shim/ksushimd.c             root 侧守护：经 SCM_RIGHTS 交付真驱动 fd
  shim/ksushim_client.c       客户端库（含清 O_CLOEXEC 的修复）
  shim/ksu_uapi.h             与 KernelSU 驱动共享的 ioctl 定义
  launcher/ksud-exec.c        ksud 启动器（本代核心修复）
  tools/ksu-grant.c           驱动 ioctl 命令行工具
  tools/probe_e2e.c           端到端探针（连 shim → 取 fd → 打 ioctl）
gui/
  rootweb.py                  Web GUI 服务端（Python 标准库，零依赖）
  index.html                  单文件深色前端
  build_exe.ps1               PyInstaller 打包脚本
scripts/
  post-root.sh                root 后的全部后置步骤（幂等）
  deploy-launcher.sh          把启动器部署进管理器 lib 目录（幂等）
  start_shim.sh               拉起 ksushimd
  retry_run.ps1               命令行版一键 Root
  build-manager-full.ps1      管理器 APK 改造脚本（见下方 GPL 说明）
  diag/                       本次排障留下的一批诊断脚本
build/kernel-module/          内核模块构建链（vermagic / CRC / struct module）
```

---

## 从源码构建

### 内核模块 `ghostlock.ko`

这台设备的内核开了 `CONFIG_MODVERSIONS`、`CONFIG_CFI_CLANG`、`CONFIG_DEBUG_INFO_BTF_MODULES`，
模块必须**逐字节对齐**才能 `insmod`。踩过的三个坑：

1. **vermagic** 必须精确为
   `6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64`
   （注意末尾的 `vivo`，缺了就 `Exec format error` 且 dmesg 无任何输出）
2. **`struct module` 必须是 `0x440` 字节**（70 个成员）。内核直接取模块
   `.gnu.linkonce.this_module` 段，尺寸不对 `mod_sysfs_setup` 就会读到垃圾而 panic。
   **构建验收门槛：`0x440`，不满足绝不 insmod。**
3. `make M=...` **不会**跑 `syncconfig`，`CONFIG_STACKPROTECTOR_PER_TASK` 需要
   `make prepare` 生成的 `asm-offsets.h`，否则报
   `invalid value '' in 'mstack-protector-guard-offset='`

构建链见 `build/kernel-module/`，顺序是
`78-devconfig.sh` → `81-sync-rebuild.sh` → `83-prepare-rebuild.sh`。

> 排查时的关键教训：内核打印的是 **`version magic`**（带空格），
> 用 `vermagic` 去 grep dmesg 会一无所获，白找很久。

### 管理器 APK

`scripts/build-manager-full.ps1` 以官方 KernelSU v3.3.0 为基础，做四件事：

1. 三处握手补丁（上表）
2. 注入 `libksushim.so`
3. smali 注入 `System.loadLibrary("ksushim")`
   （`KernelSUApplication.<init>` 与 `AppZygotePreload.doPreload` 两处，缺一不可）
4. `zipalign` + `apksigner`（v2 + v3）

### GUI 单文件 EXE

```powershell
powershell -ExecutionPolicy Bypass -File .\gui\build_exe.ps1
```

会自动收集资源（含内嵌 adb）→ PyInstaller `--onefile` → 输出到 `gui\dist\`。

---

## 已知限制

- **只支持上述机型与内核版本**。exploit 的偏移是设备专属的，换机型不要尝试。
- Root 为**临时**，重启后需重新执行。
- 打包成单文件 EXE 时，**杀毒软件可能误报**（自解压行为的通病）。
  本工具只监听 `127.0.0.1`，不联网上传任何数据。
- 上一代的 `mcast` transport 移植补丁（针对该机型 `+pgo,+bolt` 内核的栈帧错位）
  仍是前置条件，见 [ghostlock-kit](https://github.com/zhubaohe123/ghostlock-kit)。

---

## 致谢

- **GhostLock** exploit 与 mcast transport 移植 —— [ghostlock-kit](https://github.com/zhubaohe123/ghostlock-kit)
- **KernelSU** —— [tiann/KernelSU](https://github.com/tiann/KernelSU)（管理器 APK 的上游）
- **libsu** —— [topjohnwu/libsu](https://github.com/topjohnwu/libsu)

## 许可

本仓库自有代码以 **Apache-2.0** 发布，见 [LICENSE](LICENSE)。

`Releases` 中的**管理器 APK 是 KernelSU 的修改版**，KernelSU 以 **GPL-3.0** 授权。
按 GPL 要求，其完整修改内容以源码形式提供：
`scripts/build-manager-full.ps1`（补丁偏移与注入点）+ `src/shim/`（注入的库源码）+ `src/launcher/`。
KernelSU 上游源码见 [tiann/KernelSU](https://github.com/tiann/KernelSU)。

## 免责声明

本项目仅用于**安全研究与自有设备**。使用它可能使设备变砖、丢失数据或失去保修。
作者不对任何后果负责。**请勿在非本人设备上使用。**
