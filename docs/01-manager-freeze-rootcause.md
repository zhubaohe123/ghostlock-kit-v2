# GhostLock / KernelSU 管理器卡死 —— 根因定位、修复与剩余阻塞

> 日期：2026-10-12（当日两轮迭代）
> 设备：vivo iQOO Neo9S Pro（V2339FA / PD2339，MT6989 / Dimensity 9300+）
> 系统：`vivo/PD2339M/PD2339:16/BP2A.250605.031.A3/compiler260716172950:user/release-keys`
> 内核：`6.1.145-android14-11-maybe-dirty`，`CONFIG_CFI_CLANG=y`，`CONFIG_SECURITY_SELINUX_DEVELOP=y`
>
> **结论：管理器卡死/看门狗复位已彻底根治；App 进程已能拿到真实驱动 fd；GUI 连驱动仍差最后一步。**

---

## 1. 根因：`libksud.so` 有【两处】驱动 fd 握手，Android 16 都会 SIGSYS 击杀

KernelSU 靠一个「reboot 魔数握手」把驱动 fd 装进调用进程（内核 hook `__NR_reboot`）。
Android 16 OriginOS 的 `/system/etc/seccomp_policy/app.policy` 对 app 封锁 syscall 142。

### 站点 1 —— 内联 `svc`（函数 `su` 内），文件偏移 `0x338be0`

```asm
338bcc: movk w0, #0xdead, lsl #16    ; 0xDEADBEEF
338bd4: mov  w8, #0x8e               ; 142 = __NR_reboot
338bd8: movk w1, #0xcafe, lsl #16    ; 0xCAFEBABE
338be0: svc  #0                     ; ← 击杀点（内联指令，用户态 hook 拦不到）
338be4: ldr  w0, [sp, #0x8b0]
338be8: tbnz w0, #0x1f, <error>
```

### 站点 2 —— libc `syscall()` 调用点，`0x34c364`

```asm
34c340: mov  w1, #0xbeef
34c348: mov  w8, #-1
34c350: mov  w0, #0x8e               ; 142
34c354: movk w1, #0xdead, lsl #16
34c358: movk w2, #0xcafe, lsl #16
34c360: str  w8, [sp]                ; status = -1
34c364: bl   0x491470 <syscall@plt>  ; ← 击杀点（走 libc，可被 hook 覆盖，但没必要）
34c368: ldr  w21, [sp]
34c370: lsr  w0, w8, #31             ; 返回 (status < 0)
```

**只补站点 1 不够**：实测 `ksud`（管理器 fork 出来执行 `libksud.so feature check …` 的
子进程）以 **app uid 且带 seccomp** 运行，命中站点 2 → SIGSYS → 崩溃风暴。tombstone 铁证：

```
Cmdline: .../lib/arm64/libksud.so feature check adb_root
uid: 10402
signal 31 (SIGSYS), code 1 (SYS_SECCOMP)
Cause: seccomp prevented call to disallowed arm64 system call 142
    x0 00000000deadbeef  x1 00000000cafebabe  x8 000000000000008e
backtrace:
  #00 libc.so (syscall+32)          ← 注意：走 libc syscall，不是内联 svc
  #01 libksud.so 0x34c364
```

### 致死链与放大器

```
svc / syscall(142) → SIGSYS(signal 31) → 进程被杀
   → 内核侧 fd 已装上，随进程死亡
   → AMS/zygote 重启风暴
   → 与 exploit 的 CPU 绑核争用叠加 → RCU stall
   → MTK aee_hangdet 判定 CPU 失联 → 硬件看门狗复位
```

放大器：管理器注册了 `me.weishu.kernelsu/.magica.BootCompletedReceiver`
（`LOCKED_BOOT_COMPLETED` / `BOOT_COMPLETED`），**每次开机自动触发一遍**。

**决定性反证**：同一次利用从 adb/shell 流程运行时打印
`[+] no app seccomp filter (adb/shell flow); skipping W3` —— shell 无该过滤器故稳定；
`ksushimd`（root）执行**同一个** syscall 142 握手**成功**（`driver fd installed: 3`）。
同一系统调用，root 过、app 死，差异全在 seccomp。

---

## 2. 已落地的修复

### 2.1 两处握手补丁（各 4 字节 / 8 字节）

| 站点 | 偏移 | 原字节 | 补丁后 | 作用 |
|---|---|---|---|---|
| 1 | `0x338be0` | `01 00 00 d4`（`svc #0`） | `1f 20 03 d5`（`nop`） | 不执行 svc，`status` 保持 -1 → 走失败分支 |
| 2 | `0x34c364` | `43 14 05 94`（`bl syscall`） | `1f 20 03 d5`（`nop`） | 不调用 syscall |
| 2 | `0x34c370` | `00 7d 1f 53`（`lsr w0,w8,#31`） | `20 00 80 52`（`mov w0,#1`） | 明确返回"失败"，而非"成功但 fd=-1" |

> 字节序陷阱：`llvm-objdump` 显示的是指令字（大端书写），文件里是小端字节序。
> `531f7d00` → 文件字节为 `00 7d 1f 53`。

### 2.2 shim socket：从"app 不可达"改为多路径 + 目录属主鉴权

原设计把 socket 放在 `/data/adb/ksu_shim.sock`，注释写「目录仍是 0700(root)，
进程要过 SELinux 才能到这里」—— **把 DAC 与 SELinux 混为一谈**。
`/data/adb` 是 `drwx------ root root`，非 root 进程在 **DAC 层**就无法穿越，
根本轮不到 SELinux 表态，于是 socket 对唯一的目标客户端（App）不可达。
这正是方案2 从未跑通的根因。

现改为：daemon 监听 **三条候选路径**，客户端按序尝试。

```
/data/data/me.weishu.kernelsu/ksu_shim.sock   ← 实测 App 可连（DAC+SELinux 均放行）
/data/local/tmp/ksu_shim.sock
/data/adb/ksu_shim.sock                       （兼容 root 客户端）
```

**鉴权**：`peer_uid == 0` 或 `peer_uid == socket 所在目录的属主` 或已配置允许集。
管理器私有目录是 0700，只有该 app 与 root 能穿越 —— **能连上本身就是身份证明**，
无需人工配置，也不受 `pm` 输出里 appId / fullUid 差异影响。

### 2.3 驱动 fd 交付：改用 `SCM_RIGHTS` 传【真】fd

原 `make_fake_driver_fd()` 只是把 shim socket `dup` 一份，内核 readlink 是
`socket:[N]`，要骗过 `scan_driver_fd()` 只能覆盖 `readlink()`。而 bionic 的符号
查找是「本库 → 本地组 → 全局组」，**libc 就在 `libksud.so` 自身的 `DT_NEEDED`
本地组里，会先于全局组命中** —— 单靠 `RTLD_GLOBAL` 并不能保证抢先。

现改为：`ksushimd` 用 `sendmsg + SCM_RIGHTS` 把**它自己持有的真实驱动 fd**
交给客户端。实测 App 进程内：

```
96 -> anon_inode:[ksu_driver]        ← 内核原生身份
[ksushimd] driver fd sent to uid=10403 (dup=8 sendmsg=8)
```

真 fd 的好处：`scan_driver_fd()` 用内核 readlink 天然命中（**无需任何符号 hook**），
`ioctl` 也直通驱动，不必逐条转发。且 `flags: 02`（仅 O_RDWR，**无 O_CLOEXEC**），
可跨 `exec` 被 `ksud` 继承。

### 2.4 smali 注入点（两处，缺一不可）

| 类 | 方法 | 为什么 |
|---|---|---|
| `me.weishu.kernelsu.KernelSUApplication` | `<init>` | 最早的 app 代码，必须早于 `libksud`/`libkernelsu` 首次扫描 |
| `me.weishu.kernelsu.magica.AppZygotePreload` | `doPreload` | KernelSU 的特权路径跑在 **app zygote** 派生进程里，那里也要有驱动 fd |

**注入位置必须落在已有的 `try` 块【内】**：早先注在 `try` 之外，一旦
`loadLibrary` 在 app zygote 中抛异常就会让 `doPreload` 整体失败，AMS 于是
回退到普通 zygote，**app zygote 根本不会出现**（实测现象正是如此）。

```smali
:try_start_0
const-string v1, "kernelsu"
invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const-string v2, "ksushim"                                    ← 注入在这里
    invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

> 另注：`<init>` 注入必须插在方法**已有** `.locals` 之后。原方法 `.locals 2`，
> 若再插 `.locals 1` 会报 `There can only be a single .registers or .locals directive`。

### 2.5 产物与复现

| 文件 | 说明 |
|---|---|
| `manager-fix/KernelSU-ghostlock-full.apk` | 双站点补丁 + 双注入 + shim（11,089,706 B） |
| `shim-build/ksushimd` | 多路径监听 + SCM_RIGHTS + 目录属主鉴权（2,170,152 B） |
| `shim-build/libksushim.so` | 加载即取真 fd（14,880 B） |
| `build-manager-full.ps1` | 一键构建（含全部断言校验） |
| `start_shim.sh` | 设备侧启动 daemon（permissive 窗口内启动后恢复 enforcing） |

```powershell
# 构建
.\build-manager-full.ps1
# 部署（装 APK 必须用 root；shell 会被 INSTALL_FAILED_ABORTED 拒）
adb push KernelSU-ghostlock-full.apk /data/local/tmp/
adb shell "su -c 'pm install -r /data/local/tmp/KernelSU-ghostlock-full.apk'"
# daemon
adb push shim-build/ksushimd /data/local/tmp/ ; adb shell "su -c 'sh /data/local/tmp/start_shim.sh'"
# 启动（必须显式意图：新装应用处于 stopped 态，隐式意图会被 FLAG_EXCLUDE_STOPPED_PACKAGES 排除）
adb shell 'am start -n me.weishu.kernelsu/.ui.MainActivity'
```

---

## 3. 已验证的稳定状态

```
su -c id            → uid=0(root) gid=0(root) context=u:r:ksu:s0
getenforce          → Enforcing
/proc/modules       → kernelsu 217088 3 - Live
管理器              → 进程存活 + topResumedActivity = .ui.MainActivity
uptime              → 6814s 连续（自 16:42 起约 1.9 小时无重启）
logcat              → 零 SIGSYS / seccomp prevented / aee_hangdet / panic
ksud                → 不再崩溃，优雅报错：Error: Failed to get feature adb_root
```

---

## 4. 剩余阻塞：GUI 显示"未安装"

`ksud` 已能正常运行，但**拿不到驱动**（`Error: Failed to get feature selinux_hide / adb_root / …`）。

### 4.1 KernelSU 3.x 的真实特权路径

清单里藏着机制：

```xml
<service android:isolatedProcess="true" android:useAppZygote="true"
         android:name="me.weishu.kernelsu.magica.MagicaService"/>
```

`libkernelsu.so` 只导出 `Java_..._magica_AppZygotePreload_forkDontCareAndExecKsud`，
其 `doPreload()` 做：`loadLibrary("kernelsu")` → `forkDontCareAndExecKsud()`。

设计意图：MagicaService 跑在 **app zygote 派生的 isolated 进程**里 —— 那个进程
**没有 app 的 seccomp 过滤器**，所以 fork+exec 出的 `ksud` 能正常做 reboot 握手、
或继承 zygote 扫描到的驱动 fd。

### 4.2 实测偏差

`ps` 中**从未出现 app zygote**（`me.weishu.kernelsu_zygote`）或 isolated 进程；
App 进程 PPID 恒为 `zygote64`。`ksud` 以 **uid 10402（app uid，带 seccomp）**
从普通 app 进程路径被 fork，因此既做不了握手，也没继承到驱动 fd。

### 4.3 为什么没继承到 fd（待解）

App 进程确实持有 `anon_inode:[ksu_driver]`（fd 96，无 O_CLOEXEC），按理 fork+exec
后 `ksud` 应当继承。但 `ksud` 的 feature 查询全部失败，说明它没有该 fd。
需进一步确认 `forkDontCareAndExecKsud` 的 fork 源进程与其 fd 清理行为。

### 4.4 另一条硬上限

```
$ su -c '/data/local/tmp/ksud debug set-manager <apk>'
Error: CONFIG_KSU_DEBUG is not enabled
```

预编译 `kernelsu.ko`（32601）**未开启该调试开关** → 重签名管理器**永远无法登记
为官方管理器**。而驱动按 APK 签名（size + 证书 sha256）识别管理器，重签名必然失配。
（附：`resign-manager.ps1` 写的 `ksud set-manager` 少了 `debug` 一层；
`ksud debug get-sign` 只接受 v2 签名，v3 会报 `Unexpected v3 signature found!`。）

**加之**：即使 app zygote/isolated 路径打通，isolated 进程是**独立 uid**
（90xxx）且在 `isolated_app` SELinux 域 —— 它连我们放在管理器私有目录的 socket
会在 DAC（目录属主不符）与 SELinux 两处同时被拒。shim 需相应放宽与放行。

### 4.5 决定性实验：app uid 下全链路可用（推翻此前假设）

写了一个端到端探针 `probe_e2e.c`（连接 shim socket → 请求 SCM_RIGHTS 真 fd →
对它发 `KSU_IOCTL_GET_INFO`），分别以 root 和 **app uid** 运行：

```
=== A. root（基准）===
ioctl(GET_INFO) = 0
  version=32601 flags=0x5 features=6 uid=2

=== B. --uid 10403（决定性）===
[*] dropped to uid=10403
[*] connected via /data/data/me.weishu.kernelsu/ksu_shim.sock
[*] rsp.ret=0 driver_fd=4
[*] fd 4 -> anon_inode:[ksu_driver]
ioctl(GET_INFO) = 0 errno=0
  version=32601 flags=0x5 features=6 uid=2
RESULT: DRIVER ACCEPTS a non-manager uid
```

**结论推翻了「驱动按 uid 拒绝」的假设**：只要进程手里有真驱动 fd，
**驱动对任意 uid 都接受 ioctl**。也就是说 ——
**App uid 下全链路（socket 连接 → fd 交付 → 驱动 ioctl）完全打通。**

### 4.6 真正的最后一道门：KernelSU 主动丢弃 fd

设备侧高频轮询（50ms 间隔）抓到了 fork 现场：

```
pid=21393 ppid=19951(zygote64)   uid=10403  ksu_driver_fds=1   ← 主 app 进程，有 fd
pid=21767 ppid=21718             uid=(空)   ksu_driver_fds=0   ← fork 出的子进程，0 个
```

主 app 进程**有** fd，fork 出的子进程 **0 个** —— 而 fd 96 是无 O_CLOEXEC 的
（`flags: 02`，仅 O_RDWR），本应跨 exec 存活。

**唯一解释：KernelSU 在 fork 后主动清空了子进程的 fd 表**（进程名
`me.weishu.kernelsu:root:0` 印证这是刻意的「root helper」隔离设计，
`forkDontCareAndExecKsud` 的 "DontCare" 即指此 —— fork 时不管/丢弃 fd）。

因此 `ksud` exec 后必须**自己重新拿 fd**：扫描自身 fd 表（空的）→ 回退握手
→ app uid + seccomp → 站点 2（现已补掉）→ 优雅失败 → feature 查询全部失败
→ 管理器显示「未安装」。

**这不是 bug，是 KernelSU 有意的进程隔离设计。**

### 4.7 由此导出的解法与代价

| 路线 | 做法 | 代价 |
|---|---|---|
| A. 让 `ksud` 进程内出现 fd | 给 `libksud.so` 加 `DT_NEEDED libksushim.so`，exec 时 linker 自动加载 shim，其构造函数主动连 socket 取真 fd | `DT_NEEDED` 用相对名时，exec 场景的 linker 搜索路径不含 app lib 目录；写绝对路径则随每次安装变化 → 不可靠 |
| B. 让管理器不走 fork `ksud` | 补丁管理器 smali，把 `KsuCli` 的判定改为直接用本进程已持有的 fd 96 | 要改 R8 混淆后的 Java 逻辑，工程量大 |
| C. 恢复 app zygote/isolated 路径 | 让 `MagicaService` 的 `useAppZygote` 真正生效 | app zygote 从不出现的原因未明；且 isolated 进程是独立 uid(90xxx)+`isolated_app` 域，连 shim socket 会被 DAC+SELinux 双拒，shim 需再放宽 |
| D. 驱动登记管理器 | `ksud debug set-manager` | 被 `CONFIG_KSU_DEBUG is not enabled` 阻塞；需重编 `kernelsu.ko`，而 `CONFIG_MODVERSIONS=y` + CFI 使重编困难 |

**探针结论（4.5）使得「驱动侧拒绝」这一项被排除** —— 剩下的全是
KernelSU 自身进程模型与签名/编译限制，不是本设备特有问题。

### 4.8 结论

> **GUI 完全可用**需要三条同时成立：① app zygote/isolated 路径恢复正常；
> ② 该路径能拿到驱动 fd（继承或 shim 放行 isolated uid）；③ 管理器被驱动登记
> （受 `CONFIG_KSU_DEBUG` 阻塞，需重编 `kernelsu.ko`，而 `CONFIG_MODVERSIONS=y`
> + CFI 使重编困难）。
>
> **就「临时 root」本身而言，`adb shell su` 已 100% 可用且稳定**；
> 管理器的价值在于 GUI 管理，属可选增强。

---

## 5. 本次踩过的坑（操作手册增补）

| 坑 | 现象 | 处理 |
|---|---|---|
| `pkill -f ksushimd` | 把调用它的 `su -c '…ksushimd…'` 自身一起杀掉，脚本半途截断并留下多个残留 daemon | 用 `pkill -x ksushimd` |
| `adb push` 不带可执行位 | 脚本 `[ -x ]` 判为不存在 | 启动脚本内先 `chmod 755` |
| shell 装 APK | `INSTALL_FAILED_ABORTED: User rejected permissions`（锁屏无法确认对话框） | 用 `su -c 'pm install …'` |
| 隐式意图启动新装应用 | `monkey`/`resolve-activity` 报找不到 activity（stopped 态被 `FLAG_EXCLUDE_STOPPED_PACKAGES` 排除） | 用显式 `am start -n` |
| `pm list packages -U` | 输出 `uid:<appId>,<fullUid>`；`SO_PEERCRED` 报的是 **appId** | 取第一个字段；更稳的是用 socket 目录属主鉴权 |
| apktool smali 注入 | 重复 `.locals` 直接编译失败 | 注入点放在既有 `.locals` 之后，不新增 |
| apktool smali 注入（zygote） | 注在 `try` 外会让 `doPreload` 失败 → app zygote 不出现 | 注入进已有 `try` 块内 |
| 二进制补丁字节序 | 断言写指令字（`531f7d00`）会失败 | 文件是小端：`00 7d 1f 53` |
| 杀死持有 ksu 驱动 fd 的进程 | `ghostlock`、`ksushimd` 均属此类，KernelSU 清理路径可能触碰被污染的 rt_mutex 状态 | 不要 kill |
| `ksushimd` 启动时机 | 驱动握手需要 permissive 窗口 | `start_shim.sh` 已封装（permissive → 启动 → 恢复 enforcing） |
