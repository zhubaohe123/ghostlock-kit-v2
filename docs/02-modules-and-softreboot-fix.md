# 修复：模块安装/更新失败 + 软重启无效

> 2026-10-13 凌晨 · 接 `BREAKTHROUGH_2026-10-13_kmod_works.md`
> 症状：管理器 GUI 显示「工作中」，但**模块无法更新/安装**、**软重启点了没反应**

---

## 症状与根因

### 直接证据

从 GUI 点「软重启」后，logcat 给出确切错误：

```
I KernelSU: ksud::cli: command: SoftReboot
E KernelSU: ksud::init_event: UAPI version mismatch: kernel=0, ksud=2.
                             Please update KernelSU!, skip soft_reboot
```

**`kernel=0`** —— ksud 读不到驱动（`get_info()` 返回全零）。

`ksud` 源码里这个分支是**静默 return** 的：

```rust
pub fn soft_reboot() -> Result<()> {
    // check it avoid user click "soft_reboot" in manager when version mismatch
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip soft_reboot");
        return Ok(());        // ← 什么都不做，界面毫无反应
    }
```

### 为什么 ksud 读不到驱动

管理器执行特权命令的**真实路径**（`KsuCli.kt`）：

```kotlin
private fun getKsuDaemonPath(): String =
    ksuApp.applicationInfo.nativeLibraryDir + "/libksud.so"   // APK 内置的那份

object KsuCli { val SHELL = createRootShell() }               // libsu
fun createRootShell() = Shell.Builder.create()
    .build(getKsuDaemonPath(), "debug", "su")                 // ← root shell
```

即：**app → libsu `su`(root shell) → `<nativeLibraryDir>/libksud.so <命令>`**

这条链上的子进程有两个致命问题：

1. **继承 app 的 seccomp 过滤器**（seccomp 不因 setuid 而移除）
   → ksud 的「reboot 魔数握手」（syscall 142）被 **SIGSYS** 击杀
2. **拿不到 app 的驱动 fd**
   → 既不能握手，又没有可继承的 fd → `get_info()` 全零

### 还有第二个坑：`/data/adb/ksud` 被污染

```rust
// ksud 的 install 实现
let _ = std::fs::remove_file(defs::DAEMON_PATH);
std::fs::copy("/proc/self/exe", defs::DAEMON_PATH)?;   // 把自己复制过去
```

`KsuCli.install()` 在 App 启动时执行（`MainActivity.kt:110`，
条件 `Natives.isManager && !Natives.requireNewKernel()`）。

**因为我们的 App 现在 `isManager == true`，每次启动都会把它自己那份
（被我们 NOP 掉握手的）`libksud.so` 复制成 `/data/adb/ksud`。**

实测对比（补丁字节逐一吻合）：

| 文件 | site1 | site2 | site3 | `debug info` |
|---|---|---|---|---|
| `/data/adb/ksud`（被污染） | `1f2003d5` NOP | NOP | mov w0,#1 | version=**0** ❌ |
| `/data/local/tmp/ksud`（原始） | `010000d4` svc#0 | bl | lsr | version=**32601** ✅ |

---

## 修复：ksud 启动器（`ksud-exec`）

**思路**：既然子进程无法握手（seccomp）、也拿不到继承的 fd，
就让一个**能拿到 fd 的进程**去拿，再把它交给 ksud。

`ksud-exec.c` 做三件事：

1. 连接 `ksushimd` 的 socket，用 `SCM_RIGHTS` 取一份**真驱动 fd**
   （shim 的鉴权里有 `peer_uid == 0`，而启动器跑在 root shell 里就是 uid 0）
2. **清掉该 fd 的 `O_CLOEXEC`**，使它穿过 `execve`
3. `execv()` 真 ksud —— ksud 的 `scan_driver_fd()` 在 `/proc/self/fd` 里
   直接扫到内核原生的 `anon_inode:[ksu_driver]`，**完全不需要握手**

**部署方式**：把 `<nativeLibraryDir>/libksud.so` 原地替换为启动器
（`cat > 文件` 保留 inode 与 SELinux 上下文 `apk_data_file`）。

自保护：启动器 exec 前会检查目标是否为自身（inode 比对 + 内容标记扫描），
避免 `install()` 把启动器复制到 `/data/adb/ksud` 后形成无限 exec 循环。

---

## 验证结果

### 软重启

```
[2s]  uptime=2642.62 boot=0     ← boot_completed 翻转（框架停止）
[8s]  offline（框架重启中）      ← adb 断开约 8 秒
[16s] uptime=2657.36 boot=1     ← 框架恢复
```

`uptime` 持续增长（**内核未重启**）、`boot_completed` 1→0→1 —— 软重启语义完全正确。

### 模块安装

```
- Module size: 154 B
- Installing to /data/adb/modules_update/ghostlocktest
- Extracting module files
- Running module installer
- Current boot slot: _b
- Device is system-as-root
```

软重启后：

```
/data/adb/modules:  ghostlocktest  zygisk_vector  zygisksu
/data/adb/modules_update:  (空)
```

**模块成功从待激活转为正式生效。**

### 软重启后状态保持

| 项 | 结果 |
|---|---|
| `ghostlock` 内核模块 | ✅ 仍加载 |
| `kernelsu` 模块 | ✅ 仍加载（refcount 4） |
| `ksu_manager_appid` | ✅ 仍为 10403 |
| root | ✅ `su -c id` → uid=0 ksu |
| 已授权 App | ✅ 未丢失 |

---

## 另一处修复：shim 交付的 fd 清掉 CLOEXEC

`ksushim_client.c` 的 `obtain_real_driver_fd()` 现在会清掉收到 fd 的 `O_CLOEXEC`：

```c
int fl = fcntl(got, F_GETFD);
if (fl >= 0) fcntl(got, F_SETFD, fl & ~FD_CLOEXEC);
```

这样 app 进程里出现两个驱动 fd：

```
fd 3  -> anon_inode:[ksu_driver]   flags=02000002  (KernelSU 自己的，带 CLOEXEC)
fd 97 -> anon_inode:[ksu_driver]   flags=02        (shim 交付的，无 CLOEXEC)
```

虽然 libsu 仍会关闭继承的 fd（所以最终靠启动器解决），但这一改动让 fd 至少
在普通 `fork+exec` 场景下可继承，是必要的补强。

---

## 自动化

`post-root.sh` 新增第 6 步（幂等）：

```
manager uid: 10403
== deploy-launcher 02:09:39 ==
[*] LIBDIR=/data/app/.../lib/arm64
[=] launcher already deployed
[=] /data/adb/ksud already the original
[*] verify: version: 32601 flags: 0x5 uapi_version: 2
```

`retry_run.ps1` 会一并推送 `ksud-exec`、`deploy-launcher.sh`、`start_shim.sh`。

**注意**：`/data/adb/ksud` 现在是**自愈**的 —— 因为 `install()` 走的是启动器，
`/proc/self/exe` 就是真 ksud，复制回去仍是真 ksud。

---

## 产物

| 文件 | 说明 |
|---|---|
| `kmod/ksud-exec.c` / `ksud-exec` | 启动器（静态链接，2.1 MB） |
| `kmod/wsl/deploy-launcher.sh` | 部署脚本（幂等） |
| `kmod/wsl/fd-check.sh` | 检查 fd 的 CLOEXEC 状态 |
| `kmod/wsl/sr-test.sh` | 软重启日志捕获 |
| `/data/local/tmp/libksud.so.orig` | 原 APK 内置 libksud.so 备份 |
