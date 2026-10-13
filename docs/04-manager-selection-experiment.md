# 模块切换实验记录（2026-10-12 晚）

> 目的：验证「重编 kernelsu.ko / 换 SukiSU-Ultra」以解锁 GUI 管理器
> 结果：**两条切换路径都被结构性挡住**，GUI 线到此收束

---

## 实验时间线

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 官方 32601 在线（refcount 3），`ksud-sukisu late-load` 干跑 | exit=0，走完全流程（检测已加载→跳过→install/sepolicy/features），refcount 3→4 |
| 2 | `pkill -x ksushimd` + force-stop 两个管理器 + `pkill -f libksud.so` | refcount 3→**2** |
| 3 | `rmmod kernelsu` | **`Try again`**（失败） |
| 4 | （此前的独立测试）SukiSU `.ko` 直接 `insmod` | **`Exec format error`**（vermagic 6.1.166 vs 内核 6.1.145） |
| 5 | 改写 vermagic 后 `insmod` | 仍 `Exec format error`（截断破坏了格式，且 CRC/结构校验仍在） |
| 6 | SukiSU `late-load --magica` | 需要 `ro.debuggable=1`，BL 锁定下只读，**无法设置** |

## 关键事实（均有实测证据）

### 1. SukiSU 的加载器确实强大，但入口被堵

`libksud.so` 内嵌 **8 个 KMI 的模块资产**（android12-5.10 … android17-6.18 全齐），
且它的加载器**不是** `finit_module`，而是：

```
BTF 读取内核自身 struct load_info 布局
→ .text.ksu_bootstrap / .rodata.ksu_bootstrap
→ 内核内手工重定位（绕过 vermagic/部分校验）
```

这正是能加载 vermagic 不匹配模块的技术。**但它要求「内核里没有已加载的 kernelsu」**
（`ksuinit::has_kernelsu()` 为假才走到加载），而官方模块卸不掉。

### 2. `rmmod kernelsu` 被内核侧引用挡住

- 用户态持有者（ksushimd、两个管理器、ksud）全部清掉后 refcount 3→2
- 剩余 2 个引用来自**内核侧**（kernelsu 的 syscall hook / 内核态注册），
  `holders/` 目录不存在，无法枚举
- 硬卸（`rmmod -f`）在 vivo 内核上有 panic 风险，不做

### 3. 重启后无法进入「无模块」状态（鸡生蛋）

```
重启 → root 消失 → 需要 GhostLock 恢复 → GhostLock 加载的是官方 32601
     → 官方模块又在内核里 → rmmod 依旧失败
```

打破循环需要修改 GhostLock 的 root 脚本，让它加载 **SukiSU 的 .ko** 而非官方的——
但 GhostLock 的 `ksud late-load` 是从**它自己内嵌 assets** 取模块，不接受外部 .ko。

### 4. MODVERSIONS 实际是空转（重要修正）

内核报告 §5 曾判断「重编内核模块的真正门槛是 CONFIG_MODVERSIONS=y」——**实测推翻**：

```
/proc/kallsyms 里 __crc_ 符号共 5194 个，非零 CRC 数 = 0
```

CRC 全为 0 → MODVERSIONS 校验形同虚设。**真正的门槛只有两个**：
- vermagic 字符串比对（可用 SukiSU 的重写加载器绕过）
- **符号解析**：模块引用的内核符号必须真实存在（commit_creds/prepare_creds/filp_open 等均确认存在）

即：**在这台内核上重编 kernelsu.ko 的难度比预期低**，vermagic 可以靠 SukiSU
加载器或直接改写 .modinfo 解决。

## 结论

**GUI 线收束。** 三条路的状态：

| 路线 | 状态 |
|---|---|
| 重编 kernelsu.ko（开 CONFIG_KSU_DEBUG） | 理论可行，但**装不进当前内核**（官方模块卸不掉 + 重启后无 root 装新模块） |
| 切换到 SukiSU-Ultra 全套 | 同样卡在「官方模块卸不掉」 |
| GhostLock shim + CLI（现状） | **可用且稳定**：`adb shell su` + `ksu-grant` |

**根本矛盾**：late-load 方案下，模块只在 root 存在期间驻留；切换模块需要
「无模块但有 root」的窗口期，而这台设备的生产不出来（root 依赖 GhostLock
加载官方模块；官方模块无法在 root 存在时卸载）。

## 交付物状态（本日累计）

| 项 | 状态 |
|---|---|
| 临时 root（`adb shell su`） | ✅ 稳定，`retry_run.ps1` 一键恢复 |
| 管理器卡死/看门狗复位 | ✅ 根治（两处握手补丁） |
| App uid 下驱动 ioctl | ✅ 已证明可用（probe_e2e） |
| `ksu-grant` CLI | ✅ 驱动查询全通；写 profile 需 manager 身份 |
| GUI 管理器 | ❌ 受 KernelSU 进程模型 + 模块切换死锁限制 |
