# 🎉 突破：自研内核模块加载成功 + KernelSU 管理器完全可用

> 2026-10-13 凌晨 · iQOO Neo9S Pro (PD2339) · kernel 6.1.145-android14-11-maybe-dirty
> 结果：**管理器 GUI 显示「工作中 [越狱模式]」，超级用户页正常，3 个 App 已授权 ROOT**

---

## 最终成果

| 项 | 状态 |
|---|---|
| Manager GUI | **工作中 [越狱模式]** ✅ |
| 超级用户页 | ✅ 正常列出并显示 ROOT 授权（MMRL / MT管理器 / Operit AI） |
| 模块页 | ✅ 徽标 2 |
| SELinux | 强制执行（未关闭） |
| 内核污染标记 | 未增加（tainted 13825 → 13825） |
| 设备稳定性 | 持续运行，未 panic |

**关键指标**：管理器进程（uid 10403）查询驱动的 `GET_INFO` 返回 **`flags=0x7`**（LKM | **MANAGER** | LATE_LOAD），
而之前一直是 `0x5`（无 MANAGER 位）。

---

## 三个根因（按发现的先后）

### 根因 1：vermagic 必须**包含** `vivo ` 前缀

**我之前的结论是错的。** 我曾从官方 `kernelsu.ko` 的 vermagic（`6.1.166-dirty ... aarch64`，无 vivo）
反推出「不能含 vivo」——但那个 .ko 的 vermagic 在加载时被 ksud 的**内存加载器改写**了，
所以它根本不是设备要求的格式。

设备真正要求的（dmesg 证据 `version magic '...' should be '...'`）：

```
6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64
```

**教训**：我当时的 grep 模式是 `vermagic`（无空格），而内核打印的是 **`version magic`**（有空格）
——**那条关键日志一直都在，只是被我漏掉了**，导致我误判为「vivo 静默校验」。

### 根因 2：MODVERSIONS 的 CRC 门槛真实存在

`/proc/kallsyms` 里的 `__crc_*` 是 CRC 表的**地址**（因 kptr_restrict 显示为 0），
我却误读成「CRC 值为 0」，从而得出「MODVERSIONS 空转，无 CRC 门槛」——**错的**。

**正确做法**：从设备上的**厂商 .ko**（`vendor-kos/vk/*.ko`）的 `__versions` 段里
**挖出真实 CRC**，生成 `real.symvers`，用它做 `KBUILD_EXTRA_SYMBOLS`。

```bash
# 45-mine-crc.sh：解析每个 .ko 的 __versions 段
# struct modversion_info { unsigned long crc; char name[56]; }
```

### 根因 3（真正的 panic 原因）：`struct module` 尺寸必须是 **0x440**

**panic 现场**（console-ramoops）：

```
insmod: Unable to handle kernel paging request at virtual address 0000000096d23cdf
insmod: pc : mod_sysfs_setup+0x208/0x418
insmod: x3 : 4c452064696c6176   → ASCII "valid EL"
```

**内核把模块自带的 `.gnu.linkonce.this_module` 段直接当作 `struct module` 使用。**
尺寸/布局不匹配 → `mod_sysfs_setup` 读 `->name` 读到垃圾 → panic。

| | `.gnu.linkonce.this_module` |
|---|---|
| 出问题的 ghostlock.ko | **0x400（1024 字节，68 成员）** ❌ |
| 设备内核 BTF (`vmlinux.btf`) | **0x440（1088 字节，70 成员）** ✅ |
| 全部厂商 .ko（12 个） | **0x440** ✅ |

**差额来源**：缺 `btf_data_size` + `btf_data` 两个字段（`CONFIG_DEBUG_INFO_BTF_MODULES`）。

**为什么会缺**——三层叠加，每一层都必须修：

1. **`.config` 派生有损**：旧流程从设备 `autoconf.h` 反推 `.config`，
   而 `autoconf.h` **只列已启用的项**，导致 1602 个符号丢失（含 KASAN、BTF、BTF_MODULES）。
   → **修法：直接用设备内核的真实完整配置 `kconfig.txt`**（9246 行，含 4365 条 `is not set`）。

2. **生成的 `autoconf.h` 陈旧**：`make M=... modules`（外部模块构建）
   **不会触发 `syncconfig`**。改完 `.config` 后编译器仍读旧的 `autoconf.h`。
   → **修法：显式 `make ... syncconfig`**。

3. **`asm-offsets.h` 陈旧**：设备配置开了 `CONFIG_STACKPROTECTOR_PER_TASK`，
   需要 `-mstack-protector-guard-offset`，该值来自 `include/generated/asm-offsets.h`，
   而它只在 `make prepare` 里生成。否则报
   `invalid value '' in 'mstack-protector-guard-offset='`。
   → **修法：`make ... prepare`**。

**验收闸门**：每次构建后检查 `.gnu.linkonce.this_module == 0x440`，不等就**绝不加载**。

---

## 完整流程

```powershell
# 1) 恢复 root（含 post-root 自动步骤）
cd D:\daima\root2\ghostlock
.\retry_run.ps1
```

事后脚本 `post-root.sh` 做四件事：

```sh
1. insmod /data/local/tmp/ghostlock.ko        # 失败会重试，幂等
2. ADDR=$(grep -w ksu_manager_appid /proc/kallsyms)   # 运行时地址（每次开机变化）
3. MGR_UID=$(pm list packages -U | grep me.weishu.kernelsu | ...)  # 10403
4. echo "0x$ADDR $MGR_UID" > /proc/ghostlock  # 写内核内存 → 登记管理器
   + 重启 shim
```

**驱动侧判定逻辑**（`kernel/manager/manager_identity.h`）：

```c
extern uid_t ksu_manager_appid;          // 模块内全局变量，初始 -1
is_manager() { return ksu_manager_appid == current_uid().val % 100000; }
```

管理器 App 的 `uid = 1010403` → `appId = 10403` → 写入后该进程即成为 manager。

---

## 构建环境（WSL Ubuntu-22.04）

| 项 | 路径/值 |
|---|---|
| 内核源码 | `/root/gki/android14-6.1`（ACK tag `ASB-2025-08-05_14-6.1`，SUBLEVEL=145） |
| 编译器 | `/root/gki/clang-r487747c`（AOSP clang 17.0.2，与设备 `compile.h` 逐字一致） |
| 构建输出 | `/root/gki/out-6.1.145` |
| 模块源码 | `/root/gki/ghostlock-build` ← `kmod/ghostlock-src/` |
| 真实 CRC | `/root/gki/real.symvers` |
| 设备真实配置 | `D:\daima\root\build\kernel-extract\kconfig.txt` |

**关键脚本（`kmod/wsl/`）**：

| 脚本 | 作用 |
|---|---|
| `78-devconfig.sh` | 用设备真实 `kconfig.txt` 替换 `.config` |
| `81-sync-rebuild.sh` | `syncconfig` + 重建（修 syncconfig 层） |
| `83-prepare-rebuild.sh` | `make prepare` + 重建（修 asm-offsets 层）**← 最终可用** |
| `82-build-err.sh` | 编译错误捕获 |

**一条命令重建**：

```powershell
wsl -d Ubuntu-22.04 -u root -- bash /mnt/d/.../kmod/wsl/83-prepare-rebuild.sh
```

---

## 诊断工具（本次新增，可复用）

| 工具 | 用途 |
|---|---|
| `btf_struct.py` | 从 `vmlinux.btf` 解析任意结构体的**真实布局**（设备权威） |
| `btf_vs_pahole.py` | 设备 BTF ↔ 本地 pahole 布局**逐成员对比** |
| `72-structdiff.sh` | 预处理器展开对比（设备 autoconf.h vs 构建 autoconf.h） |
| `71-fulldiff.sh` | 全量 CONFIG 比对 |

---

## 与之前结论的修正关系

| 之前的结论 | 修正 |
|---|---|
| 「vivo 加了静默签名校验，自编模块路线被堵死」 | ❌ **错误**。真实原因是 vermagic 缺 `vivo`、CRC 缺失、`struct module` 尺寸不匹配三层叠加 |
| 「MODVERSIONS 空转，无 CRC 门槛」 | ❌ **错误**。CRC 门槛真实存在，只是符号值被误读 |
| 「GUI 受双重锁无法绕过」 | ❌ **错误**。GUI 现已完全可用 |
| 「需要 2-4 周重编内核模块」 | 实际在本次会话内完成 |

---

## 重启后的行为

**重启会丢失**：`ghostlock.ko` 加载状态、`ksu_manager_appid` 补丁（内核内存）、root。

**恢复方式**：跑一次 `retry_run.ps1`（约 30 秒～4 分钟，取决于 exploit 一次成功与否），
`post-root.sh` 会自动完成全部登记。

**不随重启丢失**：`/data/local/tmp/` 下的所有工具、`ghostlock.ko`、管理器 App 及其授权列表。

---

## 后续可做

1. **验证可复现性**：主动重启一次，确认 `retry_run.ps1` 全自动恢复
2. **持久化**：把 `post-root.sh` 挂进 GhostLock 的 root 脚本模板（需先确认模板是否可改）
3. **能力扩展**：`/proc/ghostlock` 已是通用内核任意 4 字节写，可用于
   - 修改其他内核变量（如 `selinux_state`、feature 开关）
   - 绕过 `SET_FEATURE` 的 manager 限制
4. **清理**：设备上堆积了大量 `.ghostlock_policy.*` 文件（~50 个 × 1.6 MB）
