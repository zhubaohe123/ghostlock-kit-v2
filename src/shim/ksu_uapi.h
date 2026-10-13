/*
 * ksu_uapi.h — KernelSU 用户态/内核态 ABI 子集（与上游 uapi/supercall.h 对齐）
 * ---------------------------------------------------------------------------
 * 用途：KSUShim 代理与 App 侧客户端共用。
 * 版本基线：KernelSU 3.3.0 / KERNEL_SU_UAPI_VERSION = 4 / 驱动版本 32601。
 *
 * 注意：本文件只复刻代理链路真正需要的最小集合。
 * 所有多字节字段一律 little-endian（arm64 Android 恒为 LE），
 * 因此结构体布局与内核 ABI 天然一致，无需 byteswap。
 */
#ifndef GHOSTLOCK_KSU_UAPI_H
#define GHOSTLOCK_KSU_UAPI_H

#include <stdint.h>

/* --- 驱动 fd 安装魔数（reboot 系统调用 hook 识别用）--- */
#define KSU_INSTALL_MAGIC1 0xDEADBEEFu
#define KSU_INSTALL_MAGIC2 0xCAFEBABEu

#define KERNEL_SU_UAPI_VERSION 4u
/* 驱动版本号不在此硬编码：实际值由 KSU_IOCTL_GET_INFO 返回（本机为 32601）。 */

/* --- ksu_get_info_cmd 的 flags --- */
#define KSU_GET_INFO_FLAG_LKM        (1u << 0)
#define KSU_GET_INFO_FLAG_MANAGER    (1u << 1)
#define KSU_GET_INFO_FLAG_LATE_LOAD  (1u << 2)
#define KSU_GET_INFO_FLAG_PR_BUILD   (1u << 3)
#define KSU_GET_INFO_FLAG_BUNDLED    (1u << 4)

struct ksu_get_info_cmd {
    uint32_t version;      /* 输出: KERNEL_SU_VERSION */
    uint32_t flags;        /* 输出: KSU_GET_INFO_FLAG_* */
    uint32_t features;     /* 输出: 支持的最大 feature ID */
    uint32_t uapi_version; /* 输出: KERNEL_SU_UAPI_VERSION */
};

struct ksu_get_info_legacy_cmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
};

struct ksu_uid_granted_root_cmd {
    uint32_t uid;    /* 输入 */
    uint8_t  granted;/* 输出 */
    uint8_t  _pad[3];
};

struct ksu_uid_should_umount_cmd {
    uint32_t uid;         /* 输入 */
    uint8_t  should_umount;/* 输出 */
    uint8_t  _pad[3];
};

struct ksu_get_manager_appid_cmd {
    uint32_t appid; /* 输出 */
};

struct ksu_check_safemode_cmd {
    uint8_t in_safe_mode; /* 输出 */
    uint8_t _pad[3];
};

struct ksu_get_feature_cmd {
    uint32_t feature_id; /* 输入 */
    uint64_t value;      /* 输出 */
    uint8_t  supported;  /* 输出 */
    uint8_t  _pad[7];
};

struct ksu_set_feature_cmd {
    uint32_t feature_id; /* 输入 */
    uint64_t value;      /* 输入 */
};

struct ksu_get_sulog_fd_cmd {
    uint32_t flags; /* 输入: 必须为 0 */
};

struct ksu_report_event_cmd {
    uint32_t event; /* 输入 */
};

#define EVENT_POST_FS_DATA   1u
#define EVENT_BOOT_COMPLETED 2u
#define EVENT_MODULE_MOUNTED 3u

struct ksu_manage_mark_cmd {
    uint32_t operation; /* 输入: KSU_MARK_* */
    int32_t  pid;       /* 输入: 目标 pid，0 表示全部 */
    uint32_t result;    /* 输出: get 时为 mark 状态或 reg_count */
};

#define KSU_MARK_GET     1u
#define KSU_MARK_MARK    2u
#define KSU_MARK_UNMARK  3u
#define KSU_MARK_REFRESH 4u

/* ---------------------------------------------------------------------------
 * app_profile —— 必须与内核 uapi/app_profile.h 逐字节一致！
 *
 * 布局由 ABI 复算确认（aarch64/x86_64 System V，对齐取成员最大对齐）：
 *   root_profile    : size=248  (caps@144 selinux_domain@168 namespaces@232 flags@240)
 *   rp_config       : size=512  (use_default@0 template_name@1 profile@264)
 *   app_profile     : size=784  (version@0 key@4 curr_uid@260 allow_su@264 union@272)
 *
 * 早期版本曾按猜测把 key 写成 [MAX_PACKAGE_NAME-32]，那会算成 224 字节，
 * 偏移全错 —— 传给内核会直接破坏内核内存。这里按上游定义严格复刻。
 * ------------------------------------------------------------------------- */
#define KSU_APP_PROFILE_VER 4u
#define KSU_MAX_PACKAGE_NAME 256
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64
#define FLAG_KSU_NO_NEW_PRIVS (1ULL << 0)

struct ksu_capabilities {
    uint64_t effective;
    uint64_t permitted;
    uint64_t inheritable;
};

struct root_profile {
    int32_t  uid;
    int32_t  gid;
    uint32_t groups_count;
    int32_t  groups[KSU_MAX_GROUPS];
    struct ksu_capabilities capabilities;
    char     selinux_domain[KSU_SELINUX_DOMAIN];
    int32_t  namespaces;
    uint64_t flags;
};

struct non_root_profile {
    uint8_t umount_modules;
};

struct app_profile {
    uint32_t version;
    char     key[KSU_MAX_PACKAGE_NAME];
    int32_t  curr_uid;
    uint8_t  allow_su;
    union {
        struct {
            uint8_t use_default;
            char    template_name[KSU_MAX_PACKAGE_NAME];
            struct root_profile profile;
        } rp_config;
        struct {
            uint8_t use_default;
            struct non_root_profile profile;
        } nrp_config;
    };
};

struct ksu_get_app_profile_cmd {
    struct app_profile profile;
};

struct ksu_set_app_profile_cmd {
    struct app_profile profile;
};

struct ksu_get_wrapper_fd_cmd {
    uint32_t fd;    /* 输入 */
    uint32_t flags; /* 输入 */
};

struct ksu_nuke_ext4_sysfs_cmd {
    uint64_t arg; /* 对齐指针 */
};

struct ksu_add_try_umount_cmd {
    uint64_t arg;   /* char* 挂载点 */
    uint32_t flags;
    uint8_t  mode;  /* 0=wipe 1=add 2=del */
    uint8_t  _pad[3];
};

struct ksu_new_get_allow_list_cmd {
    uint16_t count;       /* 输入/输出 */
    uint16_t total_count; /* 输出 */
    uint32_t uids[];      /* 输出: 柔性数组 */
};

/* ---------------------------------------------------------------------------
 * 动态管理器签名配置（ReSukiSU v4.2.0-rc1）
 *
 * 内核侧结构体（kernel/feature/dynamic_manager.h + uapi/supercall.h）：
 *   struct ksu_dynamic_manager_cmd { __u8 operation; unsigned int size; __u8 hash[64]; }
 * 注意内核侧动态管理器无法跨重启持久化（无 ksu_load_dynamic_manager），
 * 每次重载内核模块后都需要重新下发。
 * ------------------------------------------------------------------------- */
struct ksu_dynamic_manager_cmd {
    uint8_t  operation;  /* 0=SET 1=GET 2=WIPE 3=SET_SYNCHRONOUS */
    uint32_t size;       /* 证书 DER 长度，内核要求 0x100 <= size <= 0x1000 */
    uint8_t  hash[64];   /* 证书 DER 的 sha256 十六进制小写字符串（无 NUL） */
};

#define KSU_DYNAMIC_MANAGER_OP_SET              0
#define KSU_DYNAMIC_MANAGER_OP_GET              1
#define KSU_DYNAMIC_MANAGER_OP_WIPE             2
#define KSU_DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS  3

/* ---------------------------------------------------------------------------
 * ioctl 编码：与 <linux/ioctl.h> 的 _IOC/_IOR/_IOW/_IOWR 完全一致。
 * 这里显式展开，避免 Windows 侧编译时缺少 linux/ioctl.h。
 *   _IOC(dir,type,nr,size) = (dir<<30) | (size<<16) | (type<<8) | nr
 *   _IOC_NONE=0 _IOC_WRITE=1 _IOC_READ=2
 * type 一律为 'K' (0x4B)
 * ------------------------------------------------------------------------- */
#define KSU_IOC(dir, nr, size) \
    (((uint32_t)(dir) << 30) | ((uint32_t)(size) << 16) | ((uint32_t)('K') << 8) | ((uint32_t)(nr)))

#define KSU_IOCTL_GRANT_ROOT              KSU_IOC(0, 1, 0)
#define KSU_IOCTL_GET_INFO                KSU_IOC(2, 2, sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_GET_INFO_LEGACY         KSU_IOC(2, 2, 0)
#define KSU_IOCTL_REPORT_EVENT            KSU_IOC(1, 3, 0)
#define KSU_IOCTL_SET_SEPOLICY            KSU_IOC(3, 4, 0)
#define KSU_IOCTL_CHECK_SAFEMODE          KSU_IOC(2, 5, 0)
#define KSU_IOCTL_GET_ALLOW_LIST          KSU_IOC(3, 6, 0)
#define KSU_IOCTL_GET_DENY_LIST           KSU_IOC(3, 7, 0)
#define KSU_IOCTL_NEW_GET_ALLOW_LIST      KSU_IOC(3, 6, sizeof(struct ksu_new_get_allow_list_cmd))
#define KSU_IOCTL_NEW_GET_DENY_LIST       KSU_IOC(3, 7, sizeof(struct ksu_new_get_allow_list_cmd))
#define KSU_IOCTL_UID_GRANTED_ROOT        KSU_IOC(3, 8, 0)
#define KSU_IOCTL_UID_SHOULD_UMOUNT       KSU_IOC(3, 9, 0)
#define KSU_IOCTL_GET_MANAGER_APPID       KSU_IOC(2, 10, 0)
#define KSU_IOCTL_GET_APP_PROFILE         KSU_IOC(3, 11, 0)
#define KSU_IOCTL_SET_APP_PROFILE         KSU_IOC(1, 12, 0)
#define KSU_IOCTL_GET_FEATURE             KSU_IOC(3, 13, 0)
#define KSU_IOCTL_SET_FEATURE             KSU_IOC(1, 14, 0)
#define KSU_IOCTL_GET_WRAPPER_FD          KSU_IOC(1, 15, 0)
#define KSU_IOCTL_MANAGE_MARK             KSU_IOC(3, 16, 0)
#define KSU_IOCTL_NUKE_EXT4_SYSFS         KSU_IOC(1, 17, 0)
#define KSU_IOCTL_ADD_TRY_UMOUNT          KSU_IOC(1, 18, 0)
#define KSU_IOCTL_SET_INIT_PGRP           KSU_IOC(0, 19, 0)
#define KSU_IOCTL_GET_SULOG_FD            KSU_IOC(1, 20, sizeof(struct ksu_get_sulog_fd_cmd))
#define KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT  KSU_IOC(0, 21, 0)
/* nr 103：动态管理器签名配置（ReSukiSU v4.2.0-rc1 引入）
 * 内核侧 perm_check = only_root，因此只能由 root 进程发起 ——
 * 恰好是本 shim 的典型场景。 */
#define KSU_IOCTL_DYNAMIC_MANAGER         KSU_IOC(3, 103, 0)

/* ---------------------------------------------------------------------------
 * 代理策略：白名单 / 黑名单
 *
 * 设计原则 —— 代理只放行「控制面」，绝不放行「提权面」。
 * 管理器 App 需要的只是查询与配置，真正的 root 授予仍由内核根据
 * uid 白名单自行判定，代理无法伪造 uid（UID 由内核在 connect 时记录）。
 * ------------------------------------------------------------------------- */

/* 允许：只读查询 + 配置管理（管理器正常开屏即可工作） */
#define KSU_SHIM_ALLOW_READONLY(op) \
    ((op) == KSU_IOCTL_GET_INFO || \
     (op) == KSU_IOCTL_GET_INFO_LEGACY || \
     (op) == KSU_IOCTL_GET_MANAGER_APPID || \
     (op) == KSU_IOCTL_CHECK_SAFEMODE || \
     (op) == KSU_IOCTL_UID_GRANTED_ROOT || \
     (op) == KSU_IOCTL_UID_SHOULD_UMOUNT || \
     (op) == KSU_IOCTL_NEW_GET_ALLOW_LIST || \
     (op) == KSU_IOCTL_NEW_GET_DENY_LIST || \
     (op) == KSU_IOCTL_GET_APP_PROFILE || \
     (op) == KSU_IOCTL_GET_FEATURE || \
     (op) == KSU_IOCTL_GET_SULOG_FD || \
     (op) == KSU_IOCTL_MANAGE_MARK)

/* 允许：配置写入（授权/解授权、策略下发）——但这要求调用者本身已被内核
 * 判定为 manager，内核会自行校验，代理不额外加码。 */
#define KSU_SHIM_ALLOW_CONFIG(op) \
    ((op) == KSU_IOCTL_SET_APP_PROFILE || \
     (op) == KSU_IOCTL_SET_FEATURE || \
     (op) == KSU_IOCTL_SET_SEPOLICY || \
     (op) == KSU_IOCTL_ADD_TRY_UMOUNT || \
     (op) == KSU_IOCTL_REPORT_EVENT || \
     (op) == KSU_IOCTL_DYNAMIC_MANAGER)
/* ↑ DYNAMIC_MANAGER 归入 config：它只改写「管理器证书白名单」这一条策略，
 *   本身不授予任何 uid root。内核侧要求 only_root，而 shim 就是 root。
 *   写权限仍受 uid_may_write() 门禁（默认仅 uid 0 / 已登记管理器）。 */

/* 永久禁止：这些 op 直接授予 root、操纵 fd、破坏内核状态。
 * 尤其 GRANT_ROOT —— 管理器不应通过代理拿到它，否则等于开了后门。 */
#define KSU_SHIM_FORBIDDEN(op) \
    ((op) == KSU_IOCTL_GRANT_ROOT || \
     (op) == KSU_IOCTL_GET_WRAPPER_FD || \
     (op) == KSU_IOCTL_NUKE_EXT4_SYSFS || \
     (op) == KSU_IOCTL_SET_INIT_PGRP || \
     (op) == KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT || \
     (op) == KSU_IOCTL_GET_ALLOW_LIST || \
     (op) == KSU_IOCTL_GET_DENY_LIST)

#define KSU_SHIM_ALLOWED(op) \
    (!KSU_SHIM_FORBIDDEN(op) && (KSU_SHIM_ALLOW_READONLY(op) || KSU_SHIM_ALLOW_CONFIG(op)))

/* 从 ioctl 号反解 nr，便于日志 */
#define KSU_IOC_NR(op)  ((uint32_t)((op) & 0xFFu))
#define KSU_IOC_TYPE(op) ((uint32_t)(((op) >> 8) & 0xFFu))
#define KSU_IOC_SIZE(op) ((uint32_t)(((op) >> 16) & 0x3FFFu))
#define KSU_IOC_DIR(op)  ((uint32_t)(((op) >> 30) & 0x3u))

/* 代理 socket 路径与协议版本
 *
 * 为什么需要多个候选路径
 * ----------------------
 * 管理器 App 运行在 untrusted_app 域，而 /data/adb 是 0700(root)。
 * 非 root 进程连该目录都无法穿越 —— 这是 **DAC** 层面的拒绝，发生在
 * SELinux 之前。旧注释「目录 /data/adb 仍是 0700(root)，进程要过 SELinux
 * 才能到这里」把 DAC 与 SELinux 混为一谈，导致 socket 对唯一的目标客户端
 * （App）根本不可达，方案2 因此从未真正跑通。
 *
 * 对策：daemon 把所有候选路径都监听上，客户端按序尝试连接，
 * 由实测决定哪条能同时通过 DAC 与 SELinux 检查。 */
#define KSU_SHIM_SOCKET_PATH "/data/adb/ksu_shim.sock" /* 兼容保留（root 客户端） */
#define KSU_SHIM_READY_PATH  "/data/adb/ksu_shim.ready"
#define KSU_SHIM_SOCKET_LIST                     \
    "/data/data/me.weishu.kernelsu/ksu_shim.sock", \
    "/data/local/tmp/ksu_shim.sock",             \
    "/data/adb/ksu_shim.sock"

#define KSU_SHIM_PROTO_MAGIC 0x4B53554Du /* "KSUM" */
#define KSU_SHIM_PROTO_VERSION 1u

/* 专用 op：请求把**真实**驱动 fd 经 SCM_RIGHTS 传给客户端。
 * 值落在 ioctl 空间之外，不会与 K 类命令混淆。
 *
 * 为什么需要它：伪装 fd（shim socket 的 dup）内核 readlink 是 "socket:[N]"，
 * 要骗过 libksud 的 scan_driver_fd() 只能覆盖 readlink()；而 bionic 的符号
 * 查找顺序是「本库 → 本地组 → 全局组」，libc 位于 libksud 自身的 DT_NEEDED
 * 本地组中，会先于全局组命中，RTLD_GLOBAL 并不能保证抢先。
 * 直接交付真 fd 后，/proc/self/fd 中出现的是内核原生的
 * anon_inode:[ksu_driver]，扫描天然命中，ioctl 亦直通驱动。 */
#define KSU_SHIM_OP_GET_DRIVER_FD 0xFFFF0001u

/* 代理请求头：客户端 -> 守护进程 */
struct shim_req {
    uint32_t magic;  /* KSU_SHIM_PROTO_MAGIC */
    uint32_t version;/* KSU_SHIM_PROTO_VERSION */
    uint32_t op;     /* ioctl 命令号 */
    uint32_t len;    /* payload 长度（<= SHIM_MAX_PAYLOAD） */
    /* 其后紧跟 len 字节 payload */
};

/* 代理响应头：守护进程 -> 客户端 */
struct shim_rsp {
    int32_t  ret;    /* ioctl 返回值，或 -errno */
    uint32_t len;    /* 回填的 payload 长度 */
    /* 其后紧跟 len 字节 payload */
};

#define SHIM_MAX_PAYLOAD 8192

/* ---------------------------------------------------------------------------
 * 编译期 ABI 断言 —— 防止结构体布局再次静默漂移。
 * 一旦上游 uapi 变更或本地误改，编译会立刻失败而不是运行时破坏内核内存。
 * ------------------------------------------------------------------------- */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16,
               "ksu_get_info_cmd must be 16 bytes");
_Static_assert(sizeof(struct root_profile) == 248,
               "root_profile must be 248 bytes");
_Static_assert(sizeof(struct app_profile) == 784,
               "app_profile must be 784 bytes");
_Static_assert(sizeof(struct ksu_get_feature_cmd) == 24,
               "ksu_get_feature_cmd must be 24 bytes");
_Static_assert(sizeof(struct ksu_uid_granted_root_cmd) == 8,
               "ksu_uid_granted_root_cmd must be 8 bytes");
_Static_assert(sizeof(struct ksu_manage_mark_cmd) == 12,
               "ksu_manage_mark_cmd must be 12 bytes");
#endif

#endif /* GHOSTLOCK_KSU_UAPI_H */
