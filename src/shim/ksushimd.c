/*
 * ksushimd.c — KSUShim 代理守护进程
 * ---------------------------------------------------------------------------
 * 背景（为什么需要它）
 *
 * Android 16 (OriginOS 5) 的 app.policy seccomp 过滤器封禁了 syscall 142
 * (__NR_reboot)。KernelSU 的驱动 fd 正是通过 reboot 系统调用 hook 下发的：
 *
 *   内核侧 (kernel/supercall/supercall.c):
 *     reboot_handler_pre() 检查 magic1==0xDEADBEEF && magic2==0xCAFEBABE，
 *     命中则 task_work_add(ksu_install_fd_tw_func)，
 *     由 ksu_install_fd() 用 anon_inode_getfile("[ksu_driver]") + fd_install()
 *     把驱动 fd 装进 **当前进程** 的 fd 表，并把 fd 号写回用户提供的第 4 参数。
 *
 *   用户侧 (ksud/src/ksucalls.rs):
 *     init_driver_fd() 先 scan_driver_fd() 扫 /proc/self/fd（找 "[ksu_driver]"），
 *     扫不到才退化成 libc::syscall(SYS_reboot, MAGIC1, MAGIC2, 0, &fd)。
 *
 * 关键洞察 —— 这决定了整个方案：
 *   驱动 fd 是 anon_inode 文件描述符（O_RDWR），**不带 O_CLOEXEC 之外的限制，
 *   且可跨 fork 继承**。一旦**任何**进程持有它，就能直接 ioctl() 走
 *   ksu_supercall_handle_ioctl()，完全不需要再碰 syscall 142。
 *
 *   所以：让一个**不受该 seccomp 策略约束**的 root 进程（我们的 shim 守护）去
 *   完成握手并长期持有该 fd，然后通过 Unix domain socket 把 ioctl 转发给
 *   管理器 App —— App 侧永远不碰 syscall 142，SIGSYS 链条被彻底切断。
 *
 * 安全边界（务必遵守）
 *   1. 只转发 KSU_SHIM_ALLOWED() 判定通过的 op。GRANT_ROOT / GET_WRAPPER_FD /
 *      NUKE_EXT4_SYSFS / SET_INIT_PGRP / DISABLE_ESCAPE_TO_ROOT 一律拒绝。
 *   2. 不做 uid 伪造。内核在做提权判定时读取的是「真正发起 ioctl 的进程 cred」，
 *      而经代理后发起者是 shim（root）。因此**必须**由 shim 自己执行 uid 校验：
 *      只有 connect 时 uid 位于允许集合（默认 0 与管理器 uid）才放行写类 op。
 *      只读 op 对所有调用者开放，便于其他工具做状态探测。
 *   3. socket 放在 /data/adb/（0700 目录），文件 mode 0600，并显式 fchown 到
 *      root:root；通过 SO_PEERCRED 取真实 uid，绝不信任 payload 里的自称。
 *
 * 编译（NDK）:
 *   aarch64-linux-android35-clang -O2 -static -o ksushimd ksushimd.c
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "ksu_uapi.h"

#ifndef __NR_reboot
#define __NR_reboot 142
#endif

#define LOG_TAG "ksushimd"

/* ------------------------------------------------------------------ 日志 */
static int g_log_fd = -1;      /* 优先写 stderr；无效时退回 /dev/kmsg */
static bool g_verbose = false;

static void log_line(const char *level, const char *fmt, ...) {
    char buf[768];
    int n = snprintf(buf, sizeof(buf), "[%s] %s: ", LOG_TAG, level);
    if (n < 0 || n >= (int)sizeof(buf)) return;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0) return;

    size_t len = strnlen(buf, sizeof(buf));
    if (len < sizeof(buf) - 1) buf[len++] = '\n';

    if (g_log_fd >= 0) {
        ssize_t w = write(g_log_fd, buf, len);
        (void)w;
    }
    /* 同时落盘，便于事后取证（App 侧读不到 stderr） */
    int fd = open("/data/adb/ksu_shim.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, buf, len);
        (void)w;
        close(fd);
    }
}

#define LOGI(...) log_line("I", __VA_ARGS__)
#define LOGE(...) log_line("E", __VA_ARGS__)
#define LOGW(...) log_line("W", __VA_ARGS__)
#define LOGV(...) do { if (g_verbose) log_line("V", __VA_ARGS__); } while (0)

/* ------------------------------------------------------ 驱动 fd 获取 */
/*
 * 三级回退策略，按「不触发 seccomp」优先：
 *   1. 已有 env / 继承的 fd（GHOSTLOCK_KSU_FD）——ghostlock 主进程若已持有，
 *      可直接继承，零 syscall。
 *   2. 扫 /proc/self/fd 找 "[ksu_driver]" —— 若 ghostlock 已 fork 前拿到过。
 *   3. 自己发 reboot(MAGIC1, MAGIC2) 握手 —— shim 是 root 且不受 app.policy
 *      约束（app.policy 是 untrusted_app 域的过滤器），此路通常畅通。
 */
static int scan_driver_fd(void) {
    const char *name = "[ksu_driver]";

    /* 不引 dirent 依赖，用 getdents64 手工遍历更可控 */
    int dfd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;

    char buf[4096];
    int found = -1;
    for (;;) {
        long nread = syscall(SYS_getdents64, dfd, buf, sizeof(buf));
        if (nread <= 0) break;
        for (long off = 0; off < nread;) {
            /* struct linux_dirent64 { u64 ino; s64 off; u16 reclen; u8 type; char name[]; } */
            unsigned short reclen = *(unsigned short *)(buf + off + 16);
            char *dname = buf + off + 19;
            if (reclen == 0) { off = nread; break; }

            if (dname[0] != '.') {
                char *end = NULL;
                long fdnum = strtol(dname, &end, 10);
                if (end && *end == '\0' && fdnum >= 0) {
                    char path[64], target[512];
                    snprintf(path, sizeof(path), "/proc/self/fd/%ld", fdnum);
                    ssize_t t = readlink(path, target, sizeof(target) - 1);
                    if (t > 0) {
                        target[t] = '\0';
                        /* 匹配 "[ksu_driver]" 与 "[ksu_driver_su]" */
                        if (strstr(target, name)) { found = (int)fdnum; break; }
                    }
                }
            }
            off += reclen;
        }
        if (found >= 0) break;
    }
    close(dfd);
    return found;
}

/* reboot 握手：内核 hook 会把 ksu_driver 的 fd 写进第 4 个参数指向的 int。
 *
 * ⚠ 2026-09-19 修复：旧实现信任 ret != 0 之外的一切，直接把 fd 返回，
 * 结果在「hook 未命中」时返回未初始化的 fd（实测拿到过 fd=3，实为
 * /proc/<pid>/fd 目录句柄），后续 ioctl 报 ENOTTY 被误读成「内核不支持」。
 * 现在改为：无论返回值如何，都必须用 readlink("/proc/self/fd/N") 验证该 fd
 * 确实指向 "[ksu_driver]" 才认账。 */
static int install_driver_fd_via_reboot(void) {
    int fd = -1;
    long ret = syscall(__NR_reboot, (long)KSU_INSTALL_MAGIC1, (long)KSU_INSTALL_MAGIC2, 0L, &fd);
    LOGV("reboot handshake returned %ld (errno=%d) fd=%d", ret, errno, fd);

    if (fd < 0) return -1;

    /* 必须真是指向 ksu_driver 的 fd，否则是垃圾值 */
    char path[64], target[512];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t t = readlink(path, target, sizeof(target) - 1);
    if (t <= 0) {
        LOGW("reboot handshake gave fd=%d but it is not open", fd);
        return -1;
    }
    target[t] = '\0';
    if (!strstr(target, "[ksu_driver]")) {
        LOGW("reboot handshake gave fd=%d -> \"%s\" (not ksu_driver)", fd, target);
        return -1;
    }

    /* 清 CLOEXEC，保证 fork/exec 后仍可用 */
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl & ~FD_CLOEXEC);

    LOGI("driver fd installed via reboot handshake: %d (%s)", fd, target);
    return fd;
}

static int acquire_driver_fd(void) {
    /* 1) 环境变量显式指定 */
    const char *env = getenv("GHOSTLOCK_KSU_FD");
    if (env && *env) {
        int fd = atoi(env);
        if (fd >= 0 && fcntl(fd, F_GETFD) >= 0) {
            /* 清掉 CLOEXEC，保证自身与后续 fork 都可见 */
            int fl = fcntl(fd, F_GETFD);
            if (fl >= 0) fcntl(fd, F_SETFD, fl & ~FD_CLOEXEC);
            LOGI("driver fd from env: %d", fd);
            return fd;
        }
    }

    /* 2) 扫 fd 表 */
    int fd = scan_driver_fd();
    if (fd >= 0) {
        LOGI("driver fd found by scan: %d", fd);
        return fd;
    }

    /* 3) reboot 握手 */
    LOGI("driver fd not inherited; performing reboot handshake");
    fd = install_driver_fd_via_reboot();
    if (fd >= 0) {
        return fd;
    }

    LOGE("all driver-fd acquisition paths failed");
    return -1;
}

/* ------------------------------------------------ 权限校验与转发 */
/* 允许写类 op 的 uid 集合：默认 root(0) + 管理器 uid（由启动参数注入） */
static uint32_t g_allowed_uids[8];
static int g_allowed_count = 0;

static bool uid_may_write(uint32_t uid) {
    if (uid == 0) return true;
    for (int i = 0; i < g_allowed_count; i++)
        if (g_allowed_uids[i] == uid) return true;
    return false;
}

static void add_allowed_uid(uint32_t uid) {
    if (uid == 0) return;
    for (int i = 0; i < g_allowed_count; i++)
        if (g_allowed_uids[i] == uid) return;
    if (g_allowed_count < (int)(sizeof(g_allowed_uids) / sizeof(g_allowed_uids[0])))
        g_allowed_uids[g_allowed_count++] = uid;
}

/* 找 KernelSU 管理器的 uid。
 *
 * 权威来源是 /data/system/packages.list（Android 的 uid 映射表），格式：
 *     <pkg> <uid> <debuggable> <dataDir> <seinfo> <gids> ...
 * 注意：不要走 /data/app 目录属主 —— 那里所有 base.apk 属主都是 system(1000)，
 * 拿不到真实应用 uid；也不要走 pm / cmd package / dumpsys，它们在
 * late-load 后的 root shell 里常常返回空（实测）。 */
static const char *const g_mgr_pkgs[] = {
    "me.weishu.kernelsu",
    "com.resukisu.resukisu",
    "me.bmax.apatch",
};

/* 备选：目录名里带这些关键字的包，命中即取 */
static const char *const g_mgr_hints[] = {
    "kernelsu", "resukisu", "supermanager",
};

static uint32_t lookup_uid_in_packages_list(const char *pkg) {
    FILE *fp = fopen("/data/system/packages.list", "r");
    if (!fp) return 0;

    char line[512];
    uint32_t uid = 0;
    size_t plen = strlen(pkg);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, pkg, plen) != 0) continue;
        if (line[plen] != ' ' && line[plen] != '\t') continue;

        char *p = line + plen;
        while (*p == ' ' || *p == '\t') p++;
        uid = (uint32_t)strtoul(p, NULL, 10);
        if (uid != 0) break;
    }
    fclose(fp);
    return uid;
}

static uint32_t discover_manager_uid(void) {
    /* 1) 精确包名 */
    for (size_t i = 0; i < sizeof(g_mgr_pkgs) / sizeof(g_mgr_pkgs[0]); i++) {
        uint32_t u = lookup_uid_in_packages_list(g_mgr_pkgs[i]);
        if (u != 0) {
            LOGI("manager pkg %s -> uid=%u", g_mgr_pkgs[i], u);
            return u;
        }
    }

    /* 2) 模糊：扫 packages.list 第一列，命中关键字即取 */
    FILE *fp = fopen("/data/system/packages.list", "r");
    if (!fp) return 0;

    char line[512];
    uint32_t uid = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t n = strcspn(line, " \t");
        if (n == 0 || n >= sizeof(line)) continue;

        char pkg[256];
        if (n >= sizeof(pkg)) continue;
        memcpy(pkg, line, n);
        pkg[n] = '\0';

        bool hit = false;
        for (size_t i = 0; i < sizeof(g_mgr_hints) / sizeof(g_mgr_hints[0]); i++) {
            if (strstr(pkg, g_mgr_hints[i])) { hit = true; break; }
        }
        if (!hit) continue;

        char *p = line + n;
        while (*p == ' ' || *p == '\t') p++;
        uid = (uint32_t)strtoul(p, NULL, 10);
        if (uid != 0) {
            LOGI("manager pkg (fuzzy) %s -> uid=%u", pkg, uid);
            break;
        }
    }
    fclose(fp);
    return uid;
}

static ssize_t read_full(int fd, void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, (char *)buf + done, len - done);
        if (r <= 0) return done ? (ssize_t)done : r;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

static ssize_t write_full(int fd, const void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, (const char *)buf + done, len - done);
        if (w <= 0) return w;
        done += (size_t)w;
    }
    return (ssize_t)done;
}

static void handle_client(int cfd, int drv_fd, uint32_t dir_uid) {
    struct ucred cred;
    socklen_t clen = sizeof(cred);
    uint32_t peer_uid = (uint32_t)-1;
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0) {
        peer_uid = (uint32_t)cred.uid;
    }
    /* 连接可观测性：没有这行，客户端连没连上只能靠猜 */
    LOGI("client connected uid=%u", peer_uid);

    struct shim_req req;
    if (read_full(cfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        LOGV("short request from uid=%u", peer_uid);
        return;
    }
    if (req.magic != KSU_SHIM_PROTO_MAGIC || req.version != KSU_SHIM_PROTO_VERSION) {
        LOGE("bad protocol header from uid=%u (magic=0x%x ver=%u)",
             peer_uid, req.magic, req.version);
        return;
    }
    if (req.len > SHIM_MAX_PAYLOAD) {
        LOGE("oversized payload %u from uid=%u", req.len, peer_uid);
        return;
    }

    /* 专用 op：把真实驱动 fd 经 SCM_RIGHTS 交给客户端。
     * 客户端拿到的是内核原生的 anon_inode:[ksu_driver]，
     * scan_driver_fd() 用 readlink 即可命中，无需任何符号 hook；
     * 其 ioctl 也直通驱动，不必再经本进程逐条转发。 */
    if (req.op == KSU_SHIM_OP_GET_DRIVER_FD) {
        struct shim_rsp rsp;
        memset(&rsp, 0, sizeof(rsp));

        /* 鉴权：root、已配置的 allow 集合，或 **socket 所在目录的属主**。
         * 最后一条是关键 —— 管理器私有目录 /data/data/me.weishu.kernelsu 是
         * 0700，只有该 app 与 root 能穿越并连上这个 socket；能连上本身就是
         * 身份证明，无需人工配置，也不受 pm 输出里 appId / fullUid 差异影响。 */
        bool allowed = (peer_uid == 0) ||
                       (dir_uid != 0 && peer_uid == dir_uid) ||
                       uid_may_write(peer_uid);
        if (!allowed) {
            rsp.ret = -EPERM;
            LOGW("uid=%u refused driver fd (dir_uid=%u allow-set=%d)",
                 peer_uid, dir_uid, g_allowed_count);
            write_full(cfd, &rsp, sizeof(rsp));
            return;
        }
        if (drv_fd < 0) {
            rsp.ret = -EBADF;
            LOGE("driver fd unavailable for uid=%u", peer_uid);
            write_full(cfd, &rsp, sizeof(rsp));
            return;
        }

        int dupfd = dup(drv_fd);
        if (dupfd < 0) {
            rsp.ret = -errno;
            LOGE("dup(driver fd) failed errno=%d", errno);
            write_full(cfd, &rsp, sizeof(rsp));
            return;
        }

        rsp.ret = 0;
        rsp.len = 0;

        struct iovec io;
        io.iov_base = &rsp;
        io.iov_len = sizeof(rsp);

        char cbuf[CMSG_SPACE(sizeof(int))];
        memset(cbuf, 0, sizeof(cbuf));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &dupfd, sizeof(int));

        ssize_t sent = sendmsg(cfd, &msg, 0);
        LOGI("driver fd sent to uid=%u (dup=%d sendmsg=%zd)", peer_uid, dupfd, sent);
        close(dupfd);
        return;
    }

    uint8_t payload[SHIM_MAX_PAYLOAD];
    if (req.len && read_full(cfd, payload, req.len) != (ssize_t)req.len) {
        LOGE("truncated payload from uid=%u", peer_uid);
        return;
    }

    const uint32_t op = req.op;
    const uint32_t nr = KSU_IOC_NR(op);
    const uint32_t type = KSU_IOC_TYPE(op);

    struct shim_rsp rsp = { .ret = -EPERM, .len = req.len };

    if (type != (uint32_t)'K') {
        LOGE("uid=%u rejected: bad ioctl type 0x%x", peer_uid, type);
        rsp.ret = -ENOTTY;
        goto reply;
    }

    /* 读取方向 op：GET_INFO / GET_FEATURE 等，内核写入结构体 */
    if (KSU_SHIM_ALLOW_READONLY(op)) {
        LOGV("uid=%u ro op nr=%u", peer_uid, nr);
        /* fallthrough to ioctl */
    } else if (KSU_SHIM_FORBIDDEN(op)) {
        LOGE("uid=%u DENIED forbidden op nr=%u", peer_uid, nr);
        rsp.ret = -EPERM;
        goto reply;
    } else if (KSU_SHIM_ALLOW_CONFIG(op)) {
        if (!uid_may_write(peer_uid)) {
            LOGE("uid=%u DENIED config op nr=%u (not in allow set)", peer_uid, nr);
            rsp.ret = -EPERM;
            goto reply;
        }
        LOGV("uid=%u cfg op nr=%u", peer_uid, nr);
    } else {
        LOGE("uid=%u DENIED unknown op 0x%08x (nr=%u)", peer_uid, op, nr);
        rsp.ret = -ENOTTY;
        goto reply;
    }

    {
        int ret = ioctl(drv_fd, (unsigned long)op, payload);
        rsp.ret = ret;
        if (ret < 0) {
            LOGV("ioctl nr=%u failed errno=%d", nr, errno);
        }
        /* 写方向的 op 需要回填；读方向恒回填以便客户端取结果 */
        rsp.len = req.len;
    }

reply:
    if (write_full(cfd, &rsp, sizeof(rsp)) != (ssize_t)sizeof(rsp)) return;
    if (rsp.len && write_full(cfd, payload, rsp.len) != (ssize_t)rsp.len) {
        LOGV("failed to return payload to uid=%u", peer_uid);
    }
}

/* 每个连接一个线程，避免单客户端阻塞整个代理 */
struct client_arg {
    int cfd;
    int drv_fd;
    uint32_t dir_uid;   /* 该监听 socket 所在目录的属主（0 = 未知） */
};

static void *client_thread(void *p) {
    struct client_arg *a = p;
    handle_client(a->cfd, a->drv_fd, a->dir_uid);
    close(a->cfd);
    free(a);
    return NULL;
}

/* -------------------------------------------- 一次性 helper 模式
 *
 * 新版 KernelSU (3.3.0 / uapi 4) 已移除 CLI 授权命令
 * （旧版 `ksud profile allow <uid>` 不复存在），授权只能写 app_profile。
 * 为了给 grant-app.ps1 提供零 GUI 的授权通路，这里内建三个一次性子命令：
 *
 *   --grant-uid <uid> [--pkg <name>]   置 allow_su=1 并下发 SET_APP_PROFILE
 *   --revoke-uid <uid>                 置 allow_su=0 并下发
 *   --query-uid <uid>                  回读并打印 allow_su
 *
 * 这比自己写一个独立二进制省事，且天然复用同一份 uapi 定义与驱动 fd 获取逻辑。
 */
static int helper_set_profile(int drv_fd, uint32_t uid, const char *pkg, int grant) {
    struct ksu_set_app_profile_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.profile.version = KSU_APP_PROFILE_VER;
    cmd.profile.curr_uid = (int32_t)uid;
    cmd.profile.allow_su = grant ? 1 : 0;
    if (pkg && *pkg) {
        strncpy(cmd.profile.key, pkg, sizeof(cmd.profile.key) - 1);
    } else {
        /* 无包名时用 uid 字符串作 key，内核接受非包名 key */
        snprintf(cmd.profile.key, sizeof(cmd.profile.key), "uid:%u", uid);
    }

    if (grant) {
        /* 授予 root：使用默认模板，内核会填充 uid/gid/domain */
        cmd.profile.rp_config.use_default = 1;
        cmd.profile.rp_config.profile.uid = 0;
        cmd.profile.rp_config.profile.gid = 0;
        cmd.profile.rp_config.profile.namespaces = 0;
        cmd.profile.rp_config.profile.groups_count = 0;
        /* 保持内核默认：不额外设置 capabilities/flags */
    } else {
        cmd.profile.nrp_config.use_default = 1;
        cmd.profile.nrp_config.profile.umount_modules = 0;
    }

    int ret = ioctl(drv_fd, KSU_IOCTL_SET_APP_PROFILE, &cmd);
    if (ret < 0) {
        printf("SET_APP_PROFILE failed errno=%d\n", errno);
        return 1;
    }
    printf("SET_APP_PROFILE ok uid=%u key=%s allow_su=%d\n", uid, cmd.profile.key, grant);
    return 0;
}

static int helper_query_profile(int drv_fd, uint32_t uid, const char *pkg) {
    struct ksu_get_app_profile_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.profile.curr_uid = (int32_t)uid;
    if (pkg && *pkg) {
        strncpy(cmd.profile.key, pkg, sizeof(cmd.profile.key) - 1);
    } else {
        snprintf(cmd.profile.key, sizeof(cmd.profile.key), "uid:%u", uid);
    }

    int ret = ioctl(drv_fd, KSU_IOCTL_GET_APP_PROFILE, &cmd);
    if (ret < 0) {
        printf("GET_APP_PROFILE failed errno=%d\n", errno);
        return 1;
    }
    printf("uid=%u key=%s allow_su=%d\n",
           uid, cmd.profile.key, cmd.profile.allow_su);
    return 0;
}

/* ---------------------------------------- 动态管理器签名下发（helper）
 *
 * 背景（2026-09-19 逆向结论，详见 docs/2026-09-19_证书白名单判定链最终定论.md）：
 *   本机内核 kernelsu-vivo.ko (v4.2.0-rc1@ReSukiSU) 的 apk_sign_keys[] 只认
 *   6 种「证书 DER 长度 + sha256」组合：
 *     ReSukiSU  0x377(887) / OFFICIAL 0x33b(827) / MKSU 384
 *     RKSU      0x396(918) / SukiSU   0x35c(860) / KowSU 0x375(885)
 *   长度不匹配则连哈希比较都不会做 —— 直接 return false。
 *   GhostLock 自签证书长度 1391、官方 KernelSU release 也是 1391，
 *   都不在表内，故 Root 管理器始终显示「未安装」。
 *
 *   内核内建有 dynamic_manager 旁路（feature/dynamic_manager.c）：
 *   只要通过 KSU_IOCTL_DYNAMIC_MANAGER 下发 (size, hash)，
 *   check_block() 会在静态白名单未命中后回退比对该动态签名，
 *   命中则 matched_index = 255（KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER）。
 *   内核侧 perm_check = only_root —— 本 shim 正好是 uid 0。
 *
 *   注意：内核没有 ksu_load_dynamic_manager()（本版本符号表可见），
 *   意味着该配置不跨重启持久化，每次 late-load 后需重新下发。
 *
 * 用法：
 *   ksushimd --set-dynamic-manager <size_dec> <hash64_hex>
 *   ksushimd --get-dynamic-manager
 *   ksushimd --wipe-dynamic-manager
 */
static int helper_dynamic_manager(int drv_fd, int op, uint32_t size, const char *hash) {
    struct ksu_dynamic_manager_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.operation = (uint8_t)op;

    if (op == KSU_DYNAMIC_MANAGER_OP_SET ||
        op == KSU_DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS) {
        if (!hash || strlen(hash) != 64) {
            printf("hash must be exactly 64 lowercase hex chars\n");
            return 1;
        }
        if (size < 0x100 || size > 0x1000) {
            printf("size out of range (kernel requires 0x100..0x1000): 0x%x\n", size);
            return 1;
        }
        cmd.size = size;
        memcpy(cmd.hash, hash, 64);
    }

    int ret = ioctl(drv_fd, KSU_IOCTL_DYNAMIC_MANAGER, &cmd);
    int err = errno;
    if (ret < 0) {
        /* -ENOTTY 表示内核没有注册该 ioctl；-EINVAL 表示参数被内核拒绝 */
        printf("DYNAMIC_MANAGER op=%d failed ret=%d errno=%d (%s)\n",
               op, ret, err, strerror(err));
        return 1;
    }

    if (op == KSU_DYNAMIC_MANAGER_OP_GET) {
        printf("DYNAMIC_MANAGER size=0x%x (%u) hash=%.64s\n",
               cmd.size, cmd.size, (char *)cmd.hash);
    } else if (op == KSU_DYNAMIC_MANAGER_OP_WIPE) {
        printf("DYNAMIC_MANAGER wiped\n");
    } else {
        printf("DYNAMIC_MANAGER set ok: size=0x%x (%u) hash=%.64s\n",
               size, size, hash);
    }
    return 0;
}

/* ------------------------------------------------------------ 启动 */
static int setup_socket(const char *path) {
    /* /data/adb 确保存在且属主 root，避免他人抢占 socket 路径 */
    mkdir("/data/adb", 0700);
    chmod("/data/adb", 0700);

    unlink(path);

    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) {
        LOGE("socket() failed errno=%d", errno);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        LOGE("socket path too long");
        close(sfd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    /* umask 保证 socket 刚创建即 0600，不给竞态窗口 */
    mode_t old_mask = umask(0077);
    int r = bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_mask);
    if (r < 0) {
        LOGE("bind(%s) failed errno=%d", path, errno);
        close(sfd);
        return -1;
    }

    /* socket 必须让 App(非 root) 连得上，否则代理毫无意义。
     * 鉴权不靠文件权限，而是靠 SO_PEERCRED + op 白名单：
     *   - 未在 allow 集合里的 uid 只能做只读查询；
     *   - 禁写类 op 一律 -EPERM。
     * 目录 /data/adb 仍是 0700(root)，进程要过 SELinux 才能到这里。 */
    chmod(path, 0666);
    /* 显式 chown 到 root:root——即使被误以其他 uid 启动也纠正过来 */
    if (chown(path, 0, 0) < 0) {
        LOGV("chown(%s) errno=%d (可能非 root，忽略)", path, errno);
    }

    if (listen(sfd, 8) < 0) {
        LOGE("listen() failed errno=%d", errno);
        close(sfd);
        return -1;
    }
    return sfd;
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv) {
    g_log_fd = STDERR_FILENO;

    /* 一次性 helper 模式参数 */
    int   mode = 0;              /* 0=daemon 1=grant 2=revoke 3=query
                                  * 4=set-dynmgr 5=get-dynmgr 6=wipe-dynmgr */
    uint32_t mode_uid = 0;
    const char *mode_pkg = NULL;
    uint32_t dyn_size = 0;
    const char *dyn_hash = NULL;
    int dyn_sync = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            g_verbose = true;
        } else if (!strcmp(argv[i], "--allow-uid") && i + 1 < argc) {
            add_allowed_uid((uint32_t)strtoul(argv[++i], NULL, 10));
        } else if (!strcmp(argv[i], "--socket") && i + 1 < argc) {
            /* 预留：允许自定义 socket 路径 */
            (void)argv[++i];
        } else if (!strcmp(argv[i], "--grant-uid") && i + 1 < argc) {
            mode = 1;
            mode_uid = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--revoke-uid") && i + 1 < argc) {
            mode = 2;
            mode_uid = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--query-uid") && i + 1 < argc) {
            mode = 3;
            mode_uid = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--set-dynamic-manager") && i + 2 < argc) {
            /* --set-dynamic-manager <size_dec> <hash64_hex> */
            mode = 4;
            dyn_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            dyn_hash = argv[++i];
        } else if (!strcmp(argv[i], "--set-dynamic-manager-sync") && i + 2 < argc) {
            /* 同上，但要求内合同步重新扫描 /data/app 并立即登记管理器 */
            mode = 4;
            dyn_sync = 1;
            dyn_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            dyn_hash = argv[++i];
        } else if (!strcmp(argv[i], "--get-dynamic-manager")) {
            mode = 5;
        } else if (!strcmp(argv[i], "--wipe-dynamic-manager")) {
            mode = 6;
        } else if (!strcmp(argv[i], "--pkg") && i + 1 < argc) {
            mode_pkg = argv[++i];
        }
    }

    signal(SIGPIPE, SIG_IGN);

    /* helper 模式：拿 fd -> 执行一次性操作 -> 退出（不建 socket） */
    if (mode != 0) {
        int drv_fd = acquire_driver_fd();
        if (drv_fd < 0) {
            printf("no KernelSU driver fd (late-load 未完成?)\n");
            return 1;
        }
        if (mode == 1) return helper_set_profile(drv_fd, mode_uid, mode_pkg, 1);
        if (mode == 2) return helper_set_profile(drv_fd, mode_uid, mode_pkg, 0);
        if (mode == 3) return helper_query_profile(drv_fd, mode_uid, mode_pkg);
        if (mode == 4) return helper_dynamic_manager(
            drv_fd,
            dyn_sync ? KSU_DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS : KSU_DYNAMIC_MANAGER_OP_SET,
            dyn_size, dyn_hash);
        if (mode == 5) return helper_dynamic_manager(
            drv_fd, KSU_DYNAMIC_MANAGER_OP_GET, 0, NULL);
        return helper_dynamic_manager(drv_fd, KSU_DYNAMIC_MANAGER_OP_WIPE, 0, NULL);
    }

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGHUP, SIG_IGN);

    LOGI("starting (uid=%d, euid=%d)", getuid(), geteuid());

    int drv_fd = acquire_driver_fd();
    if (drv_fd < 0) {
        LOGE("no KernelSU driver fd; aborting (late-load 未完成?)");
        return 1;
    }

    /* 自检：用 GET_INFO 验证 fd 确实可用 */
    {
        struct ksu_get_info_cmd info;
        memset(&info, 0, sizeof(info));
        if (ioctl(drv_fd, KSU_IOCTL_GET_INFO, &info) == 0) {
            LOGI("driver ok: version=%u uapi=%u flags=0x%x features=%u",
                 info.version, info.uapi_version, info.flags, info.features);
        } else {
            struct ksu_get_info_legacy_cmd legacy;
            memset(&legacy, 0, sizeof(legacy));
            if (ioctl(drv_fd, KSU_IOCTL_GET_INFO_LEGACY, &legacy) == 0) {
                LOGI("driver ok (legacy): version=%u flags=0x%x",
                     legacy.version, legacy.flags);
            } else {
                LOGE("GET_INFO failed errno=%d; driver fd unusable", errno);
                return 1;
            }
        }
    }

    /* 默认放行管理器 uid（若调用方通过 --allow-uid 注入则叠加） */
    {
        int32_t mgr = -1;   /* 必须用有符号：未登记时内核回 -1 (0xFFFFFFFF) */
        if (ioctl(drv_fd, KSU_IOCTL_GET_MANAGER_APPID, &mgr) == 0 && mgr > 0) {
            /* GET_MANAGER_APPID 返回 appid；Android appid 即 uid 的别名 */
            add_allowed_uid((uint32_t)mgr);
            LOGI("manager appid=%d added to write-allow set", mgr);
        } else {
            LOGI("manager not registered in kernel (appid=%d errno=%d); "
                 "falling back to packages.list scan", mgr, errno);
        }
    }

    /* 兜底：内核没登记管理器时（late-load --package-name none），
     * 直接扫 /data/app 找管理器 uid。root 下读 package 的 uid 可靠，
     * 不依赖 pm（pm 在 root shell 下常返回空）。 */
    if (g_allowed_count == 0) {
        uint32_t found = discover_manager_uid();
        if (found != 0) {
            add_allowed_uid(found);
            LOGI("manager uid=%u discovered from packages.list", found);
        } else {
            LOGW("no manager uid found; write ops will be denied until "
                 "--allow-uid is supplied");
        }
    }

    /* 监听所有候选路径。
     * 单一路径 /data/adb/ksu_shim.sock 对本 daemon 的唯一目标客户端（App）
     * 不可达：/data/adb 是 0700(root)，untrusted_app 在 DAC 层即无法穿越，
     * 根本轮不到 SELinux 表态。因此必须同时提供 App 真能到达的通道。 */
    static const char *listen_paths[] = { KSU_SHIM_SOCKET_LIST };
    const int n_paths = (int)(sizeof(listen_paths) / sizeof(listen_paths[0]));
    int lfds[8];
    uint32_t dir_uids[8];
    int nlfds = 0;

    for (int i = 0; i < n_paths && nlfds < (int)(sizeof(lfds) / sizeof(lfds[0])); i++) {
        int fd = setup_socket(listen_paths[i]);
        if (fd < 0) {
            LOGW("listen skipped (unreachable?): %s", listen_paths[i]);
            continue;
        }
        /* 记录 socket 所在目录的属主：0799 私有目录的 owner 就是管理器 uid */
        uint32_t du = 0;
        const char *slash = strrchr(listen_paths[i], '/');
        if (slash) {
            char dirbuf[256];
            size_t dl = (size_t)(slash - listen_paths[i]);
            if (dl > 0 && dl < sizeof(dirbuf)) {
                memcpy(dirbuf, listen_paths[i], dl);
                dirbuf[dl] = 0;
                struct stat st;
                if (stat(dirbuf, &st) == 0) du = (uint32_t)st.st_uid;
            }
        }
        lfds[nlfds] = fd;
        dir_uids[nlfds] = du;
        nlfds++;
        LOGI("listening on %s (dir_uid=%u)", listen_paths[i], du);
    }
    if (nlfds == 0) {
        LOGE("no listener could be created; aborting");
        if (drv_fd >= 0) close(drv_fd);
        return 1;
    }
    LOGI("listeners=%d write-allowed uids=%d", nlfds, g_allowed_count);

    /* 通知 init/调用方已就绪：写一行可读的 ready 标记 */
    {
        int rfd = open(KSU_SHIM_READY_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (rfd >= 0) {
            char line[64];
            int n = snprintf(line, sizeof(line), "%d\n", getpid());
            ssize_t w = write(rfd, line, (size_t)n);
            (void)w;
            close(rfd);
        }
    }

    while (!g_stop) {
        struct pollfd pfd[8];
        for (int i = 0; i < nlfds; i++) {
            pfd[i].fd = lfds[i];
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }

        int pr = poll(pfd, (nfds_t)nlfds, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            LOGE("poll failed errno=%d", errno);
            break;
        }
        if (pr == 0) continue;

        for (int i = 0; i < nlfds; i++) {
            if (!(pfd[i].revents & POLLIN)) continue;

            int cfd = accept(lfds[i], NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                LOGE("accept failed errno=%d", errno);
                continue;
            }

            struct client_arg *a = malloc(sizeof(*a));
            if (!a) { close(cfd); continue; }
            a->cfd = cfd;
            a->drv_fd = drv_fd;
            a->dir_uid = dir_uids[i];

            pthread_t th;
            if (pthread_create(&th, NULL, client_thread, a) != 0) {
                LOGE("pthread_create failed; serving inline");
                handle_client(cfd, drv_fd, dir_uids[i]);
                close(cfd);
                free(a);
                continue;
            }
            pthread_detach(th);
        }
    }

    LOGI("shutting down");
    for (int i = 0; i < nlfds; i++) close(lfds[i]);
    for (int i = 0; i < n_paths; i++) unlink(listen_paths[i]);
    if (drv_fd >= 0) close(drv_fd);
    return 0;
}
