/*
 * ksushim_client.c — App 侧代理客户端（JNI 可加载共享库）
 * ---------------------------------------------------------------------------
 * 目标：让 KernelSU 管理器在 **不触发 syscall 142** 的前提下拿到可用驱动 fd。
 *
 * 难点分析
 * --------
 * 管理器通过 libksud.so 的 ksucalls::init_driver_fd() 获取驱动 fd：
 *
 *     fn init_driver_fd() -> Option<RawFd> {
 *         let fd = scan_driver_fd()...;            // 扫 /proc/self/fd 找 "[ksu_driver]"
 *         if fd.is_none() {
 *             libc::syscall(SYS_reboot, MAGIC1, MAGIC2, 0, &mut fd);  // ← 被 seccomp 杀
 *         }
 *         ...
 *     }
 *
 * 也就是说：**只要 scan_driver_fd() 能命中，syscall 142 这条路根本不会被走到。**
 *
 * scan_driver_fd() 的判定依据是 readlink("/proc/self/fd/N") 的结果字符串里
 * 含 "[ksu_driver]"（注意：内核 anon_inode 的名字是 "[ksu_driver]"，
 * 用户态 readlink 看到的是 "anon_inode:[ksu_driver]"）。
 *
 * 因此本客户端要做两件事：
 *   1. 通过 /data/adb/ksu_shim.sock 连到 ksushimd；
 *   2. 构造一个「能被 readlink 读出 anon_inode:[ksu_driver] 名字」且
 *      「ioctl 会被转发到 shim」的本地 fd，并让它出现在本进程的 fd 表中。
 *
 * 实现选择：Unix domain socket 直连 + dup 伪装
 * ------------------------------------------------
 * 纯 socket fd 的 readlink 结果是 "socket:[inode]" 而非 "anon_inode:[ksu_driver]"，
 * 无法骗过 scan_driver_fd()。
 *
 * 所以采用**两层方案**：
 *   (A) 对「支持 env 注入」的场景（我们自己打的补丁 / LD_PRELOAD），
 *       直接导出 shim socket fd 给 libksud.so 复用；
 *   (B) 对「原版 APK 不可改」的场景，用 LD_PRELOAD 拦截 libc 的
 *       syscall()/readlink()/ioctl()，把 reboot 握手改写到 shim 通道，
 *       并把 socket fd 的 readlink 结果伪装成 anon_inode:[ksu_driver]。
 *
 * 本文件实现 (B) 的完整预加载库 —— 这是唯一能对未修改的原版管理器生效的路径。
 * 同时提供 (A) 的显式 API，供我们自己构建的管理器直接调用。
 *
 * 编译:
 *   aarch64-linux-android35-clang -shared -fPIC -O2 -o libksushim.so ksushim_client.c -ldl
 * 使用:
 *   在管理器启动前 export LD_PRELOAD=.../libksushim.so
 *   （或在 App 的 Application.onCreate 前通过 JNI 注入）
 */

#define _GNU_SOURCE
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
#include <sys/un.h>
#include <unistd.h>

#include "ksu_uapi.h"

#ifndef __NR_reboot
#define __NR_reboot 142
#endif

/* ------------------------------------------------------------------ 工具 */
static int g_shim_fd = -1;              /* 与 ksushimd 的长连接 */
static int g_fake_driver_fd = -1;       /* 暴露给 scan_driver_fd 的伪装 fd */
static int g_real_driver_fd = -1;       /* 经 SCM_RIGHTS 取得的真驱动 fd */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_inited = false;

typedef long (*syscall_fn)(long, ...);
typedef int  (*ioctl_fn)(int, int, ...);
typedef ssize_t (*readlink_fn)(const char *, char *, size_t);

static syscall_fn real_syscall = NULL;
static ioctl_fn  real_ioctl = NULL;
static readlink_fn real_readlink = NULL;

/* 诊断输出。
 * 原先受 KSU_SHIM_DEBUG 门控、且只写 /data/local/tmp/ksushim_client.log：
 * App 属 untrusted_app，既拿不到该环境变量、也无权在 /data/local/tmp 建文件
 * （该目录 0711，其他用户只有 x），于是全程静默 —— 排障时看不到任何线索。
 * 改为始终写 logcat（App 本就有权写），并保留文件日志供 root 上下文使用。 */
static void shim_dbg(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    __android_log_write(ANDROID_LOG_INFO, "ksushim", buf);

    int fd = open("/data/local/tmp/ksushim_client.log",
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, buf, strlen(buf));
        (void)w;
        close(fd);
    }
}

/* ------------------------------------------------------- shim 连接 */
/* 候选路径（见 ksu_uapi.h 的说明）：daemon 全部监听，客户端按序尝试。
 * 单一路径 /data/adb/ksu_shim.sock 对本进程不可达 —— 那里是 0700(root)。 */
static const char *g_candidate_paths[] = { KSU_SHIM_SOCKET_LIST };
#define NUM_CANDIDATES \
    ((int)(sizeof(g_candidate_paths) / sizeof(g_candidate_paths[0])))

static int connect_one(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        shim_dbg("connect(%s) failed errno=%d\n", path, e);
        close(fd);
        errno = e;
        return -1;
    }
    /* 该 fd 不能带 CLOEXEC——需要让 ksud 子进程也能继承复用 */
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl & ~FD_CLOEXEC);
    shim_dbg("connected via %s fd=%d\n", path, fd);
    return fd;
}

static int shim_connect(void) {
    for (int i = 0; i < NUM_CANDIDATES; i++) {
        int fd = connect_one(g_candidate_paths[i]);
        if (fd >= 0) return fd;
    }
    shim_dbg("shim_connect: all %d candidate paths failed\n", NUM_CANDIDATES);
    errno = ENOTCONN;
    return -1;
}

static int ensure_shim(void) {
    if (g_shim_fd >= 0) return g_shim_fd;
    g_shim_fd = shim_connect();
    if (g_shim_fd < 0) {
        shim_dbg("shim_connect failed errno=%d\n", errno);
    } else {
        shim_dbg("shim connected fd=%d\n", g_shim_fd);
    }
    return g_shim_fd;
}

/* 通过 SCM_RIGHTS 从 ksushimd 取一份**真实**驱动 fd。
 *
 * 为什么必须如此：伪装 fd 只是 shim socket 的 dup，其内核 readlink 是
 * "socket:[N]"，要骗过 libksud 的 scan_driver_fd() 只能覆盖 readlink()。
 * 但 bionic 的符号查找是「本库 → 本地组 → 全局组」，而 libc 就在 libksud
 * 自身的 DT_NEEDED 本地组里，会先于全局组命中 —— 单靠 RTLD_GLOBAL 并不能
 * 保证抢先。拿到真 fd 后，/proc/self/fd 中出现的就是内核原生的
 * anon_inode:[ksu_driver]，扫描天然命中，ioctl 亦直通驱动。 */
static int obtain_real_driver_fd(void) {
    int sfd = ensure_shim();
    if (sfd < 0) return -1;

    struct shim_req req;
    memset(&req, 0, sizeof(req));
    req.magic = KSU_SHIM_PROTO_MAGIC;
    req.version = KSU_SHIM_PROTO_VERSION;
    req.op = KSU_SHIM_OP_GET_DRIVER_FD;
    req.len = 0;

    if (write(sfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        shim_dbg("fd-req write failed errno=%d\n", errno);
        return -1;
    }

    struct shim_rsp rsp;
    memset(&rsp, 0, sizeof(rsp));

    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));

    struct iovec io;
    io.iov_base = &rsp;
    io.iov_len = sizeof(rsp);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t n = recvmsg(sfd, &msg, 0);
    if (n != (ssize_t)sizeof(rsp)) {
        shim_dbg("fd-req recv failed n=%zd errno=%d\n", n, errno);
        return -1;
    }

    int got = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
         cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
            cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&got, CMSG_DATA(cm), sizeof(int));
            break;
        }
    }

    if (rsp.ret < 0 || got < 0) {
        shim_dbg("driver fd refused ret=%d fd=%d\n", rsp.ret, got);
        if (got >= 0) close(got);
        return -1;
    }

    /* 清掉 CLOEXEC，让这个真驱动 fd 能穿过 execve 被子进程继承。
     *
     * 为什么这是必需的：管理器的所有特权命令都不是在本进程里跑，而是
     *   app → libsu `su`(root shell) → 执行 /data/adb/ksud <cmd>
     * 这条链上有两次 execve。而 app 从 zygote 继承的 seccomp 过滤器会
     * 一直跟着这些子进程（seccomp 不因 setuid 而移除），所以子进程里的
     * ksud 走「重启握手」拿 fd 会被 SIGSYS 杀掉。
     *
     * 结果就是 ksud 拿不到驱动 fd，get_info() 全为 0，表现为：
     *   - 软重启静默跳过（soft_reboot() 里 ensure_uapi_version_matched 失败）
     *   - 模块安装/更新失败
     *
     * fd 不带 CLOEXEC 后，ksud 的 scan_driver_fd() 会在 /proc/self/fd 里
     * 直接扫到这个内核原生的 anon_inode:[ksu_driver]，无需任何握手。 */
    {
        int fl = fcntl(got, F_GETFD);
        if (fl >= 0)
            fcntl(got, F_SETFD, fl & ~FD_CLOEXEC);
    }

    shim_dbg("real driver fd acquired = %d (cloexec cleared)\n", got);
    return got;
}

/* 通过 shim 执行一次 ioctl，返回 ioctl 语义的返回值 */
static int shim_ioctl(unsigned long op, void *payload, size_t len) {
    int sfd = ensure_shim();
    if (sfd < 0) { errno = ENOTCONN; return -1; }
    if (len > SHIM_MAX_PAYLOAD) { errno = EINVAL; return -1; }

    struct shim_req req = {
        .magic = KSU_SHIM_PROTO_MAGIC,
        .version = KSU_SHIM_PROTO_VERSION,
        .op = (uint32_t)op,
        .len = (uint32_t)len,
    };

    if (write(sfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        shim_dbg("write req failed errno=%d\n", errno);
        close(sfd); g_shim_fd = -1;
        errno = EIO;
        return -1;
    }
    if (len && write(sfd, payload, len) != (ssize_t)len) {
        shim_dbg("write payload failed\n");
        close(sfd); g_shim_fd = -1;
        errno = EIO;
        return -1;
    }

    struct shim_rsp rsp;
    ssize_t r = 0;
    while (r < (ssize_t)sizeof(rsp)) {
        ssize_t n = read(sfd, (char *)&rsp + r, sizeof(rsp) - (size_t)r);
        if (n <= 0) {
            shim_dbg("read rsp failed n=%zd\n", n);
            close(sfd); g_shim_fd = -1;
            errno = EIO;
            return -1;
        }
        r += n;
    }

    if (rsp.len && rsp.len <= len) {
        size_t got = 0;
        while (got < rsp.len) {
            ssize_t n = read(sfd, (char *)payload + got, rsp.len - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
    }

    if (rsp.ret < 0) {
        errno = -rsp.ret;
        return -1;
    }
    return rsp.ret;
}

/* ------------------------------------------------- 伪装驱动 fd 的构造 */
/*
 * scan_driver_fd() 用 readlink("/proc/self/fd/N") 的结果做子串匹配。
 * 我们要让某个 fd 的 readlink 结果含 "[ksu_driver]"。
 *
 * 手段：memfd 无法自定义 anon_inode 名字。真正可控的是 **eventfd / epoll /
 * socket 都无法命名**。因此唯一可行的办法是在 LD_PRELOAD 层拦截 readlink()，
 * 对「我们登记过的 fd」返回伪造的 "anon_inode:[ksu_driver]"。
 *
 * 于是 g_fake_driver_fd 实际是一个指向 shim 的 socket/pipe fd，其 readlink
 * 被我们 hook 掉；而它的 ioctl 也被我们要么 hook、要么由 shim 直接接管。
 */
static int make_fake_driver_fd(void) {
    /* 用 shim 连接本身作为伪装 fd：ioctl 已由 ioctl hook 接管转发 */
    int fd = ensure_shim();
    if (fd < 0) return -1;

    /* 复制成独立 fd，避免被调用方意外 close 掉主干连接 */
    int dupfd = fcntl(fd, F_DUPFD_CLOEXEC, 100);
    if (dupfd < 0) {
        shim_dbg("F_DUPFD failed errno=%d\n", errno);
        return -1;
    }
    shim_dbg("fake driver fd = %d (backed by shim %d)\n", dupfd, fd);
    return dupfd;
}

/* ------------------------------------------------------- hook 实现 */
static bool is_fake_driver_fd(int fd) {
    return g_fake_driver_fd >= 0 && fd == g_fake_driver_fd;
}

/* ioctl hook：伪装 fd 上的操作一律走 shim 转发。
 * 注意 bionic 的 ioctl 第二参数是 int（不是 glibc 的 unsigned long），
 * 必须保持一致，否则触发 overloadable 冲突。 */
int ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    unsigned long op = (unsigned long)(unsigned int)request;

    if (is_fake_driver_fd(fd)) {
        /* 只有 'K' 类（KernelSU）命令才转发，其余给 ENOTTY */
        if (KSU_IOC_TYPE(op) == (uint32_t)'K') {
            size_t len = KSU_IOC_SIZE(op);
            if (len == 0) len = SHIM_MAX_PAYLOAD;
            return shim_ioctl(op, arg, len);
        }
        errno = ENOTTY;
        return -1;
    }

    if (!real_ioctl) {
        real_ioctl = (ioctl_fn)dlsym(RTLD_NEXT, "ioctl");
    }
    return real_ioctl(fd, request, arg);
}

/* readlink hook：把伪装 fd 的名字改成 anon_inode:[ksu_driver] */
ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
    if (!real_readlink) {
        real_readlink = (readlink_fn)dlsym(RTLD_NEXT, "readlink");
    }

    if (g_fake_driver_fd >= 0) {
        /* 解析 /proc/self/fd/N 形式 */
        const char *prefix = "/proc/self/fd/";
        size_t plen = strlen(prefix);
        if (strncmp(path, prefix, plen) == 0) {
            char *end = NULL;
            long n = strtol(path + plen, &end, 10);
            if (end && *end == '\0' && is_fake_driver_fd((int)n)) {
                static const char fake[] = "anon_inode:[ksu_driver]";
                size_t l = sizeof(fake) - 1;
                if (bufsiz < l) l = bufsiz;
                memcpy(buf, fake, l);
                return (ssize_t)l;
            }
        }
    }

    return real_readlink(path, buf, bufsiz);
}

/*
 * syscall hook —— 这是切断 SIGSYS 的核心。
 * 必须拦下 reboot(MAGIC1, MAGIC2, 0, &fd) 这种握手形式，改为走 shim，
 * 并把得到的伪装 fd 号写回调用方提供的地址（第 4 参数）。
 */
long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (number == __NR_reboot &&
        (uint32_t)a1 == KSU_INSTALL_MAGIC1 &&
        (uint32_t)a2 == KSU_INSTALL_MAGIC2) {

        pthread_mutex_lock(&g_lock);
        if (g_fake_driver_fd < 0) {
            g_fake_driver_fd = make_fake_driver_fd();
        }
        int fd = g_fake_driver_fd;
        pthread_mutex_unlock(&g_lock);

        shim_dbg("intercepted reboot handshake -> fake fd %d\n", fd);

        if (fd < 0) { errno = EPERM; return -1; }

        /* 内核语义：把 fd 号写回第 4 个参数指向的 int* */
        if (a4) {
            *(int *)(intptr_t)a4 = fd;
        }
        return 0;
    }

    if (!real_syscall) {
        real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

/* --------------------------------------------------- 构造函数与显式 API */

/* 从 /proc/self/maps 取本库被加载的绝对路径 */
static const char *self_mapped_path(void) {
    static char path[512];
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return NULL;
    buf[n] = 0;

    char *p = strstr(buf, "libksushim.so");
    if (!p) return NULL;
    char *line = p;
    while (line > buf && line[-1] != '\n') line--;
    char *slash = strchr(line, '/');
    if (!slash) return NULL;
    char *end = strchr(line, '\n');
    size_t len = end ? (size_t)(end - slash) : strlen(slash);
    if (len == 0 || len >= sizeof(path)) return NULL;
    memcpy(path, slash, len);
    path[len] = 0;
    return path;
}

/* 关键：System.loadLibrary 走 RTLD_LOCAL，本库对 readlink / ioctl 的
 * 覆盖不会进入全局符号组，于是 libksud.so 解析 readlink 时仍命中 libc，
 * 伪装 fd 骗不过 scan_driver_fd()。bionic 对**已加载**的库再次 dlopen
 * 并带 RTLD_GLOBAL 时，会把它提升进全局组，从而让 hook 对之后加载的
 * libksud.so / libkernelsu.so 生效。 */
static void promote_to_global(void) {
    void *h = dlopen("libksushim.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        const char *self = self_mapped_path();
        if (self) h = dlopen(self, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
    }
    shim_dbg("RTLD_GLOBAL promote: %s\n", h ? "ok" : "FAILED");
}

__attribute__((constructor))
static void ksushim_init(void) {
    shim_dbg("ksushim preload loaded pid=%d\n", getpid());
    promote_to_global();

    /* 必须在此主动取真驱动 fd。
     * 原来的「等真正被需要时再连」在本设计下永远不会被触发：显式 API 无人
     * 调用，而 readlink hook 又可能被 libc 抢先。且必须早于 libksud /
     * libkernelsu 的首次 scan_driver_fd() —— 本库在 Application.<init>
     * 中加载，早于任何 UI/JNI 调用，时机正好。 */
    g_real_driver_fd = obtain_real_driver_fd();
    shim_dbg("init done: real_driver_fd=%d shim_fd=%d\n",
             g_real_driver_fd, g_shim_fd);
}

/*
 * 显式 API —— 供我们自己构建/打补丁的管理器直接调用，
 * 无需 LD_PRELOAD，也不必依赖 syscall hook。
 * 返回可用作驱动 fd 的伪装 fd；失败返回 -1。
 */
int ksushim_get_driver_fd(void) {
    pthread_mutex_lock(&g_lock);
    if (g_real_driver_fd < 0) {
        if (!g_inited) {
            g_inited = true;
            ensure_shim();
        }
        g_real_driver_fd = obtain_real_driver_fd();
    }
    int fd = (g_real_driver_fd >= 0) ? g_real_driver_fd
                                     : make_fake_driver_fd();
    pthread_mutex_unlock(&g_lock);
    return fd;
}

/* 主动探测 shim 是否在线（供管理器 UI 显示状态） */
int ksushim_ping(void) {
    unsigned char info[sizeof(struct ksu_get_info_cmd)];
    memset(info, 0, sizeof(info));
    if (shim_ioctl(KSU_IOCTL_GET_INFO, info, sizeof(info)) == 0) {
        return 0;
    }
    return -1;
}
