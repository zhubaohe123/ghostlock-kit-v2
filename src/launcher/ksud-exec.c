// ksud-exec.c — fetch a REAL KernelSU driver fd from the ksushimd daemon,
// then exec ksud with that fd inherited.
//
// Why this exists
// ---------------
// The manager app runs every privileged command as
//     <nativeLibraryDir>/libksud.so <args>
// inside a root shell (libsu). That child:
//   * inherits the app's seccomp filter, which blocks syscall 142 (reboot) —
//     so ksud's reboot-magic handshake gets SIGSYS, and
//   * does not reliably inherit the app's driver fd (libsu closes fds across
//     fork/exec).
// Net effect: ksud reports "kernel=0" (uapi 0), so
//   * soft reboot silently skips ("UAPI version mismatch: kernel=0, ksud=2")
//   * module install / update fails
//
// This launcher runs as root — uid 0, which ksushimd explicitly allows —
// receives a real driver fd over SCM_RIGHTS, clears CLOEXEC, then execs the
// real ksud. ksud's scan_driver_fd() finds anon_inode:[ksu_driver] in
// /proc/self/fd, so it never touches the handshake.
//
// Usage: identical to ksud — argv is passed through unchanged.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SHIM_MAGIC   0x4B53554Du   /* "KSUM" */
#define SHIM_VERSION 1u
#define SHIM_OP_GET_DRIVER_FD 0xFFFF0001u

struct shim_req {
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t len;
};

struct shim_rsp {
    int32_t  ret;
    uint32_t len;
};

static const char *kSockets[] = {
    "/data/data/me.weishu.kernelsu/ksu_shim.sock",
    "/data/local/tmp/ksu_shim.sock",
    "/data/adb/ksu_shim.sock",
    NULL
};

/* the real ksud to hand control to.
 * NOTE: /data/adb/ksud can itself end up BEING this launcher — the manager's
 * KsuCli.install() copies /proc/self/exe there, and after we exec ksud that is
 * the ksud binary... but if a user replaces it, we must not exec ourselves in
 * a loop. The inode guard below handles that. */
static const char *kRealKsud[] = {
    "/data/adb/ksu/bin/ksud",
    "/data/adb/ksud",
    "/data/local/tmp/ksud",
    NULL
};

/* true if `path` is this launcher itself (by inode OR by content marker).
 *
 * The inode test alone is not enough: KsuCli.install() copies /proc/self/exe
 * to /data/adb/ksud, and a plain `cp` of our launcher there would be a
 * DIFFERENT inode — exec'ing it would recurse forever. So also look for a
 * string that only this binary contains. */
static int is_self(const char *path) {
    struct stat a, b;
    if (stat(path, &a) != 0) return 0;
    if (stat("/proc/self/exe", &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino)
        return 1;

    /* content marker */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    static const char marker[] = "ksud-exec: cannot exec ksud";
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return 0;
    for (ssize_t i = 0; i + (ssize_t)sizeof(marker) - 1 <= n; i++) {
        if (memcmp(buf + i, marker, sizeof(marker) - 1) == 0)
            return 1;
    }
    return 0;
}

static int get_driver_fd(void);

int main(int argc, char **argv) {
    /* argv is passed through verbatim: argv[0] is our own path */
    char **child_argv = argv;

    int fd = get_driver_fd();
    if (fd < 0) {
        fprintf(stderr, "ksud-exec: warning: no driver fd from shim "
                        "(errno=%d); falling back to plain ksud\n", errno);
    }

    for (int i = 0; kRealKsud[i]; i++) {
        if (is_self(kRealKsud[i])) {
            fprintf(stderr, "ksud-exec: skipping self (%s)\n", kRealKsud[i]);
            continue;
        }
        execv(kRealKsud[i], child_argv);
        /* only reached on failure */
    }

    fprintf(stderr, "ksud-exec: cannot exec ksud: %s\n", strerror(errno));
    return 127;
}

static int get_driver_fd(void) {
    for (int i = 0; kSockets[i]; i++) {
        int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sfd < 0) continue;

        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, kSockets[i], sizeof(sa.sun_path) - 1);

        if (connect(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            close(sfd);
            continue;
        }

        struct shim_req req;
        memset(&req, 0, sizeof(req));
        req.magic = SHIM_MAGIC;
        req.version = SHIM_VERSION;
        req.op = SHIM_OP_GET_DRIVER_FD;
        req.len = 0;

        if (write(sfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
            close(sfd);
            continue;
        }

        struct shim_rsp rsp;
        memset(&rsp, 0, sizeof(rsp));
        char cbuf[CMSG_SPACE(sizeof(int))];
        memset(cbuf, 0, sizeof(cbuf));

        struct iovec io = { .iov_base = &rsp, .iov_len = sizeof(rsp) };
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        ssize_t n = recvmsg(sfd, &msg, 0);
        int got = -1;
        if (n == (ssize_t)sizeof(rsp)) {
            for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm;
                 cm = CMSG_NXTHDR(&msg, cm)) {
                if (cm->cmsg_level == SOL_SOCKET &&
                    cm->cmsg_type == SCM_RIGHTS &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
                    memcpy(&got, CMSG_DATA(cm), sizeof(int));
                    break;
                }
            }
        }
        close(sfd);

        if (got >= 0 && rsp.ret >= 0) {
            /* must survive execve so ksud sees it in /proc/self/fd */
            int fl = fcntl(got, F_GETFD);
            if (fl >= 0) fcntl(got, F_SETFD, fl & ~FD_CLOEXEC);
            return got;
        }
        if (got >= 0) close(got);
    }
    return -1;
}

