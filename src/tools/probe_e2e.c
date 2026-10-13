// End-to-end probe, meant to run AS THE APP UID (no root):
//   1. connect to the shim socket (dir-owner auth lets us through)
//   2. request the real driver fd via SCM_RIGHTS
//   3. issue KSU_IOCTL_GET_INFO on it
//   4. report whether the driver accepts a non-manager uid
// Answers: "is the remaining blocker fd delivery, or driver-side manager auth?"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#define MAGIC   0x4B53554Du
#define VERSION 1u
#define OP_GET_DRIVER_FD 0xFFFF0001u

#ifndef KSU_IOCTL_GET_INFO
#define KSU_IOCTL_GET_INFO 0x80104b02
#endif

struct shim_req { uint32_t magic, version, op, len; };
struct shim_rsp { int32_t ret; uint32_t len; };

struct ksu_get_info_cmd { uint32_t version, flags, features, uid; };

static const char *paths[] = {
    "/data/data/me.weishu.kernelsu/ksu_shim.sock",
    "/data/local/tmp/ksu_shim.sock",
    "/data/adb/ksu_shim.sock",
};

static int connect_shim(void) {
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        struct sockaddr_un a; memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, paths[i], sizeof(a.sun_path) - 1);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            printf("[*] connected via %s\n", paths[i]);
            return fd;
        }
        printf("[!] connect(%s) failed errno=%d\n", paths[i], errno);
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv) {
    /* optional: drop to a target uid to prove the driver's per-caller rules */
    if (argc > 2 && strcmp(argv[1], "--uid") == 0) {
        uid_t u = (uid_t)strtoul(argv[2], NULL, 10);
        if (setuid(u) != 0) { printf("setuid(%u) failed errno=%d\n", u, errno); return 3; }
        printf("[*] dropped to uid=%d\n", getuid());
    }
    printf("uid=%d euid=%d\n", getuid(), geteuid());

    int s = connect_shim();
    if (s < 0) { printf("FAIL: no shim socket reachable\n"); return 1; }

    struct shim_req req = { MAGIC, VERSION, OP_GET_DRIVER_FD, 0 };
    if (write(s, &req, sizeof(req)) != sizeof(req)) {
        printf("FAIL: write errno=%d\n", errno); return 1;
    }

    struct shim_rsp rsp; memset(&rsp, 0, sizeof(rsp));
    char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof(cbuf));
    struct iovec io = { &rsp, sizeof(rsp) };
    struct msghdr msg; memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);

    ssize_t n = recvmsg(s, &msg, 0);
    if (n != (ssize_t)sizeof(rsp)) { printf("FAIL: recvmsg n=%zd errno=%d\n", n, errno); return 1; }

    int fd = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
            cm->cmsg_len >= CMSG_LEN(sizeof(int)))
            memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    }
    printf("[*] rsp.ret=%d driver_fd=%d\n", rsp.ret, fd);
    if (rsp.ret < 0 || fd < 0) { printf("RESULT: fd delivery REFUSED\n"); return 1; }

    /* verify the fd really is the driver */
    char lnk[256]; char p[64];
    snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
    ssize_t l = readlink(p, lnk, sizeof(lnk) - 1);
    if (l > 0) { lnk[l] = 0; printf("[*] fd %d -> %s\n", fd, lnk); }

    struct ksu_get_info_cmd info; memset(&info, 0, sizeof(info));
    long r = ioctl(fd, KSU_IOCTL_GET_INFO, &info);
    printf("ioctl(GET_INFO) = %ld errno=%d\n", r, errno);
    if (r == 0) {
        printf("  version=%u flags=0x%x features=%u uid=%u\n",
               info.version, info.flags, info.features, info.uid);
        printf("RESULT: DRIVER ACCEPTS a non-manager uid -> fd delivery is sufficient\n");
        return 0;
    }
    printf("RESULT: DRIVER REJECTS non-manager uid (errno=%d) -> manager registration is required\n",
           errno);
    return 1;
}
