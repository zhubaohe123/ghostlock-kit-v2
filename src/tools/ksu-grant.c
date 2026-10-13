// ksu-grant: root-grant CLI that works WITHOUT the manager GUI.
// Talks to the KernelSU driver through the shim socket (SCM_RIGHTS fd
// delivery), which we proved works for any uid as long as the process
// holds a real driver fd.
//
// Usage:
//   ksu-grant allow <uid>              grant root to a uid (set app profile)
//   ksu-grant deny  <uid>              revoke
//   ksu-grant status <uid>             show profile
//   ksu-grant list                     dump allow list
//   ksu-grant manager                  try to register as dynamic manager
//   ksu-grant info                     driver info
//
// Must be run as root (or any uid the driver accepts); it gets its own
// driver fd from ksushimd, so it never needs the manager GUI.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#define MAGIC   0x4B53554Du
#define VERSION 1u
#define OP_GET_DRIVER_FD 0xFFFF0001u

/* --- ioctl numbers, mirrored from ksu_uapi.h --- */
/* real layout: dir<<30 | size<<16 | 'K'<<8 | nr   (nr in the LOW 8 bits) */
#define KSU_IOC(dir, nr, size) \
    (((uint32_t)(dir) << 30) | ((uint32_t)(size) << 16) | ((uint32_t)('K') << 8) | ((uint32_t)(nr)))
#define KSU_IOCTL_GET_INFO            KSU_IOC(2, 2, sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_GET_MANAGER_APPID   KSU_IOC(2, 10, 0)
#define KSU_IOCTL_SET_APP_PROFILE     KSU_IOC(1, 12, 0)
#define KSU_IOCTL_GET_APP_PROFILE     KSU_IOC(3, 11, 0)
#define KSU_IOCTL_DYNAMIC_MANAGER     KSU_IOC(3, 103, 0)
#define KSU_IOCTL_NEW_GET_ALLOW_LIST  KSU_IOC(3, 6, sizeof(struct ksu_new_get_allow_list_cmd))
#define KSU_IOCTL_UID_GRANTED_ROOT    KSU_IOC(3, 8, 0)

struct ksu_get_info_cmd { uint32_t version, flags, features, uid; };

/* KernelSU app profile (must match kernel struct layout) */
struct ksu_app_profile {
    uint32_t version;
    uint32_t uid;
    uint32_t allow_su;
    uint32_t groups_count;
    uint32_t non_root_use_default_profile;
    char rvs[32];
    /* variable part follows in the kernel's real struct; the fixed part is
     * what the driver reads for a "simple" allow/deny toggle. We send a
     * version-1 profile with allow_su and defaults, which is what ksud does
     * for `ksud profile allow <uid>`. */
};

struct ksu_new_get_allow_list_cmd {
    uint32_t count;
    uint32_t uids[64];
};

struct shim_req { uint32_t magic, version, op, len; };
struct shim_rsp { int32_t ret; uint32_t len; };

static const char *paths[] = {
    "/data/data/me.weishu.kernelsu/ksu_shim.sock",
    "/data/local/tmp/ksu_shim.sock",
    "/data/adb/ksu_shim.sock",
};

static int get_driver_fd(void) {
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) continue;
        struct sockaddr_un a; memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, paths[i], sizeof(a.sun_path) - 1);
        if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) { close(s); continue; }

        struct shim_req req = { MAGIC, VERSION, OP_GET_DRIVER_FD, 0 };
        if (write(s, &req, sizeof(req)) != sizeof(req)) { close(s); continue; }

        struct shim_rsp rsp; memset(&rsp, 0, sizeof(rsp));
        char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof(cbuf));
        struct iovec io = { &rsp, sizeof(rsp) };
        struct msghdr msg; memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &io; msg.msg_iovlen = 1;
        msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
        if (recvmsg(s, &msg, 0) != (ssize_t)sizeof(rsp)) { close(s); continue; }

        int fd = -1;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
                cm->cmsg_len >= CMSG_LEN(sizeof(int)))
                memcpy(&fd, CMSG_DATA(cm), sizeof(int));
        }
        close(s);
        if (rsp.ret == 0 && fd >= 0) return fd;
    }
    return -1;
}

static void usage(void) {
    printf("usage: ksu-grant <cmd> [args]\n"
           "  info                driver info\n"
           "  manager-appid       query registered manager appid\n"
           "  list                dump root allow list\n"
           "  granted-root <uid>  check if uid has root\n"
           "  dynmgr              try DYNAMIC_MANAGER registration\n"
           "  setprofile <uid> <allow:0|1>   set app profile (root grant)\n"
           "  getprofile <uid>    read app profile\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    int fd = get_driver_fd();
    if (fd < 0) { printf("FAIL: could not obtain driver fd from shim\n"); return 1; }
    printf("[*] driver fd = %d\n", fd);

    if (!strcmp(argv[1], "info")) {
        struct ksu_get_info_cmd i; memset(&i, 0, sizeof(i));
        long r = ioctl(fd, KSU_IOCTL_GET_INFO, &i);
        printf("ioctl=%ld errno=%d\n", r, errno);
        if (r == 0) printf("  version=%u flags=0x%x features=%u uid=%u\n",
                           i.version, i.flags, i.features, i.uid);
    }
    else if (!strcmp(argv[1], "manager-appid")) {
        uint32_t appid = 0;
        long r = ioctl(fd, KSU_IOCTL_GET_MANAGER_APPID, &appid);
        printf("ioctl=%ld errno=%d manager_appid=%u\n", r, errno, appid);
    }
    else if (!strcmp(argv[1], "granted-root")) {
        if (argc < 3) { usage(); return 2; }
        uint32_t uid = (uint32_t)strtoul(argv[2], NULL, 10);
        uint32_t out = 0;
        /* UID_GRANTED_ROOT takes a pointer to the uid in/out */
        struct { uint32_t uid; uint32_t result; } cmd = { uid, 0 };
        long r = ioctl(fd, KSU_IOCTL_UID_GRANTED_ROOT, &cmd);
        printf("ioctl=%ld errno=%d uid=%u granted=%u\n", r, errno, uid, cmd.result);
        (void)out;
    }
    else if (!strcmp(argv[1], "list")) {
        struct ksu_new_get_allow_list_cmd cmd; memset(&cmd, 0, sizeof(cmd));
        cmd.count = 64;
        long r = ioctl(fd, KSU_IOCTL_NEW_GET_ALLOW_LIST, &cmd);
        printf("ioctl=%ld errno=%d count=%u\n", r, errno, cmd.count);
        if (r == 0) {
            for (uint32_t i = 0; i < cmd.count && i < 64; i++)
                printf("  uid=%u\n", cmd.uids[i]);
        }
    }
    else if (!strcmp(argv[1], "dynmgr")) {
        /* DYNAMIC_MANAGER: kernel-side manager registration; the payload
         * layout is driver-version specific, so we send a zeroed buffer and
         * report the driver's answer. */
        uint8_t buf[256]; memset(buf, 0, sizeof(buf));
        long r = ioctl(fd, KSU_IOCTL_DYNAMIC_MANAGER, buf);
        printf("ioctl=%ld errno=%d\n", r, errno);
        printf("  -> %s\n", r == 0 ? "accepted (check manager state)"
                                  : "rejected (needs valid payload / CONFIG)");
    }
    else if (!strcmp(argv[1], "setprofile")) {
        if (argc < 4) { usage(); return 2; }
        struct ksu_app_profile p; memset(&p, 0, sizeof(p));
        p.version = 1;
        p.uid = (uint32_t)strtoul(argv[2], NULL, 10);
        p.allow_su = (uint32_t)strtoul(argv[3], NULL, 10);
        long r = ioctl(fd, KSU_IOCTL_SET_APP_PROFILE, &p);
        printf("ioctl=%ld errno=%d (uid=%u allow_su=%u)\n", r, errno, p.uid, p.allow_su);
        printf("  -> %s\n", r == 0 ? "OK" : "REJECTED (struct layout may differ)");
    }
    else if (!strcmp(argv[1], "getprofile")) {
        if (argc < 3) { usage(); return 2; }
        struct ksu_app_profile p; memset(&p, 0, sizeof(p));
        p.version = 1;
        p.uid = (uint32_t)strtoul(argv[2], NULL, 10);
        long r = ioctl(fd, KSU_IOCTL_GET_APP_PROFILE, &p);
        printf("ioctl=%ld errno=%d uid=%u allow_su=%u\n", r, errno, p.uid, p.allow_su);
    }
    else { usage(); return 2; }

    close(fd);
    return 0;
}
