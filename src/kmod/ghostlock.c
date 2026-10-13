// ghostlock.c — GhostLock kernel module for vivo iQOO Neo9S Pro
// Target kernel: 6.1.145-android14-11-maybe-dirty (GKI android14-6.1, KMI 2024-11)
//
// Requirements baked in (see README):
//   - vermagic must equal "6.1.145-android14-11-maybe-dirty SMP preempt mod_unload
//     modversions aarch64 " (no "vivo " prefix) — produced by the build config.
//   - must carry modinfo import_ns=VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver
//     — produced by MODULE_IMPORT_NS below.
//   - MODVERSIONS CRCs are all zero (device kernel's symbol CRCs are all zero)
//     — produced by building with CONFIG_MODVERSIONS=y without Module.symvers.
//
// Interface (root only):
//   cat /proc/ghostlock
//       -> status line + last poke target/value
//   echo 0xKERNEL_ADDR 0xVALUE > /proc/ghostlock
//       -> 32-bit write of VALUE to KERNEL_ADDR (kernel-space guard applied)
//
// Use only symbols the GKI kernel exports (scnprintf, simple_strtoul,
// proc_create/proc_remove); importing non-exported libc names makes the
// hardened loader reject the module silently with ENOEXEC.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/string.h>

#define MODNAME  "ghostlock"
#define PROCNAME "ghostlock"

static unsigned long gl_target;
static unsigned int  gl_value;
static struct proc_dir_entry *gl_entry;

static ssize_t gl_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
    char msg[160];
    int len;

    if (*ppos > 0)
        return 0;

    if (gl_target)
        len = scnprintf(msg, sizeof(msg),
                        "ghostlock: target=%px value=0x%08x\n",
                        (void *)gl_target, gl_value);
    else
        len = scnprintf(msg, sizeof(msg),
                        "ghostlock: armed. echo 0xKERNEL_ADDR 0xVALUE > /proc/%s\n",
                        PROCNAME);

    if (count < len)
        len = count;
    if (copy_to_user(buf, msg, len))
        return -EFAULT;
    *ppos = len;
    return len;
}

static ssize_t gl_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[96];
    char *p;
    unsigned long addr;
    unsigned int val;

    if (count > sizeof(kbuf) - 1)
        return -EINVAL;
    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = '\0';

    p = kbuf;
    if (strncmp(p, "0x", 2) == 0)
        p += 2;
    addr = simple_strtoul(p, &p, 16);
    while (*p == ' ' || *p == '\t')
        p++;
    val = (unsigned int)simple_strtoul(p, NULL, 0);

    if (!addr || addr < PAGE_OFFSET) {
        pr_err(MODNAME ": refusing non-kernel address %px\n", (void *)addr);
        return -EINVAL;
    }

    pr_info(MODNAME ": poke 0x%08x -> %px\n", val, (void *)addr);
    *(volatile unsigned int *)addr = val;
    gl_target = addr;
    gl_value  = val;
    return count;
}

static const struct proc_ops gl_fops = {
    .proc_read  = gl_read,
    .proc_write = gl_write,
};

static int __init ghostlock_init(void)
{
    gl_entry = proc_create(PROCNAME, 0600, NULL, &gl_fops);
    if (!gl_entry) {
        pr_err(MODNAME ": proc_create failed\n");
        return -ENOMEM;
    }
    pr_info(MODNAME ": loaded (ghostlock armed)\n");
    return 0;
}

static void __exit ghostlock_exit(void)
{
    if (gl_entry)
        proc_remove(gl_entry);
    pr_info(MODNAME ": unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GhostLock: kernel-space poke for ksu_manager_appid patching");
MODULE_AUTHOR("ghostlock");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

module_init(ghostlock_init);
module_exit(ghostlock_exit);
