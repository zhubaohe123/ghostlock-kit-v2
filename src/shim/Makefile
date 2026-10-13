# KSUShim —— KernelSU 驱动 FD 代理（方案2：Binder/Local Socket 代理）
#
# 产物：
#   ksushimd        root 守护进程，持有 ksu_driver fd 并转发白名单 ioctl
#   libksushim.so   App 侧 LD_PRELOAD 库，拦截 reboot 握手并伪装驱动 fd
#
# 用法：make    （需 NDK 29，与 ghostlock-app 共用环境）

API ?= 35

# 优先使用 29.x（与 ghostlock-app 构建链一致），否则回退到最新可用 NDK。
ifeq ($(OS),Windows_NT)
  NDK_BASE := D:/AndroidSDK/ndk
  NDK_ROOT ?= $(subst \,/,$(lastword $(sort $(wildcard $(NDK_BASE)/29.*))))
  ifeq ($(strip $(NDK_ROOT)),)
    NDK_ROOT := $(subst \,/,$(lastword $(sort $(wildcard $(NDK_BASE)/*))))
  endif
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang.cmd
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  PREBUILT := linux-x86_64
  CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
endif

CFLAGS := -O2 -Wall -Wextra -Wno-unused-parameter
HDRS   := ksu_uapi.h

.PHONY: all clean check install

all: ksushimd libksushim.so

ksushimd: ksushimd.c $(HDRS)
	@echo "CC (daemon): $(CC)"
	$(CC) $(CFLAGS) -static -o $@ ksushimd.c
	@echo "=== built: ksushimd ==="

libksushim.so: ksushim_client.c $(HDRS)
	@echo "CC (client): $(CC)"
	$(CC) -shared -fPIC $(CFLAGS) -o $@ ksushim_client.c -ldl -llog
	@echo "=== built: libksushim.so ==="

# 在设备上部署：需先完成 late-load（KernelSU 已就绪）
install: all
	adb push ksushimd /data/local/tmp/ksushimd
	adb push libksushim.so /data/local/tmp/libksushim.so
	adb shell "chmod 755 /data/local/tmp/ksushimd"
	@echo "[*] 启动沙箱验证："
	adb shell "su -c '/data/local/tmp/ksushimd -v &' ; sleep 1; ls -l /data/adb/ksu_shim.sock /data/adb/ksu_shim.ready"

clean:
	rm -f ksushimd libksushim.so
