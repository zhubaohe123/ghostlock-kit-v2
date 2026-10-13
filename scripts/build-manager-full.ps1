$ErrorActionPreference = 'Stop'

$kit     = 'D:\daima\root\ghostlock-kit'
$src     = Join-Path $kit 'apk\KernelSU-v3.3.0-32601-arm64.apk'
$work    = 'D:\daima\root2\ghostlock\manager-fix\build'
$dec     = Join-Path $work 'decoded'
$out     = 'D:\daima\root2\ghostlock\manager-fix\KernelSU-ghostlock-full.apk'
$apktool = 'D:\daima\root\tools\apktool\final\apktool.jar'
$bt      = 'D:\AndroidSDK\build-tools\34.0.0'
$shim    = Join-Path $kit 'src\ksu-proxy\libksushim.so'
$py      = 'D:\Miniconda3-latest-Windows-x86_64\python.exe'

if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host '### 1/6 apktool decode'
& java -jar $apktool decode --force --output $dec $src
if ($LASTEXITCODE -ne 0) { throw 'decode failed' }
$libDir = Join-Path $dec 'lib\arm64-v8a'

Write-Host '### 2/6 patch libksud.so + inject smali'
$patchPy = Join-Path $work 'patch.py'
@'
import re, sys
lib = sys.argv[1]
dec = sys.argv[2]

# ---------------------------------------------------------------- libksud.so
# KernelSU 用一个「reboot 魔数握手」把驱动 fd 装进调用进程。libksud.so 里有
# **两处**实现，Android 16 的 app.policy 封了 syscall 142，两处都会被 SIGSYS
# 击杀 —— 只补一处不够（实测另一处让 fork 出来的 ksud 崩溃）。
p = lib + r'\libksud.so'
d = bytearray(open(p, 'rb').read())

# 站点 1：内联 svc 指令（函数 su 内）
assert d[0x338be0:0x338be4] == bytes.fromhex('010000d4'), d[0x338be0:0x338be4].hex()
d[0x338be0:0x338be4] = bytes.fromhex('1f2003d5')      # nop
print('   site1 @0x338be0 (inline svc) -> nop')

# 站点 2：libc syscall() 调用点
assert d[0x34c364:0x34c368] == bytes.fromhex('43140594'), d[0x34c364:0x34c368].hex()
d[0x34c364:0x34c368] = bytes.fromhex('1f2003d5')      # nop  (去掉 bl syscall@plt)
assert d[0x34c370:0x34c374] == bytes.fromhex('007d1f53'), d[0x34c370:0x34c374].hex()
d[0x34c370:0x34c374] = bytes.fromhex('20008052')      # mov w0, #1  (明确返回失败)
print('   site2 @0x34c364/@0x34c370 (bl syscall) -> nop + mov w0,#1')

open(p, 'wb').write(d)

# ------------------------------------------------- KernelSUApplication.<init>
# shim 必须在最早的应用代码里加载，才能在 libksud/libkernelsu 首次扫描前拿到 fd。
s = dec + r'\smali\me\weishu\kernelsu\KernelSUApplication.smali'
t = open(s, encoding='utf-8').read()
if 'loadLibrary("ksushim")' in t:
    print('   app smali already injected')
else:
    inj = ('\n    const-string v0, "ksushim"\n'
           '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')
    m = re.search(r'\.method\s+public\s+constructor\s+<init>\(\)V\s*\n(\s*\.locals\s+\d+\s*\n)', t)
    if not m:
        print('   [!] <init>/.locals pattern not found'); sys.exit(2)
    pos = m.end()
    t = t[:pos] + inj + t[pos:]
    open(s, 'w', encoding='utf-8', newline='\n').write(t)
    print('   app smali injected after:', m.group(1).strip())

# --------------------------------------------------- AppZygotePreload.doPreload
# KernelSU 3.x 的特权路径：MagicaService(isolatedProcess + useAppZygote) 跑在
# app zygote 派生的 isolated 进程里 —— 那里**没有 app 的 seccomp 过滤器**，
# 所以 fork 出的 ksud 可以正常做 reboot 握手。
#
# 因此 shim 必须在 app zygote 里也加载（否则 zygote 没有驱动 fd，fork 出的
# ksud 扫描落空 → 回退握手 → 带 seccomp 时被杀）。
#
# 注入点必须落在**已有的 try 块内**：早先注在 try 之外，一旦 loadLibrary 在
# app zygote 中抛异常就会让 doPreload 整体失败，AMS 于是回退到普通 zygote，
# app zygote 根本不会出现（实测现象正是如此）。
z = dec + r'\smali\me\weishu\kernelsu\magica\AppZygotePreload.smali'
try:
    tz = open(z, encoding='utf-8').read()
except FileNotFoundError:
    print('   [i] AppZygotePreload.smali absent; skipped')
    tz = None
if tz is not None:
    if 'loadLibrary("ksushim")' in tz:
        print('   zygote smali already injected')
    else:
        mz = re.search(
            r'(\.method\s+public\s+final\s+doPreload\(Landroid/content/pm/ApplicationInfo;\)V'
            r'.*?invoke-static\s+\{v1\},\s+Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V\s*\n)',
            tz, re.S)
        if not mz:
            print('   [!] doPreload loadLibrary("kernelsu") anchor not found'); sys.exit(3)
        pz = mz.end()
        injz = ('\n    const-string v2, "ksushim"\n'
                '    invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')
        tz = tz[:pz] + injz + tz[pz:]
        open(z, 'w', encoding='utf-8', newline='\n').write(tz)
        print('   zygote smali injected INSIDE existing try block')
'@ | Out-File -Encoding ascii $patchPy
& $py $patchPy $libDir $dec
if ($LASTEXITCODE -ne 0) { throw 'patch/inject failed' }

Write-Host '### 3/6 inject libksushim.so'
Copy-Item $shim (Join-Path $libDir 'libksushim.so') -Force
Write-Host ('   written: ' + (Get-Item (Join-Path $libDir 'libksushim.so')).Length + ' bytes')

Write-Host '### 4/6 apktool build'
$unsigned = Join-Path $work 'unsigned.apk'
& java -jar $apktool build --output $unsigned $dec
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

Write-Host '### 5/6 zipalign'
$aligned = Join-Path $work 'aligned.apk'
& (Join-Path $bt 'zipalign.exe') -f -p 4 $unsigned $aligned
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

Write-Host '### 6/6 sign'
& (Join-Path $bt 'apksigner.bat') sign `
  --ks (Join-Path $kit 'signing\ghostlock-release.jks') `
  --ks-pass 'pass:ghostlock2026' --ks-key-alias 'ghostlock' --key-pass 'pass:ghostlock2026' `
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true `
  --out $out $aligned
if ($LASTEXITCODE -ne 0) { throw 'sign failed' }
& (Join-Path $bt 'apksigner.bat') verify --print-certs $out | Select-Object -First 3

Write-Host '### verify final apk'
$verifyPy = Join-Path $work 'verify.py'
@'
import zipfile, sys
z = zipfile.ZipFile(sys.argv[1])
d = z.read('lib/arm64-v8a/libksud.so')
print('   site1 @0x338be0 =', d[0x338be0:0x338be4].hex(' '), '(nop = 1f 20 03 d5)')
print('   site2 @0x34c364 =', d[0x34c364:0x34c368].hex(' '), '(nop = 1f 20 03 d5)')
print('   site2 @0x34c370 =', d[0x34c370:0x34c374].hex(' '), '(mov w0,#1 = 20 00 80 52)')
print('   ksushim entries:', [n for n in z.namelist() if 'ksushim' in n])
'@ | Out-File -Encoding ascii $verifyPy
& $py $verifyPy $out

Get-Item $out | Select-Object Name, Length
