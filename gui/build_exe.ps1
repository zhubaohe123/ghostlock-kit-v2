# build_exe.ps1 — 把一键 ROOT 工具打包成免环境的单文件 EXE
#
# 产物： webui\dist\GhostLock一键ROOT.exe
#        自带全部资源（内核模块、ksud、exploit、shim、脚本、adb），
#        目标机器无需安装 Python 或 platform-tools。
$ErrorActionPreference = 'Stop'

$py      = 'D:\Miniconda3-latest-Windows-x86_64\python.exe'
$webui   = 'D:\daima\root2\ghostlock\webui'
$gl      = 'D:\daima\root2\ghostlock'
$kit     = 'D:\daima\root\ghostlock-kit\files'
$assets  = Join-Path $webui 'assets'
$dist    = Join-Path $webui 'dist'
$build   = Join-Path $webui 'build'

# ---------------------------------------------------------------- 1. 收集资源
Write-Host '### 1/4 收集资源到 assets\' -ForegroundColor Cyan
if (Test-Path $assets) { Remove-Item $assets -Recurse -Force }
New-Item -ItemType Directory -Force -Path $assets | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $assets 'adb') | Out-Null

$map = @(
    @{ src = "$gl\kmod\ghostlock.ko";                  dst = 'ghostlock.ko' },
    @{ src = "$gl\shim-build\ksushimd";                dst = 'ksushimd' },
    @{ src = "$gl\shim-build\ksu-grant";               dst = 'ksu-grant' },
    @{ src = "$gl\kmod\ksud-exec";                     dst = 'ksud-exec' },
    @{ src = "$gl\kmod\wsl\deploy-launcher.sh";        dst = 'deploy-launcher.sh' },
    @{ src = "$webui\list-su.sh";                      dst = 'list-su.sh' },
    @{ src = "$gl\start_shim.sh";                      dst = 'start_shim.sh' },
    @{ src = "$gl\post-root.sh";                       dst = 'post-root.sh' },
    @{ src = "$webui\index.html";                      dst = 'index.html' },
    # 我们改造过的 KernelSU 管理器（已内置 libksushim.so + 握手补丁）。
    # 必须打包：exploit 就是用它 APK 里的 libksud.so 当加载器来 late-load
    # kernelsu.ko 的 —— 全新设备上没装管理器，内核模块就永远加载不上。
    @{ src = "$gl\manager-fix\KernelSU-ghostlock-full.apk"; dst = 'KernelSU-manager.apk' },
    # 来自 ghostlock-kit：原始未打补丁的 ksud、exploit 本体、设备偏移
    @{ src = "$kit\ksud";                              dst = 'ksud' },
    @{ src = "$kit\ghostlock";                         dst = 'ghostlock' },
    @{ src = "$kit\offsets.json";                      dst = 'offsets.json' }
)

$total = 0
foreach ($m in $map) {
    if (-not (Test-Path $m.src)) { throw "缺少资源: $($m.src)" }
    $out = Join-Path $assets $m.dst
    Copy-Item $m.src $out -Force
    $sz = (Get-Item $out).Length
    $total += $sz
    Write-Host ('    {0,-22} {1,10:N0} B' -f $m.dst, $sz)
}

# 内嵌 adb（免装 platform-tools）
$adbd = Split-Path (Get-Command adb).Source
foreach ($f in 'adb.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll') {
    $src = Join-Path $adbd $f
    if (-not (Test-Path $src)) { throw "缺少 adb 组件: $src" }
    Copy-Item $src (Join-Path $assets "adb\$f") -Force
    $sz = (Get-Item $src).Length
    $total += $sz
    Write-Host ('    adb\{0,-18} {1,10:N0} B' -f $f, $sz)
}
Write-Host ('    合计 {0:N2} MB' -f ($total / 1MB)) -ForegroundColor Green

# ---------------------------------------------------------------- 2. 清理旧产物
Write-Host ''
Write-Host '### 2/4 清理旧产物' -ForegroundColor Cyan
foreach ($d in $dist, $build) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
$spec = Join-Path $webui 'GhostLock-OneClickROOT.spec'
if (Test-Path $spec) { Remove-Item $spec -Force }

# ---------------------------------------------------------------- 3. 打包
Write-Host ''
Write-Host '### 3/4 PyInstaller 打包（单文件，内嵌资源）' -ForegroundColor Cyan
Push-Location $webui
try {
    $args = @(
        '-m', 'PyInstaller',
        '--noconfirm', '--clean',
        '--onefile',
        '--console',
        '--name', 'GhostLock-OneClickROOT',
        '--add-data', 'assets;assets',
        # 只用到标准库；显式排除科学计算等大包，避免 conda 环境被拖进去
        '--exclude-module', 'numpy', '--exclude-module', 'pandas',
        '--exclude-module', 'matplotlib', '--exclude-module', 'scipy',
        '--exclude-module', 'PIL', '--exclude-module', 'tkinter',
        '--exclude-module', 'PyQt5', '--exclude-module', 'PySide2',
        '--exclude-module', 'IPython', '--exclude-module', 'jupyter',
        '--exclude-module', 'pytest', '--exclude-module', 'setuptools',
        'rootweb.py'
    )
    & $py @args
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller 失败 (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------- 4. 收尾
Write-Host ''
Write-Host '### 4/4 收尾' -ForegroundColor Cyan
$built = Join-Path $dist 'GhostLock-OneClickROOT.exe'
if (-not (Test-Path $built)) { throw "产物不存在: $built" }

# 改成中文名，方便分享（重命名不影响运行）
$final = Join-Path $dist 'GhostLock一键ROOT.exe'
Move-Item $built $final -Force

# 附带一份使用说明
$readme = Join-Path $dist '使用说明.txt'
@'
GhostLock 一键 ROOT 工具
========================================

【怎么用】
  1. 数据线连接手机，打开「USB 调试」，并在手机上允许本机调试
  2. 双击 GhostLock一键ROOT.exe
  3. 浏览器会自动打开界面 -> 点「一键 ROOT」
  4. 关闭那个黑色命令行窗口即停止服务

【需要什么】
  - Windows 10/11 64 位
  - 手机：iQOO Neo9S Pro (PD2339)，内核 6.1.145-android14-11
  - 不需要安装 Python，不需要装 platform-tools（adb 已内置）
  - 如果电脑上已有 adb 且版本冲突，可先关掉「adb.exe」进程再运行

【管理器 APK 也自带】
  本工具内置了改造过的 KernelSU 管理器 APK（约 10.6 MB），
  第一次运行时会自动装到手机上 —— 全新手机也能直接用。
  之所以必须内置：GhostLock exploit 是拿「管理器 APK 里的 libksud.so」
  当加载器来加载内核模块的，手机上没装管理器，root 就建立不起来。

【注意】
  - root 是临时的：手机关机/重启后需要重新点一次「一键 ROOT」
  - 杀毒软件可能误报（这是打包成单文件 EXE 的常见现象），
    加白名单即可；本工具只在本机 127.0.0.1 上监听，不联网上传任何东西
  - 只支持上述机型/内核，其他机型不要尝试

【出问题怎么办】
  - 界面显示「设备未连接」：换根数据线 / 重新插拔 / 看手机上有没有授权弹窗
  - 一直卡在「等待系统稳定」：正常，exploit 在开机 4 分钟后才可靠
  - 管理器显示「未安装」：重新打开一次管理器 App
  - 想彻底重来：再点一次「一键 ROOT」（本工具是幂等的）
'@ | Set-Content -Path $readme -Encoding Default

$exe = Get-Item $final
Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host ('  打包完成: ' + $exe.FullName)
Write-Host ('  大小    : {0:N2} MB' -f ($exe.Length / 1MB))
Write-Host ('  说明    : ' + $readme)
Write-Host '============================================================' -ForegroundColor Green
