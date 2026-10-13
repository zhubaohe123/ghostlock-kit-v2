$ErrorActionPreference = 'Continue'
$serial = '10AE8G1QXL0016B'
$log = 'D:\daima\root2\ghostlock\root_run.log'
function W($m) { $line = "$(Get-Date -Format 'HH:mm:ss') $m"; $line | Tee-Object -FilePath $log -Append }
W "=== runner start ==="
$success = $false
for ($run = 100; $run -le 112 -and -not $success; $run++) {
    # 1) wait device online + boot completed
    $up = $false
    for ($i = 0; $i -lt 150; $i++) {
        $d = (adb devices) -join "`n"
        if ($d -match "$serial\s+device") {
            $b = (adb -s $serial shell getprop sys.boot_completed 2>$null) -join ''
            if ($b.Trim() -eq '1') { $up = $true; break }
        }
        Start-Sleep -Seconds 2
    }
    if (-not $up) { W "run ${run}: device never came up"; break }

    # 2) settle: uptime > 240s
    for ($i = 0; $i -lt 40; $i++) {
        $raw = (adb -s $serial shell "cut -d' ' -f1 /proc/uptime" 2>$null) -join ''
        $m = [regex]::Match($raw, '(\d+\.\d+)')
        if ($m.Success -and [double]$m.Groups[1].Value -gt 240) { break }
        Start-Sleep -Seconds 15
    }
    $u = ((adb -s $serial shell "cut -d' ' -f1 /proc/uptime" 2>$null) -join '').Trim()
    W "run ${run}: launching (uptime=$u)"

    # 3) launch exploit detached on device
    adb -s $serial shell "cd /data/local/tmp && nohup sh -c 'GHOSTLOCK_ROUTE=mcast GHOSTLOCK_CORE=4 GHOSTLOCK_CONSUMER_CORE=5 ./ghostlock' > run_mcast$run.log 2>&1 & echo started" | Out-Null

    # 4) watch up to 200s
    $crashed = $false
    for ($t = 0; $t -lt 40; $t++) {
        Start-Sleep -Seconds 5
        $d = (adb devices) -join "`n"
        if ($d -notmatch "$serial\s+device") {
            W "run ${run}: CRASH/reboot at $(Get-Date -Format HH:mm:ss)"
            $crashed = $true
            break
        }
        $m = (adb -s $serial shell "grep -c kernelsu /proc/modules 2>/dev/null" 2>$null) -join ''
        if ($m.Trim() -match '^[1-9]') {
            W "run ${run}: *** KERNELSU LOADED ***"
            $success = $true
            break
        }
    }
    if (-not $success -and -not $crashed) { W "run ${run}: timeout, no module" }
}
W "=== success=$success"
if ($success) {
    Start-Sleep -Seconds 10
    $id = (adb -s $serial shell "su -c id" 2>&1) -join ' '
    W "su -c id => $id"
    $mod = (adb -s $serial shell "grep -i kernelsu /proc/modules" 2>&1) -join ' '
    W "module => $mod"
    $v = (adb -s $serial shell "/data/local/tmp/ksud -V" 2>&1) -join ' '
    W "ksud => $v"

    # --- post-root: self-built kmod + manager registration -----------------
    # Loads ghostlock.ko (arbitrary kernel-memory write) and writes the manager
    # appId into the loaded kernelsu module's ksu_manager_appid, which makes the
    # KernelSU GUI report "working" and unlocks SET_APP_PROFILE.
    W "--- post-root ---"
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    foreach ($f in @(@("$here\kmod\ghostlock.ko",   '/data/local/tmp/ghostlock.ko'),
                     @("$here\post-root.sh",        '/data/local/tmp/post-root.sh'),
                     @("$here\kmod\ksu-grant",      '/data/local/tmp/ksu-grant'),
                     @("$here\kmod\ksud-exec",      '/data/local/tmp/ksud-exec'),
                     @("$here\start_shim.sh",       '/data/local/tmp/start_shim.sh'),
                     @("$here\kmod\wsl\deploy-launcher.sh", '/data/local/tmp/deploy-launcher.sh'))) {
        if (Test-Path $f[0]) { adb -s $serial push $f[0] $f[1] 2>&1 | Out-Null }
    }
    adb -s $serial shell "chmod 755 /data/local/tmp/post-root.sh /data/local/tmp/ksu-grant /data/local/tmp/ksushimd /data/local/tmp/ksud-exec /data/local/tmp/deploy-launcher.sh /data/local/tmp/start_shim.sh 2>/dev/null" | Out-Null
    $pr = (adb -s $serial shell "su -c 'sh /data/local/tmp/post-root.sh'" 2>&1) -join ' '
    W "post-root rc => $pr"
    $plog = (adb -s $serial shell "cat /data/local/tmp/post_root.log" 2>&1) -join "`n"
    W $plog
    W "--- post-root end ---"
}
