# Re-record docs/master-bot-demo.gif end to end (Windows, PowerShell 5.1+).
#
#   powershell -ExecutionPolicy Bypass -File scripts\demo\record.ps1
#
# Needs: Windows Terminal (wt.exe), ffmpeg on PATH, python with the package
# installed (pip install -e .), a seeded examples/demo/company.db
# (rbic-seed --config-dir examples/demo), and ANTHROPIC_API_KEY in .env (real API calls,
# roughly 10 model requests per take). Leave the desktop alone while it runs:
# it captures the screen region of the new Windows Terminal window.
#
# What it does:
#   1. backs up examples/demo/casbin/policy.csv, worker_attributes.json and
#      policy_changes.jsonl
#   2. sets examples/demo/casbin/policy.csv to the committed version (git HEAD), so alice
#      starts without any personal grant
#   3. opens a Windows Terminal window split horizontally: top pane runs
#      scripts/demo/drive.py master (rbic.cli.master), bottom pane runs
#      scripts/demo/drive.py alice (rbic.cli.chat); see drive.py
#   4. records the window with ffmpeg gdigrab, then builds the GIF with a
#      two-pass palette (palettegen / paletteuse)
#   5. ALWAYS (finally) restores the backed-up files byte for byte, verifies
#      their SHA-256, and removes an examples/demo/casbin/.policy.lock left by the run
# examples/demo/casbin/model.conf is never touched.

param(
    [string]$Out = "docs\master-bot-demo.gif",
    [int]$Cols = 100,
    [int]$Rows = 50,
    [int]$Fps = 8,
    [double]$Speed = 1.0          # >1 plays the GIF faster than real time
)

$ErrorActionPreference = "Stop"
$proj = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $proj

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class DemoWin {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int s);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public static IntPtr Find(string title) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, l) => {
            var t = new StringBuilder(256); var c = new StringBuilder(256);
            GetWindowText(h, t, 256); GetClassName(h, c, 256);
            if (IsWindowVisible(h) && t.ToString() == title &&
                c.ToString() == "CASCADIA_HOSTING_WINDOW_CLASS") { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@
[void][DemoWin]::SetProcessDPIAware()

$files = @("examples\demo\casbin\policy.csv", "examples\demo\worker_attributes.json",
           "examples\demo\policy_changes.jsonl")
$work = Join-Path $env:TEMP ("rbic-demo-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$bak = Join-Path $work "backup"
$sync = Join-Path $work "sync"
New-Item -ItemType Directory -Force $bak, $sync | Out-Null
$lock = Join-Path $proj "examples\demo\casbin\.policy.lock"
$lockExisted = Test-Path $lock
$hashes = @{}
foreach ($f in $files) {
    if (Test-Path $f) {
        Copy-Item $f (Join-Path $bak ($f -replace '[\\/]', '__'))
        $hashes[$f] = (Get-FileHash $f -Algorithm SHA256).Hash
    } else { $hashes[$f] = $null }
}
Write-Host "backup: $bak"

$ffmpeg = $null
$title = "rbic-plugin demo"
$raw = Join-Path $work "raw.mkv"
try {
    # Committed policy (raw bytes from git, no PowerShell re-encoding).
    python -c "import subprocess; open(r'examples\demo\casbin\policy.csv','wb').write(subprocess.check_output(['git','show','HEAD:examples/demo/casbin/policy.csv']))"
    if ($LASTEXITCODE -ne 0) { throw "could not write HEAD policy.csv" }

    $drive = "python scripts/demo/drive.py"
    $wtArgs = "-w new --focus --pos 40,40 --size $Cols,$Rows " +
        "new-tab --title `"$title`" --suppressApplicationTitle -d `"$proj`" $drive master `"$sync`" ; " +
        "split-pane -H --size 0.42 --title `"$title`" --suppressApplicationTitle -d `"$proj`" $drive alice `"$sync`""
    Start-Process wt.exe -ArgumentList $wtArgs

    $hwnd = [IntPtr]::Zero
    for ($i = 0; $i -lt 100 -and $hwnd -eq [IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 200; $hwnd = [DemoWin]::Find($title)
    }
    if ($hwnd -eq [IntPtr]::Zero) { throw "Windows Terminal window '$title' not found" }
    Start-Sleep -Seconds 3                      # let the bots print their banners
    [void][DemoWin]::SetForegroundWindow($hwnd)
    $r = New-Object DemoWin+RECT
    [void][DemoWin]::DwmGetWindowAttribute($hwnd, 9, [ref]$r, 16)   # extended frame bounds
    $w = ($r.R - $r.L) - (($r.R - $r.L) % 2); $h = ($r.B - $r.T) - (($r.B - $r.T) % 2)
    Write-Host "capturing ${w}x${h} at $($r.L),$($r.T)"

    $psi = New-Object System.Diagnostics.ProcessStartInfo "ffmpeg"
    $psi.Arguments = "-loglevel error -y -f gdigrab -framerate 10 -draw_mouse 0 " +
        "-offset_x $($r.L) -offset_y $($r.T) -video_size ${w}x${h} -i desktop " +
        "-c:v libx264 -preset ultrafast -qp 0 -pix_fmt yuv444p `"$raw`""
    $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true
    $ffmpeg = [System.Diagnostics.Process]::Start($psi)
    Start-Sleep -Seconds 1
    New-Item -ItemType File (Join-Path $sync "go") | Out-Null

    $deadline = (Get-Date).AddMinutes(15)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path (Join-Path $sync "FAIL")) { break }
        if ((Test-Path (Join-Path $sync "done_master")) -and
            (Test-Path (Join-Path $sync "done_alice"))) { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 4                      # hold the final screen
    $ffmpeg.StandardInput.Write("q"); $ffmpeg.StandardInput.Close()
    if (-not $ffmpeg.WaitForExit(30000)) { $ffmpeg.Kill() }
    New-Item -ItemType File (Join-Path $sync "close") | Out-Null

    if (Test-Path (Join-Path $sync "FAIL")) {
        throw ("demo failed: " + (Get-Content (Join-Path $sync "FAIL") -Raw))
    }
    if (-not (Test-Path (Join-Path $sync "done_alice"))) { throw "demo timed out" }

    # Wait for both drivers to exit before the files are restored.
    for ($i = 0; $i -lt 60; $i++) {
        if ((Test-Path (Join-Path $sync "exit_master")) -and
            (Test-Path (Join-Path $sync "exit_alice"))) { break }
        Start-Sleep -Milliseconds 500
    }

    New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
    $pal = Join-Path $work "palette.png"
    $vf = "setpts=PTS/$Speed,fps=$Fps"
    ffmpeg -loglevel error -y -ss 0.5 -i $raw -vf "$vf,palettegen=max_colors=64:stats_mode=diff" $pal
    ffmpeg -loglevel error -y -ss 0.5 -i $raw -i $pal -lavfi "$vf [x]; [x][1:v] paletteuse=dither=none:diff_mode=rectangle" $Out
    if ($LASTEXITCODE -ne 0) { throw "GIF conversion failed" }
    Write-Host ("wrote $Out ({0:N1} MB)" -f ((Get-Item $Out).Length / 1MB))
    Write-Host "raw capture kept at $raw"
}
finally {
    if ($ffmpeg -and -not $ffmpeg.HasExited) { $ffmpeg.Kill() }
    if (-not (Test-Path (Join-Path $sync "close"))) {
        New-Item -ItemType File (Join-Path $sync "close") | Out-Null
    }
    Start-Sleep -Seconds 2
    # Kill anything still running from this take (drivers and their bots).
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like "*drive.py*$sync*" } |
        ForEach-Object { taskkill /T /F /PID $_.ProcessId 2>$null | Out-Null }
    $ok = $true
    foreach ($f in $files) {
        $b = Join-Path $bak ($f -replace '[\\/]', '__')
        if ($null -ne $hashes[$f]) {
            Copy-Item $b $f -Force
            $now = (Get-FileHash $f -Algorithm SHA256).Hash
            $match = $now -eq $hashes[$f]
            if (-not $match) { $ok = $false }
            Write-Host "restored $f sha256=$now match=$match"
        } elseif (Test-Path $f) {
            Remove-Item $f -Force; Write-Host "removed $f (did not exist before)"
        }
    }
    if (-not $lockExisted -and (Test-Path $lock)) { Remove-Item $lock -Force; Write-Host "removed stale lock" }
    if (-not $ok) { Write-Error "RESTORE MISMATCH - backups are in $bak" }
}
