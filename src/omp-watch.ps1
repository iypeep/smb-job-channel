# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
<#
  omp-watch.ps1  v1.0.0  -  self-healing watchdog for the OMP bridge body.

  Why this exists
    start-bridge.cmd only restarts omp-body.ps1 when the process EXITS. A body that is
    blocked inside a share (SMB) call keeps its pid, keeps bridge.lock, and keeps the
    hub heartbeat frozen - so nothing restarts it and no manual reinstall can take over.
    This watchdog judges health from a LOCAL beacon (state\hb.json, written by the body
    every second) and kills + respawns the body when that beacon stops moving.

  Decision table (all inputs local, no share access on the critical path)
    body pid gone                                  -> start the launcher
    beacon age > StaleSec, no job                  -> kill tree, launcher restarts it
    beacon age > StaleSec + JobGraceSec, job in it -> kill tree (stuck job), same
    beacon fresh                                   -> healthy, touch nothing

  Modes
    (default)   resident loop, every -IntervalSec
    -Once       single pass, for the scheduled-task backstop (5 min)

  Files
    <local>\state\hb.json        written by the body (read here)
    <local>\state\watch.json     written here: pid/restarts/last_reason/ages
    <local>\watch.log            rolling ASCII log
    <local>\watch.lock           single-instance guard

  v1.1.0: the watchdog no longer touches the share at all. It used to mirror itself to
  <hub>\machines\<M>\state\watchdog.json through a hidden `powershell -ExecutionPolicy Bypass
  -Command` child; that is exactly the pattern endpoint security (Huorong 系统加固: 利用
  PowerShell 执行可疑脚本) blocks, so on protected machines the mirror silently froze while
  the body still beat. The body now copies this file's contents into its own heartbeat
  (`watch`), which it already writes to every live hub - same information, no child process.
#>
param(
  [string]$Local = '',
  [int]$StaleSec = 120,
  [int]$JobGraceSec = 120,
  [int]$IntervalSec = 30,
  [int]$MaxRestartsPerHour = 12,
  [switch]$Once,
  [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$WatchVersion = '1.1.0'
$Utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false

if (-not $Local) {
  # self-locating first: the install directory may be outside the user profile
  try { $Local = Split-Path -Parent $MyInvocation.MyCommand.Definition } catch { }
}
if (-not $Local -or -not (Test-Path $Local)) {
  $Local = Join-Path $env:LOCALAPPDATA 'smb-job-channel'
  if (-not (Test-Path $Local)) { $Local = Join-Path $env:TEMP 'smb-job-channel' }
}
$Local = $Local.TrimEnd('\')
$StateDir = Join-Path $Local 'state'
$HbFile = Join-Path $StateDir 'hb.json'
$StatsFile = Join-Path $StateDir 'watch.json'
$LogFile = Join-Path $Local 'watch.log'
$LockFile = Join-Path $Local 'watch.lock'
$BodyLock = Join-Path $Local 'bridge.lock'
# the launcher and body file names are deployment details, not protocol:
# this install renames both, so read them from settings.ini when present.
$BodyName = 'omp-body.ps1'
$LauncherName = 'start-bridge.cmd'
$cfgFile = Join-Path $Local 'settings.ini'
if (Test-Path $cfgFile) {
  foreach ($line in (Get-Content -Path $cfgFile -ErrorAction SilentlyContinue)) {
    $t = $line.Trim()
    if ($t -match '^(?i)BODY_NAME\s*=\s*(.+)$') { $BodyName = $Matches[1].Trim() }
    if ($t -match '^(?i)LAUNCHER_NAME\s*=\s*(.+)$') { $LauncherName = $Matches[1].Trim() }
  }
}
$Launcher = Join-Path $Local $LauncherName
$BodyExe = Join-Path $Local $BodyName

foreach ($d in @($StateDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null } }

function Say([string]$m) {
  if (-not $Quiet) { Write-Host $m }
}
function Log([string]$m) {
  $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $m
  Say $line
  try {
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1000000)) {
      Move-Item -Path $LogFile -Destination ($LogFile + '.1') -Force -ErrorAction SilentlyContinue
    }
  } catch { }
  try { Add-Content -Path $LogFile -Value $line -Encoding ASCII } catch { }
}
function Read-JsonFile([string]$p) {
  try { if (Test-Path $p) { return ((Get-Content -Path $p -Raw -ErrorAction Stop) | ConvertFrom-Json) } } catch { }
  return $null
}
function Write-JsonFile([string]$p, $obj) {
  try { [System.IO.File]::WriteAllText($p, ($obj | ConvertTo-Json -Depth 5), $Utf8) } catch { }
}
function Get-UnixNow() { return [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Set-Prop($obj, [string]$name, $value) {
  # ConvertFrom-Json objects have a fixed shape: overwriting unknown members throws
  $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
}
function Test-Pid([int64]$procId) {
  if ($procId -le 0) { return $false }
  try { [void](Get-Process -Id $procId -ErrorAction Stop); return $true } catch { return $false }
}

# ---------------------------------------------------------------- single instance
if (Test-Path $LockFile) {
  $oldPid = 0
  [void][int]::TryParse(((Get-Content -Path $LockFile -TotalCount 1) -replace '\s.*$', ''), [ref]$oldPid)
  if (Test-Pid $oldPid) {
    Say ('watchdog already running (pid ' + $oldPid + ') - nothing to do')
    exit 0
  }
}
[System.IO.File]::WriteAllText($LockFile, ([string]$PID + ' ' + (Get-Date).ToString('s')), $Utf8)

# ---------------------------------------------------------------- helpers
function Get-LauncherPid {
  try {
    $c = @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -and $_.CommandLine -like ('*' + $LauncherName + '*') })
    if ($c.Count -gt 0) { return [int64]$c[0].ProcessId }
  } catch { }
  return 0
}

function Start-Launcher {
  if (-not (Test-Path $Launcher)) {
    Log ('launcher missing: ' + $Launcher + ' - run install.cmd on this machine')
    return $false
  }
  # Never start a SECOND loop: two start-bridge.cmd loops plus a self-update handover is what
  # produced duplicate bodies (a wedged one then swallowed jobs -> "timeout, no output").
  if ((Get-LauncherPid) -ne 0) { Log 'launcher already alive - not starting another'; return $true }
  $stamp = Join-Path $Local 'launcher.started'
  if (Test-Path $stamp) {
    try { if (((Get-Date) - (Get-Item $stamp).LastWriteTime).TotalSeconds -lt 120) { Log 'launcher started recently - waiting'; return $true } } catch { }
  }
  try {
    Set-Content -Path $stamp -Value (Get-Date).ToString('s') -Encoding ASCII
    Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c "' + $Launcher + '"') -WindowStyle Hidden -WorkingDirectory $Local | Out-Null
    Log 'launcher started (start-bridge.cmd)'
    Start-Sleep -Seconds 3
    if ((Get-LauncherPid) -eq 0) { Log 'WARNING: launcher did not appear' }
    return $true
  } catch {
    Log ('failed to start launcher: ' + $_.Exception.Message)
    return $false
  }
}

# v1.1.0: Publish-Hub() used to spawn `powershell -ExecutionPolicy Bypass -Command` hidden to
# copy watch.json to the share. Endpoint security blocks that launch (it looks like a hidden
# script payload), which froze the mirror on protected machines. The body reports this file's
# contents inside its heartbeat instead - see the `watch` member in omp-body.ps1.

function Restart-Body([int64]$procId, [string]$reason, $stats) {
  Log ('RESTART reason=' + $reason + ' target_pid=' + $procId)
  if ($procId -gt 0) {
    try { & taskkill.exe /PID $procId /T /F 2>&1 | Out-Null } catch { }
    Start-Sleep -Seconds 2
    if (Test-Pid $procId) {
      try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch { }
      Start-Sleep -Milliseconds 500
    }
  }
  # release a lock left behind by the process we just killed
  try {
    if (Test-Path $BodyLock) {
      $lockPid = 0
      [void][int]::TryParse(((Get-Content -Path $BodyLock -TotalCount 1) -replace '\s.*$', ''), [ref]$lockPid)
      if ($lockPid -eq $procId -or -not (Test-Pid $lockPid)) { Remove-Item $BodyLock -Force -ErrorAction SilentlyContinue }
    }
  } catch { }
  if ((Get-LauncherPid) -eq 0) { [void](Start-Launcher) } else { Log 'launcher is alive - it will respawn the body within ~20s' }
  Set-Prop $stats 'restarts' ([int64]$stats.restarts + 1)
  Set-Prop $stats 'last_reason' $reason
  Set-Prop $stats 'last_restart_at' ((Get-Date).ToString('s'))
  $stamp = Get-UnixNow
  $stamps = @()
  foreach ($s in @($stats.restart_stamps)) { if ($s -and ($stamp - [int64]$s) -lt 3600) { $stamps += [int64]$s } }
  $stamps += $stamp
  Set-Prop $stats 'restart_stamps' $stamps
}

# ---------------------------------------------------------------- one pass
$stats = Read-JsonFile $StatsFile
if (-not $stats) { $stats = [pscustomobject]@{ restarts = 0 } }
if ($null -eq $stats.restarts) { $stats | Add-Member -NotePropertyName restarts -NotePropertyValue 0 -Force }
$stats | Add-Member -NotePropertyName pid -NotePropertyValue $PID -Force
$stats | Add-Member -NotePropertyName version -NotePropertyValue $WatchVersion -Force
$stats | Add-Member -NotePropertyName checked_at -NotePropertyValue ((Get-Date).ToString('s')) -Force
$stats | Add-Member -NotePropertyName stale_sec -NotePropertyValue $StaleSec -Force

$hb = Read-JsonFile $HbFile
$bodyPid = 0
$age = -1
$inJob = $false
$jobDesc = ''
if ($hb -and $hb.pid) {
  $bodyPid = [int64]$hb.pid
  if ($hb.ts) { $age = (Get-UnixNow) - [int64]$hb.ts }
  if ($hb.job_id) {
    $inJob = $true
    $jobDesc = [string]$hb.job_id + '/' + [string]$hb.job_kind
  }
}

$stats | Add-Member -NotePropertyName body_pid -NotePropertyValue $bodyPid -Force
$stats | Add-Member -NotePropertyName body_alive -NotePropertyValue (Test-Pid $bodyPid) -Force
$stats | Add-Member -NotePropertyName beacon_age_sec -NotePropertyValue $age -Force
$stats | Add-Member -NotePropertyName body_phase -NotePropertyValue ($(if ($hb) { [string]$hb.phase } else { 'no-beacon' })) -Force
$stats | Add-Member -NotePropertyName body_job -NotePropertyValue $jobDesc -Force
$stats | Add-Member -NotePropertyName launcher_pid -NotePropertyValue (Get-LauncherPid) -Force

$budgetLeft = $MaxRestartsPerHour
if ($stats.restart_stamps) {
  $now = Get-UnixNow
  $recent = @(@($stats.restart_stamps) | Where-Object { $now - [int64]$_ -lt 3600 })
  $budgetLeft = $MaxRestartsPerHour - $recent.Count
}
$stats | Add-Member -NotePropertyName restarts_last_hour -NotePropertyValue ($MaxRestartsPerHour - $budgetLeft) -Force

$healthy = $true
$reason = ''

if (-not (Test-Path $HbFile)) {
  # no beacon at all: either a pre-2.3 body or a body that never got as far as writing it
  if (Test-Pid $bodyPid) {
    $healthy = $false
    $reason = 'no-beacon'
  } elseif ($stats.launcher_pid -eq 0) {
    $healthy = $false
    $reason = 'no-body'
  }
} elseif (-not (Test-Pid $bodyPid)) {
  $healthy = $false
  $reason = 'body-gone'
} elseif ($age -gt ($StaleSec + $(if ($inJob) { $JobGraceSec } else { 0 }))) {
  $healthy = $false
  $reason = $(if ($inJob) { 'stuck-job:' + $jobDesc } else { 'stale-idle' })
}

$stats | Add-Member -NotePropertyName healthy -NotePropertyValue $healthy -Force
$stats | Add-Member -NotePropertyName reason -NotePropertyValue $reason -Force

if ($healthy) {
  Set-Prop $stats 'last_ok' ((Get-Date).ToString('s'))
  Write-JsonFile $StatsFile $stats
  if (-not $Once) { Say ('ok  body=' + $bodyPid + ' phase=' + $stats.body_phase + ' age=' + $age + 's') }
} elseif ($budgetLeft -le 0) {
  Set-Prop $stats 'last_reason' 'restart-budget-exhausted'
  Write-JsonFile $StatsFile $stats
  Log ('unhealthy (' + $reason + ') but ' + $MaxRestartsPerHour + ' restarts in the last hour - backing off 5 min')
  if (-not $Once) { Start-Sleep -Seconds 300 }
} else {
  Restart-Body $bodyPid $reason $stats
  Write-JsonFile $StatsFile $stats
}

if ($Once) {
  Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
  exit 0
}

# ---------------------------------------------------------------- resident loop
Log ('watchdog v' + $WatchVersion + ' up pid=' + $PID + ' stale=' + $StaleSec + 's interval=' + $IntervalSec + 's')
while ($true) {
  Start-Sleep -Seconds $IntervalSec
  $hb = Read-JsonFile $HbFile
  $bodyPid = 0; $age = -1; $inJob = $false; $jobDesc = ''
  if ($hb -and $hb.pid) {
    $bodyPid = [int64]$hb.pid
    if ($hb.ts) { $age = (Get-UnixNow) - [int64]$hb.ts }
    if ($hb.job_id) { $inJob = $true; $jobDesc = [string]$hb.job_id + '/' + [string]$hb.job_kind }
  }
  $stats | Add-Member -NotePropertyName checked_at -NotePropertyValue ((Get-Date).ToString('s')) -Force
  $stats | Add-Member -NotePropertyName body_pid -NotePropertyValue $bodyPid -Force
  $stats | Add-Member -NotePropertyName body_alive -NotePropertyValue (Test-Pid $bodyPid) -Force
  $stats | Add-Member -NotePropertyName beacon_age_sec -NotePropertyValue $age -Force
  $stats | Add-Member -NotePropertyName body_phase -NotePropertyValue ($(if ($hb) { [string]$hb.phase } else { 'no-beacon' })) -Force
  $stats | Add-Member -NotePropertyName body_job -NotePropertyValue $jobDesc -Force
  $stats | Add-Member -NotePropertyName launcher_pid -NotePropertyValue (Get-LauncherPid) -Force

  $healthy = $true; $reason = ''
  if (-not (Test-Path $HbFile)) {
    if (Test-Pid $bodyPid) { $healthy = $false; $reason = 'no-beacon' }
    elseif ($stats.launcher_pid -eq 0) { $healthy = $false; $reason = 'no-body' }
  } elseif (-not (Test-Pid $bodyPid)) {
    $healthy = $false; $reason = 'body-gone'
  } elseif ($age -gt ($StaleSec + $(if ($inJob) { $JobGraceSec } else { 0 }))) {
    $healthy = $false; $reason = $(if ($inJob) { 'stuck-job:' + $jobDesc } else { 'stale-idle' })
  }

  $stats | Add-Member -NotePropertyName healthy -NotePropertyValue $healthy -Force
  $stats | Add-Member -NotePropertyName reason -NotePropertyValue $reason -Force

  if ($healthy) {
    Set-Prop $stats 'last_ok' ((Get-Date).ToString('s'))
  } else {
    $now = Get-UnixNow
    $recent = @(@($stats.restart_stamps) | Where-Object { $_ -and ($now - [int64]$_) -lt 3600 })
    if ($recent.Count -ge $MaxRestartsPerHour) {
      Log ('unhealthy (' + $reason + ') but restart budget used up - backing off')
      Set-Prop $stats 'last_reason' 'restart-budget-exhausted'
      Start-Sleep -Seconds 300
    } else {
      Restart-Body $bodyPid $reason $stats
    }
  }
  Write-JsonFile $StatsFile $stats
}

Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
