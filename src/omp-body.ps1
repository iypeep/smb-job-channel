# SPDX-License-Identifier: AGPL-3.0-or-later
<#
  omp-body.ps1  v2.0.0  -  the machine end of a file-hub remote-control channel.

  The machines have no path to a model, so they do not think: they execute.
  This script polls a folder on the public share, runs the task it finds, streams
  output back, and writes a verdict. The intelligence stays on the operator box.

  Job kinds
    ps      run a PowerShell script (job.file or job.code)      -> stdout/stderr/result
    cmd     run a batch file (job.file or job.code)             -> same
    fetch   copy files matching job.patterns into out\<id>.files\ + manifest.tsv
    push    copy inbox\push\<id>\<name> to job.target (sha1 verified)
    kill    terminate job.pid (tree) or job.name
    ping    liveness + capabilities
    omp     run omp.exe non-interactively (only if installed and configured)

  Shared fields: id, kind, cwd, timeout, note, args, env (name->value)

  Self-healing (v2.3.0)
    This process may block inside a share (SMB) call and then never return - the pid stays
    alive, bridge.lock stays held, and the hub heartbeat freezes. It therefore writes a
    LOCAL beacon every second (<local>\state\hb.json) that omp-watch.ps1 uses to decide
    whether it is still making progress. Do not judge health from the share alone.

  Identity (v2.4.0)
    %COMPUTERNAME% is not unique: cloned machines share it (and MachineGuid too), so their
    jobs landed in one folder. The name is now derived from a hardware fingerprint
    (system disk serial, else physical NIC MACs), persisted in <local>\machine.name and
    claimed on the hub as <hub>\machines\<name>\state\identity.json. When the name is
    already owned by a different fingerprint the body appends -<fp4>. Override on purpose
    with MACHINE_NAME= in settings.ini (a clash then fails loudly instead of sharing).

  Layout
    <local>\state\hb.json                       local progress beacon (watchdog input)
    <hub>\machines\<M>\inbox\<id>.job.json      task
    <hub>\machines\<M>\inbox\files\<id>-x.ps1   script payload (UTF-8 BOM)
    <hub>\machines\<M>\inbox\push\<id>\<name>   file to push
    <hub>\machines\<M>\inbox\<id>.cancel        stop it
    <hub>\machines\<M>\run\<id>.stdout.txt      live output
    <hub>\machines\<M>\run\<id>.stderr.txt      live progress/errors
    <hub>\machines\<M>\out\<id>.result.json     verdict
    <hub>\machines\<M>\out\<id>.manifest.tsv    fetch listing (rel, size, sha1)
    <hub>\machines\<M>\state\heartbeat.json     liveness
#>
param(
  [string]$Hub = '',
  [string]$Machine = '',
  [int]$PollSec = 5,
  [switch]$Once,
  [switch]$Console
)

$ErrorActionPreference = 'Continue'
$BodyVersion = '2.7.3'
$Utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$SelfPath = $MyInvocation.MyCommand.Definition
$Local = Split-Path -Parent $SelfPath
$LogFile = Join-Path $Local 'bridge.log'
$Verbose = [bool]$Console
$RunsRoot = Join-Path $Local 'runs'
$LocalState = Join-Path $Local 'state'
$LocalHb = Join-Path $LocalState 'hb.json'
$WatchLock = Join-Path $Local 'watch.lock'
$HandoverFile = Join-Path $Local 'handover.txt'
$script:JobsDone = 0
$script:LastJob = '-'
$script:OmpVersion = '-'
$script:StartedAt = Get-Date
# health/progress state - written to a LOCAL file so that the watchdog never has to
# touch the share to decide whether this process is still making progress.
$script:Phase = 'bootstrap'
$script:JobId = ''
$script:JobKind = ''
$script:JobStart = 0
$script:JobTimeout = 0
$script:Loop = 0
$script:HubErrors = 0
$script:HubOk = $true
$script:BeatEveryMs = 1000
$script:LastBeatMs = [int64]0

function Write-Log {
  param([string]$msg)
  $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $msg
  if ($Verbose) { Write-Host $line }
  try {
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1000000)) {
      Move-Item -Path $LogFile -Destination ($LogFile + '.1') -Force
    }
  } catch { }
  try { Add-Content -Path $LogFile -Value $line -Encoding ASCII } catch { }
}

function Read-Text {
  param([string]$path)
  try { if (Test-Path $path) { return [System.IO.File]::ReadAllText($path) } } catch { }
  return ''
}

function Write-Text {
  param([string]$path, [string]$text, [int]$tries = 3)
  for ($i = 0; $i -lt $tries; $i++) {
    try { [System.IO.File]::WriteAllText($path, $text, $Utf8); return $true } catch {
      Start-Sleep -Milliseconds 400
    }
  }
  return $false
}

function Read-Json {
  param([string]$path)
  $t = Read-Text $path
  if (-not $t) { return $null }
  try { return ($t | ConvertFrom-Json) } catch { return $null }
}

function Write-LocalBeat {
  # Local, share-independent progress beacon. The watchdog reads this file only.
  param([string]$phase = '', [switch]$Force)
  if ($phase) { $script:Phase = $phase }
  $nowMs = [int64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  if (-not $Force -and ($nowMs - $script:LastBeatMs) -lt $script:BeatEveryMs) { return }
  $script:LastBeatMs = $nowMs
  $o = [ordered]@{
    ah = 1
    machine = $Machine
    version = $BodyVersion
    pid = $PID
    ts = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    iso = (Get-Date).ToString('s')
    loop = $script:Loop
    phase = $script:Phase
    job_id = $script:JobId
    job_kind = $script:JobKind
    job_started = $script:JobStart
    job_timeout = $script:JobTimeout
    jobs_done = $script:JobsDone
    last_job = $script:LastJob
    hub_ok = $script:HubOk
  }
  Write-Text $LocalHb ($o | ConvertTo-Json -Depth 3) | Out-Null
}

function Ensure-Dir {
  param([string]$path)
  try {
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
    return $true
  } catch {
    Write-Log ('cannot create dir ' + $path + ' : ' + $_.Exception.Message)
    return $false
  }
}

# ---------------------------------------------------------------- identity
# Why: cloned images ship the same %COMPUTERNAME% (and the same MachineGuid as well).
# Two hosts then share one <hub>\machines\<name> folder: jobs land on either box,
# heartbeats overwrite each other and Repair-OrphanJobs kills the peer's live job.
# Identity = a hardware fingerprint, persisted locally and claimed on the hub.
function Get-MachineFingerprint {
  $s = ''
  try {
    $d = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.Index -eq 0 })[0]
    if ($d -and $d.SerialNumber) { $s = 'disk:' + ($d.SerialNumber.Trim().ToUpper()) }
  } catch { }
  if (-not $s) {
    try {
      $macs = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceDescription -notmatch 'USB|Wireless|Wi-Fi|Bluetooth' } |
                Sort-Object MacAddress | ForEach-Object { $_.MacAddress })
      if ($macs.Count -gt 0) { $s = 'mac:' + ($macs -join '|') }
    } catch { }
  }
  if (-not $s) { $s = 'host:' + $env:COMPUTERNAME }
  try {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s))
    return ((@($h | ForEach-Object { $_.ToString('x2') }) -join '')).Substring(0, 8).ToUpper()
  } catch { return '00000000' }
}

function Get-MachineNetInfo {
  $ips = @()
  $macs = @()
  try {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
             ForEach-Object { $_.IPAddress })
  } catch { }
  try {
    $macs = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
              Where-Object { $_.InterfaceDescription -notmatch 'USB|Wireless|Wi-Fi|Bluetooth' } |
              Sort-Object MacAddress | ForEach-Object { $_.MacAddress })
  } catch { }
  return @{ ips = $ips; macs = $macs }
}

function Resolve-MachineName {
  # Returns the folder name to use under <hub>\machines. Always returns something usable:
  # on any hub trouble it falls back to %COMPUTERNAME% rather than blocking the machine.
  param([string]$Hub, [string]$Explicit = '')

  $base = (($env:COMPUTERNAME) -replace '[^A-Za-z0-9_.\-]', '_').ToUpper()
  try {
    $fp = Get-MachineFingerprint
    $net = Get-MachineNetInfo
    $cache = Join-Path $Local 'machine.name'

    $candidate = ''
    if ($Explicit) { $candidate = (($Explicit -replace '[^A-Za-z0-9_.\-]', '_').ToUpper()) }
    elseif (Test-Path $cache) {
      $t = ((Read-Text $cache).Trim() -split '\|')
      if ($t[0]) { $candidate = $t[0].ToUpper() }
    }
    if (-not $candidate) { $candidate = $base }

    $state = Join-Path $Hub 'machines'
    for ($i = 0; $i -lt 3; $i++) {
      if ($i -eq 0) { $name = $candidate }
      else {
        $len = 4 + 2 * ($i - 1)
        if ($len -gt 8) { $len = 8 }
        $name = $base + '-' + $fp.Substring(0, $len)
      }
      $idDir = Join-Path (Join-Path $state $name) 'state'
      if (-not (Ensure-Dir $idDir)) { break }
      $idFile = Join-Path $idDir 'identity.json'

      $ok = $false
      $fs = $null
      try {
        $fs = [System.IO.File]::Open($idFile, 'CreateNew', 'Write', 'None')
        $bw = New-Object System.IO.StreamWriter($fs, $Utf8)
        $bw.Write(([ordered]@{
          ah = 1; name = $name; fp = $fp; hostname = $env:COMPUTERNAME
          ips = @($net.ips); macs = @($net.macs)
          fp_history = @($fp); claimed_at = (Get-Date).ToString('s')
        } | ConvertTo-Json -Depth 4))
        $bw.Close()
        $ok = $true
        Write-Log ('identity claimed: ' + $name + ' fp=' + $fp + ' host=' + $env:COMPUTERNAME)
      } catch {
        $other = Read-Json $idFile
        if (-not $other) {
          # unreadable (transient SMB / ACL) - do not churn the name, reuse it
          Write-Log ('identity unreadable at ' + $name + ' - reusing it')
          $ok = $true
        } elseif ($other.fp -eq $fp) {
          $ok = $true
          Write-Log ('identity reused: ' + $name + ' fp=' + $fp)
        } elseif (@($other.fp_history) -contains $fp) {
          $ok = $true
          Write-Log ('identity reused via history: ' + $name + ' fp=' + $fp)
        } else {
          Write-Log ('identity taken: ' + $name + ' by fp=' + $other.fp + ' (host ' + $other.hostname + ') - trying a suffixed name')
        }
      } finally {
        if ($fs) { try { $fs.Close() } catch { } }
      }

      if ($ok) {
        [void](Write-Text $cache ($name + '|' + $fp + "`r`n"))
        return $name
      }
      if ($Explicit) {
        Write-Log ('FATAL: name ' + $name + ' is owned by a different machine; fix settings.ini MACHINE_NAME')
        return ''
      }
    }
    Write-Log ('identity: could not claim a unique name under ' + $state + ' - falling back to ' + $base)
  } catch {
    Write-Log ('identity resolve failed: ' + $_.Exception.Message)
  }
  return $base
}


function Confirm-MachineIdentity {
  # Used when the name was passed explicitly (-Machine / MACHINE_NAME=). The operator
  # owns the name, so we never rename - but we still record the fingerprint so the office
  # side can tell which physical box is behind it, and we shout if it is someone else's.
  param([string]$Hub, [string]$Name)
  try {
    $fp = Get-MachineFingerprint
    $idDir = Join-Path (Join-Path (Join-Path $Hub 'machines') $Name) 'state'
    if (-not (Ensure-Dir $idDir)) { return }
    $idFile = Join-Path $idDir 'identity.json'
    $existing = Read-Json $idFile
    if ($existing -and $existing.fp -and ($existing.fp -ne $fp)) {
      Write-Log ('WARNING: name ' + $Name + ' was first used by fp=' + $existing.fp + ' (host ' + $existing.hostname + '), this box is fp=' + $fp)
      return
    }
    if ($existing) { return }
    $net = Get-MachineNetInfo
    [void](Write-Text $idFile (([ordered]@{
      ah = 1; name = $Name; fp = $fp; hostname = $env:COMPUTERNAME
      ips = @($net.ips); macs = @($net.macs)
      fp_history = @($fp); claimed_at = (Get-Date).ToString('s'); pinned = $true
    } | ConvertTo-Json -Depth 4)))
    [void](Write-Text (Join-Path $Local 'machine.name') ($Name + '|' + $fp + "`r`n"))
    Write-Log ('identity pinned: ' + $Name + ' fp=' + $fp)
  } catch { Write-Log ('identity pin failed: ' + $_.Exception.Message) }
}

function Get-Sha1 {
  param([string]$Path)
  try {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $h = $sha.ComputeHash($fs)
    $fs.Close()
    $s = ''
    foreach ($b in $h) { $s += $b.ToString('x2') }
    return $s
  } catch { return '' }
}

# ---------------------------------------------------------------- settings
$Settings = @{}
$SettingsFile = Join-Path $Local 'settings.ini'
if (Test-Path $SettingsFile) {
  foreach ($line in ((Read-Text $SettingsFile) -split "`r?`n")) {
    $t = $line.Trim()
    if (-not $t -or $t.StartsWith('#') -or $t.StartsWith(';')) { continue }
    $eq = $t.IndexOf('=')
    if ($eq -gt 0) { $Settings[$t.Substring(0, $eq).Trim().ToUpper()] = $t.Substring($eq + 1).Trim() }
  }
}
$OmpExe = Join-Path $Local 'omp\omp.exe'
if ($Settings['OMP_EXE']) { $OmpExe = $Settings['OMP_EXE'] }
elseif (-not (Test-Path $OmpExe)) {
  $cmd = Get-Command omp -ErrorAction SilentlyContinue
  if ($cmd) { $OmpExe = $cmd.Source }
}
$DefaultModel = $Settings['MODEL']
$ApiKey = $Settings['API_KEY']
if (-not $ApiKey) {
  $kf = Join-Path $Local 'api.key'
  if (Test-Path $kf) { $ApiKey = (Read-Text $kf).Trim() }
}
$ExtraArgs = $Settings['EXTRA_ARGS']
$AllowedCwd = $Settings['ALLOWED_CWD']
$SessionDir = Join-Path $Local 'sessions'
foreach ($d in @($SessionDir, $RunsRoot, (Join-Path $Local 'tmp'), $LocalState)) { Ensure-Dir $d }

# ---------------------------------------------------------------- job integrity
# The hub is a company share: anybody with write access to it can drop a job file.
# A job therefore carries an HMAC over its routing fields and an AES-encrypted body;
# without the pre-shared key nothing on the share can make this process run code.
#   PSK=<32-byte hex>      shared with the control box only (never stored on the share)
#   ALLOW_LEGACY=0         refuse unsigned jobs (rollout switch, default 1)
#   ENC_RESULTS=0          leave results in clear text (default 1 = encrypt)
$script:KeyMac = $null
$script:KeyEnc = $null
$script:AllowLegacy = $true
$script:EncResults = $true
if ($Settings['ALLOW_LEGACY'] -eq '0') { $script:AllowLegacy = $false }
if ($Settings['ENC_RESULTS'] -eq '0') { $script:EncResults = $false }
$script:HavePsk = $false
$script:KeyScope = ''
# v2.7.0 key material: the machine holds a PER-MACHINE seed, never the fleet master.
#   PSK_PROTECTED=<base64 DPAPI blob>   preferred: only this user on this box can unprotect it
#   PSK=<64 hex>                        legacy / fallback (a copied settings.ini leaks it)
#   KEY_SCHEME=hkdf2                    seed -> (K_mac, K_enc) via HKDF-SHA256
# Without KEY_SCHEME the old derivation is used, so a mixed fleet keeps working during migration.
$script:KeyScheme = 'v1'
if ($Settings['KEY_SCHEME']) { $script:KeyScheme = ([string]$Settings['KEY_SCHEME']).Trim().ToLower() }

function Get-HkdfSha256([byte[]]$ikm, [string]$info, [int]$len) {
  # RFC 5869. 32-byte output needs one expand block; kept general for clarity.
  if ($null -eq $ikm -or $ikm.Length -eq 0) { throw 'hkdf: empty ikm' }
  $salt = New-Object byte[] 32
  $hm = New-Object System.Security.Cryptography.HMACSHA256
  $hm.Key = $salt
  $prk = $hm.ComputeHash($ikm)
  $hm2 = New-Object System.Security.Cryptography.HMACSHA256
  $hm2.Key = $prk
  $infoBytes = [System.Text.Encoding]::UTF8.GetBytes($info)
  $okm = New-Object 'System.Collections.Generic.List[byte]'
  $t = New-Object byte[] 0
  $counter = 1
  while ($okm.Count -lt $len) {
    $buf = New-Object 'System.Collections.Generic.List[byte]'
    if ($t.Length -gt 0) { $buf.AddRange($t) }
    $buf.AddRange($infoBytes)
    $buf.Add([byte]$counter)
    $t = $hm2.ComputeHash($buf.ToArray())
    $okm.AddRange($t)
    $counter++
  }
  return $okm.GetRange(0, $len).ToArray()
}

$pskBytes = $null
$script:KeyError = ''
if ($Settings['PSK_PROTECTED']) {
  # PS 5.1 does not auto-load System.Security: without this the type does not resolve and the
  # body silently runs keyless (seen on the first v2 canary). CurrentUser first (the normal
  # case: agent and provisioning job run as the operator account), then LocalMachine (agent
  # started by a SYSTEM scheduled task).
  try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
  $blob = $null
  try { $blob = [Convert]::FromBase64String([string]$Settings['PSK_PROTECTED']) } catch { $script:KeyError = 'PSK_PROTECTED is not base64' }
  foreach ($scopeName in @('CurrentUser', 'LocalMachine')) {
    if ($pskBytes -or -not $blob) { break }
    try {
      $scope = [System.Security.Cryptography.DataProtectionScope]::$scopeName
      $cand = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, $scope)
      if ($cand -and $cand.Length -eq 32) { $pskBytes = $cand; $script:KeyScope = $scopeName }
      else { $script:KeyError = ('unprotected length ' + $(if ($cand) { $cand.Length } else { 0 })) }
    } catch {
      $script:KeyError = ($scopeName + ': ' + $_.Exception.Message)
    }
  }
  if (-not $pskBytes) { Write-Log ('PSK_PROTECTED could not be unprotected: ' + $script:KeyError) }
}
if (-not $pskBytes -and $Settings['PSK']) {
  try {
    $hex = ([string]$Settings['PSK']).Trim()
    $pskBytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $pskBytes.Length; $i++) { $pskBytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
  } catch { Write-Log 'PSK is not valid hex - integrity checks disabled' }
}
if ($pskBytes) {
  try {
    if ($script:KeyScheme -eq 'hkdf2') {
      $script:KeyMac = Get-HkdfSha256 $pskBytes 'omp/job-mac' 32
      $script:KeyEnc = Get-HkdfSha256 $pskBytes 'omp/job-enc' 32
    } else {
      $sha = [System.Security.Cryptography.SHA256]::Create()
      $script:KeyMac = $sha.ComputeHash([byte[]]($pskBytes + [System.Text.Encoding]::ASCII.GetBytes('omp-job-mac')))
      $script:KeyEnc = $sha.ComputeHash([byte[]]($pskBytes + [System.Text.Encoding]::ASCII.GetBytes('omp-job-enc')))
    }
    $script:HavePsk = $true
    Write-Log ('key ready: scheme=' + $script:KeyScheme + ' seed=' + $pskBytes.Length + 'B')
  } catch { Write-Log ('key derivation failed: ' + $_.Exception.Message) }
}
if (-not $script:HavePsk) {
  # No key material at all: refusing unsigned jobs would make the agent unreachable forever.
  # ALLOW_LEGACY=0 must not turn a provisioning mistake into a bricked box, so fall back to
  # legacy with a loud log (a keyed body still refuses unsigned jobs).
  $script:AllowLegacy = $true
  Write-Log 'NO KEY (no PSK and no PSK_PROTECTED) - falling back to legacy unsigned mode for recovery'
}

function Get-Hex([byte[]]$b) { $s = ''; foreach ($x in $b) { $s += $x.ToString('x2') }; return $s }

function Test-MacEquals([string]$a, [string]$b) {
  if (-not $a -or -not $b) { return $false }
  if ($a.Length -ne $b.Length) { return $false }
  $d = 0
  for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
  return ($d -eq 0)
}

# HMAC-SHA256 over an ASCII string -> lowercase hex
function Get-Mac([byte[]]$key, [string]$text) {
  # the key is raw bytes: never round-trip it through a text encoding
  $h = New-Object System.Security.Cryptography.HMACSHA256 (,[byte[]]$key)
  return (Get-Hex ($h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))))
}

# AES-256-CBC/PKCS7. Input: plain bytes. Output: base64(IV || ciphertext)
function Protect-Bytes([byte[]]$key, [byte[]]$plain) {
  $aes = [System.Security.Cryptography.Aes]::Create()
  try {
    $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
    $aes.Key = [byte[]]$key
    $aes.GenerateIV()
    $enc = $aes.CreateEncryptor()
    $ct = $enc.TransformFinalBlock($plain, 0, $plain.Length)
    $all = New-Object byte[] ($aes.IV.Length + $ct.Length)
    [Array]::Copy($aes.IV, 0, $all, 0, $aes.IV.Length)
    [Array]::Copy($ct, 0, $all, $aes.IV.Length, $ct.Length)
    return [Convert]::ToBase64String($all)
  } finally { $aes.Dispose() }
}

function Unprotect-Bytes([byte[]]$key, [string]$b64) {
  $all = [Convert]::FromBase64String($b64)
  if ($all.Length -lt 32) { throw 'ciphertext too short' }
  $iv = New-Object byte[] 16
  [Array]::Copy($all, 0, $iv, 0, 16)
  $ct = New-Object byte[] ($all.Length - 16)
  [Array]::Copy($all, 16, $ct, 0, $ct.Length)
  $aes = [System.Security.Cryptography.Aes]::Create()
  try {
    $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
    $aes.Key = [byte[]]$key; $aes.IV = $iv
    $dec = $aes.CreateDecryptor()
    return $dec.TransformFinalBlock($ct, 0, $ct.Length)
  } finally { $aes.Dispose() }
}

# replays: a nonce may be redeemed once, and only inside the clock window
$NonceFile = Join-Path $LocalState 'nonces.txt'
function Test-NonceUsed([string]$n) {
  if (-not (Test-Path $NonceFile)) { return $false }
  return (@(Get-Content -Path $NonceFile -ErrorAction SilentlyContinue) -contains $n)
}
function Add-Nonce([string]$n) {
  try { Add-Content -Path $NonceFile -Value $n -Encoding ASCII } catch { }
  # keep the file small: 2000 newest entries is many hours of legit traffic
  try {
    $all = @(Get-Content -Path $NonceFile -ErrorAction SilentlyContinue)
    if ($all.Count -gt 2000) { $all[($all.Count - 2000)..($all.Count - 1)] | Set-Content -Path $NonceFile -Encoding ASCII }
  } catch { }
}

# Verify + unwrap a job envelope. Returns @{ok=;job=;err=}
function Open-Job([string]$jobFile) {
  $job = Read-Json $jobFile
  if (-not $job) { return @{ ok = $false; err = 'job json unparseable' } }
  $ah = 0
  if ($job.ah) { $ah = [int][string]$job.ah }
  if ($job.enc -or $ah -ge 2) {
    if (-not $script:HavePsk) { return @{ ok = $false; err = 'unsigned hub job but this body has no PSK' } }
    $sig = [string]$job.mac
    if (-not $sig) { return @{ ok = $false; err = 'missing mac' } }
    $mwant = [string]$job.m
    if ($mwant -and ($mwant.ToUpper() -ne $Machine.ToUpper())) {
      return @{ ok = $false; err = ('job addressed to ' + $mwant + ', not me') }
    }
    $ts = 0L
    [void][int64]::TryParse([string]$job.ts, [ref]$ts)
    $now = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($ts -le 0 -or ([Math]::Abs($now - $ts) -gt 900)) { return @{ ok = $false; err = 'stale or future job (clock window 900s)' } }
    $nonce = [string]$job.nonce
    if (-not $nonce) { return @{ ok = $false; err = 'missing nonce' } }
    if (Test-NonceUsed $nonce) { return @{ ok = $false; err = 'replayed nonce' } }
    $blobName = [string]$job.blob
    if (-not $blobName) { return @{ ok = $false; err = 'missing blob' } }
    $blobPath = Join-Path $InboxFiles $blobName
    if (-not (Test-Path $blobPath)) { return @{ ok = $false; err = ('blob not found: ' + $blobName) } }
    $blobText = (Read-Text $blobPath).Trim()
    $blobSha = ''
    $h = [System.Security.Cryptography.SHA256]::Create()
    $blobSha = Get-Hex ($h.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($blobText)))
    $canon = @('ah2', [string]$job.id, [string]$job.kind, $Machine.ToUpper(), [string]$job.ts, $nonce, $blobSha,
               [string]$job.enc_res, [string]$job.timeout) -join '|'
    $want = Get-Mac $script:KeyMac $canon
    if (-not (Test-MacEquals $want $sig)) { return @{ ok = $false; err = 'bad mac' } }
    try {
      $plain = Unprotect-Bytes $script:KeyEnc $blobText
      $body = [System.Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    } catch { return @{ ok = $false; err = 'blob decrypt failed' } }
    foreach ($p in $body.PSObject.Properties) {
      if ($p.Name -eq 'id' -or $p.Name -eq 'mac' -or $p.Name -eq 'nonce') { continue }
      $job | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
    }
    Add-Nonce $nonce
    return @{ ok = $true; job = $job }
  }
  if (-not $script:AllowLegacy) { return @{ ok = $false; err = 'unsigned job refused (ALLOW_LEGACY=0)' } }
  return @{ ok = $true; job = $job }
}

# ---------------------------------------------------------------- hub
if (-not $Hub) {
  $cfg = Join-Path $Local 'hub.txt'
  if (Test-Path $cfg) { $Hub = (Read-Text $cfg).TrimStart([char]0xFEFF).Trim() }
}
if (-not $Hub) { Write-Log 'FATAL: no hub configured (hub.txt missing)'; exit 2 }
$Hub = $Hub.TrimEnd('\')

# ---------------------------------------------------------------- mirrors
# A single share is a single point of failure. hubs.txt may list several roots of the
# same logical channel (different shares on the same file server today); the body works
# on the first reachable one and keeps its heartbeat on every reachable one.
$HubList = @($Hub)
$hubCfg = Join-Path $Local 'hubs.txt'
if (Test-Path $hubCfg) {
  $extra = @((Read-Text $hubCfg) -split "`r?`n" | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object { $_ -and -not $_.StartsWith('#') })
  foreach ($h in $extra) { if ($HubList -notcontains $h) { $HubList += $h } }
}
if ($Settings['HUBS']) {
  foreach ($h in @($Settings['HUBS'] -split ';')) {
    $t = $h.Trim().TrimEnd('\')
    if ($t -and $HubList -notcontains $t) { $HubList += $t }
  }
}
$script:HubList = $HubList
function Get-LiveHubs {
  $live = @()
  foreach ($h in $script:HubList) {
    try { if (Test-Path (Join-Path $h 'machines')) { $live += $h } } catch { }
  }
  return $live
}

# hubs.txt can change while we run (a mirror is added, a share is retired). Re-reading it
# costs one stat and lets the control box provision a key across two roots without a
# restart - a job queued on a brand-new mirror is then picked up on the next loop.
$script:HubCfgStamp = [datetime]::MinValue
function Refresh-Hubs {
  $cfgPath = Join-Path $Local 'hubs.txt'
  if (-not (Test-Path $cfgPath)) { return }
  try {
    $stamp = (Get-Item $cfgPath).LastWriteTimeUtc
    if ($stamp -eq $script:HubCfgStamp) { return }
    $script:HubCfgStamp = $stamp
  } catch { return }
  $list = @($Hub)
  foreach ($line in @((Read-Text $cfgPath) -split "`r?`n")) {
    $t = $line.Trim().TrimEnd('\')
    if ($t -and -not $t.StartsWith('#') -and ($list -notcontains $t)) { $list += $t }
  }
  $diff = @(Compare-Object -ReferenceObject @($script:HubList) -DifferenceObject @($list) -ErrorAction SilentlyContinue)
  if ($diff.Count -gt 0) { Write-Log ('hubs refreshed: ' + ($list -join ' ; ')) }
  $script:HubList = $list
}
$script:MachinePinned = [bool]$Machine
if (-not $Machine) {
  if ($Settings['MACHINE_NAME']) { $script:MachinePinned = $true }
  $Machine = Resolve-MachineName -Hub $Hub -Explicit $Settings['MACHINE_NAME']
  if (-not $Machine) { Write-Log 'FATAL: machine identity could not be claimed'; exit 3 }
} else {
  Confirm-MachineIdentity -Hub $Hub -Name $Machine
}
$Machine = (($Machine -replace '[^A-Za-z0-9_.\-]', '_')).ToUpper()

$Lock = Join-Path $Local 'bridge.lock'

# Rebind every hub-relative path at once so a failed share can be swapped for a mirror.
function Set-ActiveHub([string]$h) {
  $script:Hub = $h
  $script:HubM = Join-Path $h ('machines\' + $Machine)
  $script:Inbox = Join-Path $script:HubM 'inbox'
  $script:InboxFiles = Join-Path $script:Inbox 'files'
  $script:InboxPush = Join-Path $script:Inbox 'push'
  $script:RunDir = Join-Path $script:HubM 'run'
  $script:OutDir = Join-Path $script:HubM 'out'
  $script:StateDir = Join-Path $script:HubM 'state'
}
Set-ActiveHub $Hub

function Test-LockOwner {
  # v2.6.2: an orphan body is the reason two instances raced on the same inbox - duplicated
  # work and `rejected / replayed nonce` answers that overwrote good results (measured: three
  # powershell bodies alive on MACHINE-001). Whoever owns bridge.lock is the body; the rest exit.
  try {
    $txt = (Read-Text $Lock).Trim()
    if (-not $txt) { return $false }
    $owner = 0
    [void][int64]::TryParse(($txt -split '\s+')[0], [ref]$owner)
    return ($owner -eq $PID)
  } catch { return $false }
}

function Test-BodyProgress([int]$procId) {
  # Two bodies on one box used to kill each other: the beacon file is SHARED, so a peer's
  # pid in it looked like "the owner is frozen". Ask the process first - it is authoritative.
  $isBody = $false
  try {
    $pr = @(Get-CimInstance Win32_Process -Filter ('ProcessId=' + $procId) -ErrorAction Stop)
    if ($pr.Count -gt 0 -and (([string]$pr[0].CommandLine) -like '*omp-body.ps1*')) { $isBody = $true }
  } catch {
    return $true          # cannot inspect -> never kill someone we cannot judge
  }
  if (-not $isBody) { return $false }

  # Only trust the beacon when it belongs to THIS pid; a foreign pid in it means a peer
  # overwrote it, which says nothing about us.
  $hb = Read-Json $LocalHb
  if ($hb -and $hb.pid -eq $procId -and $hb.ts) {
    $age = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$hb.ts
    if ($age -le 300) { return $true }
    if ($hb.job_id -and $hb.job_started) {
      $deadline = [int64]$hb.job_started + [int64]$hb.job_timeout + 300
      if ([int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -le $deadline) { return $true }
    }
    return $false
  }
  return $true
}

# Atomic claim: CreateNew (O_EXCL) - overwriting a lock file is what produced two live bodies,
# because a launcher and the watchdog could both write it within the same instant.
$gotLock = $false
for ($attempt = 1; $attempt -le 4 -and -not $gotLock; $attempt++) {
  try {
    $fs = [System.IO.File]::Open($Lock, 'CreateNew', 'Write', 'None')
    try {
      $sw = New-Object System.IO.StreamWriter($fs, $Utf8)
      $sw.Write([string]$PID + ' ' + (Get-Date).ToString('s'))
      $sw.Flush()
    } finally { $fs.Close() }
    $gotLock = $true
    break
  } catch { }

  $old = (Read-Text $Lock).Trim()
  $oldPid = 0
  [void][int]::TryParse(($old -split ' ')[0], [ref]$oldPid)
  $alive = $false
  if ($oldPid -gt 0) { try { [void](Get-Process -Id $oldPid -ErrorAction Stop); $alive = $true } catch { } }

  if ($alive -and (Test-BodyProgress $oldPid)) {
    Write-Log ('another body is running (pid ' + $oldPid + ') - exit')
    exit 0
  }
  if ($alive) {
    Write-Log ('taking over from unresponsive body pid ' + $oldPid + ' (no progress in the local beacon)')
    try { & taskkill.exe /PID $oldPid /T /F 2>&1 | Out-Null } catch { }
    Start-Sleep -Seconds 2
    try { if (Get-Process -Id $oldPid -ErrorAction SilentlyContinue) { Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue } } catch { }
  } else {
    Write-Log ('stale lock from pid ' + $oldPid + ' (gone) - reclaiming')
  }
  Remove-Item $Lock -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 300
}
if (-not $gotLock) { Write-Log 'FATAL: could not acquire bridge.lock'; exit 4 }

# belt and braces: re-read shortly after; if somebody else owns it now, they won
Start-Sleep -Milliseconds 700
$chk = (Read-Text $Lock).Trim()
$chkPid = 0
[void][int]::TryParse(($chk -split ' ')[0], [ref]$chkPid)
if ($chkPid -gt 0 -and $chkPid -ne $PID) {
  Write-Log ('lost the lock race to pid ' + $chkPid + ' - exit')
  exit 0
}
Remove-Item $HandoverFile -Force -ErrorAction SilentlyContinue

$wait = 0
while (-not (Test-Path $Hub)) {
  if ($wait -eq 0) { Write-Log ('hub not reachable: ' + $Hub) }
  $wait++
  Start-Sleep -Seconds 15
  if ($wait -ge 20) { Write-Log 'hub unreachable for 5 min, still waiting'; $wait = 0 }
}
$dirFail = 0
foreach ($d in @($HubM, $Inbox, $InboxFiles, $InboxPush, $RunDir, $OutDir, $StateDir)) {
  if (-not (Ensure-Dir $d)) { $dirFail++ }
}
if ($dirFail -gt 0) {
  Write-Log ('WARNING ' + $dirFail + ' hub dir(s) missing and NOT creatable - the office side must run: python ctl\ompremote.py deploy')
}

$script:OmpVersion = 'not-installed'
if (Test-Path $OmpExe) { $script:OmpVersion = 'installed' }
Write-Log ('start v' + $BodyVersion + ' machine=' + $Machine + ' pid=' + $PID + ' omp=' + $script:OmpVersion)

function Get-OmpVersion {
  if (-not (Test-Path $OmpExe)) { return 'not-installed' }
  if ($script:OmpVersion -and $script:OmpVersion -ne 'installed') { return $script:OmpVersion }
  try {
    $out = & $OmpExe --version
    $first = @($out)[0]
    if ($first) { $script:OmpVersion = ([string]$first).Trim() } else { $script:OmpVersion = 'unknown' }
  } catch { $script:OmpVersion = 'unknown' }
  return $script:OmpVersion
}

# ---------------------------------------------------------------- self update
$LocalVersionFile = Join-Path $Local 'body-version.txt'
if (Test-Path $LocalVersionFile) {
  $lv = (Read-Text $LocalVersionFile).Trim()
  if ($lv) { $BodyVersion = $lv }
}

function Try-UpdateFrom {
  param([string]$HubBundle)
  $hubVerFile = Join-Path $HubBundle 'version.txt'
  $hubScript = Join-Path $HubBundle 'omp-body.ps1'
  if (-not (Test-Path $hubVerFile)) { return $false }
  if (-not (Test-Path $hubScript)) { return $false }
  $hubVer = (Read-Text $hubVerFile).Trim()
  if (-not $hubVer) { return $false }
  if ($hubVer -eq $BodyVersion) { return $false }

  $text = Read-Text $hubScript
  if ($text.Length -lt 5000) { Write-Log ('self-update skipped: hub script too small (' + $text.Length + ' bytes)'); return $false }
  try {
    $errs = $null
    [void][System.Management.Automation.PSParser]::Tokenize($text, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) { Write-Log ('self-update skipped: published script does not parse (' + $errs[0].Message + ')'); return $false }
  } catch { Write-Log ('self-update skipped: tokenizer failed'); return $false }

  # our own file, whatever it is called: this install renames it
  $selfPath = $SelfPath
  Write-Log ('self-update ' + $BodyVersion + ' -> ' + $hubVer + ' accepted')
  try { Copy-Item -Path $selfPath -Destination ($selfPath + '.bak') -Force -ErrorAction SilentlyContinue } catch { }
  try {
    [System.IO.File]::WriteAllText($selfPath + '.new', $text, $Utf8)
    Move-Item -Path ($selfPath + '.new') -Destination $selfPath -Force
    [System.IO.File]::WriteAllText($LocalVersionFile, $hubVer + "`r`n", $Utf8)
  } catch {
    Write-Log ('self-update failed while swapping files: ' + $_.Exception.Message)
    return $false
  }
  # hand the lock over first: otherwise the replacement starts while our pid still owns
  # bridge.lock and (correctly) refuses to run, leaving nobody in charge.
  [void](Write-Text $HandoverFile ([string]$PID + ' ' + (Get-Date).ToString('s')))
  Remove-Item $Lock -Force -ErrorAction SilentlyContinue
  $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $selfPath + '"'),
            '-Hub', ('"' + $Hub + '"'), '-PollSec', [string]$PollSec)
  # A pinned name must survive the restart; a derived one must be re-resolved from
  # <local>\machine.name + the hub claim, so that a name split (v2.4.0) also lands here.
  if ($script:MachinePinned) { $args += @('-Machine', $Machine) }
  try { Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden } catch { }
  Start-Sleep -Seconds 2
  return $true
}

function Try-SelfUpdate {
  param([string]$HubBundle)
  # The bundle is published to every mirror, but a body only looks at the share it happens to
  # be talking to. Machines whose active hub is TBZ2 never saw a release published to TBZ:
  # on 2026-11-12 only 13 of 104 bodies updated until the mirror got the same bundle. Ask all
  # reachable roots, cheapest (active) first.
  if (Try-UpdateFrom $HubBundle) { return $true }
  foreach ($h in @(Get-LiveHubs)) {
    $b = Join-Path $h 'bundle'
    if ($b -eq $HubBundle) { continue }
    if (-not (Test-Path $b)) { continue }
    if (Try-UpdateFrom $b) { return $true }
  }
  return $false
}

# ---------------------------------------------------------------- heartbeat
function Write-Heartbeat {
  $pending = 0
  try {
    $done = Get-DoneIds
    $pending = @(Get-ChildItem -Path $Inbox -Filter '*.job.json' -ErrorAction SilentlyContinue |
                 Where-Object { $done -notcontains $_.Name.Replace('.job.json', '') }).Count
  } catch { }
  $watchPid = 0
  try {
    $wl = (Read-Text $WatchLock).Trim()
    if ($wl) { [void][int]::TryParse(($wl -split ' ')[0], [ref]$watchPid) }
  } catch { }
  $watchStats = Read-Json (Join-Path $LocalState 'watch.json')
  # v2.6.0: the watchdog stopped publishing itself to the share - the hidden
  # `powershell -ExecutionPolicy Bypass -Command` child it used to spawn is what endpoint
  # security flags (Huorong 系统加固: 利用 PowerShell 执行可疑脚本), and blocking it froze
  # machines\<M>\state\watchdog.json while this beat kept ticking. Its state rides along here
  # instead: same facts, no child process.
  $watch = $null
  if ($watchStats) {
    $watch = [ordered]@{}
    foreach ($k in @('pid', 'version', 'host', 'checked_at', 'stale_sec', 'healthy', 'reason',
                     'last_ok', 'last_reason', 'last_restart_at', 'restarts',
                     'restarts_last_hour', 'beacon_age_sec', 'body_pid', 'body_alive',
                     'body_phase', 'body_job', 'launcher_pid')) {
      $v = $watchStats.$k
      if ($null -ne $v) { $watch[$k] = $v }
    }
    $stamps = @($watchStats.restart_stamps | Where-Object { $_ })
    if ($stamps.Count -gt 0) { $watch['restart_stamps'] = $stamps }
    if ($watchStats.pid) { $watchPid = [int64]$watchStats.pid }
  }
  $o = [ordered]@{
    ah = 1
    machine = $Machine
    hostname = $env:COMPUTERNAME
    user = $env:USERDOMAIN + '\' + $env:USERNAME
    body_version = $BodyVersion
    omp_version = $script:OmpVersion
    model_default = $DefaultModel
    api_key = [bool]$ApiKey
    pid = $PID
    started_at = $script:StartedAt.ToString('s')
    now = (Get-Date).ToString('s')
    pending = $pending
    jobs_done = $script:JobsDone
    last_job = $script:LastJob
    phase = $script:Phase
    job_id = $script:JobId
    heartbeat_file = $LocalHb
    watchdog_pid = $watchPid
    watchdog_restarts = $(if ($watchStats) { $watchStats.restarts } else { 0 })
    watch = $(if ($watch) { [pscustomobject]$watch } else { $null })
    local_root = $Local
    psk = $script:HavePsk
    key_scheme = $script:KeyScheme
    key_scope = $(if ($script:KeyScope) { $script:KeyScope } else { '' })
    key_error = $script:KeyError
    allow_legacy = $script:AllowLegacy
    enc_results = $script:EncResults
    hubs = @($script:HubList)
  }
  Write-Text (Join-Path $script:StateDir 'heartbeat.json') ($o | ConvertTo-Json -Depth 5) | Out-Null
  # keep a heartbeat on every reachable mirror so the office side can see this machine
  # even when the primary share is dead (read-only redundancy, no job mirroring here)
  foreach ($h in @(Get-LiveHubs)) {
    if ($h -eq $script:Hub) { continue }
    try {
      $d = Join-Path $h ('machines\' + $Machine + '\state')
      if (-not (Test-Path $d)) { [void](Ensure-Dir $d) }
      Write-Text (Join-Path $d 'heartbeat.json') ($o | ConvertTo-Json -Depth 5) | Out-Null
    } catch { }
  }
  Write-LocalBeat -Force
}

function Write-Sysinfo {
  $o = [ordered]@{ ah = 1; machine = $Machine; hostname = $env:COMPUTERNAME }
  $o.user = $env:USERDOMAIN + '\' + $env:USERNAME
  try { $os = Get-WmiObject Win32_OperatingSystem; $o.os = $os.Caption; $o.build = $os.BuildNumber; $o.mem_mb = [int]($os.TotalVisibleMemorySize / 1024) } catch { }
  try { $cpu = @(Get-WmiObject Win32_Processor)[0]; $o.cpu = $cpu.Name; $o.logical = $cpu.NumberOfLogicalProcessors } catch { }
  try { $o.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
  try { $o.ps = $PSVersionTable.PSVersion.ToString() } catch { }
  $o.omp_version = $script:OmpVersion
  try {
    $disks = @()
    foreach ($d in @(Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 })) {
      $disks += @{ drive = $d.DeviceID; free_gb = [int]($d.FreeSpace / 1GB); total_gb = [int]($d.Size / 1GB) }
    }
    $o.disks = $disks
  } catch { }
  Write-Text (Join-Path $StateDir 'sysinfo.json') ($o | ConvertTo-Json -Depth 5) | Out-Null
}

# ---------------------------------------------------------------- done registry
$DoneRegistry = Join-Path $Local 'done-ids.txt'

function Get-DoneIds {
  if (-not (Test-Path $DoneRegistry)) { return @() }
  # the registry stores "id why timestamp": callers compare bare ids, so return the first
  # field. Before v2.6.0 this returned the whole line, which made both the replay guard
  # (`-contains $id`) and the pending count dead code - jobs that came back on a mirror
  # were re-runnable and `pending` counted leftovers as work.
  return @(Get-Content -Path $DoneRegistry -ErrorAction SilentlyContinue |
           Where-Object { $_ } | ForEach-Object { ($_ -split '\s+')[0] })
}

function Add-DoneId {
  param([string]$id, [string]$why = '')
  try { Add-Content -Path $DoneRegistry -Value ($id + ' ' + $why + ' ' + (Get-Date).ToString('s')) -Encoding ASCII } catch { }
}

function Test-AlreadyHandled {
  param([string]$id)
  if (Test-Path (Join-Path $OutDir ($id + '.result.json'))) { return 'result-exists' }
  if (@(Get-DoneIds) -contains $id) { return 'registered' }
  return ''
}

function Sweep-StaleJobs {
  # A job file that survives on a mirror inbox (delete denied for the machine account, or
  # the peer body never visited that root) makes `pending` lie for the rest of the machine's
  # life and keeps a re-runnable copy of the payload on the share. Drop done ids everywhere.
  $done = @(Get-DoneIds)
  if ($done.Count -eq 0) { return }
  foreach ($root in @(Get-LiveHubs)) {
    try {
      $inc = Join-Path $root ('machines\' + $Machine + '\inbox')
      if (-not (Test-Path $inc)) { continue }
      foreach ($f in @(Get-ChildItem -Path $inc -Filter '*.job.json' -ErrorAction SilentlyContinue)) {
        $jid = $f.Name -replace '\.job\.json$', ''
        if ($done -notcontains $jid) { continue }
        try {
          Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
          Write-Log ('swept done job ' + $jid + ' off ' + $root)
        } catch {
          Write-Log ('sweep denied for ' + $jid + ' on ' + $root + ': ' + $_.Exception.Message)
        }
      }
    } catch { }
  }
}

# ---------------------------------------------------------------- helpers
function Repair-OrphanJobs {
  # A body that was killed mid-job leaves run\<id>.job.json.lock with no result.
  # Settle it explicitly: the office side sees aborted_by_watchdog and decides whether
  # to resubmit (ps scripts are not necessarily idempotent, so we never auto-retry here).
  $locks = @(Get-ChildItem -Path $RunDir -Filter '*.job.json.lock' -ErrorAction SilentlyContinue)
  foreach ($l in $locks) {
    $id = $l.Name.Replace('.job.json.lock', '')
    if (-not $id) { continue }
    $owner = ''
    $ownerPid = 0
    try {
      $parts = ((Read-Text $l.FullName).Trim()) -split '\|'
      $owner = $parts[0].Trim()
      if ($parts.Count -gt 1) { [void][int]::TryParse($parts[1].Trim(), [ref]$ownerPid) }
    } catch { }
    if ($owner -and ($owner -ne $Machine)) {
      # another host is running it right now (legacy shared folder) - hands off
      continue
    }
    if ($ownerPid -gt 0 -and ($ownerPid -ne $PID)) {
      # same machine, different body process: only reclaim it if that one is really gone
      $aliveBody = $false
      try {
        $pr = @(Get-CimInstance Win32_Process -Filter ('ProcessId=' + $ownerPid) -ErrorAction Stop)
        if ($pr.Count -gt 0 -and ([string]$pr[0].CommandLine) -like '*omp-body.ps1*') { $aliveBody = $true }
      } catch { }
      if ($aliveBody) { continue }
    }
    if (Test-Path (Join-Path $OutDir ($id + '.result.json'))) {
      Remove-Item $l.FullName -Force -ErrorAction SilentlyContinue
      continue
    }
    if (@(Get-DoneIds) -contains $id) {
      Remove-Item $l.FullName -Force -ErrorAction SilentlyContinue
      continue
    }
    Write-Result $id @{
      ah = 1; id = $id; machine = $Machine; status = 'aborted_by_watchdog'; exit = 97
      error = 'the body was terminated while this job was running; not retried automatically'
      body_version = $BodyVersion; ended = (Get-Date).ToString('s')
    }
    Remove-Item $l.FullName -Force -ErrorAction SilentlyContinue
    Add-DoneId $id 'aborted_by_watchdog'
    Write-Log ('orphan job ' + $id + ' settled as aborted_by_watchdog (resubmit from the office side if needed)')
  }
}

function Resolve-WorkDir {
  param($job)
  $cwd = $Local
  if ($job.cwd) { $cwd = [string]$job.cwd }
  if ($AllowedCwd -and $job.cwd) {
    $ok = $false
    foreach ($r in @($AllowedCwd -split ';')) {
      if ($r -and $cwd.ToLower().StartsWith($r.Trim().ToLower())) { $ok = $true }
    }
    if (-not $ok) { Write-Log ('cwd outside ALLOWED_CWD, falling back: ' + $cwd); $cwd = $Local }
  }
  if (-not (Test-Path $cwd)) { $cwd = $Local }
  return $cwd
}

function Write-Result {
  param([string]$id, [hashtable]$res)
  $json = $res | ConvertTo-Json -Depth 6
  $path = Join-Path $OutDir ($id + '.result.json')
  if ($script:EncResults -and $script:HavePsk) {
    try {
      $b64 = Protect-Bytes $script:KeyEnc ([System.Text.Encoding]::UTF8.GetBytes($json))
      $sum = Get-Mac $script:KeyMac ('res|' + $id + '|' + $b64)
      $wrapped = @{ enc = 'a256cbc-hmac256'; id = $id; blob = $b64; mac = $sum } | ConvertTo-Json -Compress
      Write-Text $path $wrapped | Out-Null
      return
    } catch { Write-Log ('result encryption failed, writing clear text: ' + $_.Exception.Message) }
  }
  Write-Text $path $json | Out-Null
}

function Complete-Job {
  param([string]$jobFile, [string]$status, [int]$exit, [datetime]$started, [double]$seconds, [string]$extra = '')
  $jid = [System.IO.Path]::GetFileName($jobFile)
  $id = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFileNameWithoutExtension($jid))
  # settling the inbox: rename first (cheap), else delete, else just remember locally.
  # share ACLs often allow create but not delete/rename, so never rely on the move.
  $settled = $false
  try { Move-Item -Path $jobFile -Destination (Join-Path $RunDir ($jid + '.done')) -Force -ErrorAction Stop; $settled = $true } catch { }
  if (-not $settled) {
    try { Remove-Item -Path $jobFile -Force -ErrorAction Stop; $settled = $true } catch { }
  }
  if (-not $settled) { Write-Log ('inbox not writable for cleanup (id ' + $id + ') - tracked locally instead') }
  # v2.6.4: the payload used to stay in inbox\files forever. A finished job's script - and,
  # for the key-provisioning job, the PSK itself - was then readable by anyone who can open
  # the share (found: 3042 cleartext scripts, one of them carrying PSK=). Done ids only.
  try {
    foreach ($f in @(Get-ChildItem (Join-Path $Inbox 'files') -Filter ($id + '.*') -ErrorAction SilentlyContinue)) {
      Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
    }
    $pushDir = Join-Path (Join-Path $Inbox 'push') $id
    if (Test-Path $pushDir) { Remove-Item -LiteralPath $pushDir -Recurse -Force -ErrorAction SilentlyContinue }
  } catch { }
  [void](Add-DoneId $id ($status + '/exit' + $exit))
  Remove-Item (Join-Path $RunDir ($jid + '.lock')) -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $Inbox ($id + '.cancel')) -Force -ErrorAction SilentlyContinue
  $script:JobsDone++
  $script:LastJob = $id
  Write-Log ('job ' + $id + ' ' + $status + ' exit=' + $exit + ' dur=' + [int]$seconds + 's ' + $extra)
}

# ---------------------------------------------------------------- ps / cmd
function Invoke-ScriptJob {
  param($job, [string]$id, [string]$kind, [string]$jobFile)
  $srcFile = ''
  if ($job.file) {
    $cand = Join-Path $InboxFiles ([string]$job.file)
    if (Test-Path $cand) { $srcFile = $cand }
  }
  if (-not $srcFile -and $job.code) {
    $srcFile = Join-Path $RunsRoot ($id + '.src')
    $bom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true
    [System.IO.File]::WriteAllText($srcFile, [string]$job.code, $bom)
  }
  if (-not $srcFile) { Write-Result $id @{ ah = 1; id = $id; machine = $Machine; status = 'bad_job'; error = 'no script payload (file/code)' }; Complete-Job $jobFile 'bad_job' 90 (Get-Date) 0; return }

  $jobRun = Join-Path $RunsRoot $id
  Ensure-Dir $jobRun
  $ext = '.ps1'
  if ($kind -eq 'cmd') { $ext = '.cmd' }
  $taskPath = Join-Path $jobRun ('task' + $ext)
  Copy-Item -Path $srcFile -Destination $taskPath -Force -ErrorAction SilentlyContinue

  $cwd = Resolve-WorkDir $job
  $timeout = 900
  if ($job.timeout) { $timeout = [int]$job.timeout }

  $stdout = Join-Path $RunDir ($id + '.stdout.txt')
  $stderr = Join-Path $RunDir ($id + '.stderr.txt')
  [void](Write-Text $stdout '')
  [void](Write-Text $stderr ('[' + (Get-Date).ToString('s') + '] start kind=' + $kind + ' cwd=' + $cwd + "`r`n"))

  $argline = ''
  if ($job.args) { $argline = ' ' + [string]$job.args }
  if ($kind -eq 'cmd') { $inner = 'call "' + $taskPath + '"' + $argline }
  else { $inner = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + $taskPath + '"' + $argline }

  $wrapper = Join-Path $jobRun 'run.cmd'
  $batch = @()
  $batch += '@echo off'
  $batch += 'chcp 65001 >nul'
  if ($job.env) {
    foreach ($p in $job.env.PSObject.Properties) {
      $batch += 'set ' + $p.Name + '=' + [string]$p.Value
    }
  }
  $batch += $inner + ' > "' + $stdout + '" 2> "' + $stderr + '"'
  $batch += 'exit /b %ERRORLEVEL%'
  [System.IO.File]::WriteAllLines($wrapper, $batch, (New-Object -TypeName System.Text.ASCIIEncoding))

  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $timedOut = $false
  $canceled = $false
  $proc = $null
  try {
    $proc = Start-Process -FilePath $env:ComSpec -ArgumentList ('/c "' + $wrapper + '"') -PassThru -WindowStyle Hidden -WorkingDirectory $cwd
  } catch { Write-Log ('spawn failed: ' + $_.Exception.Message) }

  if ($proc) {
    while (-not $proc.HasExited) {
      Start-Sleep -Milliseconds 700
      Write-LocalBeat 'run'
      if (Test-Path (Join-Path $Inbox ($id + '.cancel'))) { $canceled = $true; try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch { }; break }
      if ($watch.Elapsed.TotalSeconds -gt $timeout) { $timedOut = $true; try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch { }; break }
    }
    try { [void]$proc.WaitForExit(10000) } catch { }
  }
  $watch.Stop()
  $exit = -1
  if ($proc) { try { $exit = $proc.ExitCode } catch { } }
  $status = 'ok'
  if ($timedOut) { $status = 'timeout' } elseif ($canceled) { $status = 'canceled' } elseif ($exit -ne 0) { $status = 'error' }

  $errText = Read-Text $stderr
  $tail = @()
  if ($errText) {
    $lines = @($errText -split "`r?`n")
    if ($lines.Count -gt 30) { $tail = $lines[($lines.Count - 30)..($lines.Count - 1)] } else { $tail = $lines }
  }
  $res = @{
    ah = 1; id = $id; machine = $Machine; hostname = $env:COMPUTERNAME; kind = $kind
    status = $status; exit = $exit; timed_out = $timedOut; canceled = $canceled
    cwd = $cwd; timeout_sec = $timeout
    started = $started.ToString('s'); ended = (Get-Date).ToString('s')
    duration_sec = [int]$watch.Elapsed.TotalSeconds
    stdout_bytes = 0; stderr_bytes = 0; stderr_tail = ($tail -join "`n")
    body_version = $BodyVersion
  }
  try { $res.stdout_bytes = (Get-Item $stdout).Length } catch { }
  try { $res.stderr_bytes = (Get-Item $stderr).Length } catch { }
  Write-Result $id $res
  Complete-Job $jobFile $status $exit $started $watch.Elapsed.TotalSeconds
}

# ---------------------------------------------------------------- fetch
function Invoke-FetchJob {
  param($job, [string]$id, [string]$jobFile)
  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $dest = Join-Path $OutDir ($id + '.files')
  Ensure-Dir $dest
  $rows = New-Object System.Collections.ArrayList
  $maxBytes = 2000MB
  if ($job.max_mb) { $maxBytes = [double]$job.max_mb * 1MB }
  $files = 0
  $failed = 0
  $skipped = 0
  $patterns = @($job.patterns)
  if ($patterns.Count -eq 0) { [void]$rows.Add("MISS`t`t0") }
  foreach ($pat in $patterns) {
    $p = [string]$pat
    $root = Split-Path -Parent $p
    if (-not $root) { $root = (Get-Location).Path }
    $items = @()
    try { $items = @(Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }) } catch { }
    if ($items.Count -eq 0) { [void]$rows.Add($p + "`tMISS`t0"); continue }
    foreach ($f in $items) {
      if ($f.Length -gt $maxBytes) { $skipped++; [void]$rows.Add($f.FullName + "`tSKIP-BIG`t" + $f.Length); continue }
      $rel = $f.FullName
      if ($f.FullName.Length -gt $root.Length) { $rel = $f.FullName.Substring($root.Length).TrimStart('\') }
      $rel = ($rel -replace '^\w:', '')
      $target = Join-Path $dest $rel
      try {
        $dir = Split-Path -Parent $target
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $in = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
        try {
          $out = [System.IO.File]::Create($target)
          try {
            $buf = New-Object byte[] (1MB)
            while ($true) {
              $n = $in.Read($buf, 0, $buf.Length)
              if ($n -le 0) { break }
              $out.Write($buf, 0, $n)
              Write-LocalBeat 'fetch'
            }
          } finally { $out.Close() }
        } finally { $in.Close() }
        $files++
        [void]$rows.Add($rel + "`t" + $f.Length + "`t" + (Get-Sha1 $target))
      } catch {
        $failed++
        [void]$rows.Add($rel + "`tFAIL`t" + $f.Length)
      }
    }
  }
  Write-Text (Join-Path $OutDir ($id + '.manifest.tsv')) ($rows -join "`r`n") | Out-Null
  $watch.Stop()
  $status = 'ok'
  if ($failed -gt 0) { $status = 'partial' }
  if ($files -eq 0) { $status = 'empty' }
  Write-Result $id @{
    ah = 1; id = $id; machine = $Machine; kind = 'fetch'; status = $status
    files = $files; failed = $failed; skipped = $skipped
    started = $started.ToString('s'); ended = (Get-Date).ToString('s')
    duration_sec = [int]$watch.Elapsed.TotalSeconds
    manifest = ('out\' + $id + '.manifest.tsv'); dest = ('out\' + $id + '.files')
    body_version = $BodyVersion
  }
  Complete-Job $jobFile $status $((if ($failed -gt 0) { 3 } else { 0 })) $started $watch.Elapsed.TotalSeconds ('files=' + $files)
}

# ---------------------------------------------------------------- push
function Invoke-PushJob {
  param($job, [string]$id, [string]$jobFile)
  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $srcDir = Join-Path $InboxPush $id
  $status = 'ok'
  $exit = 0
  $msg = ''
  $written = @()
  if (-not $job.target) { $status = 'bad_job'; $exit = 91; $msg = 'no target' }
  elseif (-not (Test-Path $srcDir)) { $status = 'bad_job'; $exit = 92; $msg = 'no staged payload' }
  else {
    $timeout = 900
    if ($job.timeout) { $timeout = [int]$job.timeout }
    $wantReady = $false
    try { $wantReady = [bool]$job.ready } catch { }
    $all = @(Get-ChildItem -Path $srcDir -Recurse -Force | Where-Object { -not $_.PSIsContainer -and $_.Name -ne '_READY' })
    if ($wantReady -and -not (Test-Path (Join-Path $srcDir '_READY'))) {
      # the client is still copying: do not touch a half-written payload, try again later
      Write-Log ('push ' + $id + ' deferred: no _READY sentinel yet')
      return
    }
    foreach ($f in $all) {
      if ($watch.Elapsed.TotalSeconds -gt $timeout) {
        $status = 'timeout'; $exit = 94; $msg += 'copy budget exhausted; '
        break
      }
      $relBase = $f.FullName.Substring($srcDir.Length).TrimStart('\')
      $target = [string]$job.target
      if ($all.Count -gt 1) { $target = Join-Path $target $relBase }
      $dir = Split-Path -Parent $target
      try {
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        # chunked copy: a stalled share read must not look like a dead process
        $in = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
        try {
          $out = [System.IO.File]::Create($target)
          try {
            $buf = New-Object byte[] (1MB)
            while ($true) {
              $n = $in.Read($buf, 0, $buf.Length)
              if ($n -le 0) { break }
              $out.Write($buf, 0, $n)
              Write-LocalBeat 'push'
              if ($watch.Elapsed.TotalSeconds -gt $timeout) { break }
            }
          } finally { $out.Close() }
        } finally { $in.Close() }
        if ($watch.Elapsed.TotalSeconds -gt $timeout) {
          $status = 'timeout'; $exit = 94; $msg += ($target + ': copy budget exhausted; ')
          break
        }
        $sha = Get-Sha1 $target
        $written += @{ path = $target; size = $f.Length; sha1 = $sha }
      } catch {
        $status = 'error'; $exit = 93; $msg += ($target + ': ' + $_.Exception.Message + '; ')
      }
    }
  }
  $watch.Stop()
  Write-Result $id @{
    ah = 1; id = $id; machine = $Machine; kind = 'push'; status = $status; exit = $exit
    target = [string]$job.target; written = $written; error = $msg
    duration_sec = [int]$watch.Elapsed.TotalSeconds
    body_version = $BodyVersion
  }
  Complete-Job $jobFile $status $exit $started $watch.Elapsed.TotalSeconds
}

# ---------------------------------------------------------------- kill / ping
function Invoke-KillJob {
  param($job, [string]$id, [string]$jobFile)
  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $status = 'ok'; $exit = 0; $msg = ''
  if ($job.pid) {
    try { & taskkill.exe /PID ([int]$job.pid) /T /F 2>&1 | Out-Null } catch { $status = 'error'; $exit = 94; $msg = $_.Exception.Message }
  } elseif ($job.name) {
    $n = [string]$job.name
    try { & taskkill.exe /IM $n /T /F 2>&1 | Out-Null } catch { $status = 'error'; $exit = 95; $msg = $_.Exception.Message }
  } else { $status = 'bad_job'; $exit = 96; $msg = 'needs pid or name' }
  $watch.Stop()
  Write-Result $id @{ ah = 1; id = $id; machine = $Machine; kind = 'kill'; status = $status; exit = $exit; error = $msg; duration_sec = [int]$watch.Elapsed.TotalSeconds }
  Complete-Job $jobFile $status $exit $started $watch.Elapsed.TotalSeconds
}

function Invoke-PingJob {
  param($job, [string]$id, [string]$jobFile)
  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $caps = [ordered]@{
    powershell = $true; cmd = $true
    omp = (Test-Path $OmpExe)
    python = [bool](Get-Command python -ErrorAction SilentlyContinue)
    node = [bool](Get-Command node -ErrorAction SilentlyContinue)
    admin = $false
  }
  try { $caps.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
  $watch.Stop()
  Write-Result $id @{
    ah = 1; id = $id; machine = $Machine; kind = 'ping'; status = 'ok'; exit = 0
    capabilities = $caps; omp_version = (Get-OmpVersion)
    duration_sec = [int]$watch.Elapsed.TotalSeconds; body_version = $BodyVersion
  }
  Complete-Job $jobFile 'ok' 0 $started $watch.Elapsed.TotalSeconds
}

# ---------------------------------------------------------------- omp (optional)
function Invoke-OmpJob {
  param($job, [string]$id, [string]$jobFile)
  if (-not (Test-Path $OmpExe)) {
    Write-Result $id @{ ah = 1; id = $id; machine = $Machine; kind = 'omp'; status = 'no_omp'; exit = 90; error = 'omp.exe not installed' }
    Complete-Job $jobFile 'no_omp' 90 (Get-Date) 0
    return
  }
  $prompt = [string]$job.prompt
  if (-not $prompt) { $prompt = 'Report the machine state briefly and exit.' }
  $mode = 'text'; if ($job.mode) { $mode = [string]$job.mode }
  $model = $DefaultModel; if ($job.model) { $model = [string]$job.model }
  $timeout = 900; if ($job.timeout) { $timeout = [int]$job.timeout }
  $approval = 'yolo'; if ($job.approval) { $approval = [string]$job.approval }
  $cwd = Resolve-WorkDir $job
  $jobRun = Join-Path $RunsRoot $id
  Ensure-Dir $jobRun
  $promptFile = Join-Path $jobRun 'prompt.txt'
  Write-Text $promptFile $prompt | Out-Null

  $stdout = Join-Path $RunDir ($id + '.stdout.txt')
  $stderr = Join-Path $RunDir ($id + '.stderr.txt')
  [void](Write-Text $stdout '')
  [void](Write-Text $stderr ('[' + (Get-Date).ToString('s') + '] omp start model=' + $model + "`r`n"))

  $argv = @('-p', '--mode', $mode, '--approval-mode', $approval, '--cwd', ('"' + $cwd + '"'), '--session-dir', ('"' + $SessionDir + '"'))
  if ($model) { $argv += @('--model', $model) }
  if ($ApiKey) { $argv += @('--api-key', $ApiKey) }
  if ($job.max_time) { $argv += @('--max-time', [string]$job.max_time) }
  if ($job.continue) { $argv += '-c' }
  if ($ExtraArgs) { $argv += ($ExtraArgs -split ' ') }
  $argv += ('@' + $promptFile)

  $started = Get-Date
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $timedOut = $false; $canceled = $false; $proc = $null
  try {
    $proc = Start-Process -FilePath $OmpExe -ArgumentList ($argv -join ' ') -PassThru -NoNewWindow -WorkingDirectory $cwd `
      -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  } catch {
    Write-Result $id @{ ah = 1; id = $id; machine = $Machine; kind = 'omp'; status = 'error'; exit = 97; error = $_.Exception.Message }
    Complete-Job $jobFile 'error' 97 (Get-Date) 0
    return
  }
  while (-not $proc.HasExited) {
    Start-Sleep -Milliseconds 800
    Write-LocalBeat 'run'
    if (Test-Path (Join-Path $Inbox ($id + '.cancel'))) { $canceled = $true; try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch { }; break }
    if ($watch.Elapsed.TotalSeconds -gt $timeout) { $timedOut = $true; try { & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null } catch { }; break }
  }
  try { [void]$proc.WaitForExit(10000) } catch { }
  $watch.Stop()
  $exit = -1
  try { $exit = $proc.ExitCode } catch { }
  $status = 'ok'
  if ($timedOut) { $status = 'timeout' } elseif ($canceled) { $status = 'canceled' } elseif ($exit -ne 0) { $status = 'error' }
  Write-Result $id @{
    ah = 1; id = $id; machine = $Machine; kind = 'omp'; status = $status; exit = $exit
    timed_out = $timedOut; model = $model; cwd = $cwd
    duration_sec = [int]$watch.Elapsed.TotalSeconds; omp_version = (Get-OmpVersion)
    stderr_tail = ((@((Read-Text $stderr) -split "`r?`n") | Select-Object -Last 30) -join "`n")
  }
  Complete-Job $jobFile $status $exit $started $watch.Elapsed.TotalSeconds
}

# ---------------------------------------------------------------- dispatch
function Invoke-Job {
  param([string]$jobFile)
  $id = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFileName($jobFile)))
  $claimed = Join-Path $RunDir ((Split-Path -Leaf $jobFile) + '.lock')
  try {
    $fs = [System.IO.File]::Open($claimed, 'CreateNew', 'Write', 'None')
    try {
      # stamp the owner: a peer body sharing this folder (legacy name clash) must not
      # mistake our live job for an orphan and kill it.
      $bw = New-Object System.IO.StreamWriter($fs, $Utf8)
      $bw.Write($Machine + '|' + $PID + '|' + (Get-Date).ToString('s'))
      $bw.Flush()
    } finally { $fs.Close() }
  } catch { return $false }

  $why = Test-AlreadyHandled $id
  if ($why) {
    Write-Log ('skip ' + $id + ' (' + $why + ') - not running it twice')
    try { Remove-Item -Path $jobFile -Force -ErrorAction SilentlyContinue } catch { }
    Remove-Item -Path $claimed -Force -ErrorAction SilentlyContinue
    return $false
  }

  $opened = Open-Job $jobFile
  if (-not $opened.ok) {
    Write-Log ('reject ' + $id + ': ' + $opened.err)
    Write-Result $id @{ ah = 1; id = $id; machine = $Machine; status = 'rejected'; exit = 97; error = $opened.err }
    Complete-Job $jobFile 'rejected' 97 (Get-Date) 0
    return $false
  }
  $job = $opened.job
  if (-not $job) {
    Write-Result $id @{ ah = 1; id = $id; machine = $Machine; status = 'bad_job'; exit = 98; error = 'job json unparseable' }
    Complete-Job $jobFile 'bad_job' 98 (Get-Date) 0
    return $false
  }
  if ($job.enc_res -and @('1', 'true') -contains ([string]$job.enc_res).ToLower()) { $script:JobEncRes = $true } else { $script:JobEncRes = $false }
  $kind = 'ps'
  if ($job.kind) { $kind = ([string]$job.kind).ToLower() }
  $script:JobId = $id
  $script:JobKind = $kind
  $script:JobStart = [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $script:JobTimeout = 900
  if ($job.timeout) { $script:JobTimeout = [int]([string]$job.timeout) }
  Write-Log ('job ' + $id + ' kind=' + $kind + ' start')
  Write-LocalBeat 'claim' -Force

  switch ($kind) {
    'ps' { Invoke-ScriptJob $job $id 'ps' $jobFile }
    'cmd' { Invoke-ScriptJob $job $id 'cmd' $jobFile }
    'fetch' { Invoke-FetchJob $job $id $jobFile }
    'push' { Invoke-PushJob $job $id $jobFile }
    'kill' { Invoke-KillJob $job $id $jobFile }
    'ping' { Invoke-PingJob $job $id $jobFile }
    'omp' { Invoke-OmpJob $job $id $jobFile }
    default {
      Write-Result $id @{ ah = 1; id = $id; machine = $Machine; status = 'bad_job'; exit = 99; error = ('unknown kind ' + $kind) }
      Complete-Job $jobFile 'bad_job' 99 (Get-Date) 0
    }
  }
  $script:JobId = ''
  $script:JobKind = ''
  $script:JobStart = 0
  $script:JobTimeout = 0
  Write-LocalBeat 'idle' -Force
  return $true
}

# ---------------------------------------------------------------- main
Write-Sysinfo
Repair-OrphanJobs
Write-Heartbeat
Write-LocalBeat 'start' -Force
$lastBeat = Get-Date

while ($true) {
  $script:Loop++
  if (($script:Loop % 4) -eq 1) { Refresh-Hubs }
  if (($script:Loop % 20) -eq 3) { Sweep-StaleJobs }
  if (($script:Loop % 10) -eq 5 -and -not (Test-LockOwner)) {
    Write-Log 'bridge.lock is owned by another pid - this instance is an orphan, exiting'
    exit 0
  }
  Write-LocalBeat 'loop'
  if (-not (Test-Path $Hub)) {
    $live = @(Get-LiveHubs)
    if ($live.Count -gt 0 -and $live[0] -ne $Hub) {
      Set-ActiveHub $live[0]
      Write-Log ('primary share gone - switched to mirror ' + $Hub)
      $lastBeat = (Get-Date).AddSeconds(-60)
      continue
    }
    $script:HubOk = $false
    Write-Log 'hub lost, waiting'
    Start-Sleep -Seconds 15
    continue
  }
  if (Try-SelfUpdate (Join-Path $Hub 'bundle')) {
    Write-Log 'restarting into the published version'
    Remove-Item $Lock -Force -ErrorAction SilentlyContinue
    exit 0
  }
  if (-not (Test-Path $Inbox)) {
    Write-Log 'hub dirs missing, re-creating'
    foreach ($d in @($HubM, $Inbox, $InboxFiles, $InboxPush, $RunDir, $OutDir, $StateDir)) { [void](Ensure-Dir $d) }
  }
  $off = Test-Path (Join-Path $Hub 'policy\disabled.txt')
  if (-not $off) {
    # Scan every reachable root, not just the active one: a job queued on a mirror must
    # still run. The done-id registry makes a duplicated job harmless.
    $jobs = @()
    try {
      foreach ($root in @(Get-LiveHubs)) {
        $inc = Join-Path $root ('machines\' + $Machine + '\inbox')
        if (-not (Test-Path $inc)) { continue }
        $found = @(Get-ChildItem -Path $inc -Filter '*.job.json' -ErrorAction SilentlyContinue | Sort-Object Name)
        if ($found.Count -eq 0) { continue }
        if ($root -ne $Hub) { Set-ActiveHub $root }
        foreach ($f in $found) { $jobs += ,@($f, $root) }
        break
      }
      $script:HubOk = $true
      $script:HubErrors = 0
    } catch {
      # a share hiccup must not silently turn into a frozen body: count it, then let the
      # wrapper (start-bridge.cmd) restart us from a clean slate.
      $script:HubOk = $false
      $script:HubErrors++
      Write-Log ('hub scan failed (' + $script:HubErrors + '/5): ' + $_.Exception.Message)
      if ($script:HubErrors -ge 5) {
        Write-Log 'hub scan failed 5 times in a row - exiting so the launcher restarts the body'
        Remove-Item $Lock -Force -ErrorAction SilentlyContinue
        exit 0
      }
      Start-Sleep -Seconds 5
      continue
    }
    foreach ($pair in $jobs) {
      [void](Invoke-Job $pair[0].FullName)
      if ($Once) { break }
    }
  }
  if ($Once) { break }
  if (((Get-Date) - $lastBeat).TotalSeconds -ge 10) { Write-Heartbeat; $lastBeat = Get-Date }
  Start-Sleep -Seconds $PollSec
}

Remove-Item $Lock -Force -ErrorAction SilentlyContinue
Write-Log 'body stopped'