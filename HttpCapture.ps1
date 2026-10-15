<#
.SYNOPSIS
  Install the HTTPDebugger capture service + driver, arm it headlessly (no GUI),
  and print every captured HTTP/HTTPS transaction in full: request headers,
  request body, response headers and response body.

.DESCRIPTION
  Three files, no GUI, fully scripted:
    HttpCapture.ps1, HTTPDebuggerSvc.exe, CtrlSM.sys

  What it does:
    1. Copies CtrlSM.sys next to the service as drv2\x64\netfilter2.sys and
       drv2\win32\netfilter2.sys (the path the service registers the driver from).
    2. Writes %ProgramData%\HTTPDebuggerPro\settings.xml (the rules profile).
    3. Runs "HTTPDebuggerSvc.exe /install" (creates the service + the TLS root CA).
    4. Starts the service.
    5. Arms capture headlessly, exactly the way the UI does:
         - acquires the Global\HttpDebuggerUiStarted mutex (poses as the UI), and
         - pushes EngineCommand selectors 4, 9, 11, 2 (install CA, build the
           80/443 rules, apply them, user handshake).
       Neither the mutex nor the commands alone start capture; together they do.
    6. Follows the HttpTransaction shared-memory ring and decodes each record.

  HTTPS is decrypted: selector 4 installs "HTTP DEBUGGER CA for DEBUG ONLY" into
  LocalMachine\Root first, so the service's MITM presents a trusted leaf.

.PARAMETER Seconds
  How long to read before exiting. 0 (default) = until Ctrl+C.

.PARAMETER NoInstall
  Skip install/arm and just read (service must already be running + armed).

.PARAMETER Uninstall
  Stop and remove the service, then exit.
#>
[CmdletBinding()]
param(
  [int]$Seconds = 0,
  [int]$TrimBody = 0,        # 0 = show the whole body; >0 = trim each body to N chars
  [switch]$NoInstall,
  [switch]$Uninstall,
  [switch]$SelfTest         # generate a few HTTP/HTTPS requests so there is traffic to show
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- tiny console helpers ---------------------------------------------------
function Step($t) { Write-Host ''; Write-Host "==> $t" -ForegroundColor White }
function Ok($t)   { Write-Host "    [ok]   $t" -ForegroundColor Green }
function Warn($t) { Write-Host "    [warn] $t" -ForegroundColor Yellow }
function Fail($t) { Write-Host "    [fail] $t" -ForegroundColor Red }

# --- paths ------------------------------------------------------------------
$svcExe      = Join-Path $here 'HTTPDebuggerSvc.exe'
$driverSrc   = Join-Path $here 'CtrlSM.sys'
$driverDsts  = @((Join-Path $here 'drv2\x64\netfilter2.sys'),
                 (Join-Path $here 'drv2\win32\netfilter2.sys'))
$SvcName     = 'HTTPDebuggerPro'
$programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$storeDir    = Join-Path $programData 'HTTPDebuggerPro'
$storePath   = Join-Path $storeDir 'settings.xml'
$sc          = Join-Path $env:SystemRoot 'System32\sc.exe'

function Sc { param([string[]]$a) (& $sc @a 2>&1) ; return $LASTEXITCODE }
function SvcState($name) {
  $o = (& $sc query $name 2>&1)
  if ($o -match 'RUNNING') { return 'RUNNING' }
  if ($o -match 'STOPPED') { return 'STOPPED' }
  if ($o -match 'START_PENDING') { return 'START_PENDING' }
  if ($o -match 'FAILED 1060') { return 'ABSENT' }
  return 'UNKNOWN'
}

# --- self-elevation ---------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Administrator rights required - relaunching elevated...' -ForegroundColor Yellow
  $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
  if ($PSBoundParameters.ContainsKey('Seconds'))  { $a += @('-Seconds',"$Seconds") }
  if ($NoInstall)  { $a += '-NoInstall' }
  if ($Uninstall)  { $a += '-Uninstall' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
  return
}

# ---------------------------------------------------------------------------
# The reader / arming engine (shared memory only - no driver handle needed).
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class HttpIpc
{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    static extern IntPtr OpenFileMappingA(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFile(IntPtr h, uint access, uint hi, uint lo, UIntPtr bytes);
    [DllImport("kernel32.dll")] static extern bool UnmapViewOfFile(IntPtr p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
    static extern IntPtr OpenEventA(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEvent(IntPtr h);

    const uint FILE_MAP_READ   = 0x0004;
    const uint FILE_MAP_WRITE  = 0x0002;
    const uint FILE_MAP_RW     = 0x0006;
    const uint EVENT_ALL       = 0x001F0003;
    const uint SLOT_STRIDE     = 0x6000;

    static uint U32(IntPtr p, int o) { return (uint)Marshal.ReadInt32(p, o); }

    public class Header {
        public uint Capacity, WriteCursor, ReadCursor, Stride, Total, Generation, Flags;
        public bool Valid;
    }
    public static Header ReadHeader(IntPtr p) {
        Header h = new Header();
        if (p == IntPtr.Zero) return h;
        h.Capacity    = U32(p, 0x00);
        h.WriteCursor = U32(p, 0x04);
        h.ReadCursor  = U32(p, 0x08);
        uint cap2     = U32(p, 0x14);
        h.Stride      = U32(p, 0x18);
        h.Total       = U32(p, 0x1C);
        h.Generation  = U32(p, 0x20);
        h.Flags       = U32(p, 0x28);
        h.Valid = h.Capacity > 0 && h.Capacity <= 0x100000 && cap2 == h.Capacity
                  && h.Stride == SLOT_STRIDE && h.Total == h.Capacity * h.Stride;
        return h;
    }

    public class Ring {
        public string Base, DataName;
        public IntPtr Mem, Data;
        public Header H = new Header();
        public long DataBytes;
    }

    static IntPtr Map(string name, UIntPtr bytes, uint access) {
        IntPtr h = OpenFileMappingA(access, false, name);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return IntPtr.Zero;
        IntPtr p = MapViewOfFile(h, access, 0, 0, bytes);
        CloseHandle(h);
        return p;
    }

    public static Ring Attach(string b, int waitMs) {
        Ring r = new Ring(); r.Base = b;
        IntPtr mem = IntPtr.Zero; int waited = 0;
        while (true) {
            mem = Map(b + "_mem", (UIntPtr)0x30, FILE_MAP_READ);
            if (mem != IntPtr.Zero) break;
            if (waited >= waitMs) return null;
            System.Threading.Thread.Sleep(50); waited += 50;
        }
        r.Mem = mem; r.H = ReadHeader(mem);
        if (!r.H.Valid) { UnmapViewOfFile(mem); return null; }
        for (int n = 0; n < 16 && r.Data == IntPtr.Zero; n++) {
            foreach (string cand in new string[]{ n + b + "_data_", b + "_data_" + n }) {
                IntPtr d = Map(cand, UIntPtr.Zero, FILE_MAP_READ);
                if (d != IntPtr.Zero) { r.Data = d; r.DataName = cand; break; }
            }
        }
        if (r.Data == IntPtr.Zero) { UnmapViewOfFile(r.Mem); return null; }
        r.DataBytes = (long)r.H.Total + (long)r.H.Capacity * 4;
        return r;
    }

    public static bool SlotRange(Ring r, uint i, out int off, out int len) {
        off = len = 0;
        if (r == null || r.Data == IntPtr.Zero || i >= r.H.Capacity) return false;
        long start = (long)i * r.H.Stride;
        if (start >= r.DataBytes) return false;
        long l = r.H.Stride;
        if (start + l > r.DataBytes) l = r.DataBytes - start;
        off = (int)start; len = (int)l; return true;
    }
    public static int SlotState(Ring r, uint i) {
        if (r == null || r.Data == IntPtr.Zero || i >= r.H.Capacity) return -1;
        long at = (long)r.H.Total + (long)i * 4;
        if (at + 4 > r.DataBytes) return -1;
        return Marshal.ReadInt32(r.Data, (int)at);
    }
    public static byte[] ReadBytes(IntPtr p, int off, int len) {
        byte[] b = new byte[len]; Marshal.Copy(p + off, b, 0, len); return b;
    }
    // Record length from the 16-byte chunk header (field D at +0x0C).
    public static int RecordLen(Ring r, int off) {
        return Marshal.ReadInt32(r.Data, off + 12);
    }

    // ---- capture arming (the service must see the UI mutex held; caller does) -
    static string Push(uint selector, byte[] extra) {
        const string b = "Global\\HttpDebuggerIpcEngineCommand";
        int bodyLen = 12 + (extra == null ? 0 : extra.Length);
        byte[] rec = new byte[16 + bodyLen];
        BitConverter.GetBytes((uint)1).CopyTo(rec, 0);
        BitConverter.GetBytes((uint)1).CopyTo(rec, 4);
        BitConverter.GetBytes((uint)bodyLen).CopyTo(rec, 8);
        BitConverter.GetBytes((uint)bodyLen).CopyTo(rec, 12);
        BitConverter.GetBytes(selector).CopyTo(rec, 16);
        if (extra != null) extra.CopyTo(rec, 28);
        IntPtr h = OpenFileMappingA(FILE_MAP_RW, false, b + "_data_0");
        if (h == IntPtr.Zero) return "sel " + selector + " open win32=" + Marshal.GetLastWin32Error();
        IntPtr p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, UIntPtr.Zero);
        if (p == IntPtr.Zero) { CloseHandle(h); return "sel " + selector + " map win32=" + Marshal.GetLastWin32Error(); }
        Marshal.Copy(rec, 0, p, rec.Length);
        Marshal.WriteInt32(p, (int)SLOT_STRIDE, 2);        // slot state = READY
        UnmapViewOfFile(p); CloseHandle(h);
        IntPtr hm = OpenFileMappingA(FILE_MAP_RW, false, b + "_mem");
        if (hm != IntPtr.Zero) {
            IntPtr pm = MapViewOfFile(hm, FILE_MAP_WRITE, 0, 0, UIntPtr.Zero);
            if (pm != IntPtr.Zero) { int wc = Marshal.ReadInt32(pm, 4); Marshal.WriteInt32(pm, 4, wc + 1); UnmapViewOfFile(pm); }
            CloseHandle(hm);
        }
        IntPtr he = OpenEventA(EVENT_ALL, false, b + "_evt_filled");
        if (he != IntPtr.Zero) { SetEvent(he); CloseHandle(he); }
        return "sel " + selector + " ok";
    }
    public static string ArmCapture(string user) {
        byte[] ub = Encoding.ASCII.GetBytes(user == null ? "" : user);
        byte[] uext = new byte[8 + ub.Length];
        BitConverter.GetBytes((uint)ub.Length).CopyTo(uext, 0);
        ub.CopyTo(uext, 4);
        string s4 = Push(4, new byte[4]);  System.Threading.Thread.Sleep(1200); // install CA (HTTPS) first
        string s9 = Push(9, new byte[4]);  System.Threading.Thread.Sleep(300);  // build 80/443 rules
        string s11 = Push(11, new byte[4]); System.Threading.Thread.Sleep(300); // apply/activate
        string s2 = Push(2, uext);         System.Threading.Thread.Sleep(300);  // user handshake
        return s4 + "; " + s9 + "; " + s11 + "; " + s2;
    }

    // Every meaningful field in a record - the metadata strings (user, process,
    // host:port, url) AND the full HTTP request/response blocks AND the bodies -
    // is stored as a u32 little-endian length followed by exactly that many bytes.
    //
    // The inter-field framing (length prefixes, the identity blob, the chunk
    // header) always contains NUL bytes, while a real string field (HTTP text,
    // host, URL, JSON/HTML body) never does. So: scan byte by byte for a
    // length-prefixed run that is NUL-free and overwhelmingly printable. That
    // alone keeps each field exact - no merges, no fragments, no trailing junk.
    public static string[] Fields(byte[] b, int total) {
        List<string> o = new List<string>();
        int p = 16;                                   // past the 16-byte chunk header
        while (p + 4 <= total) {
            uint len = (uint)(b[p] | (b[p+1] << 8) | (b[p+2] << 16) | (b[p+3] << 24));
            if (len >= 2 && len <= (uint)(total - p - 4) && len <= 0x20000) {
                int sp = p + 4, printable = 0;
                bool ok = true;
                for (int k = 0; k < (int)len; k++) {
                    byte c = b[sp + k];
                    if (c == 0) { ok = false; break; }   // NUL => this is framing, not a string
                    if ((c >= 32 && c != 127) || c == 9 || c == 10 || c == 13 || c >= 128) printable++;
                }
                if (ok && printable * 100 >= (int)len * 80) {
                    o.Add(Encoding.UTF8.GetString(b, sp, (int)len));
                    p = sp + (int)len;
                    continue;
                }
            }
            p += 1;                                   // scan forward one byte and retry
        }
        return o.ToArray();
    }
}
'@

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
  Step "Uninstalling $SvcName"
  Sc @('stop', $SvcName) | Out-Null
  Start-Sleep 2
  $r = Sc @('delete', $SvcName)
  if ($r -eq 0) { Ok "service removed" } else { Warn "sc delete returned $r" }
  return
}

# ---------------------------------------------------------------------------
# Install + start (unless -NoInstall)
# ---------------------------------------------------------------------------
if (-not $NoInstall) {
  if (-not (Test-Path $svcExe))   { Fail "HTTPDebuggerSvc.exe not found next to this script"; return }
  if (-not (Test-Path $driverSrc)){ Fail "CtrlSM.sys not found next to this script"; return }

  Step 'Deploying the packaged driver'
  foreach ($dst in $driverDsts) {
    $dir = Split-Path -Parent $dst
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item $driverSrc $dst -Force
    Ok "packaged -> $dst"
  }

  Step 'Writing the rules-profile store'
  if (-not (Test-Path $storeDir)) { New-Item -ItemType Directory -Path $storeDir -Force | Out-Null }
  if (-not (Test-Path $storePath)) {
    @'
<HTTPDebuggerPro>
  <RulesProfiles Version="1" ActiveId="profile-1" CatalogRevision="1" ActiveGeneration="1">
    <Profile Id="profile-1" Name="Main">
      <HttpFilter>
        <Rule Id="1" Enabled="1" Name="capture" UrlMatch="0" Url="" App="" Method="" IpAddr="" CaptureOnly="0" ShowOnly="0"/>
      </HttpFilter>
      <AutoResponder>
        <Rule Id="1" Enabled="0" Name="" UrlMatch="0" Url="" ResponseHeader="" ResponseContent="" ResponseFile=""/>
      </AutoResponder>
      <HostRedirector>
        <Rule Id="1" Enabled="0" Name="" FromAddr="" FromHost="" ToAddr="" ToHost=""/>
      </HostRedirector>
      <HttpModifier>
        <Rule Id="1" Enabled="0" Name="" UrlMatch="0" Url=""/>
      </HttpModifier>
      <TcpRedirector>
        <Rule Id="1" Enabled="0" Name="" FromAddr="" ToAddr=""/>
      </TcpRedirector>
      <Highlighting>
        <Rule Id="1" Enabled="0" Name="" UseRegex="0" DarkThemeColor="0" WhiteThemeColor="0" Bold="0" EntireRow="0" Column="0" Expression="0" Val1="" Val2=""/>
      </Highlighting>
    </Profile>
  </RulesProfiles>
  <HttpEngine IsAskedForChat="1" EnableAnalytics="1"/>
  <HttpSubmitter Method="GET" Url="http://" Header="" Content="" File="">
    <Rule Enabled="0" Name="" Method="GET" Url="http://" Header="" Content="" File=""/>
  </HttpSubmitter>
</HTTPDebuggerPro>
'@ | Set-Content -LiteralPath $storePath -Encoding Ascii
    Ok "wrote $storePath"
  } else { Ok "store already present: $storePath" }

  Step 'Running HTTPDebuggerSvc.exe /install (creates service + TLS root CA)'
  $p = Start-Process -FilePath $svcExe -ArgumentList '/install' -NoNewWindow -PassThru
  if (-not $p.WaitForExit(180000)) { try { $p.Kill() } catch {} ; Warn '/install still running after 180s' }
  else { Ok "/install finished" }

  if ((SvcState $SvcName) -eq 'ABSENT') {
    Sc @('create', $SvcName, 'binPath=', "`"$svcExe`"", 'start=', 'auto', 'DisplayName=', 'HTTP Debugger Pro') | Out-Null
  }

  Step 'Starting the capture service'
  if ((SvcState $SvcName) -ne 'RUNNING') { Sc @('start', $SvcName) | Out-Null }
  for ($i = 0; $i -lt 60 -and (SvcState $SvcName) -ne 'RUNNING'; $i++) { Start-Sleep 1 }
  if ((SvcState $SvcName) -eq 'RUNNING') { Ok "$SvcName running" }
  else { Warn "$SvcName is $(SvcState $SvcName) - continuing anyway" }

  $ca = @(Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue |
          Where-Object { $_.Subject -like '*HTTP DEBUGGER*' })
  if ($ca.Count) { Ok "root CA trusted: $($ca[0].Subject)" }
  else { Warn 'HTTP DEBUGGER root CA not found yet (arming installs it below)' }
}

# ---------------------------------------------------------------------------
# Arm capture headlessly: hold the UI mutex + push EngineCommand 4,9,11,2.
# ---------------------------------------------------------------------------
Step 'Arming capture (mutex + EngineCommand 4,9,11,2)'
$mutexName = 'Global\HttpDebuggerUiStarted'
try { $mutex = [System.Threading.Mutex]::OpenExisting($mutexName) }
catch { $cn = $false; $mutex = New-Object System.Threading.Mutex($false, $mutexName, [ref]$cn) }
$owned = $false
try { $owned = $mutex.WaitOne(3000) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
if ($owned) { Ok "acquired $mutexName (posing as the UI)" }
else { Warn "could not acquire $mutexName - the real UI may be open; close it and re-run" }

$arm = [HttpIpc]::ArmCapture($env:USERNAME)
Ok "arm commands -> $arm"

$ring = [HttpIpc]::Attach('Global\HttpDebuggerIpcHttpTransaction', 8000)
if (-not $ring) { Fail 'could not attach to the HttpTransaction ring (is the service running?)'; if ($owned) { $mutex.ReleaseMutex() }; return }
Ok "attached to $($ring.DataName) (capacity $($ring.H.Capacity))"

if ($SelfTest) {
  Ok 'self-test: generating sample HTTP + HTTPS requests in the background'
  Start-Job {
    Start-Sleep 2
    foreach ($n in 1..4) {
      foreach ($u in 'http://neverssl.com','https://example.com','https://httpbin.org/get') {
        try { Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 12 | Out-Null } catch {}
      }
      try { Invoke-WebRequest 'https://httpbin.org/post' -Method POST -Body "self_test_body_$n" -ContentType 'text/plain' -UseBasicParsing -TimeoutSec 12 | Out-Null } catch {}
      Start-Sleep 2
    }
  } | Out-Null
}

# ---------------------------------------------------------------------------
# Classify + print one record's text segments.
# ---------------------------------------------------------------------------
# A transaction spans several ring records (request record = tag 0, response
# headers = tag 2, response body = tag 3+), all sharing a transaction id at
# offset 0x14 of the record. We group by that id so concurrent connections do
# not interleave, then print each transaction as one unit on idle / at the end.
$script:txns = New-Object System.Collections.Specialized.OrderedDictionary
$script:txn  = 0

function Emit-Body([string]$label, [string]$text, [ConsoleColor]$color) {
  $t = $text.TrimEnd()
  if ($t.Trim().Length -eq 0) { return }
  $note = ''
  if ($TrimBody -gt 0 -and $t.Length -gt $TrimBody) {
    $note = "  ... (+$($t.Length - $TrimBody) more bytes; -TrimBody 0 shows all)"
    $t = $t.Substring(0, $TrimBody)
  }
  Write-Host "    $label" -ForegroundColor $color
  Write-Host ("        " + ($t -replace "`r?`n", "`n        ") + $note)
}

function Print-Txn($c) {
  if (-not ($c.ReqHeaders -or $c.ResHeaders -or $c.ResBody -or $c.ReqBody)) { return }
  Write-Host ''
  $who = $c.Proc; if ($c.User) { $who += " ($($c.User))" }
  if (-not $who) { $who = '(unknown process)' }
  Write-Host ("  #{0}  {1}" -f $c.Num, $who) -ForegroundColor White
  $line = @($c.Method, $c.Url) | Where-Object { $_ }
  if ($line) { Write-Host ("       " + ($line -join ' ') + $(if ($c.Status) { "   ->  $($c.Status)" } else { '' })) -ForegroundColor Gray }
  elseif ($c.Host) { Write-Host "       Host: $($c.Host)$(if ($c.Status) { "   ->  $($c.Status)" } else { '' })" -ForegroundColor Gray }
  if ($c.ReqHeaders) {
    Write-Host '    > REQUEST HEADERS' -ForegroundColor Cyan
    foreach ($ln in ($c.ReqHeaders -split "`r?`n")) { Write-Host "        $ln" }
  }
  if ($c.ReqBody.Length)  { Emit-Body '> REQUEST BODY'  $c.ReqBody  ([ConsoleColor]::Cyan) }
  if ($c.ResHeaders) {
    Write-Host '    < RESPONSE HEADERS' -ForegroundColor Green
    foreach ($ln in ($c.ResHeaders -split "`r?`n")) { Write-Host "        $ln" }
  }
  if ($c.ResBody.Length)  { Emit-Body '< RESPONSE BODY' $c.ResBody ([ConsoleColor]::Green) }
}

# Print and remove transactions that already have a response (complete). Called
# after a short lull so each exchange appears promptly without being orphaned.
function Flush-Ready {
  foreach ($key in @($script:txns.Keys)) {
    if ($script:txns[$key].ResHeaders -or $script:txns[$key].ResBody) {
      Print-Txn $script:txns[$key]; $script:txns.Remove($key)
    }
  }
}
function Flush-All {
  foreach ($key in @($script:txns.Keys)) { Print-Txn $script:txns[$key] }
  $script:txns.Clear()
}

function Ingest([string[]]$fields, [uint32]$id) {
  $key = [string]$id
  if ($script:txns.Contains($key)) { $t = $script:txns[$key] }
  else {
    $script:txn++
    $t = @{ Num = $script:txn; Proc=''; User=''; Host=''; Url=''; Method='';
            ReqHeaders=''; ReqBody=''; ResHeaders=''; ResBody=''; Status=''; SawResp=$false }
    $script:txns[$key] = $t
  }
  foreach ($f in $fields) {
    $trim = $f.Trim()
    if ($f -match '^[A-Z][A-Z]+ \S+ HTTP/\d') {
      $parts = $f -split "`r`n`r`n", 2
      $t.ReqHeaders = $parts[0].TrimEnd(); $t.Method = ($f -split '\s+', 2)[0]
      if ($parts.Count -gt 1 -and $parts[1]) { $t.ReqBody += $parts[1] }
      continue
    }
    if ($f -match '^HTTP/\d\S*\s+\d{3}') {
      $parts = $f -split "`r`n`r`n", 2
      $t.ResHeaders = $parts[0].TrimEnd(); $t.SawResp = $true
      if ($parts[0] -match '^HTTP/\S+\s+(\d{3}[^\r\n]*)') { $t.Status = $Matches[1].Trim() }
      if ($parts.Count -gt 1 -and $parts[1]) { $t.ResBody += $parts[1] }
      continue
    }
    if ($trim -match '^\d{1,3}(\.\d{1,3}){3}:\d+$') { if (-not $t.Host) { $t.Host = $trim }; continue }
    if ($trim -match '^https?://')                  { if (-not $t.Url)  { $t.Url  = $trim }; continue }
    if ($trim -match '(?i)\.(exe|dll)$' -and $trim -notmatch '\s') { if (-not $t.Proc) { $t.Proc = $trim }; continue }
    if ($trim -eq $env:USERNAME)                    { if (-not $t.User) { $t.User = $trim }; continue }
    if ($trim -match '^\d{1,4}$')                   { continue }    # bare status-code field
    if ($trim -match '^[\w.\-]{1,24}$' -and -not $t.User) { $t.User = $trim; continue }
    if ($t.SawResp) { $t.ResBody += $f } else { $t.ReqBody += $f }  # body chunk
  }
}

# ---------------------------------------------------------------------------
# Follow the publisher cursor and decode every new record.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[reading] HTTP + HTTPS transactions$(if ($Seconds -gt 0) { " for ${Seconds}s" } else { ' (Ctrl+C to stop)' })" -ForegroundColor White

$last = [uint32]::MaxValue
$stop = if ($Seconds -gt 0) { [DateTime]::UtcNow.AddSeconds($Seconds) } else { [DateTime]::MaxValue }
$idle = 0
try {
  while ([DateTime]::UtcNow -lt $stop) {
    $h = [HttpIpc]::ReadHeader($ring.Mem)
    if (-not $h.Valid) { Start-Sleep -Milliseconds 300; continue }
    if ($h.WriteCursor -eq $last) {
      # Nothing new: flush completed exchanges after a short lull; flush whatever
      # is left (e.g. a request whose response we never saw) after a longer one.
      $idle += 120
      if ($script:txns.Count) {
        if ($idle -ge 360)  { Flush-Ready }
        if ($idle -ge 1400) { Flush-All }
      }
      Start-Sleep -Milliseconds 120
      continue
    }
    $idle = 0
    $from = if ($last -eq [uint32]::MaxValue) { $h.WriteCursor } else { $last + 1 }
    for ($seq = $from; $seq -le $h.WriteCursor; $seq++) {
      $slot = [uint32]($seq % $h.Capacity)
      $st = [HttpIpc]::SlotState($ring, $slot)
      if ($st -ne 2 -and $st -ne 3) { continue }     # 2=ready, 3=already consumed (data persists)
      $off = 0; $len = 0
      if (-not [HttpIpc]::SlotRange($ring, $slot, [ref]$off, [ref]$len)) { continue }
      $d = [HttpIpc]::RecordLen($ring, $off)
      if ($d -lt 16 -or $d -gt $len) { $d = [Math]::Min($len, 0x6000) }
      $raw = [HttpIpc]::ReadBytes($ring.Data, $off, $d)
      $id = [uint32]([System.Runtime.InteropServices.Marshal]::ReadInt32($ring.Data, $off + 0x14))  # transaction id
      $segs = [HttpIpc]::Fields($raw, $raw.Length)
      if ($segs.Count) { Ingest $segs $id }
    }
    # Flush transactions once the backlog grows, so long sessions stay bounded.
    if ($script:txns.Count -ge 40) { Flush-All }
    $last = $h.WriteCursor
  }
} finally {
  Flush-All
  if ($owned) { try { $mutex.ReleaseMutex() } catch {} }
  Write-Host ''
  Write-Host "[done] $($script:txn) transaction(s) shown" -ForegroundColor White
}
