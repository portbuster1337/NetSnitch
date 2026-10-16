<#
.SYNOPSIS
  Install the HTTPDebugger capture service + driver, arm it headlessly (no GUI),
  and print every captured HTTP/HTTPS transaction in full: request headers,
  request body, response headers and response body.

.DESCRIPTION
  Three files, no GUI, fully scripted:
    netsnitch.ps1, HTTPDebuggerSvc.exe, CtrlSM.sys

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
  [string]$Server = '',     # collector URL, e.g. http://host:8771; streams captures there as JSON
  [switch]$NoInstall,
  [switch]$Uninstall,
  [switch]$SelfTest,        # generate a few HTTP/HTTPS requests so there is traffic to show
  [switch]$Background,      # detach and run continuously in a hidden process, then return
  [switch]$Persistence      # install a scheduled task that starts capture at every boot
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
  if ($PSBoundParameters.ContainsKey('TrimBody')) { $a += @('-TrimBody',"$TrimBody") }
  if ($Server)     { $a += @('-Server',$Server) }
  if ($NoInstall)  { $a += '-NoInstall' }
  if ($Uninstall)  { $a += '-Uninstall' }
  if ($SelfTest)   { $a += '-SelfTest' }
  if ($Background) { $a += '-Background' }
  if ($Persistence){ $a += '-Persistence' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
  return
}

# ---------------------------------------------------------------------------
# The reader / arming engine (shared memory only, no driver handle needed).
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
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

    // Every meaningful field in a record (the metadata strings: user, process,
    // host:port, url; plus the full HTTP request/response blocks and the bodies)
    // is stored as a u32 little-endian length followed by exactly that many bytes.
    //
    // The inter-field framing (length prefixes, the identity blob, the chunk
    // header) always contains NUL bytes, while a real string field (HTTP text,
    // host, URL, JSON/HTML body) never does. So scan byte by byte for a
    // length-prefixed run that is NUL-free and overwhelmingly printable. That
    // alone keeps each field exact, with no merges, fragments, or trailing junk.
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

    // A body record (tag 1 request body / tag 3 response body) holds one
    // length-prefixed blob that runs to the end of the record (D+16). Pull the
    // RAW bytes (no printable check) so compressed/binary bodies survive.
    public static byte[] ExtractBody(byte[] b, int D) {
        int end = D + 16;
        if (end > b.Length) end = b.Length;
        for (int p = 16; p + 4 <= end; p++) {
            long L = (long)(uint)(b[p] | (b[p+1] << 8) | (b[p+2] << 16) | (b[p+3] << 24));
            if (L >= 1 && (long)p + 4 + L == end) {
                byte[] body = new byte[L];
                Array.Copy(b, p + 4, body, 0, (int)L);
                return body;
            }
        }
        return null;
    }

    // Decode a body to text, transparently inflating gzip (magic 1f 8b) and
    // zlib/deflate (magic 78 xx), which is how servers compress responses.
    public static string DecodeBody(byte[] body) {
        if (body == null || body.Length == 0) return "";
        try {
            if (body.Length > 2 && body[0] == 0x1f && body[1] == 0x8b) {
                using (var ms = new System.IO.MemoryStream(body))
                using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                using (var sr = new System.IO.StreamReader(gz, Encoding.UTF8))
                    return sr.ReadToEnd();
            }
            if (body.Length > 2 && body[0] == 0x78 && (body[1] == 0x01 || body[1] == 0x9c || body[1] == 0xda)) {
                using (var ms = new System.IO.MemoryStream(body, 2, body.Length - 2))  // skip 2-byte zlib header
                using (var df = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress))
                using (var sr = new System.IO.StreamReader(df, Encoding.UTF8))
                    return sr.ReadToEnd();
            }
        } catch { }
        return Encoding.UTF8.GetString(body);   // plain text, or decompress failed
    }

    // ---- background capture pump -------------------------------------------
    // Request records are written then CLEARED by the service soon after it pairs
    // them with the response, so a forward "read each slot once" reader loses the
    // race and misses most requests (leaving response-only orphans). Instead a
    // native background thread re-scans EVERY slot continuously and queues a slot's
    // record whenever its content changes, which reliably catches the transient
    // request records. Grouping is by the transaction id at +0x14, which correlates
    // the request and response halves.
    //
    // The thread sleeps 1ms between passes (with 1ms timer resolution): that is
    // frequent enough to catch every request (they live tens of ms, through the
    // network round-trip) yet uses ~0.2% of one core instead of pinning it at 100%
    // like a no-sleep loop would. PowerShell just drains the queue periodically.
    [DllImport("winmm.dll")] static extern uint timeBeginPeriod(uint p);
    [DllImport("winmm.dll")] static extern uint timeEndPeriod(uint p);
    static uint[] _slotSig;
    static volatile bool _pumpRun;
    static Thread _pumpThread;
    static ConcurrentQueue<byte[]> _pumpQ = new ConcurrentQueue<byte[]>();
    static uint RU(IntPtr p, long o) { return (uint)Marshal.ReadInt32(p, (int)o); }

    public static void StartPump(IntPtr data, int cap, int stride, long dataBytes, int sleepMs) {
        _slotSig = new uint[cap];
        _pumpRun = true;
        PumpScan(data, cap, stride, dataBytes, true);   // prime: skip the pre-attach backlog
        _pumpThread = new Thread(delegate() {
            // Run the scan thread below normal priority so it can never starve the
            // OS/ssh/services even under a heavy traffic storm.
            try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
            timeBeginPeriod(1);
            try { while (_pumpRun) { PumpScan(data, cap, stride, dataBytes, false); if (sleepMs > 0) Thread.Sleep(sleepMs); } }
            finally { timeEndPeriod(1); }
        });
        _pumpThread.IsBackground = true;
        _pumpThread.Start();
    }

    static void PumpScan(IntPtr data, int cap, int stride, long dataBytes, bool primeOnly) {
        for (int slot = 0; slot < cap; slot++) {
            long off = (long)slot * stride;
            if (off + 24 > dataBytes) break;
            uint D = RU(data, off + 12);
            if (D < 16 || D > (uint)stride) continue;
            if (RU(data, off) == 0 || RU(data, off + 4) == 0) continue;    // no chunk header
            uint tag = RU(data, off + 16), id = RU(data, off + 20);
            uint sig = D ^ (tag * 2654435761u) ^ (id * 40503u)
                       ^ (RU(data, off + 0x40) * 131u) ^ (RU(data, off + 0x80) * 17u);
            if (sig == 0) sig = 1;
            if (_slotSig[slot] == sig) continue;                           // unchanged since last scan
            _slotSig[slot] = sig;
            if (primeOnly) continue;
            int n = (int)Math.Min((long)D + 48, Math.Min((long)stride, dataBytes - off));
            if (n < 16) continue;
            byte[] rec = new byte[n];
            Marshal.Copy(new IntPtr(data.ToInt64() + off), rec, 0, n);
            _pumpQ.Enqueue(rec);
        }
    }

    public static byte[][] Drain() {
        var o = new List<byte[]>();
        byte[] r;
        while (_pumpQ.TryDequeue(out r)) o.Add(r);
        return o.ToArray();
    }

    public static void StopPump() {
        _pumpRun = false;
        try { if (_pumpThread != null) _pumpThread.Join(500); } catch { }
    }
}
'@

# ---------------------------------------------------------------------------
# Uninstall (also removes the persistence task)
# ---------------------------------------------------------------------------
if ($Uninstall) {
  Step "Uninstalling $SvcName"
  foreach ($tn in 'NetSnitch','HttpCapture') {   # HttpCapture = legacy task name
    try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Stop; Ok "removed persistence task '$tn'" } catch {}
  }
  # Kill any running background/persistence capture so nothing stays armed.
  $killed = 0
  try {
    Get-CimInstance Win32_Process -Filter 'Name="powershell.exe"' |
      Where-Object { ($_.CommandLine -match 'NetSnitch' -or $_.CommandLine -match 'HttpCapture') -and $_.ProcessId -ne $PID } |
      ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $killed++ } catch {} }
  } catch {}
  if ($killed) { Ok "stopped $killed running capture process(es)" }
  try { Remove-Item (Join-Path $storeDir 'armed.boot') -Force -ErrorAction SilentlyContinue } catch {}
  # Stopping the service clears the driver's 80/443 filters and restores traffic.
  Sc @('stop', $SvcName) | Out-Null
  Start-Sleep 2
  $r = Sc @('delete', $SvcName)
  if ($r -eq 0) { Ok "service removed" } else { Warn "sc delete returned $r" }
  return
}

# ---------------------------------------------------------------------------
# -Persistence: a scheduled task that starts continuous capture at every boot
# (hidden, as SYSTEM). It uses -NoInstall because the service is installed once
# and auto-starts; the CA and rules persist across reboots.
# -Background: relaunch this script hidden + detached, running forever, and
# return immediately so the caller gets their prompt back.
# ---------------------------------------------------------------------------
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function New-PersistenceTask {
  $argline = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -NoInstall -Seconds 0"
  if ($Server)         { $argline += " -Server `"$Server`"" }
  if ($TrimBody -gt 0) { $argline += " -TrimBody $TrimBody" }
  try {
    $action    = New-ScheduledTaskAction -Execute $pwsh -Argument $argline
    # Start 90s AFTER boot, not AtStartup: the service and networking need to be
    # fully up, and starting during the early-boot traffic storm is what spiked
    # the CPU. The delayed start lets the machine settle first.
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT90S'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # No RestartCount: an auto-restart would RE-arm the already-armed service,
    # which breaks external traffic. The arm-once-per-boot guard also protects us.
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                   -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'NetSnitch' -Action $action -Trigger $trigger `
      -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Ok "persistence task 'NetSnitch' created (starts ~90s after each boot, as SYSTEM)"
  } catch {
    $tr = "`"$pwsh`" $argline"
    & (Join-Path $env:SystemRoot 'System32\schtasks.exe') /Create /TN 'NetSnitch' /TR $tr /SC ONSTART /DELAY 0001:30 /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "persistence task 'NetSnitch' created (schtasks)" }
    else { Warn "could not create persistence task: $($_.Exception.Message)" }
  }
}

if ($Persistence) {
  Step 'Installing reboot persistence'
  New-PersistenceTask
  # IMPORTANT: -Persistence only INSTALLS the boot task. It must NOT fall through
  # into the foreground capture loop. Doing so would arm the service and capture
  # in whatever session launched it, and if that session ends the armed capture is
  # orphaned (breaks external traffic, spikes CPU). To also start capturing now,
  # combine with -Background (handled below). Otherwise we are done.
  if (-not $Background) {
    Write-Host '    capture will start automatically ~90s after each boot.' -ForegroundColor DarkGray
    Write-Host '    to also start it now without rebooting, add -Background.' -ForegroundColor DarkGray
    return
  }
}

if ($Background) {
  Step 'Launching continuous capture in the background'
  # Build the hidden, run-forever command line for the detached child.
  $cl = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Seconds 0"
  if ($NoInstall)      { $cl += ' -NoInstall' }
  if ($Server)         { $cl += " -Server `"$Server`"" }
  if ($TrimBody -gt 0) { $cl += " -TrimBody $TrimBody" }
  # Spawn via WMI Win32_Process.Create, NOT Start-Process: a WMI-created process
  # is parented to WmiPrvSE and lives outside the launcher's job object/session,
  # so it survives the parent exiting (and survives the launching console/SSH
  # session closing; Start-Process children get killed with that job object).
  $launched = $false
  try {
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cl } -ErrorAction Stop
    if ($r.ReturnValue -eq 0) { $launched = $true; Ok "capture is running in the background (continuous, pid $($r.ProcessId))." }
    else { Warn "Win32_Process.Create returned $($r.ReturnValue); falling back to Start-Process" }
  } catch { Warn "WMI spawn failed ($($_.Exception.Message)); falling back to Start-Process" }
  if (-not $launched) {
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$PSCommandPath`"",'-Seconds','0')
    if ($NoInstall)      { $a += '-NoInstall' }
    if ($Server)         { $a += @('-Server',$Server) }
    if ($TrimBody -gt 0) { $a += @('-TrimBody',"$TrimBody") }
    Start-Process -FilePath $pwsh -ArgumentList $a -WindowStyle Hidden | Out-Null
    Ok 'capture is running in the background (continuous).'
  }
  Write-Host '    stop it with:  Get-CimInstance Win32_Process -Filter "Name=''powershell.exe''" | ? CommandLine -match NetSnitch | % { Stop-Process -Id $_.ProcessId }' -ForegroundColor DarkGray
  if ($Persistence) { Write-Host '    it will also start automatically at every boot.' -ForegroundColor DarkGray }
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
else { Warn "could not acquire $mutexName - another capture instance or the UI already armed this service" }

# Arm-once-per-boot guard. Arming is only safe ONCE per boot: re-arming an
# already-armed service breaks external traffic (and can spin the service CPU).
# We record the current boot timestamp in a sentinel file after arming; if a
# later run this same boot finds a matching sentinel, it skips arming and just
# attaches read-only. The service stays armed across the whole boot regardless.
$bootId = ''
try { $bootId = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o') } catch {}
$armSentinel = Join-Path $storeDir 'armed.boot'
$alreadyArmed = $false
try { if ($bootId -and (Test-Path $armSentinel) -and ((Get-Content $armSentinel -Raw).Trim() -eq $bootId)) { $alreadyArmed = $true } } catch {}

# Only push the arm commands if we own the mutex AND the service was not already
# armed this boot. Otherwise attach read-only to the already-armed service.
if ($owned -and -not $alreadyArmed) {
  $arm = [HttpIpc]::ArmCapture($env:USERNAME)
  Ok "arm commands -> $arm"
  try { if ($bootId) { if (-not (Test-Path $storeDir)) { New-Item -ItemType Directory -Path $storeDir -Force | Out-Null }; Set-Content -Path $armSentinel -Value $bootId -Encoding Ascii } } catch {}
} elseif ($alreadyArmed) {
  Warn 'service already armed this boot - NOT re-arming (would break external traffic); attaching read-only'
} else {
  Warn 'NOT re-arming (would break external traffic) - attaching read-only to the already-armed service'
}

$ring = [HttpIpc]::Attach('Global\HttpDebuggerIpcHttpTransaction', 8000)
if (-not $ring) { Fail 'could not attach to the HttpTransaction ring (is the service running?)'; if ($owned) { $mutex.ReleaseMutex() }; return }
Ok "attached to $($ring.DataName) (capacity $($ring.H.Capacity))"

if ($SelfTest) {
  Ok 'self-test: generating sample HTTP + HTTPS requests in the background'
  Start-Job {
    Start-Sleep 2
    foreach ($n in 1..4) {
      foreach ($u in 'http://neverssl.com','https://example.com','https://httpbin.org/get',
                     'https://httpbin.org/gzip','https://httpbin.org/deflate') {
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

function Now-Ms { [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) }

# A transaction's records arrive as a burst, but a request and its response can be
# seconds apart on long-lived connections. So: hold each transaction until it has
# gone quiet (SETTLE ms since its last record), then emit it ONLY if it is a
# complete request+response pair; drop one-sided transactions after GRACE ms.
$script:Settle = 500
$script:Grace  = 2500

function Flush-Settled([bool]$final) {
  $now = Now-Ms
  $send = @()
  foreach ($key in @($script:txns.Keys)) {
    $c = $script:txns[$key]
    if ($Server -and (Is-ServerTxn $c)) { $script:txns.Remove($key); continue }
    $hasReq  = [bool]($c.Method -or $c.Url -or $c.ReqHeaders)
    $hasResp = [bool]($c.ResHeaders -or $c.ResBody -or $c.Status)
    $quiet   = ($now - $c.Updated) -ge $script:Settle
    if ($hasReq -and $hasResp -and ($quiet -or $final)) {
      Print-Txn $c
      if ($Server) { $send += $c }
      $script:txns.Remove($key)
    } elseif ($final -or (($now - $c.First) -ge $script:Grace)) {
      $script:txns.Remove($key)                 # one-sided and out of time, drop it
    }
  }
  if ($Server -and $send.Count) { Send-Batch $send }
}

function Ingest([string[]]$fields, [uint32]$id, [int]$tag) {
  $key = [string]$id
  if ($script:txns.Contains($key)) { $t = $script:txns[$key] }
  else {
    $script:txn++
    $t = @{ Num = $script:txn; Proc=''; User=''; Host=''; Url=''; Method='';
            ReqHeaders=''; ReqBody=''; ResHeaders=''; ResBody=''; Status=''; SawResp=$false;
            First=(Now-Ms); Updated=(Now-Ms) }
    $script:txns[$key] = $t
  }
  $t.Updated = Now-Ms
  # The record tag says which half a loose body belongs to: 1 = request body,
  # 3 = response body. Far more reliable than guessing from order.
  if ($tag -ge 2) { $t.SawResp = $true }
  $toRes = ($tag -eq 3) -or ($tag -ne 1 -and $t.SawResp)
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
    if ($toRes) { $t.ResBody += $f } else { $t.ReqBody += $f }      # body chunk, routed by tag
  }
}

# A dedicated body record (tag 1 = request body, tag 3 = response body). The text
# is already decoded (and decompressed) by DecodeBody.
function Ingest-Body([uint32]$id, [int]$tag, [string]$text) {
  if (-not $text -or $text.Trim().Length -eq 0) { return }
  $key = [string]$id
  if ($script:txns.Contains($key)) { $t = $script:txns[$key] }
  else {
    $script:txn++
    $t = @{ Num = $script:txn; Proc=''; User=''; Host=''; Url=''; Method='';
            ReqHeaders=''; ReqBody=''; ResHeaders=''; ResBody=''; Status=''; SawResp=$false;
            First=(Now-Ms); Updated=(Now-Ms) }
    $script:txns[$key] = $t
  }
  $t.Updated = Now-Ms
  if ($tag -eq 1) { $t.ReqBody += $text } else { $t.ResBody += $text; $t.SawResp = $true }
}

# ---------------------------------------------------------------------------
# Optional collector: when -Server is given, each transaction is also POSTed to
# the server as JSON, tagged with a stable per-machine agent id.
# ---------------------------------------------------------------------------
# Deterministic per-machine id: a hash of stable system identifiers (the Windows
# MachineGuid and the SMBIOS hardware UUID), so the same machine always maps to
# the same agent, with no duplicates and no saved-file dependency.
function Get-AgentId {
  $parts = New-Object System.Collections.Generic.List[string]
  try {
    $mg = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    if ($mg) { $parts.Add("mg:$mg") }
  } catch {}
  try {
    $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID
    if ($uuid -and $uuid -notmatch '^0{8}-|FFFFFFFF') { $parts.Add("uuid:$uuid") }
  } catch {}
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($cs.Domain)       { $parts.Add("dom:$($cs.Domain)") }
  } catch {}
  if ($parts.Count -eq 0) { $parts.Add("cn:$env:COMPUTERNAME") }   # last-resort fallback
  $seed = ($parts -join '|').ToLowerInvariant()
  $sha  = [System.Security.Cryptography.SHA256]::Create()
  $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
  $sha.Dispose()
  $short = -join ($hash[0..5] | ForEach-Object { $_.ToString('x2') })   # 12 hex chars
  return "$env:COMPUTERNAME-$short"
}

# The agent's own uploads travel over HTTPS/443 and are themselves intercepted by
# the capture, forming a feedback loop. We tag every upload three ways (destination host,
# a request header, and a body sentinel) and drop any captured transaction that
# matches, so our uploads are never re-sent or shown.
$script:UploadMark = 'X-NetSnitch-Upload'
$script:UploadSentinel = '__netsnitch_upload__'

function Is-ServerTxn($c) {
  if ($script:ServerHost) {
    if (($c.Host -and $c.Host -like "*$($script:ServerHost)*") -or
        ($c.Url  -and $c.Url  -like "*$($script:ServerHost)*")) { return $true }
  }
  if ($c.ReqHeaders -and $c.ReqHeaders -match $script:UploadMark)     { return $true }
  if ($c.ReqBody    -and $c.ReqBody    -match $script:UploadSentinel) { return $true }
  return $false
}

# Send all transactions from one flush in a single POST (far less self-traffic
# than one request each).
function Send-Batch($list) {
  if (-not $list -or $list.Count -eq 0) { return }
  $items = @()
  foreach ($c in $list) {
    $items += @{
      ts = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
      process = $c.Proc; user = $c.User; host = $c.Host; url = $c.Url
      method = $c.Method; status = $c.Status
      requestHeaders = $c.ReqHeaders; requestBody = $c.ReqBody
      responseHeaders = $c.ResHeaders; responseBody = $c.ResBody
    }
  }
  $body = @{
    $script:UploadSentinel = 1
    agentId = $script:AgentId; agentName = $script:AgentName; machine = $env:COMPUTERNAME
    items = $items
  } | ConvertTo-Json -Depth 5 -Compress
  try {
    Invoke-RestMethod -Method Post -Uri "$script:ServerBase/api/ingest" -Body $body `
      -ContentType 'application/json' -Headers @{ $script:UploadMark = '1' } -TimeoutSec 10 | Out-Null
  } catch { }
}

function Register-WithServer {
  $body = @{ "$script:UploadSentinel" = 1; agentId = $script:AgentId; agentName = $script:AgentName; machine = $env:COMPUTERNAME }
  try {
    Invoke-RestMethod -Method Post -Uri "$script:ServerBase/api/agent" `
      -Body ($body | ConvertTo-Json -Compress) -ContentType 'application/json' `
      -Headers @{ $script:UploadMark = '1' } -TimeoutSec 5 | Out-Null
  } catch { }
}

# Set up the collector now that Get-AgentId / Register-WithServer are defined.
if ($Server) {
  $script:ServerBase = $Server.TrimEnd('/')
  try { $script:ServerHost = ([Uri]$Server).Host } catch { $script:ServerHost = '' }
  $script:AgentId = Get-AgentId
  $script:AgentName = $env:COMPUTERNAME
  Register-WithServer
  Ok "streaming captures to $script:ServerBase  (agent: $script:AgentId)"
}

# ---------------------------------------------------------------------------
# Follow the publisher cursor and decode every new record.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[reading] HTTP + HTTPS transactions$(if ($Seconds -gt 0) { " for ${Seconds}s" } else { ' (Ctrl+C to stop)' })" -ForegroundColor White

$cap    = [int]$ring.H.Capacity
$stride = [int]$ring.H.Stride
$dbytes = [long]$ring.DataBytes
$stop   = if ($Seconds -gt 0) { [DateTime]::UtcNow.AddSeconds($Seconds) } else { [DateTime]::MaxValue }
$flushAt = [DateTime]::UtcNow.AddMilliseconds(200)

# For continuous (background/persistence) runs, drop this process (and the HTTP
# service while it is armed) below normal priority. This is a hard safety net:
# even if traffic spikes the capture work, it can never starve the OS, sshd, or
# other services, so the machine stays responsive and reachable. (Bounded
# -Seconds runs stay at normal priority.)
if ($Seconds -le 0) {
  try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
  try { Get-Process -Name 'HTTPDebuggerSvc' -ErrorAction SilentlyContinue | ForEach-Object { $_.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } } catch {}
}
# A native background thread re-scans the ring every 1ms and queues changed
# records; we just drain the queue here. That catches every transient request
# record while using ~0.2% of one core (a no-sleep loop pins a whole core).
[HttpIpc]::StartPump($ring.Data, $cap, $stride, $dbytes, 1)
try {
  while ([DateTime]::UtcNow -lt $stop) {
    $recs = [HttpIpc]::Drain()
    foreach ($raw in $recs) {
      if ($raw.Length -lt 24) { continue }
      $d   = [System.BitConverter]::ToInt32($raw, 12)
      $tag = [System.BitConverter]::ToInt32($raw, 16)              # 0=req 1=reqbody 2=resp 3=respbody
      $id  = [uint32]([System.BitConverter]::ToInt32($raw, 20))    # transaction id (correlates req<->resp)
      if ($tag -eq 1 -or $tag -eq 3) {
        $bb = [HttpIpc]::ExtractBody($raw, $d)
        if ($bb) { Ingest-Body $id $tag ([HttpIpc]::DecodeBody($bb)) }
      } else {
        $segs = [HttpIpc]::Fields($raw, $raw.Length)
        if ($segs.Count) { Ingest $segs $id $tag }
      }
    }
    if ([DateTime]::UtcNow -ge $flushAt) {
      Flush-Settled $false                                         # emit settled complete pairs
      $flushAt = [DateTime]::UtcNow.AddMilliseconds(200)
    }
    Start-Sleep -Milliseconds 150                                  # drain cadence; the pump thread does the fast work
  }
} finally {
  [HttpIpc]::StopPump()
  Flush-Settled $true
  if ($owned) { try { $mutex.ReleaseMutex() } catch {} }
  Write-Host ''
  Write-Host "[done] $($script:txn) transaction(s) shown" -ForegroundColor White
}
