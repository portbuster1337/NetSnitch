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
         - acquires the Global\HttpDebuggerUiStarted mutex (poses as the UI),
         - pushes the rules profile over the Global\HttpDebuggerIpcSettings
           channel so the engine builds a live profile (the service never loads
           settings.xml from disk into the engine; only this IPC push does), and
         - pushes EngineCommand selectors 3, 9, 11, 2 (install CA, build the
           80/443 rules, apply the profile, user handshake).
       Neither the mutex nor the commands alone start capture; together they do.
    6. Follows the HttpTransaction shared-memory ring and decodes each record.

  HTTPS is decrypted: selector 4 installs "HTTP DEBUGGER CA for DEBUG ONLY" into
  LocalMachine\Root so the service's MITM presents a trusted leaf, and the profile
  push enables the engine's decrypt path (selector 11 apply is a no-op without it).

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
  [string[]]$Domains = @(), # only show/send transactions for these domains (e.g. -Domains google.com,github.com); empty = all
  [switch]$NoInstall,
  [switch]$Uninstall,
  [switch]$SelfTest,        # generate a few HTTP/HTTPS requests so there is traffic to show
  [switch]$Background,      # detach and run continuously in a hidden process, then return
  [switch]$Persistence,     # install a scheduled task that starts capture at every boot
  [switch]$DebugRing        # diagnosis: dump every raw ring record and every drop decision
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

# The rules profile. The service does NOT load settings.xml from disk into its
# live engine; the on-disk file is only persistence. The active profile is set
# ONLY when this document is pushed over the Global\HttpDebuggerIpcSettings
# channel (the UI does this at startup). Without it the engine has no profile,
# selector 11 (apply) is a no-op, and HTTPS is never decrypted. So we both write
# it to disk (for parity) and push it over IPC during arming.
$settingsXml = @'
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
'@

# NB: must NOT be named 'Sc' - that collides with the built-in 'sc' alias for
# Set-Content, which would shadow this function and prompt for -Value.
function Invoke-ScExe { param([string[]]$a) (& $sc @a 2>&1) ; return $LASTEXITCODE }
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
  if ($Domains)    { $a += @('-Domains', ($Domains -join ',')) }
  if ($NoInstall)  { $a += '-NoInstall' }
  if ($Uninstall)  { $a += '-Uninstall' }
  if ($SelfTest)   { $a += '-SelfTest' }
  if ($Background) { $a += '-Background' }
  if ($Persistence){ $a += '-Persistence' }
  if ($DebugRing)  { $a += '-DebugRing' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
  return
}

# Build marker - bump on every change so it is obvious which copy is running.
$NetSnitchBuild = '2026.10.20.18'
Write-Host ''
Write-Host "NetSnitch  (build $NetSnitchBuild)" -ForegroundColor Cyan

# Show exactly which switches arrived. Running a .ps1 from cmd.exe goes through
# the Windows file association, which drops the extra arguments before the
# script ever sees them; this line makes that obvious at a glance.
$gotSwitches = @($PSBoundParameters.Keys | ForEach-Object { "-$_" })
if ($gotSwitches.Count) { Write-Host "    switches: $($gotSwitches -join ' ')" -ForegroundColor DarkGray }
else { Write-Host '    switches: none (started without arguments)' -ForegroundColor DarkGray }

# Normalize -Domains into a clean, lowercased list. Accepts both array form
# (-Domains a,b) and a single comma-separated string (-Domains "a,b").
$script:Domains = @($Domains | ForEach-Object { $_ -split ',' } |
                    ForEach-Object { $_.Trim().ToLowerInvariant().TrimStart('*','.') } |
                    Where-Object { $_ })

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
        public IntPtr Mem, Data, EvtAvai;
        public Header H = new Header();
        public long DataBytes;
        public bool DataWritable;
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
            // Map the header read/write when we can: advancing the read-cursor (so the
            // service never backpressures real traffic) needs write access. Fall back
            // to read-only if the service denied write, so capture still works.
            mem = Map(b + "_mem", (UIntPtr)0x30, FILE_MAP_RW);
            if (mem == IntPtr.Zero) mem = Map(b + "_mem", (UIntPtr)0x30, FILE_MAP_READ);
            if (mem != IntPtr.Zero) break;
            if (waited >= waitMs) return null;
            System.Threading.Thread.Sleep(50); waited += 50;
        }
        r.Mem = mem; r.H = ReadHeader(mem);
        if (!r.H.Valid) { UnmapViewOfFile(mem); return null; }
        for (int n = 0; n < 16 && r.Data == IntPtr.Zero; n++) {
            foreach (string cand in new string[]{ n + b + "_data_", b + "_data_" + n }) {
                // Map the data region read/write when the service allows it. The ring's
                // per-slot state words live in this mapping (at Total + slot*4); the UI
                // consumer frees a slot by writing 0 to its state word, which is what
                // keeps the service's producer from blocking up to 500ms per record on a
                // full ring (the real cause of slow browsing). Fall back to read-only.
                IntPtr d = Map(cand, UIntPtr.Zero, FILE_MAP_RW);
                if (d != IntPtr.Zero) { r.Data = d; r.DataName = cand; r.DataWritable = true; break; }
                d = Map(cand, UIntPtr.Zero, FILE_MAP_READ);
                if (d != IntPtr.Zero) { r.Data = d; r.DataName = cand; break; }
            }
        }
        if (r.Data == IntPtr.Zero) { UnmapViewOfFile(r.Mem); return null; }
        r.DataBytes = (long)r.H.Total + (long)r.H.Capacity * 4;
        // The consumer->producer "space available" event. The service blocks on it
        // when the ring looks full and the UI signals it after draining; we must do
        // the same or the service backpressures and the real traffic slows down.
        r.EvtAvai = OpenEventA(EVENT_ALL, false, b + "_evt_avai");
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
    // Push the rules-profile document over Global\HttpDebuggerIpcSettings. The
    // service's SettingsObserver parses this into the engine's live profile
    // (engine+0x1f4). That profile is what selector 11 (apply) activates and
    // what the engine's capture/decrypt worker requires; writing settings.xml to
    // disk does NOT set it. The document body is [u32 xmlLen][xml bytes][u32 flag].
    static string PushSettings(string xml) {
        const string b = "Global\\HttpDebuggerIpcSettings";
        byte[] x = Encoding.ASCII.GetBytes(xml == null ? "" : xml);
        int bodyLen = 4 + x.Length + 4;
        byte[] rec = new byte[16 + bodyLen];
        BitConverter.GetBytes((uint)1).CopyTo(rec, 0);
        BitConverter.GetBytes((uint)1).CopyTo(rec, 4);
        BitConverter.GetBytes((uint)bodyLen).CopyTo(rec, 8);
        BitConverter.GetBytes((uint)bodyLen).CopyTo(rec, 12);
        BitConverter.GetBytes((uint)x.Length).CopyTo(rec, 16);        // body+0: xml length
        x.CopyTo(rec, 20);                                            // body+4: xml bytes
        BitConverter.GetBytes((uint)1).CopyTo(rec, 20 + x.Length);    // body+...: apply flag
        IntPtr h = OpenFileMappingA(FILE_MAP_RW, false, b + "_data_0");
        if (h == IntPtr.Zero) return "settings open win32=" + Marshal.GetLastWin32Error();
        IntPtr p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, UIntPtr.Zero);
        if (p == IntPtr.Zero) { CloseHandle(h); return "settings map win32=" + Marshal.GetLastWin32Error(); }
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
        return "settings ok (" + x.Length + " bytes)";
    }
    public static string ArmCapture(string user, string settingsXml) {
        byte[] ub = Encoding.ASCII.GetBytes(user == null ? "" : user);
        byte[] uext = new byte[8 + ub.Length];
        BitConverter.GetBytes((uint)ub.Length).CopyTo(uext, 0);
        ub.CopyTo(uext, 4);
        // Match the UI exactly. The UI only ever issues selectors 2,3,9,10,11:
        // 3 = install/verify the CA (cleanup old, reimport, verify, set the engine
        // SSL-ready flag) - the UI never uses selector 4. 9 = start (80/443 rules),
        // 11 = apply the profile, 2 = user handshake.
        string ss = PushSettings(settingsXml); System.Threading.Thread.Sleep(700); // load rules profile (enables apply + SSL decrypt)
        string s3 = Push(3, new byte[4]);  System.Threading.Thread.Sleep(1200); // install + verify CA (HTTPS), as the UI does
        string s9 = Push(9, new byte[4]);  System.Threading.Thread.Sleep(300);  // build 80/443 rules
        string s11 = Push(11, new byte[4]); System.Threading.Thread.Sleep(300); // apply/activate the profile
        string s2 = Push(2, uext);         System.Threading.Thread.Sleep(300);  // user handshake
        return "settings " + ss + "; " + s3 + "; " + s9 + "; " + s11 + "; " + s2;
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

    // ---- native transaction assembly ---------------------------------------
    // Parse + classify + group + settle entirely in native code, the way the UI
    // does it, so PowerShell only prints/uploads finished transactions instead of
    // doing per-record regex work in script (the old bottleneck).
    public class Txn {
        public int Num; public uint Id;
        public string Proc="", User="", Host="", Url="", Method="";
        public string ReqHeaders="", ReqBody="", ResHeaders="", ResBody="", Status="";
        public bool SawResp=false;
        public long First, Updated;
    }
    const System.Text.RegularExpressions.RegexOptions RXO =
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase;
    static readonly System.Text.RegularExpressions.Regex RxReq      = new System.Text.RegularExpressions.Regex(@"^[A-Z][A-Z]+ \S+ HTTP/\d", RXO);
    static readonly System.Text.RegularExpressions.Regex RxStatus   = new System.Text.RegularExpressions.Regex(@"^HTTP/\d\S*\s+\d{3}", RXO);
    static readonly System.Text.RegularExpressions.Regex RxStatusCd = new System.Text.RegularExpressions.Regex(@"^HTTP/\S+\s+(\d{3}[^\r\n]*)", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Method = new System.Text.RegularExpressions.Regex(@"(?m)^x-exhdr-method:[ \t]*(\S+)", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Auth   = new System.Text.RegularExpressions.Regex(@"(?m)^x-exhdr-authority:[ \t]*([^\r\n]+)", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Path   = new System.Text.RegularExpressions.Regex(@"(?m)^x-exhdr-path:[ \t]*([^\r\n]+)", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Stream = new System.Text.RegularExpressions.Regex(@"(?m)^x-exhdr-streamid:", RXO);
    static readonly System.Text.RegularExpressions.Regex RxHdrLine  = new System.Text.RegularExpressions.Regex(@"(?m)^[A-Za-z][\w\-]*:[ \t]", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Stat1  = new System.Text.RegularExpressions.Regex(@"[:\s]status:?[ \t]*(\d{3})", RXO);
    static readonly System.Text.RegularExpressions.Regex RxH2Stat2  = new System.Text.RegularExpressions.Regex(@"HTTP/\d\S*\s+(\d{3})", RXO);
    static readonly System.Text.RegularExpressions.Regex RxHostPort = new System.Text.RegularExpressions.Regex(@"^\d{1,3}(\.\d{1,3}){3}:\d+$", RXO);
    static readonly System.Text.RegularExpressions.Regex RxUrl      = new System.Text.RegularExpressions.Regex(@"^https?://", RXO);
    static readonly System.Text.RegularExpressions.Regex RxProc     = new System.Text.RegularExpressions.Regex(@"\.(exe|dll)$", RXO);
    static readonly System.Text.RegularExpressions.Regex RxNum      = new System.Text.RegularExpressions.Regex(@"^\d{1,4}$", RXO);
    static readonly System.Text.RegularExpressions.Regex RxShort    = new System.Text.RegularExpressions.Regex(@"^[\w.\-]{1,24}$", RXO);
    static readonly string[] _crlf2 = new string[] { "\r\n\r\n" };

    static readonly Dictionary<uint,Txn> _txns = new Dictionary<uint,Txn>();
    static int _txnNum = 0;
    static readonly Queue<Txn> _done = new Queue<Txn>();
    static long _settle = 400, _grace = 2500;
    static string _user = "";
    static bool _debug = false;
    static readonly Queue<string> _dbg = new Queue<string>();
    static long _dT0,_dT1,_dT2,_dT3,_dTo,_dNoFields,_dNullBody,_dHttpsish;

    public static void Configure(long settleMs, long graceMs, string user, bool debug) {
        _settle = settleMs; _grace = graceMs; _user = user ?? ""; _debug = debug;
    }
    public static long NowMs() { return (long)(DateTime.UtcNow - new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds; }
    public static int Created() { return _txnNum; }

    static Txn GetTxn(uint id) {
        Txn t;
        if (!_txns.TryGetValue(id, out t)) { t = new Txn(); t.Num = ++_txnNum; t.Id = id; t.First = NowMs(); _txns[id] = t; }
        t.Updated = NowMs();
        return t;
    }
    static void IngestFields(string[] fields, uint id, int tag) {
        Txn t = GetTxn(id);
        if (tag >= 2) t.SawResp = true;
        bool toRes = (tag == 3) || (tag != 1 && t.SawResp);
        foreach (string f in fields) {
            string trim = f.Trim();
            if (RxReq.IsMatch(f)) {
                string[] p = f.Split(_crlf2, 2, StringSplitOptions.None);
                t.ReqHeaders = p[0].TrimEnd();
                int sp = f.IndexOf(' '); t.Method = sp > 0 ? f.Substring(0, sp) : f;
                if (p.Length > 1 && p[1].Length > 0) t.ReqBody += p[1];
                continue;
            }
            var mm = RxH2Method.Match(f);
            if (mm.Success) {
                t.Method = mm.Groups[1].Value;
                string auth = "", path = "";
                var am = RxH2Auth.Match(f); if (am.Success) auth = am.Groups[1].Value.Trim();
                var pm = RxH2Path.Match(f); if (pm.Success) path = pm.Groups[1].Value.Trim();
                if (t.Url.Length == 0 && (auth.Length > 0 || path.Length > 0)) t.Url = "https://" + auth + path;
                string[] p = f.Split(_crlf2, 2, StringSplitOptions.None);
                if (t.ReqHeaders.Length == 0) t.ReqHeaders = p[0].TrimEnd();
                if (p.Length > 1 && p[1].Length > 0) t.ReqBody += p[1];
                continue;
            }
            if (RxH2Stream.IsMatch(f) && RxHdrLine.IsMatch(f)) {
                string[] p = f.Split(_crlf2, 2, StringSplitOptions.None);
                if (toRes) {
                    if (t.ResHeaders.Length == 0) t.ResHeaders = p[0].TrimEnd();
                    t.SawResp = true;
                    if (t.Status.Length == 0) { var s1 = RxH2Stat1.Match(p[0]); if (s1.Success) t.Status = s1.Groups[1].Value; }
                    if (t.Status.Length == 0) { var s2 = RxH2Stat2.Match(p[0]); if (s2.Success) t.Status = s2.Groups[1].Value; }
                    if (p.Length > 1 && p[1].Length > 0) t.ResBody += p[1];
                } else {
                    if (t.ReqHeaders.Length == 0) t.ReqHeaders = p[0].TrimEnd();
                    if (p.Length > 1 && p[1].Length > 0) t.ReqBody += p[1];
                }
                continue;
            }
            if (RxStatus.IsMatch(f)) {
                string[] p = f.Split(_crlf2, 2, StringSplitOptions.None);
                t.ResHeaders = p[0].TrimEnd(); t.SawResp = true;
                var sc = RxStatusCd.Match(p[0]); if (sc.Success) t.Status = sc.Groups[1].Value.Trim();
                if (p.Length > 1 && p[1].Length > 0) t.ResBody += p[1];
                continue;
            }
            if (RxHostPort.IsMatch(trim)) { if (t.Host.Length == 0) t.Host = trim; continue; }
            if (RxUrl.IsMatch(trim))      { if (t.Url.Length  == 0) t.Url  = trim; continue; }
            if (RxProc.IsMatch(trim) && trim.IndexOf(' ') < 0 && trim.IndexOf('\t') < 0) { if (t.Proc.Length == 0) t.Proc = trim; continue; }
            if (_user.Length > 0 && string.Equals(trim, _user, StringComparison.OrdinalIgnoreCase)) { if (t.User.Length == 0) t.User = trim; continue; }
            if (RxNum.IsMatch(trim)) continue;
            if (RxShort.IsMatch(trim) && t.User.Length == 0) { t.User = trim; continue; }
            if (toRes) t.ResBody += f; else t.ReqBody += f;
        }
    }
    static void IngestBody(uint id, int tag, string text) {
        if (text == null || text.Trim().Length == 0) return;
        Txn t = GetTxn(id);
        if (tag == 1) t.ReqBody += text; else { t.ResBody += text; t.SawResp = true; }
    }
    static void IngestRecord(byte[] raw) {
        if (raw.Length < 24) return;
        int D = BitConverter.ToInt32(raw, 12);
        int tag = BitConverter.ToInt32(raw, 16);
        uint id = (uint)BitConverter.ToInt32(raw, 20);
        if (_debug) DbgRecord(raw, tag, id, D);
        if (tag == 1 || tag == 3) {
            byte[] bb = ExtractBody(raw, D);
            if (bb != null) IngestBody(id, tag, DecodeBody(bb));
            else if (_debug) _dNullBody++;
        } else {
            string[] segs = Fields(raw, raw.Length);
            if (segs.Length > 0) IngestFields(segs, id, tag);
            else if (_debug) _dNoFields++;
        }
    }
    static void FlushSettled(bool final) {
        long now = NowMs();
        List<uint> rm = new List<uint>();
        foreach (var kv in _txns) {
            Txn c = kv.Value;
            bool hasReq  = c.Method.Length > 0 || c.Url.Length > 0 || c.ReqHeaders.Length > 0;
            bool hasResp = c.ResHeaders.Length > 0 || c.ResBody.Length > 0 || c.Status.Length > 0;
            bool quiet   = (now - c.Updated) >= _settle;
            if (hasReq && hasResp && (quiet || final)) { _done.Enqueue(c); rm.Add(kv.Key); }
            else if (final || (now - c.First) >= _grace) {
                if (_debug) { string why = !hasReq ? "no-req" : (!hasResp ? "no-resp" : "grace"); _dbg.Enqueue("[dbg] drop #" + c.Num + " " + (final ? "final-" : "") + why + " | " + (c.Url.Length > 0 ? c.Url : (c.Host.Length > 0 ? c.Host : c.Method))); }
                rm.Add(kv.Key);
            }
        }
        for (int i = 0; i < rm.Count; i++) _txns.Remove(rm[i]);
    }
    // Drain the raw queue, assemble, settle, and return finished transactions.
    public static Txn[] Pump(bool final) {
        byte[] r;
        while (_pumpQ.TryDequeue(out r)) IngestRecord(r);
        FlushSettled(final);
        List<Txn> o = new List<Txn>();
        while (_done.Count > 0) o.Add(_done.Dequeue());
        return o.ToArray();
    }
    static void DbgRecord(byte[] raw, int tag, uint id, int D) {
        switch (tag) { case 0: _dT0++; break; case 1: _dT1++; break; case 2: _dT2++; break; case 3: _dT3++; break; default: _dTo++; break; }
        int n = Math.Min(140, raw.Length - 16); var sb = new StringBuilder();
        for (int i = 16; i < 16 + n; i++) { byte c = raw[i]; sb.Append((c >= 32 && c < 127) ? (char)c : '.'); }
        string s = sb.ToString();
        if (s.Contains("https://") || s.Contains(":443") || s.Contains("CONNECT") || s.Contains(":method") || s.Contains(":status") || s.Contains("x-exhdr")) _dHttpsish++;
        _dbg.Enqueue(string.Format("[dbg] {0} tag={1} id={2} D={3} len={4} | {5}", DateTime.UtcNow.ToString("HH:mm:ss.fff"), tag, id, D, raw.Length, s));
    }
    public static string[] DrainDbg() { List<string> o = new List<string>(); while (_dbg.Count > 0) o.Add(_dbg.Dequeue()); return o.ToArray(); }
    public static string DbgSummary(bool open) {
        long tot = _dT0 + _dT1 + _dT2 + _dT3 + _dTo;
        if (open) return string.Format("records={0} httpsish={1} no-fields={2} body-null={3} open-txns={4}", tot, _dHttpsish, _dNoFields, _dNullBody, _txns.Count);
        return string.Format("tag0={0} tag1={1} tag2={2} tag3={3} other={4} | httpsish={5} no-fields={6} body-null={7}", _dT0, _dT1, _dT2, _dT3, _dTo, _dHttpsish, _dNoFields, _dNullBody);
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

    static IntPtr _evtAvai = IntPtr.Zero;
    static IntPtr _memHdr  = IntPtr.Zero;
    static bool   _freeSlots;
    static long   _freed;
    public static long Freed() { return Interlocked.Read(ref _freed); }

    // Keep the consumer read-cursor (header+0x08) caught up to the producer write-cursor
    // (header+0x04). The stock UI advances this as it consumes; since our pump scans and
    // frees every ready slot each pass, the quiescent state is read==write. Harmless if
    // the header is read-only (we just skip it). The producer picks its write slot from
    // the write-cursor and only cares about the per-slot STATE, so the real fix is
    // freeing states below; this keeps the cursor consistent with what the UI leaves.
    static void AdvanceReadCursor() {
        if (_memHdr == IntPtr.Zero) return;
        try {
            int wc = Marshal.ReadInt32(_memHdr, 4);
            int rc = Marshal.ReadInt32(_memHdr, 8);
            if (wc != rc) Marshal.WriteInt32(_memHdr, 8, wc);
        } catch { }
    }
    public static void StartPump(IntPtr data, int cap, int stride, long dataBytes, int sleepMs, IntPtr evtAvai, IntPtr memHdr, bool freeSlots) {
        _slotSig = new uint[cap];
        _pumpRun = true;
        _evtAvai = evtAvai;
        _memHdr  = memHdr;
        _freeSlots = freeSlots;
        PumpScan(data, cap, stride, dataBytes, true);   // prime: skip the pre-attach backlog
        PumpScan(data, cap, stride, dataBytes, false);  // free any pre-existing backlog at once
        AdvanceReadCursor();
        if (_evtAvai != IntPtr.Zero) { try { SetEvent(_evtAvai); } catch { } }
        _pumpThread = new Thread(delegate() {
            // Run the scan thread below normal priority so it can never starve the
            // OS/ssh/services even under a heavy traffic storm.
            try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
            timeBeginPeriod(1);
            try {
                while (_pumpRun) {
                    PumpScan(data, cap, stride, dataBytes, false);
                    // Freeing ready slots (in PumpScan) is what stops the service's
                    // producer from blocking up to 500ms per record on a full ring - the
                    // real cause of slow browsing under capture. Advancing the read-cursor
                    // and signalling _evt_avai mirror what the stock UI does and wake a
                    // producer that is already parked on the event.
                    AdvanceReadCursor();
                    if (_evtAvai != IntPtr.Zero) { try { SetEvent(_evtAvai); } catch { } }
                    if (sleepMs > 0) Thread.Sleep(sleepMs);
                }
            }
            finally { timeEndPeriod(1); }
        });
        _pumpThread.IsBackground = true;
        _pumpThread.Start();
    }

    static void PumpScan(IntPtr data, int cap, int stride, long dataBytes, bool primeOnly) {
        // The per-slot state array sits right after the record region: state[slot] is at
        // (capacity*stride) + slot*4 in the data mapping. State 2 = "ready" (producer
        // finished writing). The consumer captures the record and writes 0 to free it.
        long total = (long)cap * stride;
        for (int slot = 0; slot < cap; slot++) {
            long off = (long)slot * stride;
            if (off + 24 > dataBytes) break;
            uint D = RU(data, off + 12);
            bool headerOk = D >= 16 && D <= (uint)stride && RU(data, off) != 0 && RU(data, off + 4) != 0;
            if (headerOk) {
                uint tag = RU(data, off + 16), id = RU(data, off + 20);
                uint sig = D ^ (tag * 2654435761u) ^ (id * 40503u)
                           ^ (RU(data, off + 0x40) * 131u) ^ (RU(data, off + 0x80) * 17u);
                if (sig == 0) sig = 1;
                if (_slotSig[slot] != sig) {                               // changed since last scan
                    _slotSig[slot] = sig;
                    if (!primeOnly) {
                        int n = (int)Math.Min((long)D + 48, Math.Min((long)stride, dataBytes - off));
                        if (n >= 16) {
                            byte[] rec = new byte[n];
                            Marshal.Copy(new IntPtr(data.ToInt64() + off), rec, 0, n);
                            _pumpQ.Enqueue(rec);
                        }
                    }
                }
            }
            // Free a ready slot (state 2 -> 0) after its record has been captured, exactly
            // as the UI consumer does. Only the consumer ever moves a slot out of state 2
            // and the producer only ever touches state-0 slots, so a plain read/write is
            // race-free against the producer. This is the step that keeps the ring from
            // filling and the capture engine from throttling the user's traffic.
            if (!primeOnly && _freeSlots) {
                long sOff = total + (long)slot * 4;
                if (sOff + 4 <= dataBytes && Marshal.ReadInt32(data, (int)sOff) == 2) {
                    Marshal.WriteInt32(data, (int)sOff, 0);
                    Interlocked.Increment(ref _freed);
                }
            }
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

    // ---- background collector uploader -------------------------------------
    // Uploads run on their OWN thread so a slow or flaky collector can never stall
    // the capture/display loop. This matters most for a Cloudflare quick tunnel:
    // it is HTTPS-only (port 443), and the capture engine itself intercepts and
    // MITMs every outbound 443 connection - including our own upload - then has to
    // re-originate it upstream through the slow tunnel. Under a burst that double
    // hop makes a single POST's connect/handshake (GetRequestStream) exceed any
    // sane timeout. Doing uploads off-thread with a generous timeout and one retry
    // lets a batch that loses the race simply go again a moment later instead of
    // failing the whole run. The ServicePointManager tweaks (Expect100 off, accept
    // the MITM leaf cert, TLS1.2/1.3, no proxy) are process-global, so they already
    // apply to the requests created here.
    static string _upUrl = "", _upMark = "";
    static int _upTimeoutMs = 30000;
    static volatile bool _upRun;
    static Thread _upThread;
    static ConcurrentQueue<byte[]> _upQ = new ConcurrentQueue<byte[]>();
    static long _upOk, _upDropped;
    static int _upPending;
    static volatile bool _upFailing;
    static string _upLastErr = "";

    public static void StartUploader(string url, string mark, int timeoutSec) {
        _upUrl = url; _upMark = mark == null ? "" : mark; _upTimeoutMs = timeoutSec * 1000;
        _upRun = true;
        _upThread = new Thread(delegate() {
            try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
            while (_upRun || !_upQ.IsEmpty) {
                byte[] body;
                if (!_upQ.TryDequeue(out body)) { Thread.Sleep(20); continue; }
                Interlocked.Decrement(ref _upPending);
                bool ok = false; string err = "";
                for (int attempt = 0; attempt < 2 && !ok; attempt++) {
                    try { PostOnce(_upUrl, body); ok = true; }
                    catch (Exception ex) { err = Flatten(ex); if (attempt == 0) Thread.Sleep(500); }
                }
                if (ok) { Interlocked.Increment(ref _upOk); _upFailing = false; }
                else { _upLastErr = err; _upFailing = true; }
            }
        });
        _upThread.IsBackground = true;
        _upThread.Start();
    }

    public static void EnqueueUpload(byte[] body) {
        if (body == null || body.Length == 0) return;
        // Bounded queue: if the collector is badly backed up, drop the OLDEST batch
        // so memory stays flat under a flood rather than growing without limit.
        if (_upPending >= 256) {
            byte[] junk;
            if (_upQ.TryDequeue(out junk)) { Interlocked.Decrement(ref _upPending); Interlocked.Increment(ref _upDropped); }
        }
        _upQ.Enqueue(body);
        Interlocked.Increment(ref _upPending);
    }

    static void PostOnce(string url, byte[] bytes) {
        System.Net.HttpWebRequest req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
        req.Method = "POST";
        req.ContentType = "application/json; charset=utf-8";
        req.KeepAlive = false;
        req.ProtocolVersion = System.Net.HttpVersion.Version11;
        try { req.ServicePoint.Expect100Continue = false; } catch { }
        req.Proxy = null;
        req.Timeout = _upTimeoutMs;
        req.ReadWriteTimeout = _upTimeoutMs;
        if (_upMark.Length > 0) { try { req.Headers.Add(_upMark, "1"); } catch { } }
        req.ContentLength = bytes.Length;
        using (var rs = req.GetRequestStream()) rs.Write(bytes, 0, bytes.Length);
        using (System.Net.HttpWebResponse resp = (System.Net.HttpWebResponse)req.GetResponse()) {
            int sc = (int)resp.StatusCode;
            if (sc < 200 || sc >= 300) throw new Exception("HTTP " + sc);
        }
    }

    static string Flatten(Exception ex) {
        string m = ex.Message; Exception inner = ex.InnerException;
        while (inner != null) { m += " | " + inner.Message; inner = inner.InnerException; }
        return m;
    }

    public static long UpOk()      { return Interlocked.Read(ref _upOk); }
    public static long UpDropped() { return Interlocked.Read(ref _upDropped); }
    public static int  UpPending() { return _upPending; }
    public static bool UpFailing() { return _upFailing; }
    public static string UpLastErr() { return _upLastErr; }
    public static void StopUploader() {
        _upRun = false;
        try { if (_upThread != null) _upThread.Join(4000); } catch { }
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
  Invoke-ScExe @('stop', $SvcName) | Out-Null
  Start-Sleep 2
  $r = Invoke-ScExe @('delete', $SvcName)
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
  if ($Domains)        { $argline += " -Domains `"$($script:Domains -join ',')`"" }
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

# -Persistence WITHOUT -Background: just install the boot task and exit (verbose).
# It must NOT fall through into the foreground capture loop - doing so would arm
# the service and capture in whatever session launched it, and if that session
# ends the armed capture is orphaned (breaks external traffic, spikes CPU).
if ($Persistence -and -not $Background) {
  Step 'Installing reboot persistence'
  New-PersistenceTask
  Write-Host '    capture will start automatically ~90s after each boot.' -ForegroundColor DarkGray
  Write-Host '    to also start it now without rebooting, add -Background.' -ForegroundColor DarkGray
  return
}

# -Background: start capturing now in a detached, hidden, SILENT process and
# return immediately. Every stream of the child is discarded, so nothing is ever
# printed anywhere. (With -Persistence it also installs the boot task, quietly.)
if ($Background) {
  if ($Persistence) { New-PersistenceTask *>$null }
  if ($DebugRing) { Warn '-DebugRing has no effect with -Background (all output is discarded); run it foreground' }
  # Invoke via -Command (not -File) so we can append "*> $null" and swallow ALL
  # output. Single-quote the paths/URL so spaces are safe inside the command.
  $inner = "& '$PSCommandPath' -Seconds 0"
  if ($NoInstall)      { $inner += ' -NoInstall' }
  if ($Server)         { $inner += " -Server '$Server'" }
  if ($TrimBody -gt 0) { $inner += " -TrimBody $TrimBody" }
  if ($Domains)        { $inner += " -Domains '$($script:Domains -join ',')'" }
  $inner += ' *> $null'
  $cl = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$inner`""
  # Spawn via WMI Win32_Process.Create: the child is parented to WmiPrvSE, so it
  # keeps running after this process (and its console) exits. Fall back to a
  # hidden Start-Process if WMI is unavailable.
  $launched = $false
  try {
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cl } -ErrorAction Stop
    if ($r.ReturnValue -eq 0) { $launched = $true }
  } catch {}
  if (-not $launched) {
    try {
      Start-Process -FilePath $pwsh -WindowStyle Hidden `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-Command',$inner) *>$null
    } catch {}
  }
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
    $settingsXml | Set-Content -LiteralPath $storePath -Encoding Ascii
    Ok "wrote $storePath"
  } else { Ok "store already present: $storePath" }

  Step 'Running HTTPDebuggerSvc.exe /install (creates service + TLS root CA)'
  $p = Start-Process -FilePath $svcExe -ArgumentList '/install' -NoNewWindow -PassThru
  if (-not $p.WaitForExit(180000)) { try { $p.Kill() } catch {} ; Warn '/install still running after 180s' }
  else { Ok "/install finished" }

  if ((SvcState $SvcName) -eq 'ABSENT') {
    Invoke-ScExe @('create', $SvcName, 'binPath=', "`"$svcExe`"", 'start=', 'auto', 'DisplayName=', 'HTTP Debugger Pro') | Out-Null
  }

  Step 'Starting the capture service'
  if ((SvcState $SvcName) -ne 'RUNNING') { Invoke-ScExe @('start', $SvcName) | Out-Null }
  for ($i = 0; $i -lt 60 -and (SvcState $SvcName) -ne 'RUNNING'; $i++) { Start-Sleep 1 }
  if ((SvcState $SvcName) -eq 'RUNNING') { Ok "$SvcName running" }
  else { Warn "$SvcName is $(SvcState $SvcName) - continuing anyway" }

  $ca = @(Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue |
          Where-Object { $_.Subject -like '*HTTP DEBUGGER*' })
  if ($ca.Count) { Ok "root CA trusted: $($ca[0].Subject)" }
  else { Warn 'HTTP DEBUGGER root CA not found yet (arming installs it below)' }
}

# ---------------------------------------------------------------------------
# Arm capture headlessly: hold the UI mutex, push the rules profile over
# IpcSettings, then push EngineCommand 3,9,11,2.
# ---------------------------------------------------------------------------
Step 'Arming capture (mutex + IpcSettings profile + EngineCommand 3,9,11,2)'
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
  $arm = [HttpIpc]::ArmCapture($env:USERNAME, $settingsXml)
  Ok "arm commands -> $arm"
  try { if ($bootId) { if (-not (Test-Path $storeDir)) { New-Item -ItemType Directory -Path $storeDir -Force | Out-Null }; Set-Content -Path $armSentinel -Value $bootId -Encoding Ascii } } catch {}
} elseif ($alreadyArmed) {
  Warn 'service already armed this boot - NOT re-arming (would break external traffic); attaching read-only'
} else {
  Warn 'NOT re-arming (would break external traffic) - attaching read-only to the already-armed service'
}

# HTTPS decryption depends on the HTTP DEBUGGER root CA being in
# LocalMachine\Root; selector 4 installs it, but the service processes the
# command asynchronously. Verify it here so the log says plainly whether
# https:// can be decrypted this boot.
$caTries = 2
if ($owned -and -not $alreadyArmed) { $caTries = 8 }
$caNow = @()
for ($i = 0; $i -lt $caTries; $i++) {
  $caNow = @(Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue |
             Where-Object { $_.Subject -like '*HTTP DEBUGGER*' } | Select-Object -First 1)
  if ($caNow.Count) { break }
  Start-Sleep -Milliseconds 500
}
if ($caNow.Count) { Ok "root CA trusted: $($caNow[0].Subject) - HTTPS decryption ready" }
else { Warn 'root CA NOT in LocalMachine\Root after arming - https:// traffic will not be decrypted; reboot and run again, and report this line if it repeats' }

$ring = [HttpIpc]::Attach('Global\HttpDebuggerIpcHttpTransaction', 8000)
if (-not $ring) { Fail 'could not attach to the HttpTransaction ring (is the service running?)'; if ($owned) { $mutex.ReleaseMutex() }; return }
Ok "attached to $($ring.DataName) (capacity $($ring.H.Capacity))"
if ($ring.DataWritable) {
  Ok 'ring is writable - freeing consumed slots so capture never throttles your browsing'
} else {
  Warn 'ring mapped read-only - cannot free slots; browsing may slow under heavy capture (run elevated)'
}

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

# -DebugRing: print every raw ring record plus every drop decision, so a single
# run on an affected machine proves whether 443 records arrive at all and where
# they die. Counters are cheap; the per-record [dbg] lines are the instrument.
$script:DbgTagCounts = @{}
$script:DbgNoFields  = 0
$script:DbgNullBody  = 0
$script:DbgHttpsish  = 0
$script:DbgLastBeat  = Now-Ms

function Show-RingRecord($raw, $tag, $id, $d) {
  $n  = [Math]::Min(140, $raw.Length - 16)
  $sb = New-Object System.Text.StringBuilder
  for ($i = 16; $i -lt 16 + $n; $i++) {
    $c = [int]$raw[$i]
    if ($c -ge 32 -and $c -lt 127) { [void]$sb.Append([char]$c) } else { [void]$sb.Append('.') }
  }
  $s = $sb.ToString() -replace '\.{3,}', '..'
  Write-Host ("[dbg] {0} tag={1} id={2} D={3} len={4} | {5}" -f `
    ([DateTime]::UtcNow.ToString('HH:mm:ss.fff')), $tag, $id, $d, $raw.Length, $s) -ForegroundColor DarkGray
  if (-not $script:DbgTagCounts.ContainsKey($tag)) { $script:DbgTagCounts[$tag] = 0 }
  $script:DbgTagCounts[$tag]++
  if ($s -match 'https://|:443|CONNECT|:method|:status') { $script:DbgHttpsish++ }
}

# A transaction's records arrive as a burst, but a request and its response can be
# seconds apart on long-lived connections. So: hold each transaction until it has
# gone quiet (SETTLE ms since its last record), then emit it ONLY if it is a
# complete request+response pair; drop one-sided transactions after GRACE ms.
$script:Settle = 400
$script:Grace  = 2500

# When -Domains is set, keep only transactions whose host matches one of them.
# A domain matches the exact host or any subdomain (google.com -> www.google.com).
# The host is taken from the URL, the "Host:" request header, or the Host field.
function Test-DomainMatch($c) {
  if (-not $script:Domains -or $script:Domains.Count -eq 0) { return $true }
  $cands = New-Object System.Collections.Generic.List[string]
  if ($c.Url -match '^(?i)https?://([^/:]+)')          { $cands.Add($Matches[1]) }
  if ($c.ReqHeaders -match '(?im)^Host:\s*([^\r\n:]+)') { $cands.Add($Matches[1]) }
  if ($c.Host -and $c.Host -notmatch '^\d{1,3}(\.\d{1,3}){3}') { $cands.Add(($c.Host -split ':')[0]) }
  foreach ($h in $cands) {
    $h = $h.Trim().ToLowerInvariant()
    foreach ($d in $script:Domains) {
      if ($h -eq $d -or $h.EndsWith('.' + $d)) { return $true }
    }
  }
  return $false
}

function Flush-Settled([bool]$final) {
  $now = Now-Ms
  $send = @()
  foreach ($key in @($script:txns.Keys)) {
    $c = $script:txns[$key]
    if ($Server -and (Is-ServerTxn $c)) {
      if ($DebugRing) { Write-Host ("[dbg] drop #{0} self-upload | {1}" -f $c.Num, $c.Url) -ForegroundColor DarkYellow }
      $script:txns.Remove($key); continue
    }
    $hasReq  = [bool]($c.Method -or $c.Url -or $c.ReqHeaders)
    $hasResp = [bool]($c.ResHeaders -or $c.ResBody -or $c.Status)
    $quiet   = ($now - $c.Updated) -ge $script:Settle
    if ($hasReq -and $hasResp -and ($quiet -or $final)) {
      if (Test-DomainMatch $c) {                # -Domains filter (no-op when empty)
        Print-Txn $c
        if ($Server) { $send += $c }
      } elseif ($DebugRing) {
        Write-Host ("[dbg] drop #{0} domain | {1}" -f $c.Num, $c.Url) -ForegroundColor DarkYellow
      }
      $script:txns.Remove($key)
    } elseif ($final -or (($now - $c.First) -ge $script:Grace)) {
      if ($DebugRing) {
        $why = if (-not $hasReq) { 'no-req' } elseif (-not $hasResp) { 'no-resp' } else { 'grace' }
        if ($final) { $why = 'final-' + $why }
        $pv = $c.Url; if (-not $pv) { $pv = $c.Host }; if (-not $pv) { $pv = $c.Method }
        if ($pv -and $pv.Length -gt 90) { $pv = $pv.Substring(0, 90) }
        Write-Host ("[dbg] {0} drop #{1} {2} | {3}" -f ([DateTime]::UtcNow.ToString('HH:mm:ss.fff')), $c.Num, $why, $pv) -ForegroundColor DarkYellow
      }
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
    # HTTP/2 (most HTTPS): the engine drops the classic request line and carries
    # the pseudo-headers as x-exhdr-method / x-exhdr-path / x-exhdr-authority, with
    # x-exhdr-streamid present on both halves. Without this these records have no
    # recognizable start line and get dumped into the body and then dropped, which
    # is why http shows but https does not. Rebuild a request line from them.
    if ($f -match '(?im)^x-exhdr-method:[ \t]*(\S+)') {
      $t.Method = $Matches[1]
      $auth = ''; $path = ''
      if ($f -match '(?im)^x-exhdr-authority:[ \t]*([^\r\n]+)') { $auth = $Matches[1].Trim() }
      if ($f -match '(?im)^x-exhdr-path:[ \t]*([^\r\n]+)')      { $path = $Matches[1].Trim() }
      if (-not $t.Url -and ($auth -or $path)) { $t.Url = "https://$auth$path" }
      $parts = $f -split "`r`n`r`n", 2
      if (-not $t.ReqHeaders) { $t.ReqHeaders = $parts[0].TrimEnd() }
      if ($parts.Count -gt 1 -and $parts[1]) { $t.ReqBody += $parts[1] }
      continue
    }
    if ($f -match '(?im)^x-exhdr-streamid:' -and $f -match '(?im)^[A-Za-z][\w\-]*:[ \t]') {
      $parts = $f -split "`r`n`r`n", 2
      if ($toRes) {
        if (-not $t.ResHeaders) { $t.ResHeaders = $parts[0].TrimEnd() }
        $t.SawResp = $true
        if (-not $t.Status -and $parts[0] -match '(?im)[:\s]status:?[ \t]*(\d{3})') { $t.Status = $Matches[1] }
        if (-not $t.Status -and $parts[0] -match 'HTTP/\d\S*\s+(\d{3})')           { $t.Status = $Matches[1] }
        if ($parts.Count -gt 1 -and $parts[1]) { $t.ResBody += $parts[1] }
      } else {
        if (-not $t.ReqHeaders) { $t.ReqHeaders = $parts[0].TrimEnd() }
        if ($parts.Count -gt 1 -and $parts[1]) { $t.ReqBody += $parts[1] }
      }
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

# Captured bodies can be binary (NTLM blobs, images, fonts). Their bytes get
# translated to characters, so a string can contain control characters and lone
# surrogates. PowerShell 5.1's ConvertTo-Json leaves some control characters
# unescaped, which makes the collector reject the whole batch (400) and lose
# every text record that rode along with the binary one. Strip C0 controls
# except tab / newline / carriage return.
function Clean-Text([string]$s) {
  if (-not $s) { return $s }
  return [regex]::Replace($s, '[\x00-\x08\x0B\x0C\x0E-\x1F\uD800-\uDFFF]', '')
}

# One readable error string: message, server response body (if any), inner chain.
function Expl-Err($e) {
  $msg = $e.Message
  try {
    $resp = $e.Response
    if ($resp) {
      $sr = New-Object IO.StreamReader($resp.GetResponseStream())
      $detail = $sr.ReadToEnd().Trim()
      if ($detail.Length -gt 200) { $detail = $detail.Substring(0, 200) }
      if ($detail) { $msg += ' | ' + $detail }
    }
  } catch {}
  $inner = $e.InnerException
  while ($inner) { $msg += ' | ' + $inner.Message; $inner = $inner.InnerException }
  return $msg
}

# Send all transactions from one flush in a single POST (far less self-traffic
# than one request each).
# POST bytes to the collector with a raw HttpWebRequest so we control the three
# things that make PowerShell uploads flaky against a simple server:
#  - no Expect: 100-continue wait (a basic server never answers it),
#  - no keep-alive reuse (the server closes each connection, which otherwise trips
#    "a connection that was expected to be kept alive was closed by the server"),
#  - no proxy autodetect, and accept the collector cert (it may be the MITM leaf).
function Send-Post([string]$url, [byte[]]$bytes, [int]$timeoutSec) {
  $req = [System.Net.HttpWebRequest]::Create($url)
  $req.Method = 'POST'
  $req.ContentType = 'application/json; charset=utf-8'
  $req.KeepAlive = $false
  $req.ProtocolVersion = [Version]'1.1'
  try { $req.ServicePoint.Expect100Continue = $false } catch {}
  $req.Proxy = $null
  $req.Timeout = $timeoutSec * 1000
  $req.ReadWriteTimeout = $timeoutSec * 1000
  try { $req.Headers.Add($script:UploadMark, '1') } catch {}
  $req.ContentLength = $bytes.Length
  $rs = $req.GetRequestStream()
  try { $rs.Write($bytes, 0, $bytes.Length) } finally { $rs.Close() }
  $resp = $req.GetResponse()
  $resp.Close()
}

function Send-Batch($list) {
  if (-not $list -or $list.Count -eq 0) { return }
  $items = @()
  foreach ($c in $list) {
    $items += @{
      ts = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
      process = Clean-Text $c.Proc; user = Clean-Text $c.User; host = Clean-Text $c.Host; url = Clean-Text $c.Url
      method = Clean-Text $c.Method; status = Clean-Text $c.Status
      requestHeaders = Clean-Text $c.ReqHeaders; requestBody = Clean-Text $c.ReqBody
      responseHeaders = Clean-Text $c.ResHeaders; responseBody = Clean-Text $c.ResBody
    }
  }
  $body = @{
    $script:UploadSentinel = 1
    agentId = $script:AgentId; agentName = $script:AgentName; machine = $env:COMPUTERNAME
    items = $items
  } | ConvertTo-Json -Depth 5 -Compress
  # Pre-encode to UTF-8 (PowerShell 5.1 does not reliably encode string bodies as
  # UTF-8, which would corrupt every non-ASCII byte of a binary capture), then hand
  # the batch to the background uploader thread and return at once. The capture loop
  # never blocks on the network, so a slow collector cannot stall display or let the
  # ring back up. Track whether an https record is in flight so the main loop can
  # print the one-time end-to-end confirmation once the collector acknowledges.
  $bytes = [Text.Encoding]::UTF8.GetBytes($body)
  [HttpIpc]::EnqueueUpload($bytes)
  if (-not $script:SentHttps -and -not $script:QueuedHttps) {
    if ($list | Where-Object { $_.Url -like 'https://*' } | Select-Object -First 1) { $script:QueuedHttps = $true }
  }
}

# Surface upload health from the background thread on the main thread (safe for
# colored Write-Host). Called once per display cycle.
function Report-Upload {
  if (-not $Server) { return }
  $ok = [HttpIpc]::UpOk()
  if ($ok -gt 0 -and -not $script:UploadWorkingShown) {
    $script:UploadWorkingShown = $true
    Ok "server upload working (collector acknowledged $ok batch(es))"
  }
  if ($ok -gt 0 -and $script:QueuedHttps -and -not $script:SentHttps) {
    $script:SentHttps = $true
    Ok 'https capture uploaded to collector'
  }
  $failing = [HttpIpc]::UpFailing()
  if ($failing -and -not $script:UploadErr) {
    $script:UploadErr = $true
    Warn "server upload failing: $([HttpIpc]::UpLastErr())"
  } elseif (-not $failing -and $script:UploadErr -and $ok -gt 0) {
    $script:UploadErr = $false
    Ok "server upload recovered (acknowledged $ok batch(es))"
  }
  $dropped = [HttpIpc]::UpDropped()
  if ($dropped -gt 0 -and $dropped -ne $script:UploadDropShown) {
    $script:UploadDropShown = $dropped
    Warn "collector backed up: dropped $dropped oldest batch(es) to keep memory flat"
  }
}

function Register-WithServer {
  $body = @{ "$script:UploadSentinel" = 1; agentId = $script:AgentId; agentName = $script:AgentName; machine = $env:COMPUTERNAME }
  try {
    Send-Post "$script:ServerBase/api/agent" ([Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Compress))) 10
    return $true
  } catch { $script:RegErr = Expl-Err $_.Exception; return $false }
}

# Set up the collector now that Get-AgentId / Register-WithServer are defined.
if ($Server) {
  # PowerShell 5.1 defaults to TLS 1.0, which modern servers (e.g. Cloudflare)
  # reject - that makes every upload fail silently. Force TLS 1.2/1.3.
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol `
      -bor [Net.SecurityProtocolType]::Tls12
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 } catch {}
  } catch {}
  # Kill the classic .NET upload stalls. These, not the server, are what make a
  # POST "time out":
  #  - Expect: 100-continue - .NET sends POST headers and then WAITS for a "100
  #    Continue" before sending the body. Simple servers (our Python collector)
  #    never send it, so the body is never sent and the request hangs. Turn it off
  #    so the body goes out with the headers.
  #  - Proxy autodetect (WPAD) can block for seconds before every request; we talk
  #    straight to the collector, so use no proxy.
  #  - Certificate chain / revocation (OCSP/CRL) lookups - when the collector is
  #    reached over HTTPS through the capture's own MITM leaf, these can hang or
  #    fail; we are uploading to our own collector, so accept the presented cert.
  try { [Net.ServicePointManager]::Expect100Continue = $false } catch {}
  try { [Net.ServicePointManager]::CheckCertificateRevocationList = $false } catch {}
  try { [Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$h,$e) $true } } catch {}
  try { [Net.ServicePointManager]::DefaultConnectionLimit = 64 } catch {}
  try { [Net.WebRequest]::DefaultWebProxy = (New-Object Net.WebProxy) } catch {}
  $script:ServerBase = $Server.TrimEnd('/')
  try { $script:ServerHost = ([Uri]$Server).Host; $script:ServerPort = ([Uri]$Server).Port }
  catch { $script:ServerHost = ''; $script:ServerPort = 443 }
  $script:AgentId = Get-AgentId
  $script:AgentName = $env:COMPUTERNAME
  $script:UploadOk = 0
  $script:UploadErr = $false
  $script:UploadWorkingShown = $false
  $script:QueuedHttps = $false
  $script:SentHttps = $false
  $script:UploadDropShown = 0
  # Start the background uploader. A generous 30s per-attempt timeout plus one retry
  # is what lets an upload survive the capture engine MITMing its own 443 traffic to
  # a slow Cloudflare tunnel; since this runs off-thread it costs the capture loop
  # nothing even when an attempt is slow.
  [HttpIpc]::StartUploader("$script:ServerBase/api/ingest", $script:UploadMark, 30)
  Write-Host "    contacting collector $script:ServerBase" -ForegroundColor DarkGray
  if (Register-WithServer) {
    Ok "streaming captures to $script:ServerBase  (agent: $script:AgentId)"
  } else {
    Warn "could not reach server $script:ServerBase - $script:RegErr"
    # Follow-up probes make a network failure actionable instead of a mystery.
    if ($script:ServerHost) {
      try {
        $ip = ([Net.Dns]::GetHostAddresses($script:ServerHost) | Select-Object -First 1).IPAddressToString
        Ok "DNS: $script:ServerHost resolves to $ip"
      } catch { Warn "DNS lookup for $script:ServerHost failed" }
      try {
        $tc  = New-Object Net.Sockets.TcpClient
        $iar = $tc.BeginConnect($script:ServerHost, $script:ServerPort, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(6000)) {
          $tc.EndConnect($iar); Ok "TCP $script:ServerPort to $script:ServerHost works"; $tc.Close()
        } else { Warn "TCP $script:ServerPort to $script:ServerHost timed out (6s)" }
      } catch { Warn "TCP $script:ServerPort to $script:ServerHost failed: $($_.Exception.Message)" }
    }
    Warn 'will keep trying as traffic is captured; check the URL/port and that the server is running'
  }
}

# ---------------------------------------------------------------------------
# Follow the publisher cursor and decode every new record.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[reading] HTTP + HTTPS transactions$(if ($Seconds -gt 0) { " for ${Seconds}s" } else { ' (Ctrl+C to stop)' })" -ForegroundColor White
if ($script:Domains.Count) { Write-Host "    domain filter: only $($script:Domains -join ', ')" -ForegroundColor DarkGray }
if ($DebugRing) { Write-Host '    debug: dumping every raw ring record ([dbg] lines)' -ForegroundColor DarkGray }

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
# records. Assembly - parsing, HTTP/1 and HTTP/2 classification, grouping, and
# settling - runs in native code via Pump(); this loop only filters, prints, and
# uploads finished transactions, so heavy traffic no longer bottlenecks on
# per-record script work the way it did before.
[HttpIpc]::Configure($script:Settle, $script:Grace, $env:USERNAME, [bool]$DebugRing)
[HttpIpc]::StartPump($ring.Data, $cap, $stride, $dbytes, 1, $ring.EvtAvai, $ring.Mem, $ring.DataWritable)
$dbgBeat = [DateTime]::UtcNow
try {
  while ([DateTime]::UtcNow -lt $stop) {
    $send = @()
    foreach ($c in [HttpIpc]::Pump($false)) {
      if ($Server -and (Is-ServerTxn $c)) { continue }
      if (Test-DomainMatch $c) { Print-Txn $c; if ($Server) { $send += $c } }
    }
    if ($Server -and $send.Count) { Send-Batch $send }
    Report-Upload
    if ($DebugRing) {
      foreach ($l in [HttpIpc]::DrainDbg()) { Write-Host $l -ForegroundColor DarkGray }
      if (([DateTime]::UtcNow - $dbgBeat).TotalMilliseconds -ge 5000) {
        Write-Host ("[dbg] " + [HttpIpc]::DbgSummary($true)) -ForegroundColor DarkGray
        $dbgBeat = [DateTime]::UtcNow
      }
    }
    Start-Sleep -Milliseconds 40                                   # display cadence; the native layer does the heavy work
  }
} finally {
  [HttpIpc]::StopPump()
  $send = @()
  foreach ($c in [HttpIpc]::Pump($true)) {                         # final flush: emit any paired transactions still open
    if ($Server -and (Is-ServerTxn $c)) { continue }
    if (Test-DomainMatch $c) { Print-Txn $c; if ($Server) { $send += $c } }
  }
  if ($Server -and $send.Count) { Send-Batch $send }
  # Let the uploader drain the final batches, then surface the last status.
  if ($Server) { [HttpIpc]::StopUploader(); Report-Upload }
  if ($DebugRing) {
    foreach ($l in [HttpIpc]::DrainDbg()) { Write-Host $l -ForegroundColor DarkGray }
    Write-Host ("[dbg] ring records: " + [HttpIpc]::DbgSummary($false)) -ForegroundColor DarkGray
  }
  if ($owned) { try { $mutex.ReleaseMutex() } catch {} }
  Write-Host ''
  Write-Host "[done] $([HttpIpc]::Created()) transaction(s) shown" -ForegroundColor White
}
