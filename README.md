# HttpCapture

Headless HTTP/HTTPS traffic capture on Windows, driven entirely from a single
PowerShell script. It installs the HTTPDebugger capture service + its network
filter driver, **arms capture without any GUI**, and prints every transaction —
request headers, request body, response headers and response body — decoding
HTTPS in the clear.

## Contents

| File | Purpose |
|------|---------|
| `HttpCapture.ps1`   | Installer + headless activator + live reader (the agent) |
| `HTTPDebuggerSvc.exe`| The capture service (intercepts via a WFP/NetFilter driver) |
| `CtrlSM.sys`        | The network filter driver the service registers |
| `server.py`         | Optional collector server + web UI (receives captures from agents) |

## Requirements

- Windows 10/11 (x64)
- Administrator rights (the script self-elevates)
- Windows PowerShell 5.1 (built in)

## Usage

Run from an elevated prompt (or let it elevate itself):

```powershell
# Install the service + driver, arm capture, and stream transactions until Ctrl+C
.\HttpCapture.ps1

# Capture for a fixed number of seconds
.\HttpCapture.ps1 -Seconds 60

# Service already installed and running - just arm + read
.\HttpCapture.ps1 -NoInstall

# Generate a few sample HTTP/HTTPS requests so there is something to show
.\HttpCapture.ps1 -SelfTest -Seconds 30

# Trim long bodies to N characters (default 0 = show the whole body)
.\HttpCapture.ps1 -TrimBody 2000

# Remove the service
.\HttpCapture.ps1 -Uninstall
```

### Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Seconds`   | `0` | Read duration; `0` = until Ctrl+C |
| `-TrimBody`  | `0` | Trim each body to N chars; `0` = whole body |
| `-Server`    | `''`| Stream captures as JSON to a collector (e.g. `http://host:8771`) |
| `-NoInstall` | off | Skip install/start, just arm + read |
| `-SelfTest`  | off | Emit sample HTTP/HTTPS requests in the background |
| `-Uninstall` | off | Stop and delete the service, then exit |

## Central collector (optional)

Run `server.py` on any machine to collect captures from many agents and browse
them in a web UI (Python 3, standard library only):

```bash
python3 server.py --port 8771
```

It prints a **one-time login password** and stores everything in **SQLite**
(`captures.db`). Point agents at it:

```powershell
.\HttpCapture.ps1 -Server http://<collector-host>:8771
```

- Each machine is identified by a **stable agent id** (a hash of its MachineGuid +
  SMBIOS UUID), so re-runs never create duplicate agents.
- The home page lists agents; click one to see its captures. Each entry shows the
  **site's favicon** (fetched and cached by the server), method, URL, status,
  process and time, and expands to the full request/response headers and bodies.
- Only complete request+response pairs are shown; the agent's own uploads and
  one-sided/orphan records are filtered out.

Server options: `--host`, `--port`, `--data <sqlite file>`, `--password <pw>`.

## How it works

The service only captures while it believes its UI is present and has issued the
"start capture" commands. `HttpCapture.ps1` reproduces that handshake headlessly:

1. **Install** — copies `CtrlSM.sys` to `drv2\x64\netfilter2.sys` /
   `drv2\win32\netfilter2.sys`, writes the rules profile to
   `%ProgramData%\HTTPDebuggerPro\settings.xml`, runs `HTTPDebuggerSvc.exe /install`
   (which registers the service and generates the TLS root CA), and starts the
   service.

2. **Arm (the headless trick)** —
   - acquires ownership of the mutex `Global\HttpDebuggerUiStarted` so the engine
     worker believes the UI is live, **and**
   - writes the UI's own command sequence into the `EngineCommand` shared-memory
     ring: selectors **4, 9, 11, 2** — install the CA, build the port 80/443
     filter rules, apply/activate them, and the user handshake.

   Neither the mutex nor the commands alone start capture; **together** they do.

3. **Read** — follows the publisher cursor in the `HttpTransaction` shared-memory
   ring (read-only, non-destructive) and decodes each record's length-prefixed
   fields into process / host / URL / request / response blocks.

HTTPS is decrypted because selector 4 installs `HTTP DEBUGGER CA for DEBUG ONLY`
into `LocalMachine\Root` **before** the rules go live, so the service's
man-in-the-middle presents a leaf certificate the OS already trusts.

## Output

Each transaction is printed with clear labels:

```
#1  powershell.exe (azureuser)
     URL : https://httpbin.org/post
     Host: 54.174.189.226:443
  > REQUEST HEADERS
      POST /post HTTP/1.1
      Content-Type: text/plain
      Host: httpbin.org
      ...
  > REQUEST BODY
      REQBODY123
  < RESPONSE HEADERS
      HTTP/1.1 200 OK
      Content-Type: application/json
      ...
  < RESPONSE BODY
      { "data": "REQBODY123", ... }
```

## Notes

- `HTTPDebuggerSvc.exe` and `CtrlSM.sys` are third-party components of
  HTTP Debugger Pro, included here only so the capture path can be installed.
- The TLS root CA it installs is for local debugging only; `-Uninstall` leaves it
  in place — remove it from `certmgr.msc` (Trusted Root Certification Authorities)
  if you no longer want it trusted.
- This is a security/diagnostics tool; only run it on machines you own.
