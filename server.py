#!/usr/bin/env python3
"""
NetSnitch collector server.

Receives captured HTTP/HTTPS transactions (JSON) from one or more netsnitch.ps1
agents and serves a password-protected web UI to analyze them, grouped per agent.

  - Each agent (a machine running netsnitch.ps1 -Server <this>) gets an id.
  - The home page lists all agents; click an agent to see everything it captured.
  - Every entry shows the site's favicon, method, URL, status, process and time,
    and expands to the full request headers / body and response headers / body.
  - Data is stored in SQLite.
  - A one-time login password is generated and printed at startup; it is required
    to view the UI and read APIs. Agents POST their captures without it.

No third-party dependencies - standard library only.

  python3 server.py --port 8771
  # then on the Windows machine:
  .\\netsnitch.ps1 -Server http://<this-host>:8771
"""
import argparse
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote, parse_qs, urljoin

DB = None
DBLOCK = threading.Lock()
SESSIONS = set()            # valid session tokens (in-memory, cleared on restart)
SESS_LOCK = threading.Lock()
PASSWORD = None             # the login password for this run
MAX_PER_AGENT = 20000

FAV_CACHE = {}
FAV_LOCK = threading.Lock()
DEFAULT_ICON = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24">'
    b'<circle cx="12" cy="12" r="9" fill="#2b3550" stroke="#4f9dff" stroke-width="1.5"/>'
    b'<path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" fill="none" '
    b'stroke="#4f9dff" stroke-width="1.2"/></svg>')


def now_ms():
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- DB
def db_init(path):
    global DB
    DB = sqlite3.connect(path, check_same_thread=False)
    DB.execute("PRAGMA journal_mode=WAL")
    DB.execute("""CREATE TABLE IF NOT EXISTS agents(
        id TEXT PRIMARY KEY, name TEXT, machine TEXT,
        first INTEGER, last INTEGER, count INTEGER DEFAULT 0)""")
    DB.execute("""CREATE TABLE IF NOT EXISTS txns(
        pk INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts INTEGER,
        method TEXT, url TEXT, host TEXT, status TEXT, process TEXT, user TEXT,
        req_headers TEXT, req_body TEXT, res_headers TEXT, res_body TEXT)""")
    DB.execute("CREATE INDEX IF NOT EXISTS ix_txn_agent ON txns(agent_id, pk)")
    DB.commit()


def derive_host(d):
    url = d.get("url") or ""
    host = ""
    try:
        if url:
            host = urlparse(url).hostname or ""
    except Exception:
        pass
    if not host:
        for hdrs in (d.get("requestHeaders") or "", d.get("responseHeaders") or ""):
            for line in hdrs.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip().split(":")[0].strip()
                    break
            if host:
                break
    if not host:
        host = (d.get("host") or "").split(":")[0]
    return host


def register(d):
    aid = str(d.get("agentId") or "unknown")
    name = d.get("agentName") or aid
    machine = d.get("machine") or ""
    now = now_ms()
    with DBLOCK:
        row = DB.execute("SELECT id FROM agents WHERE id=?", (aid,)).fetchone()
        if row is None:
            DB.execute("INSERT INTO agents(id,name,machine,first,last,count) VALUES(?,?,?,?,?,0)",
                       (aid, name, machine, now, now))
        else:
            DB.execute("UPDATE agents SET last=?, name=CASE WHEN ?<>'' THEN ? ELSE name END, "
                       "machine=CASE WHEN ?<>'' THEN ? ELSE machine END WHERE id=?",
                       (now, name, name, machine, machine, aid))
        DB.commit()


def ingest(d):
    aid = str(d.get("agentId") or "unknown")
    register(d)
    host = derive_host(d)
    now = now_ms()
    with DBLOCK:
        DB.execute("""INSERT INTO txns(agent_id,ts,method,url,host,status,process,user,
                        req_headers,req_body,res_headers,res_body)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (aid, d.get("ts") or now, d.get("method") or "", d.get("url") or "", host,
                    d.get("status") or "", d.get("process") or "", d.get("user") or "",
                    d.get("requestHeaders") or "", d.get("requestBody") or "",
                    d.get("responseHeaders") or "", d.get("responseBody") or ""))
        DB.execute("UPDATE agents SET count=count+1, last=? WHERE id=?", (now, aid))
        DB.execute("""DELETE FROM txns WHERE agent_id=? AND pk NOT IN
                        (SELECT pk FROM txns WHERE agent_id=? ORDER BY pk DESC LIMIT ?)""",
                   (aid, aid, MAX_PER_AGENT))
        DB.commit()


def get_agents():
    with DBLOCK:
        rows = DB.execute("SELECT id,name,machine,first,last,count FROM agents "
                          "ORDER BY last DESC").fetchall()
    return [{"id": r[0], "name": r[1], "machine": r[2], "first": r[3],
             "last": r[4], "count": r[5]} for r in rows]


def get_agent(aid, since):
    with DBLOCK:
        a = DB.execute("SELECT id,name,machine,first,last,count FROM agents WHERE id=?",
                       (aid,)).fetchone()
        if not a:
            return None
        cols = ("pk,ts,method,url,host,status,process,user,"
                "req_headers,req_body,res_headers,res_body")
        if since > 0:
            rows = DB.execute("SELECT %s FROM txns WHERE agent_id=? AND pk>? ORDER BY pk ASC"
                              % cols, (aid, since)).fetchall()
        else:
            rows = DB.execute("SELECT %s FROM txns WHERE agent_id=? ORDER BY pk DESC LIMIT 2000"
                              % cols, (aid,)).fetchall()
            rows = list(reversed(rows))
    txns = [{"id": r[0], "ts": r[1], "method": r[2], "url": r[3], "host": r[4],
             "status": r[5], "process": r[6], "user": r[7], "reqHeaders": r[8],
             "reqBody": r[9], "resHeaders": r[10], "resBody": r[11]} for r in rows]
    agent = {"id": a[0], "name": a[1], "machine": a[2], "first": a[3], "last": a[4], "count": a[5]}
    return {"agent": agent, "transactions": txns}


_ICON_RE = re.compile(r'<link[^>]+rel=["\']?[^"\'>]*icon[^"\'>]*["\']?[^>]*>', re.I)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def _get(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (NetSnitch)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(262144), (r.headers.get("Content-Type") or "")   # cap 256 KB


def _is_image(data, ct):
    if ct and ct.lower().startswith("image/"):
        return True
    if not data or len(data) < 16:
        return False
    s = data[:8]
    if s[:4] == b"\x00\x00\x01\x00":          return True   # .ico
    if s[:4] == b"\x89PNG":                   return True   # png
    if s[:3] == b"GIF":                       return True   # gif
    if s[:2] == b"\xff\xd8":                  return True   # jpeg
    if s[:4] == b"RIFF" and b"WEBP" in data[:16]: return True
    low = data[:256].lower()
    if b"<svg" in low or low[:5] == b"<?xml":  return True  # svg
    return False


def _icon_from_html(host):
    try:
        html, _ = _get("https://%s/" % host, timeout=6)
        text = html.decode("utf-8", "ignore")
    except Exception:
        return None
    for m in _ICON_RE.finditer(text[:262144]):
        hm = _HREF_RE.search(m.group(0))
        if hm:
            return urljoin("https://%s/" % host, hm.group(1).strip())
    return None


def fetch_favicon(host):
    """Get the site's real favicon: its own /favicon.ico, then the icon declared
    in its HTML, then an aggregator, caching the result (good or empty) per host."""
    with FAV_LOCK:
        if host in FAV_CACHE:
            return FAV_CACHE[host]
    data, ctype = None, None
    if host and any(c.isalpha() for c in host):
        # 1) the site's own /favicon.ico (https then http)
        for scheme in ("https", "http"):
            try:
                raw, ct = _get("%s://%s/favicon.ico" % (scheme, host))
                if _is_image(raw, ct):
                    data, ctype = raw, (ct or "image/x-icon")
                    break
            except Exception:
                pass
        # 2) the <link rel="icon"> declared in the homepage HTML
        if not data:
            href = _icon_from_html(host)
            if href:
                try:
                    raw, ct = _get(href)
                    if _is_image(raw, ct):
                        data, ctype = raw, (ct or "image/png")
                except Exception:
                    pass
        # 3) aggregator fallback (also returns the real site icon)
        if not data:
            try:
                raw, ct = _get("https://www.google.com/s2/favicons?domain=%s&sz=64" % host)
                if raw and len(raw) > 70:
                    data, ctype = raw, (ct or "image/png")
            except Exception:
                pass
    with FAV_LOCK:
        FAV_CACHE[host] = (data, ctype)
    return (data, ctype)


# --------------------------------------------------------------------------- UI
PAGE_CSS = """
:root{--bg:#0f1420;--card:#171d2b;--card2:#1d2536;--line:#28324a;--fg:#e7ecf5;
--mut:#8b97ad;--accent:#4f9dff;--ok:#3ecf8e;--warn:#f0b64b;--err:#f05c5c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:12px;position:sticky;top:0;background:var(--bg);z-index:5}
header h1{font-size:17px;margin:0;font-weight:600}
header .right{margin-left:auto;font-size:12px}
.sub{color:var(--mut);font-size:12px}
.wrap{padding:20px 24px;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:16px;display:block;transition:.15s}
.card:hover{border-color:var(--accent);transform:translateY(-2px);text-decoration:none}
.card .name{font-weight:600;font-size:15px;color:var(--fg)}
.card .meta{color:var(--mut);font-size:12px;margin-top:4px}
.card .big{font-size:26px;font-weight:700;margin-top:10px}
.m-GET{color:#8fd0ff}.m-POST{color:#ffd58f}.m-PUT{color:#c8a6ff}
.m-DELETE{color:#ff9a9a}.m-HEAD,.m-PATCH,.m-OPTIONS{color:#9ad}
.row{background:var(--card);border:1px solid var(--line);border-radius:10px;
margin-bottom:8px;overflow:hidden}
.rhead{display:flex;align-items:center;gap:10px;padding:9px 12px;cursor:pointer}
.rhead:hover{background:var(--card2)}
.fav{width:18px;height:18px;border-radius:4px;flex:0 0 18px;background:#223;object-fit:contain}
.method{font-weight:700;width:58px;flex:0 0 58px;font-size:12px}
.url{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status{font-weight:700;width:52px;text-align:right}
.s2{color:var(--ok)}.s3{color:#7fd0ff}.s4{color:var(--warn)}.s5{color:var(--err)}
.who{color:var(--mut);font-size:12px;white-space:nowrap}
.when{color:var(--mut);font-size:12px;white-space:nowrap;width:64px;text-align:right}
.detail{display:none;border-top:1px solid var(--line);padding:12px 14px;background:#121826}
.detail.open{display:block}
.sec{margin:8px 0}
.sec h4{margin:0 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.sec.req h4{color:#8fd0ff}.sec.res h4{color:#8fe0b0}
pre{margin:0;background:#0c121e;border:1px solid var(--line);border-radius:8px;
padding:10px;overflow:auto;max-height:340px;white-space:pre-wrap;word-break:break-word;
font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#cfd8e8}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px}
input.search{background:var(--card);border:1px solid var(--line);border-radius:8px;
color:var(--fg);padding:8px 12px;width:280px;outline:none}
.empty{color:var(--mut);padding:40px;text-align:center}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block}
.login{max-width:360px;margin:12vh auto;background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:28px}
.login h1{margin:0 0 6px;font-size:18px}.login p{color:var(--mut);margin:0 0 18px;font-size:13px}
.login input{width:100%;background:#0c121e;border:1px solid var(--line);border-radius:8px;
color:var(--fg);padding:11px 12px;outline:none;font-size:14px}
.login button{width:100%;margin-top:12px;background:var(--accent);border:0;border-radius:8px;
color:#06101f;font-weight:700;padding:11px;cursor:pointer;font-size:14px}
.err{color:var(--err);font-size:13px;margin-top:10px;min-height:18px}
"""

LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSnitch - sign in</title><style>__CSS__</style></head><body>
<form class="login" method="post" action="/login">
<h1><span class="dot"></span> NetSnitch</h1>
<p>Enter the one-time password shown in the server console.</p>
<input type="password" name="password" placeholder="password" autofocus autocomplete="off">
<button type="submit">Sign in</button>
<div class="err">__ERR__</div>
</form></body></html>"""

INDEX_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSnitch</title><style>__CSS__</style></head><body>
<header><span class="dot"></span><h1>NetSnitch</h1>
<span class="sub">collected agents &middot; click one to view its captures</span>
<span class="right"><a href="/logout">sign out</a></span></header>
<div class="wrap"><div id="agents" class="grid"></div>
<div id="empty" class="empty" style="display:none">
No agents yet. Run on a machine:<br><br>
<code>.\\netsnitch.ps1 -Server http://THIS-HOST:PORT</code></div></div>
<script>
function ago(ms){var s=(Date.now()-ms)/1000;if(s<60)return Math.floor(s)+'s ago';
if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';
return Math.floor(s/86400)+'d ago';}
function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
var SIG='';
async function load(){
 try{var r=await fetch('/api/agents');if(r.status===401){location='/login';return;}var a=await r.json();}catch(e){return;}
 var box=document.getElementById('agents');var em=document.getElementById('empty');
 var sig=JSON.stringify(a.map(function(x){return [x.id,x.count,x.last];}));
 if(sig===SIG){return;}SIG=sig;
 if(!a.length){em.style.display='block';box.innerHTML='';return;}em.style.display='none';
 box.innerHTML=a.map(function(x){return '<a class="card" href="/agent/'+encodeURIComponent(x.id)+'">'+
  '<div class="name">'+esc(x.name)+'</div>'+
  '<div class="meta">'+esc(x.machine||x.id)+'</div>'+
  '<div class="big">'+x.count+'</div>'+
  '<div class="meta">captures &middot; last '+ago(x.last)+'</div></a>';}).join('');
}
load();setInterval(load,3000);
</script></body></html>"""

AGENT_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSnitch - agent</title><style>__CSS__</style></head><body>
<header><a href="/">&larr;</a><h1 id="aname">agent</h1>
<span class="sub" id="ameta"></span>
<span class="right"><a href="/logout">sign out</a></span></header>
<div class="wrap">
<div class="toolbar"><input class="search" id="q" placeholder="filter by url, method, status, process...">
<span class="sub" id="count"></span></div>
<div id="list"></div><div id="empty" class="empty" style="display:none">No captures yet.</div></div>
<script>
var AID=decodeURIComponent(location.pathname.split('/agent/')[1]||'');
var maxPk=0;
function ago(ms){var s=(Date.now()-ms)/1000;if(s<60)return Math.floor(s)+'s ago';
if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}
function sclass(st){var n=parseInt(st,10)||0;return n>=500?'s5':n>=400?'s4':n>=300?'s3':n>=200?'s2':'';}
function mkSec(cls,title,txt){if(!txt)return null;var d=document.createElement('div');d.className='sec '+cls;
 var h=document.createElement('h4');h.textContent=title;var p=document.createElement('pre');p.textContent=txt;
 d.appendChild(h);d.appendChild(p);return d;}
function mkRow(t){
 var row=document.createElement('div');row.className='row';
 row.dataset.search=((t.method||'')+' '+(t.url||'')+' '+(t.status||'')+' '+(t.process||'')+' '+(t.host||'')).toLowerCase();
 var head=document.createElement('div');head.className='rhead';
 var img=document.createElement('img');img.className='fav';img.src='/fav?h='+encodeURIComponent(t.host||'');img.loading='lazy';
 var m=document.createElement('span');m.className='method m-'+(t.method||'');m.textContent=t.method||'\\u2014';
 var u=document.createElement('span');u.className='url';u.textContent=t.url||t.host||'(no url)';u.title=t.url||t.host||'';
 var who=document.createElement('span');who.className='who';who.textContent=t.process||'';
 var st=document.createElement('span');st.className='status '+sclass(t.status);st.textContent=(t.status||'').split(' ')[0];
 var wh=document.createElement('span');wh.className='when';wh.dataset.ts=t.ts;wh.textContent=ago(t.ts);
 head.appendChild(img);head.appendChild(m);head.appendChild(u);head.appendChild(who);head.appendChild(st);head.appendChild(wh);
 var det=document.createElement('div');det.className='detail';
 [['req','request headers',t.reqHeaders],['req','request body',t.reqBody],
  ['res','response headers',t.resHeaders],['res','response body',t.resBody]].forEach(function(s){
   var e=mkSec(s[0],s[1],s[2]);if(e)det.appendChild(e);});
 if(!det.children.length){var e=document.createElement('div');e.className='sec';var p=document.createElement('pre');p.textContent='(no captured detail)';e.appendChild(p);det.appendChild(e);}
 head.onclick=function(){det.classList.toggle('open');};
 row.appendChild(head);row.appendChild(det);return row;
}
function applyFilter(){
 var q=document.getElementById('q').value.toLowerCase();var list=document.getElementById('list');
 var shown=0,total=list.children.length;
 for(var i=0;i<list.children.length;i++){var r=list.children[i];
  var ok=!q||r.dataset.search.indexOf(q)>=0;r.style.display=ok?'':'none';if(ok)shown++;}
 document.getElementById('count').textContent=shown+(q?' / '+total:'')+' captures';
}
async function load(){
 try{var r=await fetch('/api/agent/'+encodeURIComponent(AID)+'?since='+maxPk);
  if(r.status===401){location='/login';return;}var j=await r.json();}catch(e){return;}
 if(j.error){document.getElementById('aname').textContent='agent not found';return;}
 document.getElementById('aname').textContent=j.agent.name;
 document.getElementById('ameta').textContent=(j.agent.machine||j.agent.id)+' \\u2014 '+j.agent.count+' captures';
 var list=document.getElementById('list');
 if(j.transactions.length){
  var atTop=window.scrollY<40;var before=document.body.scrollHeight;
  j.transactions.forEach(function(t){if(t.id>maxPk)maxPk=t.id;list.insertBefore(mkRow(t),list.firstChild);});
  applyFilter();
  if(!atTop){window.scrollBy(0,document.body.scrollHeight-before);}
 }
 var w=document.querySelectorAll('.when');
 for(var i=0;i<w.length;i++){if(w[i].dataset.ts)w[i].textContent=ago(+w[i].dataset.ts);}
 document.getElementById('empty').style.display=list.children.length?'none':'block';
}
document.getElementById('q').addEventListener('input',applyFilter);
load();setInterval(load,3000);
</script></body></html>"""


# ---------------------------------------------------------------------- handler
OPEN_PATHS = ("/login", "/api/ingest", "/api/agent")   # agent push + login


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _cookie_token(self):
        c = self.headers.get("Cookie") or ""
        for part in c.split(";"):
            part = part.strip()
            if part.startswith("hc="):
                return part[3:]
        return ""

    def _authed(self):
        tok = self._cookie_token()
        with SESS_LOCK:
            return tok in SESSIONS

    def _redirect(self, loc, extra=None):
        self.send_response(302)
        self.send_header("Location", loc)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            err = "Wrong password." if parse_qs(urlparse(self.path).query).get("e") else ""
            self._send(200, LOGIN_HTML.replace("__CSS__", PAGE_CSS).replace("__ERR__", err),
                       "text/html; charset=utf-8")
            return
        if path == "/logout":
            tok = self._cookie_token()
            with SESS_LOCK:
                SESSIONS.discard(tok)
            self._redirect("/login", [("Set-Cookie", "hc=; Path=/; Max-Age=0")])
            return
        # everything below requires a session
        if not self._authed():
            if path.startswith("/api/") or path == "/fav":
                self._send(401, json.dumps({"error": "auth required"}))
            else:
                self._redirect("/login")
            return
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML.replace("__CSS__", PAGE_CSS), "text/html; charset=utf-8")
        elif path.startswith("/agent/"):
            self._send(200, AGENT_HTML.replace("__CSS__", PAGE_CSS), "text/html; charset=utf-8")
        elif path == "/api/agents":
            self._send(200, json.dumps(get_agents()))
        elif path.startswith("/api/agent/"):
            aid = unquote(path[len("/api/agent/"):])
            since = 0
            try:
                since = int((parse_qs(urlparse(self.path).query).get("since") or ["0"])[0])
            except Exception:
                since = 0
            r = get_agent(aid, since)
            if r is None:
                self._send(404, json.dumps({"error": "no such agent"}))
            else:
                self._send(200, json.dumps(r))
        elif path == "/fav":
            host = (parse_qs(urlparse(self.path).query).get("h") or [""])[0].strip().lower()
            data, ctype = fetch_favicon(host)
            if data:
                self._send(200, data, ctype or "image/png")
            else:
                self._send(200, DEFAULT_ICON, "image/svg+xml")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/login":
            pw = (parse_qs(raw.decode("utf-8", "ignore")).get("password") or [""])[0]
            if pw and PASSWORD and hmac.compare_digest(pw, PASSWORD):
                tok = secrets.token_urlsafe(24)
                with SESS_LOCK:
                    SESSIONS.add(tok)
                self._redirect("/", [("Set-Cookie",
                               "hc=%s; HttpOnly; Path=/; SameSite=Lax" % tok)])
            else:
                self._redirect("/login?e=1")
            return
        # agent push endpoints are open
        try:
            d = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception as e:
            self._send(400, json.dumps({"error": "bad json: %s" % e}))
            return
        if path == "/api/ingest":
            try:
                if isinstance(d, dict) and "items" in d:
                    aid = d.get("agentId"); aname = d.get("agentName"); machine = d.get("machine")
                    for it in d["items"]:
                        if aid and not it.get("agentId"): it["agentId"] = aid
                        if aname and not it.get("agentName"): it["agentName"] = aname
                        if machine and not it.get("machine"): it["machine"] = machine
                        ingest(it)
                else:
                    for x in (d if isinstance(d, list) else [d]):
                        ingest(x)
                self._send(200, json.dumps({"ok": True}))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
        elif path == "/api/agent":
            register(d)
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, json.dumps({"error": "not found"}))


def main():
    global PASSWORD
    ap = argparse.ArgumentParser(description="NetSnitch collector server")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8771, help="port (default 8771)")
    ap.add_argument("--data", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "captures.db"),
        help="SQLite database file")
    ap.add_argument("--password", default=None,
        help="set the login password (default: a random one-time password)")
    args = ap.parse_args()

    db_init(args.data)
    PASSWORD = args.password or secrets.token_urlsafe(12)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    bar = "=" * 60
    print(bar)
    print("  NetSnitch server")
    print("  Web UI   : http://%s:%d/" % (args.host, args.port))
    print("  Database : %s" % args.data)
    print("  LOGIN PASSWORD (one-time, this run): %s" % PASSWORD)
    print("  Agents push with:  .\\netsnitch.ps1 -Server http://<this-host>:%d" % args.port)
    print(bar)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
