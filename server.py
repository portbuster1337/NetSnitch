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
    # WAL plus NORMAL is the standard high-write combination: durable across a
    # process crash, and far cheaper than a fsync for every upload batch. The
    # collector is a capture cache, not a ledger.
    DB.execute("PRAGMA synchronous=NORMAL")
    DB.execute("PRAGMA busy_timeout=5000")
    DB.execute("PRAGMA cache_size=-20000")
    DB.execute("PRAGMA temp_store=MEMORY")
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


def _upsert_agent_locked(aid, name, machine, now):
    row = DB.execute("SELECT id FROM agents WHERE id=?", (aid,)).fetchone()
    if row is None:
        DB.execute("INSERT INTO agents(id,name,machine,first,last,count) VALUES(?,?,?,?,?,0)",
                   (aid, name or aid, machine, now, now))
    else:
        DB.execute("UPDATE agents SET last=?, name=CASE WHEN ?<>'' THEN ? ELSE name END, "
                   "machine=CASE WHEN ?<>'' THEN ? ELSE machine END WHERE id=?",
                   (now, name, name, machine, machine, aid))


def register(d):
    aid = str(d.get("agentId") or "unknown")
    name = d.get("agentName") or aid
    machine = d.get("machine") or ""
    now = now_ms()
    with DBLOCK:
        try:
            _upsert_agent_locked(aid, name, machine, now)
            DB.commit()
        except Exception:
            DB.rollback()
            raise


# One upload batch is one SQLite transaction. Previously every item performed its
# own register/insert/count/trim/commit, which means a batch of 50 captures did 50
# commits and 50 scans of the agent's newest 20k rows. Under a burst that serialized
# the whole collector. Now the batch registers each agent once, inserts with
# executemany, updates counts in one pass, and trims each affected agent once.
def ingest_many(items):
    rows = []
    meta = {}                    # agent id -> [name, machine]
    now = now_ms()
    for d in items:
        if not isinstance(d, dict):
            continue
        aid = str(d.get("agentId") or "unknown")
        name = str(d.get("agentName") or "")
        machine = str(d.get("machine") or "")
        m = meta.get(aid)
        if m is None:
            meta[aid] = [name, machine]
        else:
            if name:
                m[0] = name
            if machine:
                m[1] = machine
        rows.append((aid, d.get("ts") or now, d.get("method") or "", d.get("url") or "",
                     derive_host(d), d.get("status") or "", d.get("process") or "",
                     d.get("user") or "", d.get("requestHeaders") or "",
                     d.get("requestBody") or "", d.get("responseHeaders") or "",
                     d.get("responseBody") or ""))
    if not rows:
        return
    counts = {}
    for r in rows:
        counts[r[0]] = counts.get(r[0], 0) + 1
    with DBLOCK:
        try:
            for aid, m in meta.items():
                _upsert_agent_locked(aid, m[0], m[1], now)
            DB.executemany("""INSERT INTO txns(agent_id,ts,method,url,host,status,process,user,
                                req_headers,req_body,res_headers,res_body)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            for aid, n in counts.items():
                DB.execute("UPDATE agents SET count=count+?, last=? WHERE id=?", (n, now, aid))
                # Keep the newest MAX_PER_AGENT rows. OFFSET is the pk of the first
                # row that falls outside the window; NULL (too few rows) deletes
                # nothing. Indexed by (agent_id, pk), and now runs once per batch.
                DB.execute("""DELETE FROM txns WHERE agent_id=? AND pk <=
                                (SELECT pk FROM txns WHERE agent_id=?
                                 ORDER BY pk DESC LIMIT 1 OFFSET ?)""",
                           (aid, aid, MAX_PER_AGENT))
            DB.commit()
        except Exception:
            DB.rollback()
            raise


def ingest(d):
    ingest_many([d])


def get_agents():
    with DBLOCK:
        rows = DB.execute("SELECT id,name,machine,first,last,count FROM agents "
                          "ORDER BY last DESC").fetchall()
    return [{"id": r[0], "name": r[1], "machine": r[2], "first": r[3],
             "last": r[4], "count": r[5]} for r in rows]


def agent_meta(aid):
    with DBLOCK:
        a = DB.execute("SELECT id,name,machine,first,last,count FROM agents WHERE id=?",
                       (aid,)).fetchone()
    if not a:
        return None
    return {"id": a[0], "name": a[1], "machine": a[2], "first": a[3], "last": a[4], "count": a[5]}


# Metadata-only columns for the list: never ship the (potentially huge) headers and
# bodies with the list itself - only their byte sizes, so the grid stays light no
# matter how many HTTP/HTTPS transactions pile up. The full detail is fetched per row
# on expand via get_txn_full().
_LIST_COLS = ("pk,ts,method,url,host,status,process,user,"
              "length(req_headers),length(req_body),length(res_headers),length(res_body)")


def _list_row(r):
    return {"id": r[0], "ts": r[1], "method": r[2], "url": r[3], "host": r[4],
            "status": r[5], "process": r[6], "user": r[7],
            "reqHeadersLen": r[8] or 0, "reqBodyLen": r[9] or 0,
            "resHeadersLen": r[10] or 0, "resBodyLen": r[11] or 0}


def list_txns(aid, since, before, limit):
    """Paginated, metadata-only listing.
      since>0  -> new rows with pk>since, ascending (live tail)
      before>0 -> older page with pk<before, descending (scroll back)
      neither  -> newest page, descending
    """
    limit = max(1, min(int(limit or 60), 500))
    with DBLOCK:
        if since > 0:
            rows = DB.execute("SELECT %s FROM txns WHERE agent_id=? AND pk>? ORDER BY pk ASC LIMIT ?"
                              % _LIST_COLS, (aid, since, limit)).fetchall()
        elif before > 0:
            rows = DB.execute("SELECT %s FROM txns WHERE agent_id=? AND pk<? ORDER BY pk DESC LIMIT ?"
                              % _LIST_COLS, (aid, before, limit)).fetchall()
        else:
            rows = DB.execute("SELECT %s FROM txns WHERE agent_id=? ORDER BY pk DESC LIMIT ?"
                              % _LIST_COLS, (aid, limit)).fetchall()
    return [_list_row(r) for r in rows]


def get_txn_full(aid, pk):
    with DBLOCK:
        r = DB.execute("SELECT pk,ts,method,url,host,status,process,user,"
                       "req_headers,req_body,res_headers,res_body "
                       "FROM txns WHERE agent_id=? AND pk=?", (aid, pk)).fetchone()
    if not r:
        return None
    return {"id": r[0], "ts": r[1], "method": r[2], "url": r[3], "host": r[4],
            "status": r[5], "process": r[6], "user": r[7], "reqHeaders": r[8],
            "reqBody": r[9], "resHeaders": r[10], "resBody": r[11]}


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
<title>NetSnitch - agent</title><style>__CSS__
.when{width:70px}.size{color:var(--mut);font-size:12px;white-space:nowrap;width:70px;text-align:right}
#more{padding:14px;text-align:center;color:var(--mut);font-size:12px}
.pausebtn{margin-left:10px;background:var(--card);border:1px solid var(--line);border-radius:8px;color:var(--fg);padding:6px 12px;cursor:pointer;font-size:12px}
</style></head><body>
<header><a href="/">&larr;</a><h1 id="aname">agent</h1>
<span class="sub" id="ameta"></span>
<span class="right"><a href="/logout">sign out</a></span></header>
<div class="wrap">
<div class="toolbar"><input class="search" id="q" placeholder="filter loaded rows by url, method, status, process...">
<button class="pausebtn" id="pause">pause live</button>
<span class="sub" id="count"></span></div>
<div id="list"></div>
<div id="more"></div>
<div id="empty" class="empty" style="display:none">No captures yet.</div></div>
<script>
var AID=decodeURIComponent(location.pathname.split('/agent/')[1]||'');
var newestPk=0, oldestPk=0, loadingOlder=false, noMore=false, live=true, total=0;
function ago(ms){var s=(Date.now()-ms)/1000;if(s<60)return Math.floor(s)+'s ago';
if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}
function sclass(st){var n=parseInt(st,10)||0;return n>=500?'s5':n>=400?'s4':n>=300?'s3':n>=200?'s2':'';}
function fmtSize(n){if(!n)return '';if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';return (n/1048576).toFixed(1)+' MB';}
function mkSec(cls,title,txt){if(txt===null||txt===undefined||txt==='')return null;var d=document.createElement('div');d.className='sec '+cls;
 var h=document.createElement('h4');h.textContent=title;var p=document.createElement('pre');p.textContent=txt;
 d.appendChild(h);d.appendChild(p);return d;}
function setMeta(a){document.getElementById('aname').textContent=a.name;
 document.getElementById('ameta').textContent=(a.machine||a.id)+' - '+a.count+' total captures';}
function mkRow(t){
 var row=document.createElement('div');row.className='row';row.dataset.pk=t.id;
 row.dataset.search=((t.method||'')+' '+(t.url||'')+' '+(t.status||'')+' '+(t.process||'')+' '+(t.host||'')).toLowerCase();
 var head=document.createElement('div');head.className='rhead';
 var img=document.createElement('img');img.className='fav';img.src='/fav?h='+encodeURIComponent(t.host||'');img.loading='lazy';
 var m=document.createElement('span');m.className='method m-'+(t.method||'');m.textContent=t.method||'-';
 var u=document.createElement('span');u.className='url';u.textContent=t.url||t.host||'(no url)';u.title=t.url||t.host||'';
 var who=document.createElement('span');who.className='who';who.textContent=t.process||'';
 var sz=document.createElement('span');sz.className='size';sz.textContent=fmtSize(t.resBodyLen||t.reqBodyLen||0);
 var st=document.createElement('span');st.className='status '+sclass(t.status);st.textContent=(t.status||'').split(' ')[0];
 var wh=document.createElement('span');wh.className='when';wh.dataset.ts=t.ts;wh.textContent=ago(t.ts);
 head.appendChild(img);head.appendChild(m);head.appendChild(u);head.appendChild(who);head.appendChild(sz);head.appendChild(st);head.appendChild(wh);
 var det=document.createElement('div');det.className='detail';
 var loaded=false;
 head.onclick=function(){
  det.classList.toggle('open');
  if(det.classList.contains('open')&&!loaded){
   loaded=true;det.innerHTML='<div class="sec"><pre>loading...</pre></div>';
   fetch('/api/txn/'+t.id+'?agent='+encodeURIComponent(AID)).then(function(r){return r.json();}).then(function(d){
    det.innerHTML='';
    [['req','request headers',d.reqHeaders],['req','request body',d.reqBody],
     ['res','response headers',d.resHeaders],['res','response body',d.resBody]].forEach(function(s){
      var e=mkSec(s[0],s[1],s[2]);if(e)det.appendChild(e);});
    if(!det.children.length){det.innerHTML='<div class="sec"><pre>(no captured detail)</pre></div>';}
   }).catch(function(){det.innerHTML='<div class="sec"><pre>(failed to load)</pre></div>';loaded=false;});
  }
 };
 row.appendChild(head);row.appendChild(det);return row;
}
function applyFilter(){
 var q=document.getElementById('q').value.toLowerCase();var list=document.getElementById('list');
 var shown=0;
 for(var i=0;i<list.children.length;i++){var r=list.children[i];
  var ok=!q||r.dataset.search.indexOf(q)>=0;r.style.display=ok?'':'none';if(ok)shown++;}
 document.getElementById('count').textContent=shown+' shown | '+total+' loaded';
}
function updateTimes(){var w=document.querySelectorAll('.when');
 for(var i=0;i<w.length;i++){if(w[i].dataset.ts)w[i].textContent=ago(+w[i].dataset.ts);}}
var list=document.getElementById('list');
async function loadNewest(){
 try{var r=await fetch('/api/agent/'+encodeURIComponent(AID)+'?limit=60');
  if(r.status===401){location='/login';return;}var j=await r.json();}catch(e){return;}
 if(j.error){document.getElementById('aname').textContent='agent not found';return;}
 setMeta(j.agent);
 j.items.forEach(function(t){if(t.id>newestPk)newestPk=t.id;if(!oldestPk||t.id<oldestPk)oldestPk=t.id;
  list.appendChild(mkRow(t));total++;});
 if(j.items.length<60)noMore=true;
 document.getElementById('empty').style.display=total?'none':'block';
 applyFilter();
}
async function loadOlder(){
 if(loadingOlder||noMore||!oldestPk)return;loadingOlder=true;
 document.getElementById('more').textContent='loading older...';
 try{var r=await fetch('/api/agent/'+encodeURIComponent(AID)+'?before='+oldestPk+'&limit=60');
  if(r.status===401){location='/login';return;}var j=await r.json();}catch(e){loadingOlder=false;document.getElementById('more').textContent='';return;}
 if(!j.items.length){noMore=true;document.getElementById('more').textContent='- end -';loadingOlder=false;return;}
 j.items.forEach(function(t){if(!oldestPk||t.id<oldestPk)oldestPk=t.id;list.appendChild(mkRow(t));total++;});
 if(j.items.length<60)noMore=true;
 document.getElementById('more').textContent=noMore?'- end -':'';
 applyFilter();loadingOlder=false;
}
async function loadNew(){
 if(!live||!newestPk)return;
 try{var r=await fetch('/api/agent/'+encodeURIComponent(AID)+'?since='+newestPk+'&limit=300');
  if(r.status===401){location='/login';return;}var j=await r.json();}catch(e){return;}
 if(j.agent)setMeta(j.agent);
 if(j.items.length){
  var atTop=window.scrollY<60;var before=document.body.scrollHeight;
  j.items.forEach(function(t){if(t.id>newestPk)newestPk=t.id;list.insertBefore(mkRow(t),list.firstChild);total++;});
  applyFilter();
  if(!atTop){window.scrollBy(0,document.body.scrollHeight-before);}  // keep scroll position when not at top
 }
 updateTimes();
}
// Infinite scroll: pull older pages as you near the bottom.
window.addEventListener('scroll',function(){
 if(window.innerHeight+window.scrollY>=document.body.scrollHeight-400){loadOlder();}
});
document.getElementById('q').addEventListener('input',applyFilter);
document.getElementById('pause').addEventListener('click',function(){
 live=!live;this.textContent=live?'pause live':'resume live';});
loadNewest();setInterval(loadNew,3000);setInterval(updateTimes,15000);
</script></body></html>"""


# ---------------------------------------------------------------------- handler
OPEN_PATHS = ("/login", "/api/ingest", "/api/agent")   # agent push + login


class Handler(BaseHTTPRequestHandler):
    # Speak HTTP/1.1 so proxies (the capture's own MITM, cloudflared) keep the
    # connection framed correctly and 100-continue is handled for us. Every
    # response below sends an explicit Content-Length, so keep-alive is safe.
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _read_body(self):
        # Read the request body regardless of how the client or any intermediary
        # framed it. An agent POST that crosses the capture MITM and then a
        # cloudflare tunnel frequently arrives chunked (Transfer-Encoding: chunked,
        # no Content-Length); reading only Content-Length would silently drop the
        # whole batch and still answer 200, which looks like "upload does nothing".
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out = []
            total = 0
            while True:
                line = self.rfile.readline(65537)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    size = int(line.split(b";", 1)[0], 16)
                except ValueError:
                    break
                if size == 0:
                    # consume trailers up to the terminating blank line
                    while True:
                        t = self.rfile.readline(65537)
                        if t in (b"\r\n", b"\n", b""):
                            break
                    break
                chunk = self.rfile.read(size)
                out.append(chunk)
                total += len(chunk)
                self.rfile.read(2)                 # trailing CRLF after each chunk
                if total > 200 * 1024 * 1024:       # hard cap, never grow unbounded
                    break
            return b"".join(out)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

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
        elif path.startswith("/api/txn/"):
            qs = parse_qs(urlparse(self.path).query)
            aid = unquote((qs.get("agent") or [""])[0])
            try:
                pk = int(path[len("/api/txn/"):])
            except Exception:
                pk = 0
            t = get_txn_full(aid, pk) if (aid and pk) else None
            if t is None:
                self._send(404, json.dumps({"error": "not found"}))
            else:
                self._send(200, json.dumps(t))
        elif path.startswith("/api/agent/"):
            aid = unquote(path[len("/api/agent/"):])
            qs = parse_qs(urlparse(self.path).query)

            def _qint(k):
                try:
                    return int((qs.get(k) or ["0"])[0])
                except Exception:
                    return 0

            meta = agent_meta(aid)
            if meta is None:
                self._send(404, json.dumps({"error": "no such agent"}))
            else:
                since = _qint("since")
                before = _qint("before")
                limit = _qint("limit")
                items = list_txns(aid, since, before, limit)
                self._send(200, json.dumps({
                    "agent": meta, "items": items,
                    "mode": "since" if since > 0 else "page"}))
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
        raw = self._read_body()
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
        # Agent push endpoints are open. The uploader sends NDJSON: one complete
        # batch object per line, so it can merge many queued batches into one POST.
        # A single batch is also valid NDJSON; plain JSON is still accepted for
        # older agents and manual posts.
        ctype = (self.headers.get("Content-Type") or "").lower()
        try:
            # Tolerant on purpose: PowerShell 5.1 clients can emit control
            # characters inside JSON strings and/or non-UTF-8 byte sequences
            # when a captured body is binary. Rejecting the whole batch loses
            # the text records that rode along with it.
            if raw and "ndjson" in ctype:
                docs = [json.loads(line.decode("utf-8", "replace"), strict=False)
                        for line in raw.splitlines() if line.strip()]
            else:
                try:
                    docs = [json.loads(raw.decode("utf-8", "replace"), strict=False)] if raw else []
                except Exception:
                    # An intermediary can rewrite Content-Type while leaving the
                    # newline-delimited body intact. Accept that shape too.
                    if raw and b"\n" in raw.strip():
                        docs = [json.loads(line.decode("utf-8", "replace"), strict=False)
                                for line in raw.splitlines() if line.strip()]
                    else:
                        raise
        except Exception as e:
            self._send(400, json.dumps({"error": "bad json: %s" % e}))
            return
        if path == "/api/ingest":
            try:
                # Flatten every line of the POST into one list, then ingest it as
                # one transaction. A coalesced upload therefore costs one commit,
                # not one commit per batch line.
                items = []
                for d in docs:
                    if isinstance(d, dict) and isinstance(d.get("items"), list):
                        aid = d.get("agentId"); aname = d.get("agentName"); machine = d.get("machine")
                        for it in d["items"]:
                            if not isinstance(it, dict):
                                continue
                            if aid and not it.get("agentId"): it["agentId"] = aid
                            if aname and not it.get("agentName"): it["agentName"] = aname
                            if machine and not it.get("machine"): it["machine"] = machine
                        items.extend(d["items"])
                    elif isinstance(d, list):
                        items.extend(d)
                    else:
                        items.append(d)
                ingest_many(items)
                self._send(200, json.dumps({"ok": True, "batches": len(docs)}))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
        elif path == "/api/agent":
            register(docs[0] if docs and isinstance(docs[0], dict) else {})
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
