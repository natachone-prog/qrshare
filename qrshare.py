#!/usr/bin/env python3
"""QRShare: รับ-ส่งไฟล์ระหว่างมือถือ/แท็บเล็ตกับคอมพิวเตอร์ผ่านเครือข่ายภายใน ด้วยการสแกน QR code

วิธีใช้:  python qrshare.py [--folder โฟลเดอร์] [--port 8765]
"""
import argparse
import html
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import segno

MAX_PIN_TRIES = 5
CHUNK = 1024 * 1024


def default_folder():
    home = os.path.expanduser("~")
    docs = os.path.join(home, "Documents")
    return os.path.join(docs if os.path.isdir(docs) else home, "QRShare")


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # ไม่ได้ส่งข้อมูลจริง แค่หา IP ของเครื่องในวง LAN
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class State:
    def __init__(self, folder, url_base):
        self.lock = threading.Lock()
        self.folder = folder
        self.token = secrets.token_urlsafe(16)
        self.url = f"{url_base}/?t={self.token}"
        self.pin = self._new_pin()
        self.fails = 0
        self.sessions = set()
        self.received = []  # [(เวลา, ชื่อไฟล์, ขนาด)]

    @staticmethod
    def _new_pin():
        return f"{secrets.randbelow(1_000_000):06d}"

    def try_login(self, token, pin):
        with self.lock:
            if not secrets.compare_digest(token or "", self.token):
                return None, "bad_token"
            if secrets.compare_digest(pin or "", self.pin):
                self.fails = 0
                sid = secrets.token_urlsafe(24)
                self.sessions.add(sid)
                return sid, "ok"
            self.fails += 1
            if self.fails >= MAX_PIN_TRIES:
                self.pin = self._new_pin()  # ใส่ผิดเกินกำหนด เปลี่ยน PIN ใหม่ทันที
                self.fails = 0
                return None, "locked"
            return None, "bad_pin"


def safe_name(name):
    name = os.path.basename(name.replace("\\", "/")).strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(". ")
    return name[:200] or "file"


def unique_path(folder, name):
    base, ext = os.path.splitext(name)
    path = os.path.join(folder, name)
    n = 1
    while os.path.exists(path):
        path = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return path


def list_files(folder):
    out = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return out
    for e in entries:
        if e.name.startswith(".") or not e.is_file(follow_symlinks=False):
            continue
        st = e.stat(follow_symlinks=False)
        out.append({"name": e.name, "size": st.st_size, "mtime": st.st_mtime})
    out.sort(key=lambda f: f["mtime"], reverse=True)
    return out


def resolve_download(folder, name):
    """คืน path ของไฟล์ถ้าอยู่ในโฟลเดอร์แชร์จริง (กันการเข้าถึงไฟล์นอกโฟลเดอร์)"""
    if not name or name != os.path.basename(name) or name.startswith(".") or "\\" in name:
        return None
    path = os.path.join(folder, name)
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(folder):
        return None
    return path


def open_folder(folder):
    try:
        if sys.platform.startswith("win"):
            os.startfile(folder)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])
    except OSError:
        pass


def already_running(port):
    """ถ้าเปิดโปรแกรมซ้ำ ให้เปิดหน้าเดิมแทนการเปิดตัวใหม่"""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as c:
            c.sendall(b"GET /host/state HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            head = c.recv(256)
            return b"200" in head.split(b"\r\n")[0] and b"QRShare" in head + c.recv(256)
    except OSError:
        return False


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "QRShare"
    state: State = None

    def log_message(self, fmt, *args):
        pass  # ปิด log รก ๆ ใน terminal

    # ---------- helpers ----------
    def is_local(self):
        return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def session_ok(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = c.get("qrshare_sid")
        return sid is not None and sid.value in self.state.sessions

    def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, name):
        size = os.path.getsize(path)
        start, end = 0, size - 1
        rng = self.headers.get("Range", "")
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
        partial = bool(m and (m.group(1) or m.group(2)))
        if partial:
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:  # bytes=-N (N ไบต์สุดท้าย)
                start = max(size - int(m.group(2)), 0)
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        ascii_name = name.encode("ascii", "replace").decode().replace('"', "_").replace("?", "_")
        self.send_header("Content-Disposition",
                         f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name)}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            with open(path, "rb") as f:
                f.seek(start)
                remaining = end - start + 1
                while remaining > 0:
                    chunk = f.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass  # มือถือยกเลิกการดาวน์โหลด

    def send_json(self, code, obj, extra=None):
        self.send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", extra)

    # ---------- routes ----------
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        st = self.state
        if u.path == "/host":
            if not self.is_local():
                return self.send(403, "Forbidden")
            return self.send(200, host_page(st))
        if u.path == "/host/state":
            if not self.is_local():
                return self.send_json(403, {})
            with st.lock:
                rec = [{"time": t, "name": n, "size": human_size(s)} for t, n, s in st.received[-20:]][::-1]
                return self.send_json(200, {"pin": st.pin, "received": rec})
        if u.path == "/api/files":
            if not self.session_ok():
                return self.send_json(401, {"error": "login"})
            files = list_files(st.folder)
            for f in files:
                f["sizeText"] = human_size(f["size"])
                f["time"] = time.strftime("%d/%m/%Y %H:%M", time.localtime(f.pop("mtime")))
            return self.send_json(200, {"files": files})
        if u.path == "/api/download":
            if not self.session_ok():
                return self.send(401, NEED_QR_PAGE)
            name = (urllib.parse.parse_qs(u.query.encode("latin-1", "ignore").decode("utf-8", "replace"))
                    .get("name") or [""])[0]
            path = resolve_download(st.folder, name)
            if not path:
                return self.send(404, "ไม่พบไฟล์")
            return self.send_file(path, name)
        if u.path == "/":
            token = (q.get("t") or [""])[0]
            if self.session_ok() or secrets.compare_digest(token, st.token):
                return self.send(200, PHONE_PAGE.replace("__TOKEN__", html.escape(token)))
            return self.send(403, NEED_QR_PAGE)
        self.send(404, "Not found")

    def do_POST(self):
        if self.path in ("/host/open-folder", "/host/quit"):
            # ต้องมาจากเครื่องนี้ และมี header พิเศษ (กันเว็บอื่นสั่งผ่านเบราว์เซอร์)
            if not self.is_local() or self.headers.get("X-QRShare") != "1":
                return self.send_json(403, {})
            if self.path == "/host/open-folder":
                open_folder(self.state.folder)
                return self.send_json(200, {"ok": True})
            self.send_json(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path != "/api/login":
            return self.send(404, "Not found")
        try:
            n = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "bad_request"})
        sid, status = self.state.try_login(str(data.get("t", "")), str(data.get("pin", "")))
        if sid:
            return self.send_json(200, {"ok": True},
                                  {"Set-Cookie": f"qrshare_sid={sid}; Path=/; HttpOnly; SameSite=Strict"})
        time.sleep(1)  # หน่วงเวลาเพื่อกันการเดา PIN
        self.send_json(403 if status != "bad_token" else 401, {"error": status})

    def do_PUT(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/api/upload":
            return self.send(404, "Not found")
        if not self.session_ok():
            return self.send_json(401, {"error": "login"})
        try:
            length = int(self.headers["Content-Length"])
        except (TypeError, ValueError):
            return self.send_json(411, {"error": "length_required"})
        query = u.query.encode("latin-1", "ignore").decode("utf-8", "replace")  # รองรับชื่อไฟล์ภาษาไทยที่ไม่ได้เข้ารหัส
        name = safe_name((urllib.parse.parse_qs(query).get("name") or ["file"])[0])
        st = self.state
        os.makedirs(st.folder, exist_ok=True)
        tmp = os.path.join(st.folder, f".qrshare-{secrets.token_hex(6)}.part")
        try:
            remaining = length
            with open(tmp, "wb") as f:
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("upload interrupted")
                    f.write(chunk)
                    remaining -= len(chunk)
            with st.lock:
                final = unique_path(st.folder, name)
                os.replace(tmp, final)
                st.received.append((time.strftime("%H:%M:%S"), os.path.basename(final), length))
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            return self.send_json(500, {"error": "write_failed"})
        print(f"  ได้รับไฟล์: {os.path.basename(final)} ({human_size(length)})")
        self.send_json(200, {"ok": True, "name": os.path.basename(final)})


# ---------------- pages ----------------
STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#667085;--accent:#2563eb;--ok:#16a34a;--err:#dc2626;--line:#e4e7ec}
@media (prefers-color-scheme: dark){:root{--bg:#111418;--card:#1b2027;--text:#e8ebf0;--muted:#9aa4b2;--accent:#5b8def;--ok:#34c26b;--err:#f26b6b;--line:#2c333d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans Thai",sans-serif}
.wrap{max-width:560px;margin:0 auto;padding:24px 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px}
h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted);font-size:14px}button{font:inherit;border:0;border-radius:10px;padding:12px 18px;background:var(--accent);color:#fff;cursor:pointer;width:100%}
button:disabled{opacity:.5}input[type=text],input[inputmode]{font:inherit;width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font-size:24px;letter-spacing:8px;text-align:center}
"""


def host_page(st):
    qr = segno.make(st.url, error="m").svg_inline(scale=8, border=2, dark="#000", light="#fff")
    return f"""<!doctype html><html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QRShare</title><style>{STYLE}
.qr{{background:#fff;border-radius:12px;padding:8px;display:flex;justify-content:center}}.qr svg{{max-width:100%;height:auto}}
.pin{{font-size:44px;font-weight:700;letter-spacing:10px;text-align:center;margin:8px 0}}ul{{padding-left:18px;margin:8px 0 0}}code{{word-break:break-all}}
button.sec{{background:var(--bg);color:var(--text);border:1px solid var(--line)}}button.stop{{background:var(--err);margin-bottom:12px}}</style></head>
<body><div class="wrap">
<div class="card"><h1>QRShare</h1><div class="muted">สแกน QR code ด้วยกล้องมือถือ (ต้องต่อ Wi‑Fi เดียวกับคอมพิวเตอร์)</div></div>
<div class="card"><div class="qr">{qr}</div><p class="muted" style="text-align:center">หรือเปิด <code>{html.escape(st.url)}</code></p></div>
<div class="card"><div class="muted" style="text-align:center">PIN สำหรับเข้าใช้งาน</div><div class="pin" id="pin">{st.pin}</div>
<div class="muted" style="text-align:center">ถ้าใส่ผิด {MAX_PIN_TRIES} ครั้ง PIN จะเปลี่ยนใหม่อัตโนมัติ</div></div>
<div class="card"><b>โฟลเดอร์แชร์</b> <span class="muted">(ไฟล์ที่ส่งมาจะเก็บที่นี่ และมือถือดาวน์โหลดไฟล์ในโฟลเดอร์นี้ได้)</span><div><code>{html.escape(st.folder)}</code></div>
<button class="sec" id="openf" style="margin-top:12px">เปิดโฟลเดอร์แชร์</button>
<p style="margin:12px 0 0"><b>ไฟล์ที่ได้รับล่าสุด</b></p><ul id="rec"><li class="muted">ยังไม่มี</li></ul></div>
<button class="stop" id="quit">หยุดโปรแกรม</button>
<p class="muted" style="text-align:center">ปิดแท็บนี้ได้ โปรแกรมยังทำงานต่อ เปิดโปรแกรมอีกครั้งเพื่อกลับมาหน้านี้</p></div>
<script>
async function poll(){{try{{const r=await fetch('/host/state');const s=await r.json();
document.getElementById('pin').textContent=s.pin;const ul=document.getElementById('rec');
ul.innerHTML=s.received.length?'':'<li class="muted">ยังไม่มี</li>';
for(const f of s.received){{const li=document.createElement('li');li.textContent=f.time+'  '+f.name+'  ('+f.size+')';ul.appendChild(li)}}}}catch(e){{}}}}
let timer=setInterval(poll,2000);poll();
const post=u=>fetch(u,{{method:'POST',headers:{{'X-QRShare':'1'}}}});
document.getElementById('openf').onclick=()=>post('/host/open-folder');
document.getElementById('quit').onclick=async()=>{{clearInterval(timer);try{{await post('/host/quit')}}catch(e){{}}
document.querySelector('.wrap').innerHTML='<div class="card"><h1>หยุดโปรแกรมแล้ว</h1><p class="muted">ปิดแท็บนี้ได้เลย มือถือจะเชื่อมต่อไม่ได้จนกว่าจะเปิดโปรแกรมใหม่</p></div>'}};
</script></body></html>"""


NEED_QR_PAGE = f"""<!doctype html><html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QRShare</title><style>{STYLE}</style></head><body><div class="wrap"><div class="card"><h1>ลิงก์หมดอายุ</h1>
<p class="muted">กรุณาสแกน QR code ใหม่จากหน้าจอคอมพิวเตอร์</p></div></div></body></html>"""

PHONE_PAGE = f"""<!doctype html><html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QRShare</title><style>{STYLE}
.file{{padding:10px 0;border-top:1px solid var(--line)}}.file:first-child{{border-top:0}}.name{{word-break:break-all}}
.bar{{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:6px}}.bar>i{{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}}
.done .bar>i{{background:var(--ok)}}.fail .bar>i{{background:var(--err)}}.st{{font-size:13px;color:var(--muted)}}#err{{color:var(--err);min-height:24px;margin-top:8px}}
.tabs{{display:flex;gap:8px;margin-bottom:16px}}.tabs button{{background:var(--card);color:var(--text);border:1px solid var(--line);padding:10px 8px;font-size:15px}}
.tabs button.on{{background:var(--accent);color:#fff;border-color:var(--accent)}}a{{color:var(--accent)}}
.dl{{display:flex;align-items:center;gap:12px;padding:12px 0;border-top:1px solid var(--line);text-decoration:none;color:var(--text)}}.dl:first-child{{border-top:0}}
.dl .meta{{flex:1;min-width:0}}.dl .name{{word-break:break-all}}.dl .get{{color:var(--accent);font-weight:600;white-space:nowrap}}</style></head>
<body><div class="wrap">
<div class="card"><h1>QRShare</h1><div class="muted">รับ–ส่งไฟล์กับคอมพิวเตอร์</div></div>
<div class="card" id="login"><p style="margin-top:0">ใส่ PIN 6 หลักที่แสดงบนจอคอมพิวเตอร์</p>
<input id="pin" inputmode="numeric" maxlength="6" autocomplete="one-time-code" autofocus>
<div id="err"></div><button id="go">เข้าใช้งาน</button></div>
<div id="app" hidden><div class="tabs"><button id="tabUp" class="on">ส่งไฟล์เข้าคอมฯ</button><button id="tabDown">ดาวน์โหลดลงเครื่องนี้</button></div>
<div class="card" id="up"><input type="file" id="files" multiple hidden>
<button id="pick">เลือกไฟล์เพื่อส่ง</button><div id="list" style="margin-top:12px"></div></div>
<div class="card" id="down" hidden><div style="display:flex;justify-content:space-between;align-items:center"><b>ไฟล์ในคอมพิวเตอร์</b>
<a href="#" id="refresh">รีเฟรช</a></div><div id="dl" style="margin-top:8px"></div></div></div>
</div>
<script>
const T="__TOKEN__";const $=id=>document.getElementById(id);
function showUpload(){{$('login').hidden=true;$('app').hidden=false;}}
function tab(down){{$('up').hidden=down;$('down').hidden=!down;$('tabUp').className=down?'':'on';$('tabDown').className=down?'on':'';if(down)loadFiles()}}
$('tabUp').onclick=()=>tab(false);$('tabDown').onclick=()=>tab(true);$('refresh').onclick=e=>{{e.preventDefault();loadFiles()}};
async function loadFiles(){{const box=$('dl');box.innerHTML='<div class="muted">กำลังโหลด…</div>';
try{{const r=await fetch('/api/files');if(r.status===401){{box.innerHTML='<div class="muted">หมดเวลาเข้าใช้งาน กรุณาสแกน QR ใหม่</div>';return}}
const j=await r.json();box.innerHTML=j.files.length?'':'<div class="muted">ยังไม่มีไฟล์ในโฟลเดอร์</div>';
for(const f of j.files){{const a=document.createElement('a');a.className='dl';a.href='/api/download?name='+encodeURIComponent(f.name);
a.innerHTML='<div class="meta"><div class="name"></div><div class="st"></div></div><span class="get">ดาวน์โหลด</span>';
a.querySelector('.name').textContent=f.name;a.querySelector('.st').textContent=f.sizeText+' · '+f.time;box.appendChild(a)}}
}}catch(e){{box.innerHTML='<div class="muted">เชื่อมต่อคอมพิวเตอร์ไม่ได้</div>'}}}}
async function login(){{const pin=$('pin').value.trim();if(pin.length!==6){{$('err').textContent='PIN ต้องมี 6 หลัก';return}}
$('go').disabled=true;$('err').textContent='';
try{{const r=await fetch('/api/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{t:T,pin}})}});
const j=await r.json();if(r.ok){{showUpload();return}}
$('err').textContent=j.error==='locked'?'ใส่ผิดหลายครั้ง PIN เปลี่ยนแล้ว ดู PIN ใหม่บนจอคอมฯ':j.error==='bad_token'?'ลิงก์หมดอายุ กรุณาสแกน QR ใหม่':'PIN ไม่ถูกต้อง';
}}catch(e){{$('err').textContent='เชื่อมต่อคอมพิวเตอร์ไม่ได้'}}$('go').disabled=false;$('pin').select();}}
$('go').onclick=login;$('pin').onkeydown=e=>{{if(e.key==='Enter')login()}};
$('pick').onclick=()=>$('files').click();
function fmt(n){{const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<3){{n/=1024;i++}}return (i?n.toFixed(1):n)+' '+u[i]}}
function uploadOne(file,row){{return new Promise(res=>{{const x=new XMLHttpRequest();
x.open('PUT','/api/upload?name='+encodeURIComponent(file.name));
const bar=row.querySelector('i'),st=row.querySelector('.st');
x.upload.onprogress=e=>{{if(e.lengthComputable){{const p=e.loaded/e.total*100;bar.style.width=p+'%';st.textContent=fmt(e.loaded)+' / '+fmt(e.total)}}}};
x.onload=()=>{{if(x.status===200){{row.className='file done';bar.style.width='100%';st.textContent='ส่งสำเร็จ ✓'}}
else if(x.status===401){{row.className='file fail';st.textContent='หมดเวลาเข้าใช้งาน กรุณาสแกน QR ใหม่'}}
else{{row.className='file fail';st.textContent='ส่งไม่สำเร็จ'}}res()}};
x.onerror=()=>{{row.className='file fail';st.textContent='การเชื่อมต่อขาด';res()}};x.send(file)}})}}
$('files').onchange=async()=>{{const files=[...$('files').files];$('files').value='';$('pick').disabled=true;
const rows=files.map(f=>{{const d=document.createElement('div');d.className='file';
d.innerHTML='<div class="name"></div><div class="bar"><i></i></div><div class="st">รอส่ง</div>';
d.querySelector('.name').textContent=f.name;$('list').prepend(d);return d}});
for(let i=0;i<files.length;i++)await uploadOne(files[i],rows[i]);$('pick').disabled=false}};
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="QRShare: ส่งไฟล์จากมือถือเข้าคอมพิวเตอร์ผ่าน QR code")
    ap.add_argument("--folder", default=default_folder(), help="โฟลเดอร์สำหรับเก็บไฟล์")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="ไม่ต้องเปิดเบราว์เซอร์อัตโนมัติ")
    a = ap.parse_args()

    if already_running(a.port):
        print("QRShare เปิดอยู่แล้ว กำลังเปิดหน้าจอ QR code")
        if not a.no_browser:
            webbrowser.open(f"http://127.0.0.1:{a.port}/host")
        return
    folder = os.path.abspath(os.path.expanduser(a.folder))
    os.makedirs(folder, exist_ok=True)
    server = None
    for port in range(a.port, a.port + 20):
        try:
            server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
            break
        except OSError:
            continue
    if server is None:
        sys.exit("ไม่พบพอร์ตว่าง")
    port = server.server_address[1]
    Handler.state = State(folder, f"http://{lan_ip()}:{port}")
    host_url = f"http://127.0.0.1:{port}/host"
    print("QRShare กำลังทำงาน")
    print(f"  หน้าจอ QR code: {host_url}")
    print(f"  โฟลเดอร์เก็บไฟล์: {folder}")
    print("  กด Ctrl+C เพื่อหยุด")
    if not a.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(host_url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print("หยุดโปรแกรมแล้ว")


if __name__ == "__main__":
    main()
