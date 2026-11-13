#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# -*- coding: utf-8 -*-
"""ompweb - a phone-sized control page for the smb-job-channel file-hub channel.

Run it on the OFFICE box (the one that can reach the public share AND is on HQ_Office):

    python ctl/mobile/ompweb.py --port 8787

Then from any phone or laptop on HQ_Office Wi-Fi:

    http://<office-wlan-ip>:8787/

Security model
  * The page is only a thin skin over ompremote: every job it queues is sealed with the
    same PSK (ctl/omp.key), so the share never sees plaintext job bodies.
  * Access needs a token from ctl/mobile/tokens.json (one per person, role viewer|operator).
    The token is exchanged for an HttpOnly cookie at /login, so it does not sit in URLs or
    browser history.
  * rate limit per token, code size cap, optional machine allowlist, audit log of every
    submit in ctl/mobile/audit.jsonl (who / from where / what).
  * HTTP on the LAN only - do not port-forward this anywhere.

Endpoints
  GET  /                      mobile page
  POST /login                 {token} -> cookie
  GET  /api/machines          machine list with beat/version/sealed state
  GET  /api/job?m=&id=        one result (decrypted)
  POST /api/run               {machine, code, timeout} -> {id}
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CTL = os.path.dirname(HERE)
sys.path.insert(0, CTL)
import ompremote as o  # noqa: E402  (reuse the sealed-job machinery)

TOKENS_FILE = os.path.join(HERE, "tokens.json")
AUDIT_FILE = os.path.join(HERE, "audit.jsonl")
COOKIE = "ompweb"
MAX_CODE = 64 * 1024
REQ_PER_MIN = 40

_state = {"hits": {}, "lock": threading.Lock()}


def load_tokens() -> dict:
    try:
        with open(TOKENS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        return {}
    out = {}
    for t in data.get("tokens", []):
        tok = str(t.get("token", "")).strip()
        if not tok:
            continue
        role = str(t.get("role", "viewer")).lower()
        # scope: an operator token must be granted machines explicitly ("*" for the owner).
        # Default for a viewer is read-only-everything; for operator it is NOTHING, so a typo
        # in tokens.json can never hand out the fleet by accident.
        machines = t.get("machines")
        if machines is None:
            machines = ["*"] if role in ("admin", "viewer") else []
        if isinstance(machines, str):
            machines = [machines]
        machines = [str(m).strip().upper() for m in machines if str(m).strip()]
        kinds = t.get("kinds")
        if kinds is None:
            kinds = ["ps", "ls", "fetch", "job"] if role != "admin" else ["*"]
        if isinstance(kinds, str):
            kinds = [kinds]
        kinds = [str(k).strip().lower() for k in kinds if str(k).strip()]
        out[tok] = {"name": str(t.get("name", "?")), "role": role,
                    "machines": machines, "kinds": kinds,
                    "expires": str(t.get("expires", "") or "")}
    return out


def _expired(info: dict) -> bool:
    """tokens.json "expires": "YYYY-MM-DD" -> that day is the last usable day."""
    exp = (info or {}).get("expires") or ""
    if not exp:
        return False
    try:
        return time.strftime("%Y-%m-%d") > exp
    except Exception:
        return False


def _machine_ok(info: dict, machine: str) -> bool:
    """fnmatch against the per-token machine list; an empty list means 'no machines'."""
    import fnmatch
    m = (machine or "").upper()
    for pat in (info or {}).get("machines") or []:
        if pat == "*" or fnmatch.fnmatchcase(m, pat):
            return True
    return False


def _kind_ok(info: dict, kind: str) -> bool:
    k = (kind or "").lower()
    allowed = (info or {}).get("kinds") or []
    return "*" in allowed or k in allowed


def audit(event: dict) -> None:
    event["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass


def rate_ok(token: str) -> bool:
    now = time.time()
    with _state["lock"]:
        slots = [t for t in _state["hits"].get(token, []) if now - t < 60]
        if len(slots) >= REQ_PER_MIN:
            _state["hits"][token] = slots
            return False
        slots.append(now)
        _state["hits"][token] = slots
        return True


def hub() -> "o.Hub":
    h = o.Hub(o.hub_env() or o.DEFAULT_HUB)
    h.mirrors = [m for m in o.DEFAULT_MIRRORS if m.rstrip("\\/") != h.root]
    return h


def machine_row(h, name: str) -> dict:
    hb = o.read_json(os.path.join(h.root, "machines", name, "state", "heartbeat.json")) or {}
    beat = str(hb.get("now") or "")
    age = None
    if beat:
        try:
            age = int(time.time() - time.mktime(time.strptime(beat, "%Y-%m-%dT%H:%M:%S")))
            # machine clocks are not in sync (some sit minutes ahead); a negative age is
            # clock skew, not a future heartbeat - clamp it so the UI stays readable
            if age < 0:
                age = 0
        except Exception:
            age = None
    return {
        "machine": name,
        "host": hb.get("hostname"),
        "version": hb.get("body_version"),
        "beat_age": age,
        "sealed": bool(hb.get("psk")) and hb.get("allow_legacy") is False,
        "phase": hb.get("phase"),
        "last_job": hb.get("last_job"),
    }


PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>机台控制</title>
<style>
:root{color-scheme:dark}
body{margin:0;font:15px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;background:#11141a;color:#e6e9ef}
header{position:sticky;top:0;background:#161b24;padding:10px 14px;display:flex;gap:10px;align-items:center;border-bottom:1px solid #222a36}
h1{font-size:15px;margin:0;font-weight:600}
.wrap{padding:14px;display:grid;gap:12px}
select,textarea,button,input{font:inherit;color:inherit;background:#1b212b;border:1px solid #2a3341;border-radius:10px;padding:10px;width:100%;box-sizing:border-box}
textarea{min-height:120px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
button{background:#2563eb;border-color:#2563eb;font-weight:600}
button.ghost{background:#1b212b;border-color:#2a3341}
pre{background:#0d1016;border:1px solid #222a36;border-radius:10px;padding:12px;overflow:auto;max-height:46vh;font-size:12.5px;white-space:pre-wrap}
.row{display:flex;gap:10px}
.meta{color:#93a0b4;font-size:12.5px}
.tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11.5px;border:1px solid #2a3341;margin-left:6px}
.ok{color:#4ade80;border-color:#1d4d33}.warn{color:#fbbf24;border-color:#4d3f1d}
#login{max-width:380px;margin:12vh auto}
</style></head><body>
<div id="login" class="wrap" hidden>
  <h1>机台控制 · 登录</h1>
  <input id="tok" type="password" placeholder="访问令牌 (tokens.json 里的 token)" autocomplete="off">
  <button onclick="login()">进入</button>
  <div class="meta" id="loginmsg"></div>
</div>
<div id="app" hidden>
  <header><h1>机台控制</h1><span class="meta" id="who"></span>
    <button class="ghost" style="width:auto;margin-left:auto;padding:6px 12px" onclick="logout()">退出</button></header>
  <div class="wrap">
    <input id="q" placeholder="筛选机台 / 线体" oninput="render()">
    <select id="m"></select>
    <div class="meta" id="mmeta"></div>
    <textarea id="code" placeholder="PowerShell 片段，例如：Get-Process | Select -First 5"></textarea>
    <div class="row">
      <button onclick="run()">运行</button>
      <button class="ghost" onclick="refresh()">刷新机台</button>
    </div>
    <pre id="out">就绪。</pre>
  </div>
</div>
<script>
let machines=[], me='';
const $=id=>document.getElementById(id);
async function api(p,opt){const r=await fetch(p,opt||{});if(r.status===401){showLogin();throw new Error('未登录')}return r.json()}
function showLogin(){$('app').hidden=true;$('login').hidden=false}
async function login(){
  const tok=$('tok').value.trim(); if(!tok) return;
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
  if(r.ok){$('login').hidden=true;$('app').hidden=false;boot()}else{$('loginmsg').textContent='令牌无效'}
}
async function logout(){await fetch('/logout',{method:'POST'});showLogin()}
async function boot(){
  const s=await api('/api/me'); me=s.name+' ('+s.role+')'; $('who').textContent=me;
  await refresh();
}
async function refresh(){
  const d=await api('/api/machines'); machines=d.machines||[]; render();
}
function render(){
  const q=$('q').value.toLowerCase();
  const list=machines.filter(m=>!q||m.machine.toLowerCase().includes(q));
  const sel=$('m'); const cur=sel.value;
  sel.innerHTML=list.map(m=>`<option value="${m.machine}">${m.machine}${m.sealed?'':' (未加固)'}</option>`).join('');
  if(cur&&list.some(m=>m.machine===cur)) sel.value=cur;
  sel.onchange=meta; meta();
}
function meta(){
  const m=machines.find(x=>x.machine===$('m').value); if(!m){$('mmeta').textContent='';return}
  $('mmeta').innerHTML=`${m.host||''} · v${m.version||'?'} · 心跳 ${m.beat_age==null?'?':m.beat_age+'s'}前
    <span class="tag ${m.sealed?'ok':'warn'}">${m.sealed?'已加固/加密':'未加固(明文)'}</span>`;
}
async function run(){
  const machine=$('m').value, code=$('code').value;
  if(!machine||!code.trim()) return;
  $('out').textContent='提交中…';
  const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({machine,code,timeout:120})});
  const d=await r.json();
  if(!r.ok){$('out').textContent='失败: '+(d.error||r.status);return}
  $('out').textContent='job '+d.id+' 已排队，等待结果…';
  poll(d.machine,d.id,0);
}
async function poll(machine,id,n){
  if(n>120){$('out').textContent+='\\n(超时，仍可能在后端运行)';return}
  const d=await api('/api/job?m='+encodeURIComponent(machine)+'&id='+encodeURIComponent(id));
  if(d.status){
    $('out').textContent=`[${d.status} exit=${d.exit}] ${d.machine}\\n`+(d.stdout||'')+(d.stderr?('\\n--- stderr ---\\n'+d.stderr):'');
    return;
  }
  setTimeout(()=>poll(machine,id,n+1),1500);
}
(async()=>{try{const s=await fetch('/api/me');if(s.ok){$('app').hidden=false;boot()}else showLogin()}catch(e){showLogin()}})();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ompweb/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), extra=extra)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if n <= 0 or n > MAX_CODE + 4096:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8")) or {}
        except Exception:
            return {}

    def _token(self) -> str:
        c = SimpleCookie(self.headers.get("Cookie") or "")
        if COOKIE in c:
            return c[COOKIE].value
        return (self.headers.get("X-OMP-Token") or "").strip()

    def _who(self):
        toks = load_tokens()
        tok = self._token()
        info = toks.get(tok)
        if not info:
            return None
        if not rate_ok(tok):
            return "rate-limited"
        return info

    def _need(self, role: str = "viewer"):
        info = self._who()
        if info == "rate-limited":
            self._json(429, {"error": "请求过于频繁"})
            return None
        if not info:
            self._json(401, {"error": "未登录或令牌无效"})
            return None
        if _expired(info):
            audit({"event": "expired", "who": info["name"], "ip": self.client_address[0]})
            self._json(401, {"error": "令牌已过期，请向机队负责人换新"})
            return None
        if role == "operator" and info["role"] not in ("operator", "admin"):
            self._json(403, {"error": "只读账号不能下发作业"})
            return None
        return info

    def log_message(self, fmt, *args):  # keep the console quiet, audit does the work
        pass

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if path == "/api/audit":
            info = self._need()
            if not info:
                return
            if info["role"] != "admin":
                return self._json(403, {"error": "只有负责人能看审计"})
            try:
                with open(AUDIT_FILE, encoding="utf-8") as f:
                    lines = f.readlines()[-300:]
            except OSError:
                lines = []
            return self._json(200, {"lines": [l.rstrip() for l in lines]})
        if path == "/api/me":
            info = self._need()
            if not info:
                return
            return self._json(200, {"name": info["name"], "role": info["role"]})
        if path == "/api/machines":
            info = self._need()
            if not info:
                return
            h = hub()
            try:
                names = sorted(d for d in os.listdir(os.path.join(h.root, "machines"))
                               if os.path.isdir(os.path.join(h.root, "machines", d)) and not d.startswith("_"))
            except OSError as exc:
                return self._json(503, {"error": f"公盘不可达: {exc}"})
            rows = [machine_row(h, n) for n in names]
            rows.sort(key=lambda r: (r["beat_age"] is None, r["beat_age"] or 0))
            return self._json(200, {"machines": rows})
        if path == "/api/job":
            info = self._need()
            if not info:
                return
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            _m = str((q.get("machine") or [""])[0]).strip().upper()
            if _m and not _machine_ok(info, _m):
                return self._json(403, {"error": f"没有 {_m} 的权限（向负责人申请）"})
            m = (q.get("m") or [""])[0]
            jid = (q.get("id") or [""])[0]
            if not m or not jid:
                return self._json(400, {"error": "需要 m 与 id"})
            h = hub()
            root, path_r = o.find_result(h, m, jid)
            if not path_r:
                return self._json(200, {})
            try:
                raw = o.read_json(path_r) or {}
                res = o.open_result_blob(raw, jid)
            except SystemExit as exc:
                return self._json(500, {"error": f"结果无法解密/校验: {exc}"})
            wh = o.Hub(root)
            res["stdout"] = (o.read_text(wh.m(m, "out", jid + ".stdout.txt")) or
                             o.read_text(wh.m(m, "run", jid + ".stdout.txt")))[:20000]
            res["stderr"] = o.read_text(wh.m(m, "run", jid + ".stderr.txt"))[:4000]
            return self._json(200, {k: res.get(k) for k in ("id", "machine", "status", "exit", "stdout", "stderr")})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            body = self._body()
            tok = str(body.get("token", "")).strip()
            info = load_tokens().get(tok)
            if not info:
                audit({"event": "login-fail", "ip": self.client_address[0]})
                return self._json(401, {"error": "令牌无效"})
            audit({"event": "login", "who": info["name"], "ip": self.client_address[0]})
            return self._json(200, {"name": info["name"], "role": info["role"]},
                              extra={"Set-Cookie": f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"})
        if path == "/logout":
            return self._json(200, {"ok": True},
                              extra={"Set-Cookie": f"{COOKIE}=; Path=/; HttpOnly; Max-Age=0"})
        if path == "/api/run":
            info = self._need("operator")
            if not info:
                return
            body = self._body()
            machine = str(body.get("machine", "")).strip().upper()
            code = str(body.get("code", ""))
            kind = str(body.get("kind", "ps")).strip().lower()
            if not _machine_ok(info, machine):
                audit({"event": "deny-machine", "who": info["name"], "machine": machine,
                       "ip": self.client_address[0]})
                return self._json(403, {"error": f"没有 {machine} 的权限（向负责人申请）"})
            if not _kind_ok(info, kind):
                audit({"event": "deny-kind", "who": info["name"], "machine": machine, "kind": kind,
                       "ip": self.client_address[0]})
                return self._json(403, {"error": f"没有 {kind} 类作业的权限（向负责人申请）"})
            timeout = int(body.get("timeout") or 120)
            if not machine or not code.strip():
                return self._json(400, {"error": "需要 machine 与 code"})
            if len(code) > MAX_CODE:
                return self._json(413, {"error": "脚本过大"})
            allow = (os.environ.get("OMPWEB_ALLOW") or "").upper()
            if allow and machine not in {a.strip() for a in allow.split(",") if a.strip()}:
                return self._json(403, {"error": "该机台不在允许列表"})
            h = hub()
            try:
                machine = o.resolve_machine(h, machine)
            except SystemExit as exc:
                return self._json(404, {"error": f"没有这台机台: {exc}"})
            if not o.can_seal(h, machine):
                return self._json(409, {"error": "该机台尚未加固（会明文下发），先在办公机跑 rollout"})
            try:
                jid = o.submit(h, machine, {"kind": "ps", "timeout": timeout, "note": f"web:{info['name']}"},
                               payload=code.encode("utf-8"))
            except SystemExit as exc:
                return self._json(503, {"error": f"提交失败: {exc}"})
            audit({"event": "run", "who": info["name"], "ip": self.client_address[0],
                   "machine": machine, "job": jid, "bytes": len(code)})
            return self._json(200, {"id": jid, "machine": machine})
        return self._json(404, {"error": "not found"})


def lan_ip() -> str:
    """The address a phone should use: the interface that actually reaches the hub.

    A plain 8.8.8.8 probe answers with the USB tether NIC on this box, which phones on
    HQ_Office cannot reach. Probe the file server instead.
    """
    host = "192.0.2.10"
    try:
        parsed = urllib.parse.urlparse(o.DEFAULT_HUB.replace("\\", "//").replace("/", "//", 1))
        if parsed.hostname:
            host = parsed.hostname
    except Exception:
        pass
    for target in (host, "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.6)
            s.connect((target, 445 if target == host else 80))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except OSError:
            continue
    return "127.0.0.1"


def main() -> None:
    ap = argparse.ArgumentParser(description="phone control page for the smb-job-channel bridge")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    if not os.path.isfile(TOKENS_FILE):
        print(f"missing {TOKENS_FILE}; create it from tokens.example.json first", file=sys.stderr)
        sys.exit(2)
    if not o.SECRET:
        print("warning: ctl/omp.key not found - only read-only endpoints will work", file=sys.stderr)
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"ompweb on http://{lan_ip()}:{args.port}/  (bind {args.bind})", flush=True)
    print(f"tokens: {', '.join(t['name'] for t in load_tokens().values()) or '(none)'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
