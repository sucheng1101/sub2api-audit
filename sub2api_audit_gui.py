#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sub2API 支付回调漏洞检测 —— 图形操作界面

基于 sub2api_payment_audit.py 引擎，提供可视化配置与实时日志。

启动:
    python sub2api_audit_gui.py
    然后浏览器访问 http://127.0.0.1:8899

特性:
    - 手动配置目标地址 / 源码目录 / 检测模式 / 授权开关
    - 实时流式日志（SSE 推送，带分级着色）
    - 一键开始 / 停止 / 清空
    - 沿用引擎内置的安全锁（默认只允许本地/私有网段）
"""

import json
import os
import queue
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sub2api_payment_audit as engine  # noqa: E402

DEFAULT_PORT = 8899


class Broadcaster:
    """一对多日志广播。

    每个 SSE 连接持有独立队列，发布时投递给全部订阅者。
    早期版本用单个 Queue 做多播 —— Queue.get 是竞争消费，
    多个客户端会互相抢走消息，导致日志缺行，故改为广播 + 历史回放。
    """
    def __init__(self, keep=1200):
        self._subs = set()
        self._lock = threading.Lock()
        self._history = []
        self._keep = keep

    def subscribe(self):
        q = queue.Queue()
        with self._lock:
            self._subs.add(q)
            hist = list(self._history)
        for item in hist:
            q.put(item)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def clear(self):
        """清空历史并通知所有在线客户端清屏，避免新任务看到上一轮残留。"""
        with self._lock:
            self._history.clear()
            subs = list(self._subs)
        for q in subs:
            q.put(("clear", ""))

    def publish(self, ev, data):
        item = (ev, data)
        with self._lock:
            self._history.append(item)
            if len(self._history) > self._keep:
                del self._history[: len(self._history) - self._keep]
            subs = list(self._subs)
        for q in subs:
            q.put(item)


BUS = Broadcaster()
STATE = {"running": False, "started_at": None, "mode": None, "target": None}
STOP_FLAG = threading.Event()


# ------------------------------------------------------------------ 日志捕获

class QueueStdout:
    """把引擎的 stdout 按行投递到广播总线。"""
    def __init__(self):
        self.buf = ""

    def write(self, s):
        if not s:
            return
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            BUS.publish("log", line)

    def flush(self):
        if self.buf:
            BUS.publish("log", self.buf)
            self.buf = ""

    def isatty(self):
        return False


def _banner(title):
    print()
    print("=" * 68)
    print(f"  {title}")
    print("=" * 68)


# ------------------------------------------------------------------ 任务执行

def run_audit(cfg):
    mode = cfg.get("mode", "fingerprint")
    target = (cfg.get("target") or "http://127.0.0.1:8080").strip()
    src = (cfg.get("src") or "").strip()
    allow_remote = bool(cfg.get("allow_remote"))
    authorized = bool(cfg.get("authorized"))
    user = cfg.get("user") or None
    password = cfg.get("password") or None

    engine._LOCAL_CACHE.clear()

    if mode in ("fingerprint", "verify", "all"):
        _banner("0. 授权范围校验")
        if not engine.enforce_scope(target, allow_remote):
            print()
            print("  已中止：目标不在允许范围内")
            return

    if mode == "fingerprint":
        engine.fingerprint(target)

    elif mode == "static":
        if not src:
            print()
            print("  错误：static 模式需要填写源码目录")
            return
        engine.static_audit(src)

    elif mode == "verify":
        engine.fingerprint(target)
        if STOP_FLAG.is_set():
            return
        engine.probe_webhook(target)
        if authorized:
            if STOP_FLAG.is_set():
                return
            engine.e2e_verify(target, user, password)
        else:
            print()
            print("  [!] 未启用端到端复现（未勾选「我已获授权」）")

    elif mode == "all":
        engine.fingerprint(target)
        if STOP_FLAG.is_set():
            return
        if src:
            engine.static_audit(src)
        if STOP_FLAG.is_set():
            return
        engine.probe_webhook(target)
        if authorized:
            if STOP_FLAG.is_set():
                return
            engine.e2e_verify(target, user, password)


def worker(cfg):
    old = sys.stdout
    sys.stdout = QueueStdout()
    STATE["running"] = True
    STATE["started_at"] = time.time()
    STATE["mode"] = cfg.get("mode")
    STATE["target"] = cfg.get("target")
    BUS.publish("state", json.dumps(STATE))
    t0 = time.time()
    try:
        run_audit(cfg)
    except Exception as e:
        BUS.publish("log", f"  [-] 执行异常: {e}")
    finally:
        sys.stdout.flush()
        sys.stdout = old
        dur = time.time() - t0
        BUS.publish("log", "")
        BUS.publish("log", f"  [i] 检测结束，耗时 {dur:.1f}s")
        STATE["running"] = False
        BUS.publish("state", json.dumps(STATE))
        BUS.publish("done", "")


# ------------------------------------------------------------------ HTTP 服务

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sub2API 漏洞检测工具</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f5f3;--card:#fff;--ink:#1b1b1a;--ink2:#5a5a56;--ink3:#8a8a84;
  --line:#e4e3de;--accent:#534AB7;--accent2:#EEEDFE;--ok:#0F6E56;--bad:#A32D2D;
  --warn:#854F0B;--term:#141418;--termline:#2a2a32;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;height:100vh;display:flex;flex-direction:column}
header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 22px;display:flex;align-items:center;gap:14px;flex:none}
header h1{font-size:15px;font-weight:600;letter-spacing:-.01em}
.badge{font-size:11.5px;padding:2px 9px;border-radius:5px;background:var(--accent2);color:var(--accent);font-weight:500}
.st{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--ink3)}
.dot{width:8px;height:8px;border-radius:50%;background:#c9c8c2}
.dot.on{background:#3fa76a;animation:p 1.2s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.35}}

main{flex:1;display:grid;grid-template-columns:340px 1fr;gap:0;min-height:0}
@media(max-width:860px){main{grid-template-columns:1fr;grid-template-rows:auto 1fr}}

aside{background:var(--card);border-right:1px solid var(--line);padding:20px;overflow-y:auto}
aside h2{font-size:12px;font-weight:600;color:var(--ink3);letter-spacing:.06em;text-transform:uppercase;margin-bottom:14px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12.5px;color:var(--ink2);margin-bottom:6px;font-weight:500}
.field .hint{font-size:11.5px;color:var(--ink3);margin-top:5px;line-height:1.5}
input[type=text],input[type=password],select{
  width:100%;padding:8px 11px;border:1px solid var(--line);border-radius:8px;
  font-size:13px;font-family:var(--mono);background:#fbfbf9;color:var(--ink);outline:none}
input:focus,select:focus{border-color:var(--accent);background:#fff}
select{font-family:var(--sans)}
.chk{display:flex;align-items:flex-start;gap:9px;margin-bottom:12px;cursor:pointer}
.chk input{margin-top:3px;accent-color:var(--accent);width:15px;height:15px;flex:none}
.chk span{font-size:12.5px;color:var(--ink2);line-height:1.5}
.btns{display:flex;gap:9px;margin-top:22px}
button{flex:1;padding:10px 14px;border-radius:8px;border:1px solid var(--line);background:#fff;
  color:var(--ink);font-size:13px;font-weight:500;cursor:pointer;font-family:var(--sans);transition:.15s}
button:hover:not(:disabled){border-color:#c9c8c2;background:#fafaf8}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover:not(:disabled){background:#46409c}
button:disabled{opacity:.42;cursor:not-allowed}
.sep{height:1px;background:var(--line);margin:20px 0}

section.term{display:flex;flex-direction:column;min-height:0;background:var(--term)}
.termbar{flex:none;padding:10px 16px;border-bottom:1px solid var(--termline);display:flex;align-items:center;gap:10px}
.termbar .t{font-size:12px;color:#7d7d8a;font-family:var(--mono)}
.termbar .r{margin-left:auto;display:flex;gap:8px}
.termbar button{flex:none;padding:4px 11px;font-size:11.5px;background:transparent;color:#a4a4b0;border-color:#3a3a44}
.termbar button:hover:not(:disabled){background:#22222a;color:#e6e6e1}
#log{flex:1;overflow-y:auto;padding:14px 16px;font-family:var(--mono);font-size:12.5px;line-height:1.65;
  color:#c9c9d1;white-space:pre-wrap;word-break:break-word}
#log .ln{display:block}
.ln.ok{color:#6fd39a}
.ln.bad{color:#f08a8a}
.ln.warn{color:#e8c46a}
.ln.info{color:#7cc4e8}
.ln.head{color:#fff;font-weight:500}
.ln.dim{color:#75757f}
#log::-webkit-scrollbar{width:9px}
#log::-webkit-scrollbar-thumb{background:#33333d;border-radius:5px}
#log::-webkit-scrollbar-track{background:transparent}
.empty{color:#5a5a64;font-style:italic}
</style>
</head>
<body>
<header>
  <h1>Sub2API 支付回调漏洞检测</h1>
  <span class="badge">EasyPay 签名复用</span>
  <div class="st"><span class="dot" id="dot"></span><span id="stxt">就绪</span></div>
</header>

<main>
<aside>
  <h2>配置</h2>

  <div class="field">
    <label>检测模式</label>
    <select id="mode">
      <option value="fingerprint">fingerprint — 指纹与版本核对</option>
      <option value="static">static — 源码静态审计</option>
      <option value="verify">verify — 动态验证（非破坏）</option>
      <option value="all">all — 全部串联</option>
    </select>
    <div class="hint" id="modehint">识别目标是否为 Sub2API 系，并尝试取版本号</div>
  </div>

  <div class="field">
    <label>目标地址</label>
    <input type="text" id="target" value="http://127.0.0.1:8080" placeholder="http://127.0.0.1:8080">
    <div class="hint">默认只允许本地 / 私有网段。容器内访问宿主机用 host.docker.internal</div>
  </div>

  <div class="field">
    <label>源码目录 <span style="color:#b4b2a9">（static / all 模式）</span></label>
    <input type="text" id="src" placeholder="D:\Desktop\object\sub2api">
    <div class="hint">指向 Sub2API 仓库根目录，用于定位根因</div>
  </div>

  <div class="field">
    <label>测试账号 <span style="color:#b4b2a9">（端到端用，可选）</span></label>
    <input type="text" id="user" placeholder="账号">
    <input type="password" id="password" placeholder="密码" style="margin-top:7px">
  </div>

  <div class="sep"></div>

  <label class="chk"><input type="checkbox" id="allowRemote">
    <span>允许公网目标<br><span style="color:#b4b2a9">默认关闭。开启前请确认已获书面授权</span></span></label>

  <label class="chk"><input type="checkbox" id="authorized">
    <span>我已获授权，启用端到端复现<br><span style="color:#b4b2a9">会走完整链路，仅限自有实例</span></span></label>

  <div class="btns">
    <button class="primary" id="run">开始检测</button>
    <button id="stop" disabled>停止</button>
  </div>
</aside>

<section class="term">
  <div class="termbar">
    <span class="t" id="meta">等待任务</span>
    <div class="r">
      <button id="clear">清空</button>
      <button id="save">导出日志</button>
    </div>
  </div>
  <div id="log"><span class="empty">配置左侧参数后点击「开始检测」，日志将实时输出。</span></div>
</section>
</main>

<script>
const $ = id => document.getElementById(id);
const logEl = $('log');
let lines = [], total = 0;

const MODE_HINT = {
  fingerprint: '识别目标是否为 Sub2API 系，并尝试取版本号',
  static: '对源码做函数级审计，输出「疑似存在缺陷 / 已见缓解 / 需人工确认」',
  verify: '非破坏性探测回调端点，判断验签是否可绕',
  all: '指纹 + 静态 + 动态验证一次跑完'
};

$('mode').onchange = e => { $('modehint').textContent = MODE_HINT[e.target.value]; };

function classify(text){
  if(/^=+$/.test(text.trim())) return 'dim';
  if(/^\s*\[!\]/.test(text)) return 'warn';
  if(/^\s*\[-\]/.test(text)) return 'bad';
  if(/^\s*\[\+\]/.test(text)) return 'ok';
  if(/^\s*\[i\]/.test(text)) return 'info';
  if(/^\s{0,3}\d+\.\s/.test(text) || /^Sub2API/.test(text)) return 'head';
  return '';
}

function append(text){
  if(logEl.querySelector('.empty')) logEl.innerHTML = '';
  const d = document.createElement('span');
  d.className = 'ln ' + classify(text);
  d.textContent = text || ' ';
  logEl.appendChild(d);
  lines.push(text);
  logEl.scrollTop = logEl.scrollHeight;
  while(logEl.childNodes.length > 4000) logEl.removeChild(logEl.firstChild);
}

function setState(running){
  $('dot').classList.toggle('on', running);
  $('stxt').textContent = running ? '检测中…' : '就绪';
  $('run').disabled = running;
  $('stop').disabled = !running;
}

$('run').onclick = async () => {
  const cfg = {
    mode: $('mode').value,
    target: $('target').value.trim(),
    src: $('src').value.trim(),
    user: $('user').value.trim(),
    password: $('password').value,
    allow_remote: $('allowRemote').checked,
    authorized: $('authorized').checked
  };
  logEl.innerHTML = '';
  lines = [];
  $('meta').textContent = cfg.mode + ' @ ' + (cfg.target || '-');
  setState(true);
  const r = await fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(cfg)});
  if(!r.ok){ const t = await r.text(); append('  [-] 启动失败: ' + t); setState(false); }
};

$('stop').onclick = async () => { await fetch('/api/stop', {method:'POST'}); };

$('clear').onclick = () => { logEl.innerHTML = '<span class="empty">已清空。</span>'; lines = []; };

$('save').onclick = () => {
  const blob = new Blob([lines.join('\n')], {type:'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sub2api-audit-' + Date.now() + '.log';
  a.click();
};

function connect(){
  const es = new EventSource('/api/stream');
  es.onmessage = ev => {
    let m; try { m = JSON.parse(ev.data); } catch(e){ return; }
    if(m.type === 'log') append(m.text);
    else if(m.type === 'clear'){ logEl.innerHTML = ''; lines = []; }
    else if(m.type === 'state'){
      try { setState(JSON.parse(m.text).running); } catch(e){}
    }
    else if(m.type === 'done'){ setState(false); $('meta').textContent += ' · 已完成'; }
  };
  es.onerror = () => { es.close(); setTimeout(connect, 2000); };
}
connect();
append('  [i] 就绪。选择模式、填好配置后点击「开始检测」。');
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # 静音，避免污染控制台

    def _send(self, code, ctype, body=b""):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif self.path == "/api/state":
            self._send(200, "application/json; charset=utf-8", json.dumps(STATE))
        elif self.path == "/api/stream":
            self._stream()
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = BUS.subscribe()
        try:
            while True:
                try:
                    ev, data = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                payload = json.dumps({"type": ev, "text": data}, ensure_ascii=False)
                self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        finally:
            BUS.unsubscribe(q)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else "{}"

        if self.path == "/api/run":
            if STATE["running"]:
                self._send(409, "text/plain; charset=utf-8", "已有任务在运行")
                return
            try:
                cfg = json.loads(raw or "{}")
            except Exception:
                self._send(400, "text/plain; charset=utf-8", "配置格式错误")
                return
            STOP_FLAG.clear()
            BUS.clear()
            threading.Thread(target=worker, args=(cfg,), daemon=True).start()
            self._send(200, "application/json", '{"ok":true}')

        elif self.path == "/api/stop":
            STOP_FLAG.set()
            STATE["running"] = False
            BUS.publish("log", "  [!] 收到停止指令，任务将在当前步骤后结束")
            BUS.publish("state", json.dumps(STATE))
            self._send(200, "application/json", '{"ok":true}')

        else:
            self._send(404, "text/plain; charset=utf-8", "not found")


def find_port(start):
    for p in range(start, start + 20):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("找不到可用端口")


def main():
    # 关闭引擎的 ANSI 转义着色 —— 网页端按行首标记自行分级渲染，避免出现乱码
    engine._c = lambda txt, color: txt

    port = find_port(DEFAULT_PORT)
    url = f"http://127.0.0.1:{port}"
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    print("=" * 60)
    print("  Sub2API 支付回调漏洞检测工具 —— 图形界面")
    print("=" * 60)
    print(f"  界面地址: {url}")
    print("  按 Ctrl+C 退出")
    print()
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  已退出")
        srv.shutdown()


if __name__ == "__main__":
    main()
