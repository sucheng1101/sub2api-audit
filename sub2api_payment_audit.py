#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sub2API 易支付回调签名复用漏洞 —— 版本核对 / 检测 / 验证工具

对应问题: EasyPay 回调验签签名复用
  缺陷 A  easyPaySign 参数拼接不转义 —— 值中的 & / = 不转义，可在值内"藏"参数
  缺陷 B  return_url 的 query 未净化 + popup 模式下单签名暴露在付款人浏览器
  缺陷 C  回调侧与下单侧对同一串的解析不一致，导致伪造回调逐字节命中下单签名

三种运行模式
  fingerprint  指纹与版本识别（判断目标是不是 Sub2API 系、能否定位版本）
  static       源码静态审计（对本地源码目录做函数级审查，最容易定位根因）
  verify       动态验证（对运行中的实例做非破坏性探测，判断验签是否可绕）

安全约束（硬性）
  1) 默认只允许 回环地址 / 私有网段 目标；公网目标必须显式 --allow-remote 并确认持有授权
  2) verify 模式默认只做"非破坏性"探测：不会构造能真正通过验签的伪造回调，
     也不会让任何订单入账。只有显式加 --i-have-authorization 才启用端到端复现。

用法示例
  python sub2api_payment_audit.py fingerprint --target http://127.0.0.1:8080
  python sub2api_payment_audit.py static      --src D:\\Desktop\\object\\sub2api
  python sub2api_payment_audit.py verify      --target http://127.0.0.1:8080
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 12
UA = "sub2api-audit/1.0 (+authorized-security-testing)"

# ---------------------------------------------------------------- 输出工具

class C:
    OK = "\033[92m"
    BAD = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[96m"
    DIM = "\033[90m"
    END = "\033[0m"

def _c(txt, color):
    if os.name == "nt" and not os.environ.get("WT_SESSION"):
        return txt
    return f"{color}{txt}{C.END}"

def ok(m):   print(f"  {_c('[+]', C.OK)} {m}")
def bad(m):  print(f"  {_c('[-]', C.BAD)} {m}")
def warn(m): print(f"  {_c('[!]', C.WARN)} {m}")
def info(m): print(f"  {_c('[i]', C.INFO)} {m}")
def dim(m):  print(f"      {_c(m, C.DIM)}")

def head(t):
    print()
    print(f"{_c('=' * 68, C.DIM)}")
    print(f"  {t}")
    print(f"{_c('=' * 68, C.DIM)}")

# ---------------------------------------------------------------- 安全锁

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def target_is_local(url):
    host = urllib.parse.urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1", "host.docker.internal"):
        return True, host
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False, host
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(ip in n for n in PRIVATE_NETS):
            return True, f"{host} -> {addr}"
    return False, host

def enforce_scope(url, allow_remote):
    local, detail = target_is_local(url)
    if local:
        info(f"目标在允许范围内（{detail}）")
        return True
    if allow_remote:
        warn(f"目标为公网地址（{detail}），已由 --allow-remote 放行")
        warn("请确认你持有该目标的书面测试授权，否则立即停止")
        return True
    bad(f"目标不在允许范围内（{detail}）")
    warn("默认仅允许回环 / 私有网段。若确已授权，请加 --allow-remote 显式放行")
    return False

# ---------------------------------------------------------------- HTTP

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_WITH_PROXY = urllib.request.build_opener()
_LOCAL_CACHE = {}

def _is_local_cached(url):
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in _LOCAL_CACHE:
        _LOCAL_CACHE[host] = target_is_local(url)[0]
    return _LOCAL_CACHE[host]

def http(url, method="GET", body=None, headers=None, allow_redirect=True):
    """本地/私有目标绕过系统代理，避免代理返回 502 造成误判。"""
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = _NO_PROXY if _is_local_cached(url) else _WITH_PROXY
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read(200000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read(200000).decode("utf-8", "ignore")
        except Exception:
            return e.code, {}, ""
    except Exception as e:
        return None, {}, str(e)

# ---------------------------------------------------------------- 指纹识别

SU2A_MARKERS = {
    "/v1/models":                "OpenAI 兼容数据面",
    "/api/v1/status":            "Sub2API 控制面状态接口",
    "/api/v1/payment/webhook/easypay": "易支付回调端点",
}

def fingerprint(base):
    head("1. 指纹与版本识别")
    base = base.rstrip("/")
    hits = []

    st, hd, body = http(base + "/")
    if st:
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if m:
            title = m.group(1).strip()[:120]
        info(f"根路径 HTTP {st}，Server={hd.get('Server','?')}")
        if title:
            info(f"页面标题: {title}")
        server = (hd.get("Server") or "")
        if server:
            dim(f"Server 头: {server}")

    # 数据面/控制面探测
    for path, desc in SU2A_MARKERS.items():
        st, hd, body = http(base + path)
        if st is None:
            dim(f"{path:42s} 不可达")
            continue
        snippet = re.sub(r"\s+", " ", body)[:90]
        if st in (200, 401, 403, 405):
            hits.append((path, st, desc, snippet))
            ok(f"{path:42s} HTTP {st}  {desc}")
            if snippet:
                dim(snippet)
        else:
            dim(f"{path:42s} HTTP {st}")

    # 版本线索
    head("2. 版本线索")
    version_paths = [
        "/api/v1/status", "/api/v1/version", "/api/version", "/version.json",
        "/api/v1/system/info", "/health", "/api/health",
    ]
    found_ver = None
    for p in version_paths:
        st, hd, body = http(base + p)
        if st != 200 or not body:
            continue
        m = re.search(r'"?version"?\s*[:=]\s*"?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body, re.I)
        if m:
            found_ver = m.group(1)
            ok(f"{p} 暴露版本号: {found_ver}")
            dim(re.sub(r"\s+", " ", body)[:160])
            break
    if not found_ver:
        warn("未能从响应中直接取到版本号")

    # 前端产物版本线索
    st, hd, body = http(base + "/")
    if st == 200:
        assets = re.findall(r'/assets/[A-Za-z0-9_.\-]+\.js', body)
        if assets:
            info(f"前端构建产物 {len(assets)} 个（可用于跨版本比对）")
            for a in assets[:3]:
                dim(a)
            warn("同一 build hash 在不同部署间一致 => 可据此判定是否同版本")

    if hits:
        print()
        warn("判定: 目标具备 Sub2API 系特征，可继续做 static / verify")
        return True
    else:
        print()
        bad("未命中 Sub2API 特征路径")
        warn("可能不是 Sub2API 系，或数据面/控制面路径被改写。不要照搬结论")
        return False

# ---------------------------------------------------------------- 静态审计

AUDIT_PATTERNS = [
    {
        "id": "A",
        "name": "easyPaySign 拼接不转义",
        "why": "值中的 & / = 未转义，攻击者可在参数值内藏入额外参数，使排序拼接后与下单签名逐字节一致",
        "regex": r"func\s+\w*[Ee]asyPay\w*\s*\(|easyPaySign|EasyPaySign",
        "risk_regex": r"WriteString\s*\(\s*\w+\s*\+\s*\"=\"\s*\+\s*\w+\[",
        "safe_regex": r"QueryEscape|PathEscape|url\.Values\s*\(|escapeValue",
    },
    {
        "id": "B1",
        "name": "CanonicalizeReturnURL 未净化 query",
        "why": "只校验 scheme/host/path 而原样保留 query，攻击者可在 query 中预置 trade_status 等参数",
        "regex": r"CanonicalizeReturnURL|canonicalizeReturnURL",
        "risk_regex": r"u\.RawQuery|URL\.Query\(\)",
        "safe_regex": r"RawQuery\s*=\s*\"\"|Query\(\)\.Encode\(\)|filter\w*Query|allow\w*Query",
    },
    {
        "id": "B2",
        "name": "buildPaymentReturnURL 追加后重排序",
        "why": "把 order_id/out_trade_no/status 追加进 return_url 后按 key 排序重编码，用户注入的参数会落在串尾",
        "regex": r"buildPaymentReturnURL|BuildPaymentReturnURL",
        "risk_regex": r"sort\.|Sort\(|sort\.Strings",
        "safe_regex": r"safeAppend|validateReturnURL",
    },
    {
        "id": "C",
        "name": "回调验签与订单绑定",
        "why": "回调必须用商户侧存储的订单标识加载订单，并校验渠道、金额、币种与状态，不能依赖回调中的金额",
        "regex": r"VerifyNotification|verifyNotification|webhook/easypay",
        "risk_regex": r"n\.Amount|params\[\"money\"\]|req\.Money",
        "safe_regex": r"hmax|ConstantTimeCompare|subtle\.|order\.Amount\s*==",
    },
]

def static_audit(src):
    head("3. 源码静态审计")
    if not os.path.isdir(src):
        bad(f"目录不存在: {src}")
        return
    info(f"扫描目录: {src}")

    go_files = []
    for root, _dirs, files in os.walk(src):
        if any(x in root for x in ("\\.git", "node_modules", "\\vendor")):
            continue
        for f in files:
            if f.endswith(".go"):
                go_files.append(os.path.join(root, f))
    if not go_files:
        bad("未找到 Go 源码文件")
        return
    info(f"发现 {len(go_files)} 个 .go 文件")

    findings = []
    for pat in AUDIT_PATTERNS:
        rx = re.compile(pat["regex"])
        hits = []
        for path in go_files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            if not rx.search(text):
                continue
            risk = bool(re.search(pat["risk_regex"], text)) if pat["risk_regex"] else False
            safe = bool(re.search(pat["safe_regex"], text)) if pat["safe_regex"] else False
            hits.append((os.path.relpath(path, src), risk, safe))
        findings.append((pat, hits))

    for pat, hits in findings:
        print()
        if not hits:
            dim(f"[{pat['id']}] {pat['name']}: 未找到相关实现")
            continue
        print(f"  {_c('[' + pat['id'] + ']', C.INFO)} {pat['name']}")
        dim(f"  关注点: {pat['why']}")
        for rel, risk, safe in hits:
            tag = _c("疑似存在缺陷", C.BAD) if (risk and not safe) else (
                  _c("已见缓解措施", C.OK) if safe else _c("需人工确认", C.WARN))
            print(f"      {rel}  ->  {tag}")
    print()
    warn("静态结论仅供定位根因，成立性必须由 verify 模式在运行实例上确认")

# ---------------------------------------------------------------- 动态验证

def probe_webhook(base):
    head("4. 回调端点行为探测（非破坏性）")
    base = base.rstrip("/")
    ep = base + "/api/v1/payment/webhook/easypay"

    st, hd, body = http(ep, "GET")
    if st is None:
        bad(f"端点不可达: {ep}")
        dim(str(body)[:160])
        return
    info(f"GET  {ep} -> HTTP {st}")
    dim(re.sub(r"\s+", " ", body)[:200])

    # 场景 1：无签名
    payload = {
        "pid": "1000", "type": "alipay", "out_trade_no": "AUDIT-NOSIG-0001",
        "notify_url": base + "/api/v1/payment/webhook/easypay",
        "name": "audit probe", "money": "0.01",
        "trade_status": "TRADE_SUCCESS",
    }
    st, hd, body = http(ep, "POST", payload)
    info(f"POST 无签名 -> HTTP {st}")
    dim(re.sub(r"\s+", " ", body)[:200])
    if st == 200 and re.search(r'"?(success|ok|paid)"?', body, re.I):
        bad("无签名回调疑似被接受 —— 验签可能缺失")
    elif st in (400, 401, 403, 422):
        ok("无签名回调被拒绝 —— 验签环节存在")

    # 场景 2：错误签名
    payload["sign"] = "0" * 32
    payload["sign_type"] = "MD5"
    st, hd, body = http(ep, "POST", payload)
    info(f"POST 错误签名 -> HTTP {st}")
    dim(re.sub(r"\s+", " ", body)[:200])
    if st in (400, 401, 403, 422) or re.search(r"sign|签名|验签", body, re.I):
        ok("错误签名被拒绝 —— 服务端确实校验签名")
    else:
        warn("错误签名未获明确拒绝，需人工复核响应语义")

    # 场景 3：订单不存在
    payload["out_trade_no"] = "AUDIT-NONEXIST-" + "9" * 8
    st, hd, body = http(ep, "POST", payload)
    info(f"POST 不存在订单 -> HTTP {st}")
    dim(re.sub(r"\s+", " ", body)[:200])

    print()
    warn("以上均为非破坏性探测：未构造可通过验签的伪造回调，未产生任何入账")

def e2e_verify(base, user, password):
    head("5. 端到端复现（已显式授权）")
    warn("本模式会走完整链路：下单 -> 提取签名 -> 构造伪造回调 -> 观察入账")
    warn("仅可在你完全掌控的本地实例上运行")
    print()
    info("所需前置：")
    dim("1) 目标已启用易支付，且为 popup(submit.php) 模式")
    dim("2) 持有一个可发起充值下单的普通账号")
    dim("3) 已知商户 pid 与下单接口路径")
    print()
    bad("当前未实现自动下单与签名提取 —— 原因：该步骤强依赖目标的具体支付渠道配置，")
    bad("自动执行容易误伤。建议按下面步骤在本地手工完成，或提供 pid/下单路径后再补全。")
    print()
    print("  手工验证步骤：")
    dim("1. 用测试账号发起一笔最小金额充值，选择易支付 + popup 模式")
    dim("2. 从跳转的支付 URL 中取出 sign 参数（popup 模式下会暴露在浏览器）")
    dim("3. 构造回调：return_url 只编码到 status=success，让 &trade_status=TRADE_SUCCESS 以裸 & 成为顶层参数")
    dim("4. 携带第 2 步拿到的 sign，POST 到 /api/v1/payment/webhook/easypay")
    dim("5. 观察该订单状态与账户余额是否被改为已支付")
    print()
    print("  判定：")
    dim("漏洞成立 -> 回调被接受且订单变为已支付（余额增加）")
    dim("已修复   -> 回调被拒绝，或订单金额/状态校验不通过")

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Sub2API 易支付回调签名复用漏洞 —— 检测与验证",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["fingerprint", "static", "verify", "all"],
                    help="运行模式")
    ap.add_argument("--target", default="http://127.0.0.1:8080", help="目标地址")
    ap.add_argument("--src", help="本地源码目录（static 模式）")
    ap.add_argument("--user", help="测试账号")
    ap.add_argument("--password", help="测试账号密码")
    ap.add_argument("--allow-remote", action="store_true",
                    help="允许公网目标（需自行确认授权）")
    ap.add_argument("--i-have-authorization", action="store_true",
                    help="显式确认已获授权，启用端到端复现")
    ap.add_argument("--json", help="将结果同时写入 JSON 文件")
    args = ap.parse_args()

    print()
    print(_c("Sub2API 易支付回调签名复用 —— 检测与验证工具", C.INFO))
    dim("仅用于已获授权的目标。默认只允许本地/私有网段。")

    result = {"mode": args.mode, "target": args.target, "src": args.src}

    if args.mode in ("fingerprint", "verify", "all"):
        head("0. 授权范围校验")
        if not enforce_scope(args.target, args.allow_remote):
            sys.exit(2)

    if args.mode == "fingerprint":
        result["is_sub2api"] = fingerprint(args.target)

    elif args.mode == "static":
        if not args.src:
            bad("static 模式需要 --src 指定源码目录")
            sys.exit(1)
        static_audit(args.src)

    elif args.mode == "verify":
        if not fingerprint(args.target):
            warn("指纹未命中，仍继续做端点探测")
        probe_webhook(args.target)
        if args.i_have_authorization:
            e2e_verify(args.target, args.user, args.password)
        else:
            print()
            warn("未启用端到端复现（缺 --i-have-authorization）")

    elif args.mode == "all":
        result["is_sub2api"] = fingerprint(args.target)
        if args.src:
            static_audit(args.src)
        probe_webhook(args.target)
        if args.i_have_authorization:
            e2e_verify(args.target, args.user, args.password)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        ok(f"结果已写入 {args.json}")

    print()

if __name__ == "__main__":
    main()
