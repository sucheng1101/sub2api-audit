#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sub2API EasyPay callback audit CLI and local GUI in one file."""

import argparse
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TIMEOUT = 10
USER_AGENT = "sub2api-audit/2.0"
WEBHOOK_PATH = "/api/v1/payment/webhook/easypay"
PRIVATE_NETS = tuple(map(ipaddress.ip_network, (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "::1/128", "fc00::/7", "169.254.0.0/16", "fe80::/10",
)))
STOP_FLAG = threading.Event()


class Colors:
    OK = "\033[92m"
    BAD = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[96m"
    DIM = "\033[90m"
    END = "\033[0m"


def color(text, code):
    if os.name == "nt" and not os.environ.get("WT_SESSION"):
        return text
    return f"{code}{text}{Colors.END}"


def line(tag, text, code=Colors.INFO):
    print(f"  {color(tag, code)} {text}")


def heading(text):
    print(f"\n{'=' * 68}\n  {text}\n{'=' * 68}")


def _parse_target(target):
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty http(s) URL")
    parsed = urllib.parse.urlsplit(target.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an http(s) URL with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("credentials in target URLs are not supported")
    if parsed.query or parsed.fragment:
        raise ValueError("target base URL must not include a query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid target port: {exc}") from exc
    return parsed


def _target_url(base, path):
    parsed = _parse_target(base)
    base_path = parsed.path.rstrip("/")
    suffix = path if path.startswith("/") else "/" + path
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path + suffix, "", ""))


def target_is_local(target):
    parsed = _parse_target(target)
    host = parsed.hostname.lower().rstrip(".")
    if host in ("localhost", "host.docker.internal"):
        return True, host
    try:
        addresses = {ipaddress.ip_address(item[4][0].split("%")[0])
                     for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))}
    except (OSError, ValueError):
        return False, host
    local = bool(addresses) and all(any(addr in net for net in PRIVATE_NETS) for addr in addresses)
    return local, f"{host} -> {', '.join(sorted(map(str, addresses)))}"


def enforce_scope(target, allow_remote=False):
    try:
        local, detail = target_is_local(target)
    except ValueError as exc:
        line("[-]", str(exc), Colors.BAD)
        return False
    if local or allow_remote:
        line("[i]", f"target: {detail}")
        if not local:
            line("[!]", "remote target explicitly enabled; confirm the address is in scope", Colors.WARN)
        return True
    line("[-]", f"target is not local/private ({detail}); pass --allow-remote to continue", Colors.BAD)
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
_WITH_PROXY = urllib.request.build_opener(_NoRedirect())
_LOCAL_CACHE = {}


def _is_local_cached(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in _LOCAL_CACHE:
        try:
            _LOCAL_CACHE[host] = target_is_local(url)[0]
        except ValueError:
            _LOCAL_CACHE[host] = False
    return _LOCAL_CACHE[host]


def http_request(url, method="GET", body=None, headers=None):
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    request_headers.update(headers or {})
    data = None
    if isinstance(body, dict):
        data = urllib.parse.urlencode(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(body, str):
        data = body.encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    opener = _NO_PROXY if _is_local_cached(url) else _WITH_PROXY
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status, dict(response.headers), response.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers), exc.read(200000).decode("utf-8", "replace")
        except OSError:
            return exc.code, {}, ""
    except Exception as exc:
        return None, {}, str(exc)


FINGERPRINT_PATHS = {
    "/v1/models": "OpenAI-compatible models endpoint",
    "/api/v1/status": "Sub2API status endpoint",
    WEBHOOK_PATH: "EasyPay webhook route",
}


def fingerprint(base):
    heading("1. Target fingerprint")
    hits = []
    for path, description in FINGERPRINT_PATHS.items():
        if STOP_FLAG.is_set():
            break
        status, headers, body = http_request(_target_url(base, path))
        if status is None:
            line("[i]", f"{path}: unreachable ({body[:120]})", Colors.DIM)
            continue
        snippet = re.sub(r"\s+", " ", body)[:120]
        if status in (200, 401, 403, 405):
            hits.append({"path": path, "status": status, "description": description})
            line("[+]", f"{path} -> HTTP {status}: {description}", Colors.OK)
        else:
            line("[i]", f"{path} -> HTTP {status}", Colors.DIM)
        if snippet:
            print(f"      {snippet}")
    if hits:
        line("[i]", f"matched {len(hits)} Sub2API-related endpoint(s)")
    else:
        line("[!]", "no known endpoint fingerprint matched; customized routes may differ", Colors.WARN)
    return hits


def _json_object(body):
    try:
        value = json.loads(body)
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError):
        return None


def _explicit_success(body):
    value = _json_object(body)
    if not value:
        return False
    message = str(value.get("message", value.get("msg", ""))).lower()
    error_text = " ".join(str(value.get(key, "")) for key in ("error", "detail", "reason")).lower()
    rejection_text = " ".join((message, error_text))
    rejected = re.search(
        r"\b(invalid|incorrect|fail(?:ed|ure)?|error|reject(?:ed)?|denied|mismatch)\b|"
        r"失败|拒绝|无效|错误|不匹配|订单不存在",
        rejection_text,
    )
    if rejected:
        return False
    for key in ("success", "is_success", "paid"):
        if value.get(key) is True:
            return True
    status = str(value.get("status", "")).strip().lower()
    if status in ("success", "accepted", "paid"):
        return True
    code = str(value.get("code", "")).strip().lower()
    positive = re.search(r"\b(success|accepted|paid|credited|ok)\b|成功|已支付|已入账", message)
    return code in ("0", "200", "success") and bool(positive) and not rejected


def _explicit_signature_rejection(status, body):
    value = _json_object(body)
    fields = ("error", "message", "msg", "detail", "reason")
    text = " ".join(str(value.get(key, "")) for key in fields).lower() if value else str(body).lower()
    mentions_signature = re.search(r"\bsign(?:ature)?\b|签名|验签", text)
    rejected = re.search(r"\b(invalid|incorrect|fail(?:ed|ure)?|error|reject(?:ed)?|mismatch)\b|无效|错误|失败|不匹配", text)
    return bool(mentions_signature and rejected)


def probe_webhook(base):
    heading("2. Webhook behavior probe (random order, no side effects expected)")
    endpoint = _target_url(base, WEBHOOK_PATH)
    status, _, body = http_request(endpoint)
    if status is None:
        line("[-]", f"webhook is unreachable: {body[:160]}", Colors.BAD)
        return [{"case": "GET", "result": "unreachable", "status": None}]
    line("[i]", f"GET {WEBHOOK_PATH} -> HTTP {status}")
    results = []
    payload = {
        "pid": "AUDIT_PID", "type": "alipay",
        "out_trade_no": f"AUDIT-NOSIG-{int(time.time())}-{os.getpid()}",
        "notify_url": endpoint, "name": "audit probe", "money": "0.01",
        "trade_status": "TRADE_SUCCESS",
    }
    for case in ("missing-signature", "invalid-signature", "random-order"):
        if STOP_FLAG.is_set():
            break
        current = dict(payload)
        if case == "invalid-signature":
            current.update(sign="0" * 32, sign_type="MD5")
        elif case == "random-order":
            current.update(sign="0" * 32, sign_type="MD5",
                           out_trade_no=f"AUDIT-NONEXIST-{int(time.time())}-{os.getpid()}")
        code, _, response = http_request(endpoint, "POST", current)
        compact = re.sub(r"\s+", " ", response)[:240]
        if _explicit_success(response):
            outcome = "explicit-success-response; investigate server-side handling"
            line("[-]", f"{case}: HTTP {code}; {outcome}", Colors.BAD)
        elif _explicit_signature_rejection(code, response):
            outcome = "explicit-signature-rejection"
            line("[+]", f"{case}: HTTP {code}; {outcome}", Colors.OK)
        elif code in (400, 401, 403, 404, 409, 422):
            outcome = "request-rejected; reason not necessarily signature validation"
            line("[i]", f"{case}: HTTP {code}; {outcome}")
        else:
            outcome = "insufficient-evidence"
            line("[!]", f"{case}: HTTP {code}; response does not prove acceptance or signature validation", Colors.WARN)
        if compact:
            print(f"      {compact}")
        results.append({"case": case, "result": outcome, "status": code, "response": compact})
    line("[i]", "HTTP 200 or generic response text alone is not treated as proof of callback acceptance")
    return results


def _brace_delta(line_text, state):
    delta = 0
    i = 0
    while i < len(line_text):
        ch = line_text[i]
        nxt = line_text[i + 1] if i + 1 < len(line_text) else ""
        if state == "line":
            break
        if state == "block":
            if ch == "*" and nxt == "/":
                state = "normal"
                i += 2
                continue
            i += 1
            continue
        if state in ("string", "rune"):
            if ch == "\\":
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "rune" and ch == "'"):
                state = "normal"
            i += 1
            continue
        if state == "raw":
            if ch == "`":
                state = "normal"
            i += 1
            continue
        if ch == "/" and nxt == "/":
            state = "line"
            break
        if ch == "/" and nxt == "*":
            state = "block"
            i += 2
            continue
        if ch == '"':
            state = "string"
        elif ch == "'":
            state = "rune"
        elif ch == "`":
            state = "raw"
        elif ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1
    return delta, "normal" if state == "line" else state


def strip_go_comments(text):
    """Blank Go comments while preserving strings and line numbers."""
    out = []
    state = "normal"
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line":
            if ch == "\n":
                out.append(ch)
                state = "normal"
            else:
                out.append(" ")
            i += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                out.extend("  ")
                state = "normal"
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        if state in ("string", "rune", "raw"):
            out.append(ch)
            if state != "raw" and ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "rune" and ch == "'") or (state == "raw" and ch == "`"):
                state = "normal"
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out.extend("  ")
            state = "line"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            out.extend("  ")
            state = "block"
            i += 2
            continue
        out.append(ch)
        if ch == '"':
            state = "string"
        elif ch == "'":
            state = "rune"
        elif ch == "`":
            state = "raw"
        i += 1
    return "".join(out)


def parse_go_functions(text):
    functions = []
    current = None
    depth = 0
    opened = False
    state = "normal"
    declaration = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
    source_lines = text.splitlines()
    code_lines = strip_go_comments(text).splitlines()
    for number, (source_line, code_line) in enumerate(zip(source_lines, code_lines), 1):
        match = declaration.match(code_line)
        if current is None and match:
            current = {"name": match.group(1), "line": number, "lines": []}
            depth = 0
            opened = False
            state = "normal"
        delta, state = _brace_delta(code_line, state if current else "normal")
        if current is not None:
            current["lines"].append((number, source_line, code_line))
            depth += delta
            opened = opened or depth > 0
            if opened and depth <= 0:
                functions.append(current)
                current = None
                depth = 0
                opened = False
                state = "normal"
    if current is not None:
        functions.append(current)
    return functions


RULES = [
    {"id": "A", "name": "EasyPay signature canonicalization", "function": re.compile(r"easypaysign", re.I),
     "description": "Signature input should encode parameter values unambiguously."},
    {"id": "B1", "name": "return_url query normalization", "function": re.compile(r"canonicalizereturnurl", re.I),
     "description": "Validated return URLs should discard or allowlist caller-supplied query keys."},
    {"id": "B2", "name": "payment return URL parameter merge", "function": re.compile(r"buildpaymentreturnurl", re.I),
     "description": "Server return parameters should not be merged with untrusted query keys."},
    {"id": "C", "name": "callback order and amount binding", "function": re.compile(r"verifynotification|easypay.*webhook", re.I),
     "description": "Callback signature, stored order, status, and amount must be validated together."},
]

RISK = "疑似存在风险"
MITIGATED = "已见针对性缓解"
MANUAL = "需要人工确认"


def _body_lines(function):
    return function["lines"]


def _evidence(function, patterns):
    matches = []
    for number, source, code in _body_lines(function):
        if any(pattern.search(code) for pattern in patterns):
            matches.append({"line": number, "text": source.strip()[:220]})
            if len(matches) == 3:
                break
    if not matches:
        matches.append({"line": function["line"], "text": f"func {function['name']}"})
    return matches


def _analyze_rule(rule_id, function, body):
    if rule_id == "A":
        write_call = re.compile(r"(?:WriteString|Fprintf)\s*\([^\n)]*\)", re.I)
        raw_value_append = re.compile(
            r"(?:WriteString|Fprintf)\s*\([^\n)]*(?:\+\s*[\"']=[\"']\s*\+\s*(?:params|values|vals)\s*\[|%s\s*=\s*%s)", re.I
        )
        encoded_values = bool(re.search(r"(?:url\.)?Values\s*\{", body) and re.search(r"\.Encode\s*\(\s*\)", body))
        escaped_param = bool(re.search(r"(?:url\.)?QueryEscape\s*\(", body, re.I))
        direct_concat = bool(raw_value_append.search(body))
        has_write = bool(write_call.search(body))
        if direct_concat and not (encoded_values or escaped_param):
            status = RISK
        elif encoded_values or escaped_param:
            status = MITIGATED
        elif has_write or direct_concat:
            status = MANUAL
        else:
            return None
        patterns = [raw_value_append, re.compile(r"QueryEscape|url\.Values|\.Encode\s*\(", re.I), write_call]
    elif rule_id == "B1":
        query_clear = re.compile(r"\b\w+\.RawQuery\s*=\s*(?:\"\"|'')")
        query_rebuild = re.compile(r"\b\w+\.RawQuery\s*=\s*\w+\.Encode\s*\(\s*\)")
        allowlist = re.compile(r"(?i)(?:allowedQueryKeys|allowlistedQueryKeys|filterAllowedQuery|sanitizeReturnQuery|allowlist|whitelist)")
        returns_url = bool(re.search(r"return\s+\w+\.String\s*\(\s*\)", body))
        parses_url = bool(re.search(r"url\.Parse\s*\(", body))
        query_touched = bool(re.search(r"RawQuery|\.Query\s*\(\s*\)", body))
        if not (returns_url and parses_url):
            return MANUAL if query_touched else None
        if query_clear.search(body) or allowlist.search(body):
            status = MITIGATED
        elif query_rebuild.search(body) and re.search(r"\.Query\s*\(\s*\)", body):
            status = MANUAL
        elif query_touched or returns_url:
            status = RISK
        else:
            status = MANUAL
        patterns = [query_clear, allowlist, query_rebuild, re.compile(r"url\.Parse|RawQuery|\.Query\s*\(|\.String\s*\(", re.I)]
    elif rule_id == "B2":
        query_assignment = re.search(r"\b(\w+)\s*(?::=|=)\s*\w+\.Query\s*\(\s*\)", body)
        query_name = query_assignment.group(1) if query_assignment else ""
        edits_query = bool(query_name and re.search(
            r"\b" + re.escape(query_name) + r"\.(?:Set|Add|Del)\s*\(", body, re.I
        ))
        encode_query = bool(query_name and re.search(
            r"RawQuery\s*=\s*" + re.escape(query_name) + r"\.Encode\s*\(\s*\)", body, re.I
        ))
        values_assignment = re.search(
            r"\b(\w+)\s*(?::=|=)\s*(?:url\.)?Values\s*\{\s*\}|"
            r"\b(\w+)\s*(?::=|=)\s*make\s*\(\s*(?:url\.)?Values\s*\)",
            body, re.I,
        )
        values_name = next((group for group in (values_assignment.groups() if values_assignment else ()) if group), "")
        new_values = bool(values_name)
        values_encode_query = bool(values_name and re.search(
            r"RawQuery\s*=\s*" + re.escape(values_name) + r"\.Encode\s*\(\s*\)", body, re.I
        ))
        clear_query = re.search(r"\b\w+\.RawQuery\s*=\s*(?:\"\"|'')", body)
        allowlist = re.compile(
            r"(?i)(?:allowedQueryKeys|allowlistedQueryKeys|filterAllowedQuery|"
            r"sanitizeReturnQuery|allowlist|whitelist|approvedQuery)")
        has_server_fields = bool(re.search(
            r"\.(?:Set|Add)\s*\(\s*[\"'](?:order_id|out_trade_no|status|resume_token)[\"']",
            body, re.I,
        ))
        clear_before_parse = bool(
            clear_query and query_assignment and clear_query.start() < query_assignment.start()
        )
        query_is_filtered = bool(allowlist.search(body) or re.search(
            r"\b\w+\s*=\s*(?:filter|sanitize|clean|allow)[A-Za-z0-9_]*\s*\(\s*" + re.escape(query_name or "QUERY") + r"\s*\)",
            body, re.I,
        ))
        if new_values and has_server_fields and values_encode_query and not query_assignment:
            status = MITIGATED
        elif query_assignment and edits_query and encode_query:
            status = MITIGATED if (query_is_filtered or clear_before_parse) else RISK
        elif query_assignment or edits_query or encode_query:
            status = MANUAL
        else:
            return None
        patterns = [re.compile(
            r"\.Query\s*\(|\.(?:Set|Add|Del)\s*\(|RawQuery\s*=|Values\s*\{|"
            r"allowedQueryKeys|filterAllowedQuery|sanitizeReturnQuery|allowlist|whitelist",
            re.I,
        )]
    else:
        callback_fields = re.compile(r"(?:\.Get\s*\(\s*[\"'](?:money|trade_status|out_trade_no|sign|sign_type)[\"']|\[\s*[\"'](?:money|trade_status|out_trade_no|sign|sign_type)[\"']\s*\])", re.I)
        parses_input = re.compile(r"ParseQuery|ParseForm|ParseMultipartForm|\.Get\s*\(", re.I)
        success_status = re.compile(r"TRADE_SUCCESS|TRADE_FINISHED|TRADE_BUYER_SIGNED", re.I)
        has_callback = bool(callback_fields.search(body))
        if not has_callback or not parses_input.search(body):
            return None
        has_success_gate = bool(success_status.search(body))
        signature_check = bool(re.search(
            r"(?i)(?:\b(?:verify|check|validate)\w*(?:sign|signature)\w*\s*\(|"
            r"\b(?:hmac\.Equal|subtle\.ConstantTimeCompare|rsa\.Verify\w*|ed25519\.Verify)\s*\(|"
            r"(?:expected|calculated|computed)\w*\s*(?:!=|==)|\bsign\s*(?:!=|==))",
            body,
        ))
        order_lookup = bool(re.search(
            r"(?i)(?:\b(?:find|get|load|query|lookup|fetch)\w*order\s*\(|"
            r"\b(?:db|repo|orderRepo|orders?)\.(?:First|Find|Get|Where|Query|Take)\s*\(|"
            r"\b(?:order|storedOrder)\s*:=\s*[^\n]*(?:Order|order))",
            body,
        ))
        amount_check = bool(re.search(
            r"(?i)(?:(?:order|storedOrder)\.(?:Amount|AmountCents|Total|TotalCents)[^\n]{0,160}"
            r"(?:!=|==|Equal|Cmp|money|amount)|(?:money|amount)[^\n]{0,160}"
            r"(?:order|storedOrder)\.(?:Amount|AmountCents|Total|TotalCents)|"
            r"(?:amount|money)\s*:\s*=\s*[^\n]*(?:order|storedOrder)\.)",
            body,
        ))
        status_check = bool(re.search(
            r"(?i)(?:(?:order|storedOrder)\.(?:Status|PaidAt|SettledAt)[^\n]{0,140}"
            r"(?:!=|==|already|paid|success|pending|completed)|"
            r"(?:already\s+paid|idempot|duplicate|processed|settled)|"
            r"(?:order|storedOrder)\.Status\s*[:=]=)",
            body,
        ))
        controls = sum((signature_check, order_lookup, amount_check, status_check))
        if controls == 4:
            status = MITIGATED
        elif has_success_gate and controls <= 1:
            status = RISK
        else:
            status = MANUAL
        patterns = [callback_fields, success_status, re.compile(
            r"(?i)verify\w*(?:sign|signature)|hmac\.Equal|ConstantTimeCompare|"
            r"\w*Order|order\.(?:Amount|AmountCents|Status)|idempot|already\s+paid",
        )]
    return status, _evidence(function, patterns)


def _go_files(root):
    ignored = {".git", "vendor", "node_modules", "build", "dist"}
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in ignored and not name.startswith(".")]
        for name in files:
            if name.endswith(".go"):
                yield os.path.join(current, name)


def analyze_source(src):
    if not os.path.isdir(src):
        raise ValueError(f"source directory does not exist: {src}")
    paths = list(_go_files(src))
    if not paths:
        return [], 0
    findings = []
    for path in paths:
        if STOP_FLAG.is_set():
            break
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as stream:
                text = stream.read()
        except OSError:
            continue
        for function in parse_go_functions(text):
            body = "\n".join(item[2] for item in function["lines"])
            for rule in RULES:
                if not rule["function"].search(function["name"]):
                    continue
                detection = _analyze_rule(rule["id"], function, body)
                if detection is None:
                    continue
                status, evidence = detection
                findings.append({
                    "rule": rule["id"], "name": rule["name"], "status": status,
                    "file": os.path.relpath(path, src), "function": function["name"],
                    "function_line": function["line"], "description": rule["description"],
                    "evidence": evidence,
                })
    return findings, len(paths)


def static_audit(src):
    heading("3. Go source audit")
    try:
        findings, file_count = analyze_source(src)
    except ValueError as exc:
        line("[-]", str(exc), Colors.BAD)
        return {"files_scanned": 0, "findings": []}
    line("[i]", f"scanned {file_count} Go source file(s) under {src}")
    if not file_count:
        line("[!]", "no Go source files found", Colors.WARN)
    if not findings:
        line("[i]", "no matching implementation functions found; confirm the target revision or custom names")
    for finding in findings:
        code = Colors.BAD if finding["status"] == RISK else Colors.OK if finding["status"] == MITIGATED else Colors.WARN
        line("[+]" if finding["status"] == MITIGATED else "[!]" if finding["status"] == MANUAL else "[-]",
             f"[{finding['rule']}] {finding['name']}: {finding['status']}", code)
        print(f"      {finding['file']}:{finding['function_line']} function={finding['function']}")
        print(f"      {finding['description']}")
        for evidence in finding["evidence"]:
            print(f"      L{evidence['line']}: {evidence['text']}")
    return {"files_scanned": file_count, "findings": findings}


def run_audit(mode, target, src=None, allow_remote=False):
    result = {"mode": mode, "target": target, "src": src}
    needs_network = mode in ("fingerprint", "verify", "all")
    if needs_network and not enforce_scope(target, allow_remote):
        result["scope_error"] = True
        return result
    if mode == "fingerprint":
        result["fingerprint"] = fingerprint(target)
    elif mode == "static":
        if not src:
            raise ValueError("static mode requires --src")
        result["static"] = static_audit(src)
    elif mode == "verify":
        result["fingerprint"] = fingerprint(target)
        if not STOP_FLAG.is_set():
            result["probe"] = probe_webhook(target)
    elif mode == "all":
        result["fingerprint"] = fingerprint(target)
        if src and not STOP_FLAG.is_set():
            result["static"] = static_audit(src)
        if not STOP_FLAG.is_set():
            result["probe"] = probe_webhook(target)
    return result


GUI_PAGE = r"""<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sub2API Audit</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f4f5f4;color:#202321;font:14px system-ui,"Microsoft YaHei",sans-serif;height:100vh;display:flex;flex-direction:column}header{height:54px;background:#fff;border-bottom:1px solid #dfe3df;display:flex;align-items:center;padding:0 18px;gap:12px}h1{font-size:15px;margin:0;font-weight:650}.badge{color:#176b58;background:#e9f4ee;padding:4px 8px;border-radius:4px;font-size:11px}main{display:grid;grid-template-columns:minmax(270px,340px) 1fr;flex:1;min-height:0}aside{background:white;border-right:1px solid #dfe3df;padding:18px;overflow:auto}.field{margin-bottom:15px}label{display:block;color:#555d57;font-size:12px;margin-bottom:6px}input,select{width:100%;height:34px;border:1px solid #cfd6d0;border-radius:4px;padding:6px 9px;background:#fff;color:#202321;font:13px ui-monospace,monospace}input:focus,select:focus{outline:2px solid #a7d4c2;border-color:#4e9379}.hint{font-size:11px;color:#747d76;line-height:1.5;margin-top:5px}.check{display:flex;gap:8px;align-items:flex-start;margin:12px 0}.check input{width:15px;height:15px;margin:1px 0 0;accent-color:#176b58}.check label{margin:0;line-height:1.5}.buttons{display:flex;gap:8px;margin-top:20px}button{height:34px;padding:0 13px;border:1px solid #cfd6d0;border-radius:4px;background:#fff;cursor:pointer;color:#29312c}button.primary{background:#176b58;color:white;border-color:#176b58}button:disabled{opacity:.5;cursor:default}.terminal{display:flex;flex-direction:column;min-width:0;background:#171a18;color:#d5ddd7}.toolbar{height:42px;border-bottom:1px solid #343a36;display:flex;align-items:center;padding:0 14px;color:#9da9a1;font-size:12px}.toolbar button{margin-left:auto;height:27px;background:#202521;color:#d5ddd7;border-color:#404842}#log{padding:13px 15px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.6 ui-monospace,Consolas,monospace}.ln{display:block}.warn{color:#e4c16a}.bad{color:#f08c85}.ok{color:#79d1a5}.info{color:#86c2dd}@media(max-width:760px){body{height:auto;min-height:100vh}main{grid-template-columns:1fr;grid-template-rows:auto minmax(50vh,1fr)}aside{border-right:0;border-bottom:1px solid #dfe3df}}
</style><header><h1>Sub2API EasyPay Audit</h1><span class="badge">CLI + GUI</span></header><main><aside>
<div class="field"><label for="mode">Detection mode</label><select id="mode"><option value="fingerprint">fingerprint</option><option value="static">static source audit</option><option value="verify">webhook probe</option><option value="all">all</option></select></div>
<div class="field"><label for="target">Target address</label><input id="target" value="http://127.0.0.1:8080"><div class="hint">Network modes default to local/private addresses. Redirects are not followed.</div></div>
<div class="field"><label for="src">Go source directory</label><input id="src" placeholder="path/to/sub2api"></div>
<div class="check"><input type="checkbox" id="remote"><label for="remote">Enable an explicitly selected remote target</label></div>
<div class="buttons"><button id="run" class="primary">Run audit</button><button id="stop" disabled>Stop</button></div>
</aside><section class="terminal"><div class="toolbar"><span id="meta">Ready</span><button id="clear">Clear</button></div><div id="log">Choose a mode and start a run.</div></section></main>
<script>
const $=id=>document.getElementById(id), log=$('log');let es;
function add(t){if(log.textContent==='Choose a mode and start a run.')log.textContent='';let n=document.createElement('span');n.className='ln '+(/\[-\]/.test(t)?'bad':/\[!\]/.test(t)?'warn':/\[\+\]/.test(t)?'ok':/\[i\]/.test(t)?'info':'');n.textContent=t||' ';log.appendChild(n);log.scrollTop=log.scrollHeight}
$('run').onclick=async()=>{log.textContent='';const cfg={mode:$('mode').value,target:$('target').value.trim(),src:$('src').value.trim(),allow_remote:$('remote').checked};$('meta').textContent=cfg.mode+' @ '+cfg.target;$('run').disabled=true;$('stop').disabled=false;try{let r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});if(!r.ok)add('[-] '+await r.text())}catch(e){add('[-] '+e)}};
$('stop').onclick=()=>fetch('/api/stop',{method:'POST'});$('clear').onclick=()=>log.textContent='';
function connect(){es=new EventSource('/api/stream');es.onmessage=e=>{let x=JSON.parse(e.data);if(x.type==='log')add(x.text);if(x.type==='state'){let s=JSON.parse(x.text);$('run').disabled=s.running;$('stop').disabled=!s.running}if(x.type==='done')$('meta').textContent+=' · complete'};es.onerror=()=>{es.close();setTimeout(connect,1500)}}connect();
</script></html>"""


class Broadcaster:
    def __init__(self, history_limit=1000):
        self.lock = threading.Lock()
        self.subscribers = set()
        self.history = []
        self.history_limit = history_limit

    def publish(self, event, text):
        item = (event, text)
        with self.lock:
            self.history.append(item)
            self.history = self.history[-self.history_limit:]
            subscribers = tuple(self.subscribers)
        for subscriber in subscribers:
            subscriber.put(item)

    def clear(self):
        with self.lock:
            self.history.clear()

    def subscribe(self):
        subscriber = queue.Queue()
        with self.lock:
            self.subscribers.add(subscriber)
            history = tuple(self.history)
        for item in history:
            subscriber.put(item)
        return subscriber

    def unsubscribe(self, subscriber):
        with self.lock:
            self.subscribers.discard(subscriber)


BUS = Broadcaster()
STATE = {"running": False, "mode": None, "target": None}
STATE_LOCK = threading.Lock()


def _state_snapshot():
    with STATE_LOCK:
        return dict(STATE)


def _claim_gui_run(cfg):
    with STATE_LOCK:
        if STATE["running"]:
            return False
        STATE.update(running=True, mode=cfg.get("mode"), target=cfg.get("target"))
    return True


def _finish_gui_run():
    with STATE_LOCK:
        STATE["running"] = False
        return dict(STATE)


class _QueueOutput:
    def __init__(self):
        self.buffer = ""

    def write(self, text):
        self.buffer += text
        while "\n" in self.buffer:
            item, self.buffer = self.buffer.split("\n", 1)
            BUS.publish("log", item)

    def flush(self):
        if self.buffer:
            BUS.publish("log", self.buffer)
            self.buffer = ""

    def isatty(self):
        return False


def _gui_worker(cfg):
    old_stdout = sys.stdout
    sys.stdout = _QueueOutput()
    start = time.time()
    try:
        run_audit(cfg.get("mode", "fingerprint"), cfg.get("target", "http://127.0.0.1:8080"),
                  cfg.get("src"), cfg.get("allow_remote", False))
    except Exception as exc:
        BUS.publish("log", f"  [-] run error: {exc}")
    finally:
        sys.stdout.flush()
        sys.stdout = old_stdout
        BUS.publish("state", json.dumps(_finish_gui_run(), ensure_ascii=False))
        BUS.publish("log", f"  [i] finished in {time.time() - start:.1f}s")
        BUS.publish("done", "")


class _GUIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _send(self, status, content_type, body):
        encoded = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", GUI_PAGE)
        elif self.path == "/api/state":
            self._send(200, "application/json; charset=utf-8", json.dumps(_state_snapshot(), ensure_ascii=False))
        elif self.path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            subscriber = BUS.subscribe()
            try:
                while True:
                    try:
                        event, text = subscriber.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    else:
                        data = json.dumps({"type": event, "text": text}, ensure_ascii=False)
                        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                BUS.unsubscribe(subscriber)
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            self._send(413, "text/plain; charset=utf-8", "request too large")
            return
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if self.path == "/api/run":
            try:
                cfg = json.loads(raw or "{}")
                if not isinstance(cfg, dict) or cfg.get("mode") not in ("fingerprint", "static", "verify", "all"):
                    raise ValueError("invalid mode")
                if cfg["mode"] == "static" and not cfg.get("src"):
                    raise ValueError("static mode requires a source directory")
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, "text/plain; charset=utf-8", str(exc))
                return
            if not _claim_gui_run(cfg):
                self._send(409, "text/plain; charset=utf-8", "audit already running")
                return
            STOP_FLAG.clear()
            BUS.clear()
            BUS.publish("state", json.dumps(_state_snapshot(), ensure_ascii=False))
            threading.Thread(target=_gui_worker, args=(cfg,), daemon=True).start()
            self._send(200, "application/json", '{"ok":true}')
        elif self.path == "/api/stop":
            STOP_FLAG.set()
            self._send(200, "application/json", '{"ok":true}')
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")


def start_gui(port=8899, open_browser=True):
    server = None
    for candidate in range(port, port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), _GUIHandler)
            break
        except OSError:
            continue
    if server is None:
        raise RuntimeError("no available local GUI port in the requested range")
    url = f"http://127.0.0.1:{server.server_address[1]}"
    line("[i]", f"GUI listening at {url}")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sub2API EasyPay callback audit (CLI and GUI)")
    parser.add_argument("mode", nargs="?", choices=("fingerprint", "static", "verify", "all"))
    parser.add_argument("--target", default="http://127.0.0.1:8080", help="base address to inspect")
    parser.add_argument("--src", help="local Go source directory for static mode")
    parser.add_argument("--allow-remote", action="store_true", help="explicitly enable a remote target")
    parser.add_argument("--json", dest="json_path", help="write machine-readable results to this path")
    parser.add_argument("--gui", action="store_true", help="start the local browser GUI")
    parser.add_argument("--no-browser", action="store_true", help="do not open the GUI in a browser")
    parser.add_argument("--port", type=int, default=8899, help="GUI port (default: 8899)")
    args = parser.parse_args(argv)
    if args.gui or args.mode is None:
        start_gui(args.port, not args.no_browser)
        return 0
    if args.mode in ("static", "all") and not args.src and args.mode == "static":
        parser.error("static mode requires --src")
    try:
        result = run_audit(args.mode, args.target, args.src, args.allow_remote)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
        line("[i]", f"JSON report written to {args.json_path}")
    return 2 if result.get("scope_error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
