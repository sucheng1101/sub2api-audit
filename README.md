# Sub2API 易支付回调签名复用 —— 检测与验证工具

针对《Sub2api 存在支付回调计费漏洞（中转站长注意）》所述问题，做**版本核对 → 检测 → 验证**三件事。

提供两种用法：**图形界面**（推荐）与**命令行**。

---

## 图形界面

```bash
python sub2api_audit_gui.py
```

启动后自动打开浏览器（默认 `http://127.0.0.1:8899`，端口被占用会自动顺延）。
加 `--no-browser` 可禁止自动打开。

界面分左右两栏：

- **左栏 · 配置**
  - 检测模式（fingerprint / static / verify / all）
  - 目标地址（默认 `http://127.0.0.1:8080`）
  - 源码目录（static / all 时启用）
  - 测试账号密码（端到端时用，可选）
  - 两个开关：`允许公网目标`、`我已获授权（启用端到端复现）`
  - 按钮：开始检测 / 停止
- **右栏 · 实时日志**
  - 流式推送（SSE），按 `[+] [-] [!] [i]` 分级着色
  - 自动滚动，最多保留 4000 行
  - 支持「清空」与「导出日志」

每次点击开始检测会先清屏，不会混入上一轮日志。

---

## 三种模式

| 模式 | 作用 | 是否触网 |
|---|---|---|
| `fingerprint` | 判断目标是不是 Sub2API 系、能否定位版本 | 只读 |
| `static` | 对本地源码做函数级审计，定位根因 | 不触网 |
| `verify` | 对运行中的实例做非破坏性探测，判断验签能否绕过 | 只读 |
| `all` | 三者串联 | 混合 |

## 用法

```bash
# 1. 版本与指纹核对（本地实例）
python sub2api_payment_audit.py fingerprint --target http://127.0.0.1:8080

# 2. 源码静态审计（指向本地源码根目录）
python sub2api_payment_audit.py static --src D:\Desktop\object\sub2api

# 3. 动态验证（非破坏性）
python sub2api_payment_audit.py verify --target http://127.0.0.1:8080

# 4. 一次跑完，并输出 JSON
python sub2api_payment_audit.py all --target http://127.0.0.1:8080 --src D:\Desktop\object\sub2api --json report.json
```

## 安全约束（脚本内置）

1. **默认只允许回环 / 私有网段目标**。公网目标必须显式加 `--allow-remote`。
2. `verify` 模式**默认不做端到端复现** —— 不会构造能真正通过验签的伪造回调，也不会让任何订单入账。
3. 只有显式加 `--i-have-authorization` 才会进入端到端流程。
4. 本地 / 私有目标自动绕过系统代理（避免代理返回 502 造成误判）。

## 检测原理

对应文章里的三处缺陷：

| 编号 | 缺陷 | 静态检测点 |
|---|---|---|
| A | `easyPaySign` 参数拼接不转义，值里的 `&` / `=` 可"藏"参数 | 是否存在 `WriteString(k + "=" + v)` 式拼接而无 `QueryEscape` |
| B1 | `CanonicalizeReturnURL` 只校验 scheme/host/path，query 原样保留 | 是否处理 / 丢弃 / 白名单化 `RawQuery` |
| B2 | `buildPaymentReturnURL` 追加参数后按 key 排序重编码 | 是否用 `sort` 且未校验注入参数位置 |
| C | 回调侧与下单侧对同一串解析不一致 | 是否从数据库订单取金额，而非回调参数 |

静态扫描结果有三种标记：`疑似存在缺陷` / `已见缓解措施` / `需人工确认`。**静态结论只用于定位根因，成立性必须由 `verify` 在运行实例上确认。**

## 判定标准

**漏洞成立**（旧版本）：
- 回调端点接受伪造的 `trade_status=TRADE_SUCCESS` 且订单状态变为已支付 / 余额增加

**已修复**：
- 回调被拒绝；或 `return_url` 中的注入参数被净化；或订单金额校验不通过

## verify 模式的探测动作

只做三件无副作用的事：

1. `GET` 回调端点，看是否可达
2. `POST` **无签名**回调 → 若被接受，说明验签缺失
3. `POST` **错误签名**回调 → 若被拒绝，说明验签环节存在

这一步能区分"验签完全缺失"和"验签存在但可被签名复用绕过"。后者需要端到端才能确认。

## 端到端复现（需显式授权）

`--i-have-authorization` 会打印手工步骤。之所以没有全自动，是因为它强依赖目标的支付渠道配置（商户 pid、下单路径、popup 模式），自动执行容易误伤。

手工链路：

```
下单(popup 模式，return_url 预置 trade_status) 
  -> 从支付 URL 取出 sign
  -> 构造回调：return_url 只编码到 status=success，
     让 &trade_status=TRADE_SUCCESS 以裸 & 升为顶层参数
  -> 带该 sign POST 到 /api/v1/payment/webhook/easypay
  -> 观察订单与余额
```

## 回归测试样本

`testdata/easypay_vulnerable.go` 是一个含全部三处缺陷的模拟实现，用于验证静态审计能力：

```bash
python sub2api_payment_audit.py static --src testdata
```

预期检出：A / B1 / B2 判为「疑似存在缺陷」，C 判为「需人工确认」。
