# Sub2API EasyPay Audit

统一的 EasyPay 回调审计工具，包含命令行、浏览器 GUI、源码静态审计和本地运行实例探测。两个历史入口 `sub2api_audit_gui.py` 与 `sub2api_payment_audit.py` 保留为兼容启动器，核心实现集中在 `sub2api_audit.py`。

## 快速开始

```powershell
py sub2api_audit.py --help
py sub2api_audit.py fingerprint --target http://127.0.0.1:8080
py sub2api_audit.py static --src C:\path\to\sub2api
py sub2api_audit.py verify --target http://127.0.0.1:8080
py sub2api_audit.py all --target http://127.0.0.1:8080 --src C:\path\to\sub2api
```

没有提供模式时启动 GUI：

```powershell
py sub2api_audit.py --gui --port 8899
```

浏览器访问 `http://127.0.0.1:8899`。历史入口也可直接启动同一 GUI：

```powershell
py sub2api_audit_gui.py
py sub2api_payment_audit.py verify --target http://127.0.0.1:8080
```

## 检测模式

- `fingerprint`：读取目标的公开响应特征，辅助判断应用类型和版本线索。
- `static`：扫描 `--src` 下的 Go 文件，输出函数级证据和行号。
- `verify`：先做指纹，再对 webhook 入口发送低影响探测请求。
- `all`：组合指纹、静态审计和动态探测。

## 静态规则

- `A` 签名规范化：检查参数值是否通过 `url.Values.Encode()` 或等价转义进入签名串。
- `B1` `return_url` 查询净化：检查原始 query 是否清空或按允许列表重建。
- `B2` 返回地址参数合并：检查服务端订单字段是否写入独立的参数表，避免继承调用方 query。
- `C` 回调绑定：检查签名、订单号、金额、成功状态和幂等状态是否联合校验。

状态分为 `疑似存在风险`、`已见针对性缓解` 和 `需要人工确认`。每条结果带文件、函数、行号和最多三条证据。

## 指定地址与范围

网络模式默认接受本机、私有网段和容器本地地址。重定向不跟随，探测请求使用固定超时和低影响参数。对明确纳入范围的公网测试地址，显式添加：

```powershell
py sub2api_audit.py verify --target https://TARGET --allow-remote
```

`--allow-remote` 只解除地址范围检查，仍建议在测试环境运行并保留服务端日志。

## JSON 报告

```powershell
py sub2api_audit.py all `
  --target http://127.0.0.1:8080 `
  --src C:\path\to\sub2api `
  --json audit-report.json
```

报告包含运行模式、目标、指纹、静态结果、探测结果和范围状态，适合接入回归脚本。

## 本地样例与测试

`testdata/easypay_vulnerable.go` 展示未编码签名、原始返回 query 合并和缺少回调绑定的样例；`testdata/easypay_safe.go` 展示对应的缓解写法。样例只用于本地静态规则回归。

```powershell
py -m py_compile sub2api_audit.py test_sub2api_audit.py
py -m unittest -v
py sub2api_audit.py static --src testdata
git diff --check
```

## 目录

```text
sub2api_audit.py          # 统一核心、CLI、GUI
sub2api_audit_gui.py      # GUI 兼容入口
sub2api_payment_audit.py  # 旧 CLI 兼容入口
test_sub2api_audit.py     # 单元测试
testdata/                 # 安全/风险 Go 样例
```
