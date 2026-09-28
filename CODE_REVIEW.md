# WiFi 监控工具 代码审查报告

审查时间：2026-09-28
审查对象：`wifi_monitor.py`（654 行）、`config.json`、`test_wifi_monitor.py`
实测环境：Windows 中文版 / Intel Wi-Fi 6E AX211 / 网关 192.168.1.1 / SSID TP-LINK_5G_D3DA

> 本报告全部结论均已在真机实测验证，非纯静态推断。

---

## P0 功能缺陷（导致误报、错误诊断结论）

### 1. WiFi 信号强度永远读不到（中文系统 100% 必现）

`check_wifi_signal()` 第 103 行用 `if "Signal" in line and "%" in line` 匹配，但中文版 Windows 的
`netsh wlan show interfaces` 输出的是 **`信号 : 80%`**，不是 `Signal`。

实测证据：数据库 `checks` 表 31 条记录，`signal` 字段**全部为 None**。

连锁后果（已在网络完全健康时复现）：

```
gateway_ok=true, internet_ok=true, dns_ok=true   ← 网络完全正常
primary_cause = "wifi"
summary = "TP-LINK_5G_D3DA 当前 WiFi 信号较弱（0%），这会导致断线和丢包。
           这不是完全断网，但很可能是高延迟或间歇性掉线的根因。"
```

因为 `parse_signal_strength(None)` 返回 0，而 `0 < 50` 命中了弱信号分支。
**只要用户网络正常，程序就一定会报「信号较弱（0%）」，这条诊断完全不可信。**

修复：改用正则同时兼容中英文，例如
`re.match(r"\s*(?:信号|Signal)\s*[:：]\s*(.+)$", line)`。
另外第 108 行的 SSID 判定靠 `"BSSID" not in line` 排除 AP 行，建议一并改成正则，避免 SSID 名里含 "bssid" 时误判。

### 2. 「DNS 检测」根本没测 DNS，而且与「外网检测」是同一个 IP

第 123-124 行：

```python
internet_ok = ping_host(target_host or "8.8.8.8")
dns_ok      = ping_host(dns_target)      # config["dns"] = "8.8.8.8"
```

两者 ping 的是**同一个地址**，而且 ICMP ping IP 根本不经过 DNS 解析流程——这个「DNS 检测」测得是空。

实测复现（模拟断网 gateway=True / internet=False / dns=False）：

```
primary_cause = "dns"
summary = "X 网关正常，但 DNS 解析失败..." 
推荐 = ["切换到 8.8.8.8 / 1.1.1.1 等公共 DNS", ...]
```

**外网真断时被判成「DNS 解析失败」，还建议用户切换到当前正在探测的 8.8.8.8。**
由于 `elif not dns_ok` 排在 `elif not internet_ok` 之前，且两者取值相同，
`internet` 这一整个分支实际上是**死代码**，永远不会命中。

修复：DNS 用域名解析验证（`socket.getaddrinfo("www.baidu.com", 80)` 或 `nslookup`），
外网用 TCP 连 `www.baidu.com:443` 或 ping 国内可达 IP，两者彻底解耦。

### 3. 默认探测目标在国内不可靠

`8.8.8.8` 在国内普遍被丢包/限制。日志中已出现同一轮 `internet=True, dns=False` 的自相矛盾记录
（两个探测指向同一 IP 却给出相反结果），证明该目标抖动严重。

建议：DNS 用 `223.5.5.5`（阿里）/ `114.114.114.114`，外网目标用 `www.baidu.com:443`。

### 4. `failure_threshold: 3` 是死配置，完全没有防抖

`config.json` 声明了 `"failure_threshold": 3`，但 `monitor_loop` 从未读取它
（实测：源码中不出现该键名）。首次检测失败就立刻建立断网事件并写日志/发邮件。

叠加 `ping -n 1` 单包探测本身易瞬时丢包，实际产生严重抖动。
真实日志：

```
09:13:08 Outage started
09:13:29 Recovered  (duration 21s)
09:13:47 Outage started
```

20 秒内反复横跳，「断网次数」统计完全失真。

修复：连续失败达到 `failure_threshold` 次才判定断网；恢复也建议连续成功 N 次才算恢复。

---

## P1 稳定性与数据完整性

### 5. 监控线程没有任何异常保护，异常即静默死亡

`monitor_loop` 的 `while` 循环体内**没有 try/except**（实测确认源码中不存在）。
任何一次异常都会让线程直接退出，而界面状态还停留在「监控中」——
用户以为在监控，实际早就停了，且没有任何提示。

风险点：sqlite 被锁（GUI 线程同时读写）、`load_config` 读到半个文件、
`record_check` / `add_event` 抛错等。

修复：循环体整体包 try/except，记录异常并把状态推给界面（如「监控异常，请重启」）。

### 6. 「停止→立即开始」存在线程竞态

`stop_monitoring()` 只 `set()` 事件、**不 `join()` 线程**；
`start_monitoring()` 看到事件已 set 就立刻创建新线程。
旧线程最长还要睡满 `check_interval_seconds`（20s）才退出，期间：

- 两个线程同时写库 → 重复记录；
- 更严重：旧线程结尾的 `app.safe_set_status("Stopped")` 会覆盖新线程刚设的「监控中」，
  界面状态错乱。

修复：`stop_monitoring` 里 `join(timeout)` 等旧线程真正退出后再允许启动。

### 7. 进行中的断网永远不会落库

`add_event()` 只在「恢复」分支被调用，`outage_start` 只存在内存变量里。
程序关闭、崩溃、或用户手动停止时若正处于断网中，这次断网记录**彻底丢失**。

日志证据：`09:13:47 Outage started` 之后再无 recovered 行——这次断网被丢弃了。

修复：程序退出 / 停止监控时，若 `outage_start` 非空，以 `status='ongoing'` 落库。

### 8. `send_email` 无超时，且阻塞监控线程

`smtplib.SMTP(smtp_server, smtp_port)` 未传 `timeout`，SMTP 无响应时会长时间挂起，
而它是从监控线程同步调用的 → **整个检测循环停摆**。

修复：传 `timeout=10`，并把发信丢到独立线程/队列里异步执行。

### 9. 邮件 TLS 方式不完整 + 明文密码

- 只支持 `starttls()`（587 端口）；465 端口需要 `smtplib.SMTP_SSL`，否则直接失败。
- SMTP 密码明文存放在 `config.json`。当前 `email_enabled=false` 尚无实际风险，
  启用前建议改环境变量或 Windows 凭据管理器。

---

## P2 报表与细节问题

### 10. SVG 图表 Y 轴刻度全是「0分钟」，且柱子与刻度错位 20px

实测生成的 `daily_wifi_report.svg`：

```xml
<line ... y1='40.0' />  <text ...>0分钟</text>   ← max=41秒，41/60 取整 = 0
<line ... y1='100.0'/>  <text ...>0分钟</text>
<line ... y1='160.0'/>  <text ...>0分钟</text>
<line ... y1='220.0'/>  <text ...>0分钟</text>
<line ... y1='280.0'/>  <text ...>0分钟</text>
```

`int(value/60)` 在最大时长不足 60 秒时全部取整为 0，**5 个刻度标签全废**。

同时坐标系不自洽：刻度线画在 y=40~280（`margin_top=40`），
而柱子的零线是写死的 `300`、高度按 `chart_height=240` 缩放 →
最高柱顶落在 y=60，永远够不到最上面的刻度线 y=40，**视觉错位 20px**。

修复：① 刻度值自适应单位（秒/分钟），至少保证不全部取整为 0；
② 零线统一用 `y0 = margin_top + chart_height` 计算，别写死 300。

### 11. 无数据时的占位 SVG 会缩成 300×150 小方块

第 275 行的占位 SVG 用了 `width='100%' height='100%'` 却**没有 viewBox**，
放进 `<img>` 时会退化成浏览器默认的 300×150 尺寸。补上 viewBox 即可。

### 12. 每 20 秒闪一次黑色命令行窗口

`run_cmd()` 传了 `creationflags=0`（等于没设）。若用 `pythonw.exe` 或无控制台方式启动，
`ping` / `netsh` 每次调用都会弹出控制台窗口一闪。

修复：`creationflags=subprocess.CREATE_NO_WINDOW`。

### 13. `main()` 只捕获 FileNotFoundError

- `config.json` 存在但 JSON 语法错误 → `json.JSONDecodeError` 未捕获，直接崩；
- 缺少字段 → 第 120-121 行 `config["gateway"]` 等直接下标取，抛 `KeyError`；
- `messagebox` 在 Tk 根窗口不存在时会隐式创建一个隐藏根窗口（可接受，但不规范）。

建议：统一捕获 `(FileNotFoundError, json.JSONDecodeError, KeyError)`，
并显式建一个隐藏 root 再弹框。

### 14. 跨天断网全部计入起始日

`get_daily_outage_summary()` 用 `GROUP BY date(start_time)`。
一个 23:50→00:20 的断网 100% 记到前一天，日报会失真。

### 15. 恢复事件的 details 存的是「恢复时刻」的状态

`add_event(..., details)` 传的是本轮 healthy 检查的 details，
**断网发生时的故障信息（哪一项失败）反而没落库**，事后无法回溯原因。

修复：保存进入断网那一刻的 details 给恢复事件使用。

### 16. 单元测试不可移植

- `test_check_connection_uses_network_probe` 真的去打网关和 8.8.8.8 → 离线/他人机器必挂；
- `test_load_config_resolves_paths` 硬编码断言 `gateway == "192.168.1.1"` → 换个路由器就挂。

建议：把网络探测抽成可注入的接口，测试里 mock 掉。

### 17. 死变量

`monitor_loop` 里的 `last_event_text` 赋值后从未被读取，可删。

---

## 环境问题（非代码缺陷，但会卡住开发）

**WorkBuddy 自带的托管 Python 没有 tkinter。**

```
C:\Users\Lenovo\.workbuddy\binaries\python\versions\3.13.12\python.exe
→ ModuleNotFoundError: No module named 'tkinter'
```

后果：`import wifi_monitor` 直接失败，`python -m unittest test_wifi_monitor` 全部报 ImportError。

**必须使用系统 Python：`D:\python\python.exe`**（3.13.7，含完整 tkinter）。
本报告所有实测均基于该解释器，5 个测试用例全部通过。

---

## 修复优先级建议

| 优先级 | 项目 | 影响 |
|---|---|---|
| 1 | #1 信号解析中文兼容 | 消除 100% 必现的误报 |
| 2 | #2 / #3 DNS 与探测目标重做 | 修正错误诊断结论 |
| 3 | #4 加入 failure_threshold 防抖 | 消除抖动误记 |
| 4 | #5 线程异常保护 | 避免静默停摆 |
| 5 | #6 / #7 停止竞态 + 断网落库 | 数据不丢不错 |
| 6 | #10 图表刻度与坐标系 | 报表可用 |
| 7 | 其余 P2 细节 | 体验优化 |
