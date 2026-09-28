"""WiFi 网络监控工具

三层探测（网关 / 外网 / DNS）互相解耦，带失败防抖、异常保护、断网事件持久化，
支持中英文 Windows 的 netsh / ipconfig 输出解析。

专业能力：
- 量化指标：RTT min/avg/max、抖动（RFC3550 标准差）、丢包率
- 退化态：区分「断网」与「通了但很差」，不再只有通/断二值
- 断网自动取证：tracert 逐跳 + WLAN 断开原因码
- 事件聚合：30 分钟内的碎片事件并成一次「事故」
- 站点级可用性：微信 / 腾讯会议 / B站等单独探活 + 证书到期
- 测速吞吐：国内镜像源限长下载计时
"""

import argparse
import csv
import functools
import json
import locale
import os
import queue
import re
import smtplib
import socket
import ssl
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, time as dtime, timedelta
from email.header import Header
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

def _app_dir():
    """程序所在目录 —— 数据文件（配置/数据库/日志/报表）都放在这里。

    ⚠️ 打包成单文件 exe 后，`__file__` 指向 PyInstaller 的**临时解包目录**
    （`sys._MEIPASS`），进程退出即被删除。如果继续用 `__file__`，
    用户的配置会「改了不生效」、断网记录会「重启就没了」。
    所以 frozen 时必须用 exe 自身所在目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    """随程序分发的**只读**资源（图标等）：打包后在临时解包目录里。"""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def console_log(message):
    """写控制台。没有控制台时（pythonw / 打包成 --noconsole）静默跳过。"""
    if sys.stdout is None:
        return
    try:
        print(message, flush=True)
    except (OSError, ValueError, RuntimeError, AttributeError):
        pass


BASE_DIR = _app_dir()
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0

# 探测目标默认值（国内可达；8.8.8.8 在国内丢包严重，仅作兜底）
DEFAULT_GATEWAY_FALLBACK = "192.168.1.1"
DEFAULT_INTERNET_TARGETS = [
    {"host": "223.5.5.5", "port": 443},
    {"host": "114.114.114.114", "port": 53},
    {"host": "223.6.6.6", "port": 53},
]
DEFAULT_DNS_PROBE_HOSTS = ["www.baidu.com", "www.qq.com"]

# 站点级可用性：默认监控国内常用站点（按需改 config.json）
DEFAULT_SITES = [
    {"name": "微信", "host": "weixin.qq.com", "port": 443},
    {"name": "腾讯会议", "host": "meeting.tencent.com", "port": 443},
    {"name": "哔哩哔哩", "host": "www.bilibili.com", "port": 443},
    {"name": "百度", "host": "www.baidu.com", "port": 443},
]

# 测速源：必须是国内可达的镜像。
# 绝对不能换成 speed.cloudflare.com —— 实测国内拉 1MB 要 29.6 秒（0.3 Mbps），
# 无论网络多好都会显示极低速度。（towerwatch 等项目用的就是它，照抄必踩坑）
DEFAULT_SPEED_SOURCES = [
    "https://mirrors.aliyun.com/ubuntu/ls-lR.gz",
    "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ls-lR.gz",
]

DEFAULT_CONFIG = {
    "gateway": "auto",
    # 实时刷新：单轮探测实测约 0.3s，每 2 秒一轮完全没有压力
    "check_interval_seconds": 2,
    "confirm_interval_seconds": 1,
    "failure_threshold": 3,
    "recovery_threshold": 3,
    "heartbeat_interval_seconds": 300,
    "probe_timeout_seconds": 2,
    "weak_signal_threshold": 50,
    "internet_targets": DEFAULT_INTERNET_TARGETS,
    "dns_probe_hosts": DEFAULT_DNS_PROBE_HOSTS,
    # --- 量化指标（多包 ping 在独立后台线程采样，不拖慢主循环） ---
    # 实测 ping -n 5 健康时约 4.2s、断网时约 6.2s，所以绝不能放进主循环。
    # ⚠️ 目标必须真的回应 ICMP：实测 114.114.114.114 完全屏蔽 ICMP（5 包全丢、耗时 8.8s），
    # 放进这里会把每次采样拖慢一倍。它适合做 TCP 探测目标（internet_targets），不适合 ping。
    "quality_targets": ["223.5.5.5", "223.6.6.6"],
    "quality_interval_seconds": 5,
    "quality_ping_count": 5,
    "quality_ping_timeout_ms": 1000,
    # 单次采样的总截止时间：超过就丢弃该目标，避免一个坏目标拖慢所有指标发布。
    # 留 0 表示按「包数 × 0.85s + 每包超时 + 1.5s」自动推算。
    "quality_deadline_seconds": 0,
    # --- 退化态（网络发虚）：通但指标差 ---
    "degrade_loss_percent": 5.0,
    "degrade_jitter_ms": 40.0,
    "degrade_rtt_ms": 300.0,
    # --- 站点级可用性 ---
    "sites": DEFAULT_SITES,
    "site_interval_seconds": 5,
    "site_great_ms": 200,
    "site_ok_ms": 800,
    "cert_warn_days": 14,
    # --- 测速 / 吞吐 ---
    "speed_test_enabled": True,
    "speed_test_interval_seconds": 600,
    "speed_test_bytes": 1048576,
    "speed_test_timeout_seconds": 20,
    "speed_test_sources": DEFAULT_SPEED_SOURCES,
    # --- 断网自动取证 ---
    "evidence_enabled": True,
    "evidence_tracert_max_hops": 8,
    "evidence_tracert_timeout_ms": 800,
    "evidence_wlan_lookback_minutes": 30,
    # --- 事件聚合与数据保留 ---
    "incident_gap_minutes": 30,
    "retention_days": 30,
    # --- 落库节流：探测很密，但不必每轮都写库，否则库会迅速膨胀 ---
    # 探测 2 秒一轮（内存里实时），写库最多 10 秒一条；健康等级一变立刻写
    "record_check_interval_seconds": 10,
    "site_record_interval_seconds": 60,
    # 日志轮转：超过阈值改名为 .log.1，只保留一代备份
    "log_max_bytes": 5 * 1024 * 1024,
    # --- 实时看板（本地网页，零依赖） ---
    "dashboard_enabled": True,
    "dashboard_host": "127.0.0.1",
    "dashboard_port": 8777,
    "dashboard_refresh_ms": 1000,
    "log_file": "logs\\wifi_monitor.log",
    "db_file": "data\\wifi_events.db",
    "notify": {
        "email_enabled": False,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "your_email@example.com",
        "smtp_password": "your_password",
        "password_env": "",
        "timeout_seconds": 10,
        "to_email": "target@example.com",
        # 断网时 SMTP 走不通，本地告警是唯一可靠的即时通道
        "local_alert_enabled": True,
        "beep_on_outage": True,
        "queue_when_offline": True,
    },
}

_LOG_LOCK = threading.Lock()

# 日志轮转阈值：常驻运行的程序日志会一直追加，必须有上限。
# 超过阈值就把当前日志改名为 .1、重新开始写，只保留一代备份。
LOG_MAX_BYTES = 5 * 1024 * 1024


def configure_log_rotation(max_bytes):
    """允许配置覆盖日志轮转阈值（monitor_loop 启动时调用一次）。"""
    global LOG_MAX_BYTES
    try:
        value = int(max_bytes)
    except (TypeError, ValueError):
        return
    if value > 0:
        LOG_MAX_BYTES = value

# 检测间隔下限，防止配置写错时把网络打满。
# 1 秒是安全下限：单轮探测是并发的（1 个 ICMP + 3 个 TCP + 2 个 DNS + 1 次 netsh），
# 实测健康时一轮约 0.3 秒，即 1 秒间隔的占空比也只有 30%。
MIN_CHECK_INTERVAL_SECONDS = 1

# 退化事件的取证冷却（tracert 约 9 秒，退化可能反复出现，不能每次都跑）
EVIDENCE_COOLDOWN_SECONDS = 300

# 断网期间积压的告警最多补发多少条
MAX_PENDING_NOTIFICATIONS = 20


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

def resolve_path(value, base_dir=BASE_DIR):
    if value is None:
        return None
    return value if os.path.isabs(value) else os.path.join(base_dir, value)


def _merge_config(raw):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    for key, value in (raw or {}).items():
        if key == "notify" and isinstance(value, dict):
            config["notify"].update(value)
        else:
            config[key] = value
    return config


def load_config(path=None):
    """读取配置并与默认值合并；缺失字段不会再抛 KeyError。"""
    path = path or CONFIG_PATH
    base_dir = os.path.dirname(os.path.abspath(path)) or BASE_DIR
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    config = _merge_config(raw)
    config["log_file"] = resolve_path(config.get("log_file") or "logs\\wifi_monitor.log", base_dir)
    config["db_file"] = resolve_path(config.get("db_file") or "data\\wifi_events.db", base_dir)
    config["reports_dir"] = resolve_path("reports", base_dir)
    return config


def ensure_config(path=None):
    """配置文件不存在时生成一份默认配置，返回是否新建。

    打包成 exe 后首次运行没有 config.json，直接弹「配置文件缺失」然后退出
    对用户来说是死路一条 —— 自动生成才对。
    """
    path = path or CONFIG_PATH
    if os.path.exists(path):
        return False
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(DEFAULT_CONFIG, handle, ensure_ascii=False, indent=2)
    return True


def ensure_paths(config):
    for key in ("log_file", "db_file"):
        target = config.get(key)
        if target:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    os.makedirs(config.get("reports_dir") or REPORTS_DIR, exist_ok=True)


# --------------------------------------------------------------------------
# 命令行与编码
# --------------------------------------------------------------------------

def decode_output(raw):
    """Windows 各命令输出编码不一致（ipconfig=GBK、netsh=UTF-8），逐个尝试解码。"""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    candidates = ["utf-8", locale.getpreferredencoding(False), "mbcs", "gbk", "cp936"]
    for encoding in candidates:
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError, TypeError):
            continue
    return raw.decode("utf-8", errors="replace")


def run_cmd(cmd, timeout=10):
    """执行命令，返回 (returncode, stdout 文本)。失败时返回 (1, "")。"""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return proc.returncode, decode_output(proc.stdout)


def _ping_args(host, count=1, timeout_ms=1200):
    if IS_WINDOWS:
        return ["ping", "-n", str(int(count)), "-w", str(int(timeout_ms)), str(host)]
    seconds = max(1, int(timeout_ms) // 1000)
    return ["ping", "-c", str(int(count)), "-W", str(seconds), str(host)]


# ping 退出码为 0 但其实是「不可达」回包的情况，必须排除
_PING_UNREACHABLE_RE = re.compile(
    r"(?:无法访问目标主机|目标主机不可达|传输失败|一般故障"
    r"|Destination host unreachable|Destination net unreachable"
    r"|Transmit failed|General failure)",
    re.IGNORECASE,
)


def ping_host(host, timeout=None):
    if not host:
        return False
    rc, out = run_cmd(_ping_args(host), timeout=timeout or 4)
    if rc != 0:
        return False
    # 中间设备可能回「目标主机不可达」而退出码仍是 0，这种不算通
    if _PING_UNREACHABLE_RE.search(out or ""):
        return False
    return True


# --------------------------------------------------------------------------
# 量化指标：RTT / 抖动 / 丢包
# --------------------------------------------------------------------------

# 逐包 RTT：中文「时间=32ms」/「时间<1ms」、英文「time=32ms」/「time<1ms」
_RTT_RE = re.compile(r"(?:时间|time)\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
# 汇总行：「最短 = 28ms，最长 = 33ms，平均 = 30ms」
_RTT_SUMMARY_RES = {
    "rtt_min_ms": re.compile(r"(?:最短|Minimum)\s*=\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
    "rtt_avg_ms": re.compile(r"(?:平均|Average)\s*=\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
    "rtt_max_ms": re.compile(r"(?:最长|Maximum)\s*=\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
}
_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%")
_PING_SENT_RE = re.compile(r"(?:已发送|Sent)\s*=\s*(\d+)", re.IGNORECASE)
_PING_RECV_RE = re.compile(r"(?:已接收|Received)\s*=\s*(\d+)", re.IGNORECASE)


def parse_ping_output(text):
    """从 ping 输出解析 RTT / 抖动 / 丢包，中英文输出都能解析。

    抖动用逐包 RTT 的总体标准差。RFC 3550 的抖动定义是相邻包延迟差的平滑值，
    在等间隔探测下用标准差近似足够；Windows 本身不提供抖动指标。
    """
    result = {
        "sent": None, "received": None, "loss_percent": None,
        "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
        "jitter_ms": None, "rtts": [],
    }
    if not text:
        return result

    rtts = [float(value) for value in _RTT_RE.findall(text)]
    result["rtts"] = rtts

    for key, pattern in _RTT_SUMMARY_RES.items():
        match = pattern.search(text)
        if match:
            result[key] = float(match.group(1))

    # 汇总行缺失时（部分语言包 / 非 Windows）用逐包数据兜底
    if rtts:
        if result["rtt_min_ms"] is None:
            result["rtt_min_ms"] = min(rtts)
        if result["rtt_max_ms"] is None:
            result["rtt_max_ms"] = max(rtts)
        if result["rtt_avg_ms"] is None:
            result["rtt_avg_ms"] = round(sum(rtts) / len(rtts), 2)
        result["jitter_ms"] = round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0

    sent = _PING_SENT_RE.search(text)
    received = _PING_RECV_RE.search(text)
    if sent:
        result["sent"] = int(sent.group(1))
    if received:
        result["received"] = int(received.group(1))

    if result["sent"] is not None and result["received"] is not None:
        if result["sent"] > 0:
            result["loss_percent"] = round(
                100.0 * (result["sent"] - result["received"]) / result["sent"], 2
            )
    else:
        loss = _PING_LOSS_RE.search(text)
        if loss:
            result["loss_percent"] = float(loss.group(1))
    return result


def ping_stats(host, count=5, timeout_ms=1000):
    """多包 ping，返回量化指标。

    ok 表示「至少收到一个回包」——部分丢包时仍算可达，但 loss_percent 会体现出来。
    实测耗时：健康约 0.85s/包、断网约 1.2s/包，**只应在后台线程调用**。
    """
    blank = {
        "host": host, "ok": False, "sent": 0, "received": 0, "loss_percent": 100.0,
        "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
        "jitter_ms": None, "rtts": [],
    }
    if not host:
        return blank

    count = max(1, int(count))
    command_timeout = count * (timeout_ms / 1000.0) + 6
    rc, out = run_cmd(_ping_args(host, count, timeout_ms), timeout=command_timeout)
    parsed = parse_ping_output(out)

    if not parsed["rtts"]:
        parsed["sent"] = parsed["sent"] or count
        parsed["received"] = parsed["received"] or 0
        parsed["loss_percent"] = 100.0
        parsed["ok"] = False
    else:
        # 有逐包 RTT 就一定收到了回包
        parsed["ok"] = True
    if _PING_UNREACHABLE_RE.search(out or "") and not parsed["rtts"]:
        parsed["ok"] = False
    parsed["host"] = host
    return {**blank, **parsed}


def quality_deadline(count=5, timeout_ms=1000):
    """推算单次采样的合理截止时间。

    Windows ping 的包间隔实测约 0.85s，所以健康时 `-n 5` 约 4.2s。
    这里额外留出「一个包超时」的余量，再留一点进程启动开销：
    这样偶发丢一个包不会导致采样被丢弃，而完全不应答 ICMP 的目标会被及时剔除。
    """
    return max(3.0, int(count) * 0.85 + int(timeout_ms) / 1000.0 + 1.5)


def sample_quality(targets, count=5, timeout_ms=1000, deadline=None):
    """并发对多个目标做多包 ping，取质量最好的一个作为本轮指标。

    「最好」= 丢包最低 → 抖动最低 → 平均 RTT 最低。
    超过 deadline 仍未返回的目标会被丢弃（不参与比较），避免一个不应答 ICMP 的
    目标把整次采样的发布时刻拖后好几秒。
    """
    targets = [t for t in (targets or []) if isinstance(t, str) and t.strip()]
    if not targets:
        return None

    count = max(1, int(count))
    if not deadline:
        deadline = quality_deadline(count, timeout_ms)

    tasks = [
        (f"ping:{index}",
         (lambda host=host: ping_stats(host, count=count, timeout_ms=timeout_ms)))
        for index, host in enumerate(targets)
    ]
    results = _run_parallel(tasks, deadline)
    candidates = [value for value in results.values() if isinstance(value, dict)]

    if not candidates:
        # 全部超时（典型场景就是断网）：合成「全丢包」结果。
        # 否则指标会冻结在最后一次健康值上，看板显示的延迟就是假的。
        return {
            "host": targets[0], "ok": False, "sent": count, "received": 0,
            "loss_percent": 100.0, "rtt_min_ms": None, "rtt_avg_ms": None,
            "rtt_max_ms": None, "jitter_ms": None, "rtts": [],
            "sampled_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets": list(targets), "timed_out": True, "deadline_seconds": deadline,
        }

    def sort_key(item):
        return (
            item.get("loss_percent") if item.get("loss_percent") is not None else 100.0,
            item.get("jitter_ms") if item.get("jitter_ms") is not None else 9999.0,
            item.get("rtt_avg_ms") if item.get("rtt_avg_ms") is not None else 9999.0,
        )

    best = sorted(candidates, key=sort_key)[0]
    best["sampled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    best["targets"] = list(targets)
    best["deadline_seconds"] = deadline
    return best


def tcp_probe(host, port, timeout=2):
    """TCP 连通性探测（不依赖 DNS，可直接传 IP）。"""
    try:
        with socket.create_connection((str(host), int(port)), timeout=timeout):
            return True
    except (OSError, ValueError, TypeError):
        return False


# getaddrinfo 是阻塞的系统调用，socket 超时管不住它：
# 断网时单次调用可能卡几十秒。用固定大小的线程池兜住，
# 保证被卡住的线程数量有上限，不会随检测轮次无限堆积。
_DNS_POOL = None
_DNS_POOL_LOCK = threading.Lock()


def _dns_pool():
    global _DNS_POOL
    with _DNS_POOL_LOCK:
        if _DNS_POOL is None:
            _DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns-probe")
        return _DNS_POOL


def dns_probe(hostname, timeout=5):
    """真实域名解析探测（走系统 DNS，不经过 ICMP）。"""
    if not hostname:
        return False
    try:
        future = _dns_pool().submit(socket.getaddrinfo, hostname, None)
        future.result(timeout=timeout)
        return True
    except Exception:
        return False


def _run_parallel(tasks, timeout):
    """并发执行 [(name, callable)]，返回 {name: value}。

    三层探测串行时，断网场景下耗时是相加的（网关超时 + 外网超时 + DNS 超时），
    并发后耗时变成取最大值，断网时单轮从 ~20 秒降到 ~4 秒。
    超时仍未返回的任务在结果里记为 None。
    """
    tasks = list(tasks)
    results = {}
    lock = threading.Lock()

    def worker(name, fn):
        try:
            value = fn()
        except Exception:
            value = None
        with lock:
            results[name] = value

    threads = [
        threading.Thread(target=worker, args=(name, fn), daemon=True, name=f"probe-{name}")
        for name, fn in tasks
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + max(0.1, float(timeout))
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))

    with lock:
        for name, _fn in tasks:
            results.setdefault(name, None)
    return results


_GATEWAY_LABEL_RE = re.compile(
    r"(?:默认网关|Default Gateway)\s*[.．\s]*[:：]\s*(.*)$", re.IGNORECASE
)
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def detect_default_gateways():
    """从 ipconfig 中解析所有默认网关（按出现顺序去重）。

    Windows 有多个默认网关时，IPv4 会写在标签行的**下一行续行**里，例如：
        默认网关. . . . . . . . . . . . . : fe80::1%16
                                            192.168.1.1
    所以必须连续行一起读。
    """
    _, out = run_cmd(["ipconfig"], timeout=10)
    lines = out.splitlines()
    found = []
    index = 0

    while index < len(lines):
        match = _GATEWAY_LABEL_RE.search(lines[index])
        if not match:
            index += 1
            continue

        values = [match.group(1)]
        look = index + 1
        while look < len(lines):
            nxt = lines[look].strip()
            # 续行是不含冒号的纯地址行；遇到空行或新标签即停止
            if not nxt or ":" in nxt or "：" in nxt:
                break
            values.append(nxt)
            look += 1

        for value in values:
            for ip in _IPV4_RE.findall(value):
                if ip != "0.0.0.0" and ip not in found:
                    found.append(ip)

        index = look if look > index else index + 1

    return found


# --------------------------------------------------------------------------
# 无线信号解析（中英文兼容）
# --------------------------------------------------------------------------

_WLAN_BLOCK_START = re.compile(r"^\s*(?:名称|Name)\s*[:：]")
_WLAN_PATTERNS = {
    "state": re.compile(r"^\s*(?:状态|State)\s*[:：]\s*(.+?)\s*$"),
    "ssid": re.compile(r"^\s*SSID\s*[:：]\s*(.+?)\s*$"),
    "bssid": re.compile(r"^\s*(?:AP\s+)?BSSID\s*[:：]\s*(.+?)\s*$"),
    "signal": re.compile(r"^\s*(?:信号|Signal)\s*[:：]\s*(\d{1,3})\s*%"),
    "rssi": re.compile(r"^\s*(?:Rssi|RSSI)\s*[:：]\s*(-?\d{1,3})"),
}


def _state_is_connected(state):
    if not state:
        return None
    lowered = state.lower()
    if "未连接" in state or "断开" in state or "disconnected" in lowered:
        return False
    if "已连接" in state or "connected" in lowered:
        return True
    return None


def parse_wlan_output(text):
    """解析 netsh wlan show interfaces 输出，返回每个接口一个 dict。"""
    blocks = []
    current = {}

    def flush():
        if current:
            blocks.append(dict(current))
            current.clear()

    for line in (text or "").splitlines():
        if _WLAN_BLOCK_START.match(line):
            flush()
        for field, pattern in _WLAN_PATTERNS.items():
            match = pattern.match(line)
            if not match:
                continue
            if field == "bssid" and "bssid" in current:
                continue
            if field == "ssid" and current.get("ssid"):
                continue
            current[field] = match.group(1).strip()
    flush()

    for block in blocks:
        # 统一补齐字段，避免调用方 KeyError（如未连接时没有 SSID 行）
        for field in ("state", "ssid", "bssid", "signal", "rssi"):
            block.setdefault(field, None)
        rssi = block.get("rssi")
        block["rssi_db"] = int(rssi) if rssi and rssi.lstrip("-").isdigit() else None
        signal = block.get("signal")
        if signal is not None and str(signal).isdigit():
            block["signal_percent"] = max(0, min(100, int(signal)))
        elif block["rssi_db"] is not None:
            # RSSI(dBm) 近似换算为百分比
            block["signal_percent"] = max(0, min(100, 2 * (block["rssi_db"] + 100)))
        else:
            block["signal_percent"] = None
        if block.get("signal_percent") is not None:
            block["signal"] = f"{block['signal_percent']}%"
        block["connected"] = _state_is_connected(block.get("state"))
    return blocks


def check_wifi_signal():
    """返回当前 WiFi 状态；未连接或非无线网卡时字段为 None。"""
    empty = {
        "ssid": None,
        "signal": None,
        "signal_percent": None,
        "rssi": None,
        "rssi_db": None,
        "state": None,
        "state_known": False,
        "connected": None,
    }
    try:
        _, output = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=10)
    except Exception:
        return dict(empty)

    blocks = parse_wlan_output(output)
    if not blocks:
        return dict(empty)

    chosen = None
    for block in blocks:
        if block.get("connected") and block.get("ssid"):
            chosen = block
            break
    if chosen is None:
        for block in blocks:
            if block.get("ssid"):
                chosen = block
                break
    if chosen is None:
        for block in blocks:
            if block.get("state"):
                chosen = block
                break
    if chosen is None:
        chosen = blocks[0]

    return {
        "ssid": chosen.get("ssid"),
        "signal": chosen.get("signal"),
        "signal_percent": chosen.get("signal_percent"),
        "rssi": chosen.get("rssi"),
        "rssi_db": chosen.get("rssi_db"),
        "state": chosen.get("state"),
        "state_known": bool(chosen.get("state")),
        "connected": chosen.get("connected"),
    }


def parse_signal_strength(signal):
    if signal is None:
        return 0
    match = re.search(r"(\d+)", str(signal))
    if not match:
        return 0
    return int(match.group(1))


# --------------------------------------------------------------------------
# 站点级可用性（含 TLS 证书到期）
# --------------------------------------------------------------------------

SITE_VERDICTS = ("GREAT", "OK", "SLOW", "DOWN")


def probe_site(name, host, port=443, timeout=4, cert_warn_days=14, great_ms=200, ok_ms=800):
    """探测单个站点：TCP 建连耗时 + TLS 握手耗时 + 证书到期。

    证书到期信息是 TLS 握手顺带拿到的，零额外成本。
    """
    result = {
        "name": name, "host": host, "port": port, "ok": False,
        "tcp_ms": None, "tls_ms": None, "total_ms": None,
        "cert_expires": None, "cert_days_left": None, "cert_warning": False,
        "verdict": "DOWN", "error": None,
    }
    if not host:
        result["error"] = "host 为空"
        return result

    start = time.perf_counter()
    try:
        raw = socket.create_connection((str(host), int(port)), timeout=timeout)
    except (OSError, ValueError, TypeError) as exc:
        result["error"] = str(exc)
        result["total_ms"] = round((time.perf_counter() - start) * 1000, 1)
        return result

    result["tcp_ms"] = round((time.perf_counter() - start) * 1000, 1)
    tls_start = time.perf_counter()
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=str(host)) as tls:
            cert = tls.getpeercert()
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 1)
        result["ok"] = True
        not_after = (cert or {}).get("notAfter")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - datetime.now()).days
                result["cert_expires"] = expires.strftime("%Y-%m-%d")
                result["cert_days_left"] = days_left
                result["cert_warning"] = days_left <= int(cert_warn_days)
            except ValueError:
                pass
    except ssl.SSLError:
        # 端口不是 TLS（例如 80），只要 TCP 通了就算站点可用
        try:
            raw.close()
        except OSError:
            pass
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 1)
        result["ok"] = True
    except (OSError, ValueError, TypeError) as exc:
        result["error"] = str(exc)

    parts = [value for value in (result["tcp_ms"], result["tls_ms"]) if value is not None]
    if parts:
        result["total_ms"] = round(sum(parts), 1)
    result["verdict"] = site_verdict(result["total_ms"], result["ok"], great_ms, ok_ms)
    return result


def site_verdict(total_ms, ok, great_ms=200, ok_ms=800):
    """把耗时折算成人话结论：GREAT / OK / SLOW / DOWN。"""
    if not ok or total_ms is None:
        return "DOWN"
    if total_ms <= float(great_ms):
        return "GREAT"
    if total_ms <= float(ok_ms):
        return "OK"
    return "SLOW"


def probe_sites(sites, timeout=4, deadline=10, great_ms=200, ok_ms=800, cert_warn_days=14):
    """并发探测所有站点，返回保持配置顺序的结果列表。"""
    entries = [s for s in (sites or []) if isinstance(s, dict) and s.get("host")]
    if not entries:
        return []

    tasks = [
        (
            f"site:{index}",
            (
                lambda item=site: probe_site(
                    item.get("name") or item["host"],
                    item["host"],
                    int(item.get("port") or 443),
                    timeout,
                    cert_warn_days,
                    great_ms,
                    ok_ms,
                )
            ),
        )
        for index, site in enumerate(entries)
    ]
    results = _run_parallel(tasks, deadline)
    sampled_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ordered = []
    for index in range(len(entries)):
        item = results.get(f"site:{index}")
        if isinstance(item, dict):
            item["sampled_at"] = sampled_at
            ordered.append(item)
    return ordered


def site_summary(sites):
    """给界面/日志用的一行摘要，按严重程度排序。"""
    if not sites:
        return "站点：暂无数据"
    rank = {"DOWN": 0, "SLOW": 1, "OK": 2, "GREAT": 3}
    ordered = sorted(sites, key=lambda item: rank.get(item.get("verdict"), 4))
    return "站点：" + "　".join(
        f"{item['name']}={item.get('verdict')}"
        + (f"({item['total_ms']:.0f}ms)" if item.get("total_ms") is not None else "")
        for item in ordered
    )


# --------------------------------------------------------------------------
# 测速 / 吞吐
# --------------------------------------------------------------------------

def measure_throughput(url, size_bytes=1048576, timeout=20):
    """限长下载计时测吞吐。用 Range 头只取前 N 字节，避免白耗流量。"""
    result = {"url": url, "ok": False, "bytes": 0, "seconds": None, "mbps": None, "error": None}
    if not url:
        result["error"] = "url 为空"
        return result

    size_bytes = max(65536, int(size_bytes))
    request = urllib.request.Request(
        url,
        headers={
            "Range": f"bytes=0-{size_bytes - 1}",
            "User-Agent": "wifi-monitor/2.0",
            "Accept": "*/*",
        },
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(size_bytes)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["error"] = str(exc)
        return result

    elapsed = time.perf_counter() - start
    if not data or elapsed <= 0:
        result["error"] = "未取到数据"
        return result

    result["ok"] = True
    result["bytes"] = len(data)
    result["seconds"] = round(elapsed, 3)
    result["mbps"] = round(len(data) * 8 / elapsed / 1e6, 2)
    return result


def run_speed_test(sources, size_bytes=1048576, timeout=20):
    """依次尝试可用测速源，返回第一个成功的结果。

    必须**串行**：并发下载会互相抢带宽，测出来的速度是假的。
    """
    last = None
    for url in sources or []:
        last = measure_throughput(url, size_bytes, timeout)
        if last["ok"]:
            last["sampled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return last
    if last is None:
        last = {"url": None, "ok": False, "bytes": 0, "seconds": None, "mbps": None,
                "error": "没有配置测速源"}
    last["sampled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return last


# --------------------------------------------------------------------------
# 断网自动取证：tracert 逐跳 + WLAN 断开原因码
# --------------------------------------------------------------------------

_TRACERT_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_TRACERT_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# WLAN-AutoConfig 事件 ID 语义表。
# 只按 ID 判定，**不解析 Message 原文** —— 实测同一台机器经 PowerShell 重定向后
# 消息文本会变成英文，按文本匹配必然失效。
WLAN_EVENT_LABELS = {
    "8000": "开始连接无线网络",
    "8001": "已成功连接无线网络",
    "8002": "连接无线网络失败",
    "8003": "已断开无线网络",
    "11000": "无线网络关联开始",
    "11001": "无线网络关联成功",
    "11002": "无线网络关联失败",
    "11004": "无线安全功能停止",
    "11005": "无线安全功能成功",
    "11006": "无线安全功能失败",
    "11010": "无线安全功能启动",
    "11013": "无线网络预关联",
    "12011": "802.1X 认证失败",
    "12012": "802.1X 认证超时",
    "12013": "802.1X 认证成功",
}
# 明确表示「异常断开」的事件 ID，用于归因
WLAN_BAD_EVENT_IDS = {"8002", "11002", "11006", "12011", "12012"}


def tracert_hops(host, max_hops=8, timeout_ms=800):
    """逐跳取证。实测 8 跳 / 800ms 超时约 9 秒，只应在后台线程调用。

    返回 (hops, raw_text)；hops 元素形如
    {'hop': 3, 'responded': True, 'ips': ['218.5.181.77'], 'raw': '9 ms 10 ms 9 ms 218.5.181.77'}
    """
    if not host:
        return [], ""
    if IS_WINDOWS:
        args = ["tracert", "-d", "-h", str(int(max_hops)), "-w", str(int(timeout_ms)), str(host)]
    else:
        args = ["traceroute", "-n", "-m", str(int(max_hops)), "-w", "1", str(host)]

    rc, out = run_cmd(args, timeout=int(max_hops) * (int(timeout_ms) / 1000.0) + 25)
    hops = []
    for line in (out or "").splitlines():
        match = _TRACERT_HOP_RE.match(line)
        if not match:
            continue
        rest = match.group(2).strip()
        ips = _TRACERT_IP_RE.findall(rest)
        # 有 "ms" 才说明这一跳回了包（中英文输出都含 ms）
        responded = "ms" in rest and bool(ips)
        hops.append(
            {
                "hop": int(match.group(1)),
                "responded": responded,
                "ips": ips,
                "raw": rest[:120],
            }
        )
    if rc not in (0, 1):
        return hops, out or ""
    return hops, out or ""


# 逐跳取证的固有局限：中间设备普遍屏蔽 ICMP，无响应 ≠ 一定故障。
# 实测本机网络完全正常时，第 8 跳也是「无响应」，所以结论必须留有余地。
TRACERT_CAVEAT = (
    "注：中间设备可能屏蔽 ICMP，无响应不等于该跳一定故障；"
    "请结合断网现象与 WLAN 事件综合判断。"
)


def summarize_tracert(hops, gateway=None, target=None):
    """把逐跳结果翻译成「断在哪一段」，返回 (segment, text)。

    segment: local（本地链路）/ isp（运营商上行）/ upstream（可达但服务不通）/ unknown

    措辞刻意保守：只陈述「到哪一跳为止可达」，不断言「故障一定在哪一跳」——
    中间设备屏蔽 ICMP 是常态，断言会误导用户。
    """
    if not hops:
        return "unknown", "逐跳探测无结果\n" + TRACERT_CAVEAT

    lines = []
    for item in hops[:12]:
        mark = "通" if item["responded"] else "无响应"
        target_ip = item["ips"][0] if item["ips"] else "—"
        lines.append(f"  第{item['hop']}跳 {target_ip} {mark}")
    text = "\n".join(lines)

    # 目标本机出现在末跳 → 链路完全通畅，问题在服务/上游
    if target and hops[-1]["ips"] and target in hops[-1]["ips"]:
        return "upstream", (
            f"逐跳可达目标 {target}，网络链路正常，问题不在本地网络\n"
            + text
        )

    last_ok = 0
    for item in hops:
        if item["responded"]:
            last_ok = item["hop"]
        else:
            break

    if last_ok == 0:
        return "local", (
            f"第 1 跳（网关 {gateway or '未知'}）即无响应 —— 故障很可能在本地网络\n"
            + text + "\n" + TRACERT_CAVEAT
        )
    if last_ok == 1:
        return "isp", (
            f"网关 {gateway or '未知'} 可达，第 2 跳起无响应 —— 故障很可能在运营商上行\n"
            + text + "\n" + TRACERT_CAVEAT
        )
    return "isp", (
        f"路径前 {last_ok} 跳可达（已进入运营商网络），其后无响应\n"
        + text + "\n" + TRACERT_CAVEAT
    )


def parse_wlan_event_lines(raw_lines, lookback_minutes=30, now=None):
    """把 `时间|事件ID|消息` 行解析成结构化事件（抽出来便于离线测试）。"""
    now = now or datetime.now()
    cutoff = now - timedelta(minutes=max(1, int(lookback_minutes)))
    events = []
    for line in raw_lines:
        parts = str(line).split("|")
        if len(parts) < 2:
            continue
        stamp = parse_ts(parts[0])
        if stamp is not None and stamp < cutoff:
            continue
        event_id = parts[1].strip()
        events.append(
            {
                "time": parts[0],
                "id": event_id,
                "label": WLAN_EVENT_LABELS.get(event_id, f"未知 WLAN 事件 {event_id}"),
                "abnormal": event_id in WLAN_BAD_EVENT_IDS,
                "raw": (parts[2] if len(parts) > 2 else "").strip()[:200],
            }
        )
    return events


def read_wlan_events(lookback_minutes=30, max_events=60, timeout=60):
    """读取 WLAN-AutoConfig 事件日志，拿到「断开原因码」。

    普通权限即可（实测本机 1462 条可读）。相比之下 `netsh wlan show wlanreport`
    需要管理员权限，所以这里用事件日志作为常规取证手段。
    """
    if not IS_WINDOWS:
        return []

    handle, path = tempfile.mkstemp(prefix="wlan_ev_", suffix=".txt")
    os.close(handle)
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$r = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' "
        f"-MaxEvents {int(max_events)} -ErrorAction SilentlyContinue | "
        "ForEach-Object { $m = ($_.Message -split \"`r?`n\")[0]; "
        "'{0}|{1}|{2}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $_.Id, $m };"
        f"$r | Out-File -FilePath '{path}' -Encoding UTF8"
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        if not os.path.isfile(path):
            return []
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            raw_lines = [line.rstrip() for line in handle if line.strip()]
    except (OSError, subprocess.SubprocessError):
        return []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    return parse_wlan_event_lines(raw_lines, lookback_minutes)


def collect_evidence(config, status, events_db=None, event_id=None):
    """断网确认后调用（后台线程）：逐跳 + WLAN 事件，返回可读的取证文本与结论段。"""
    host = status.get("gateway") if not status.get("gateway_ok") else None
    if not host:
        targets = [t.get("host") for t in (config.get("internet_targets") or []) if t.get("host")]
        host = targets[0] if targets else "223.5.5.5"

    hops, _raw = tracert_hops(
        host,
        max_hops=config.get("evidence_tracert_max_hops", 8),
        timeout_ms=config.get("evidence_tracert_timeout_ms", 800),
    )
    segment, hop_text = summarize_tracert(hops, gateway=status.get("gateway"), target=host)

    wlan_events = read_wlan_events(config.get("evidence_wlan_lookback_minutes", 30))
    abnormal = [item for item in wlan_events if item["abnormal"]]

    lines = [
        f"取证目标：{host}",
        f"结论段：{segment}",
        "【逐跳】",
        hop_text,
    ]
    if wlan_events:
        lines.append(f"【WLAN 事件】最近 {len(wlan_events)} 条，异常 {len(abnormal)} 条")
        for item in wlan_events[:8]:
            flag = "⚠ " if item["abnormal"] else "  "
            lines.append(f"  {flag}{item['time']} [{item['id']}] {item['label']}")
    else:
        lines.append("【WLAN 事件】无记录或读取失败")
    lines.append(f"【取证时刻】{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return {
        "text": "\n".join(lines),
        "segment": segment,
        "hops": hops,
        "wlan_events": wlan_events,
    }


# --------------------------------------------------------------------------
# 健康等级判定
# --------------------------------------------------------------------------

HEALTH_NORMAL = "normal"
HEALTH_DEGRADED = "degraded"
HEALTH_OUTAGE = "outage"
HEALTH_LABELS = {HEALTH_NORMAL: "正常", HEALTH_DEGRADED: "网络退化", HEALTH_OUTAGE: "断网"}

# 归因分级：把「哪里出问题」从「某一层探针失败」升级为责任方
CAUSE_LEVEL_LABELS = {
    "local": "本地网络（网卡 / 路由器）",
    "isp": "运营商上行链路",
    "upstream": "上游站点 / 服务",
    "dns": "DNS 服务",
    "wifi": "无线信号质量",
    "quality": "链路质量",
    "normal": "正常",
    "unknown": "未判定",
}

_CAUSE_LEVEL_BY_PRIMARY = {
    "wifi_link": "local",
    "gateway": "local",
    "internet": "isp",
    "dns": "dns",
    "wifi": "wifi",
    "degraded": "quality",
    "healthy": "normal",
}


def derive_cause_level(primary, segment=None):
    """把 primary_cause 映射为责任方等级；有逐跳取证时进一步细化。"""
    level = _CAUSE_LEVEL_BY_PRIMARY.get(primary, "unknown")
    if segment == "local":
        return "local"
    if segment == "upstream":
        return "upstream"
    if segment == "isp" and level in ("isp", "unknown", "quality"):
        return "isp"
    return level


def metric_degrade_reasons(metrics, config=None):
    """只看量化指标。信号弱有独立归因分支，不在这里重复。"""
    config = config or {}
    reasons = []
    if not isinstance(metrics, dict):
        return reasons
    loss = metrics.get("loss_percent")
    if loss is not None and loss >= float(config.get("degrade_loss_percent") or 5.0):
        reasons.append(f"丢包 {loss:g}%")
    jitter = metrics.get("jitter_ms")
    if jitter is not None and jitter >= float(config.get("degrade_jitter_ms") or 40.0):
        reasons.append(f"抖动 {jitter:g}ms")
    rtt = metrics.get("rtt_avg_ms")
    if rtt is not None and rtt >= float(config.get("degrade_rtt_ms") or 300.0):
        reasons.append(f"延迟 {rtt:g}ms")
    return reasons


def evaluate_health(status, metrics=None, config=None):
    """判定本轮健康等级，并给出退化原因。

    设计要点：**信号弱也算退化**。信号差会导致断线和丢包，
    属于「通了但很差」，不该被算成正常。
    """
    config = config or {}
    reachable = bool(
        status.get("gateway_ok") and status.get("internet_ok") and status.get("dns_ok")
    )
    if not reachable:
        return {"level": HEALTH_OUTAGE, "reasons": []}

    reasons = metric_degrade_reasons(metrics, config)
    signal = status.get("signal_percent")
    if signal is not None and signal < int(config.get("weak_signal_threshold") or 50):
        reasons.append(f"信号 {signal}%")

    if reasons:
        return {"level": HEALTH_DEGRADED, "reasons": reasons}
    return {"level": HEALTH_NORMAL, "reasons": []}


# --------------------------------------------------------------------------
# 三级状态机（分级防抖）
# --------------------------------------------------------------------------

class HealthTracker:
    """分级状态机：连续 N 次确认进入异常，连续 M 次确认恢复。

    状态从 A 切到 B（都属异常）时先结束 A 再开始 B —— 碎片事件交给查询层的
    「事故聚合」合并，状态机本身保持单一职责。

    update(level, now, details, metrics) 返回动作列表，元素形如：
      ('start', kind, start_dt, details, metrics)
      ('end',   kind, start_dt, end_dt, duration_seconds)
    """

    def __init__(self, failure_threshold=2, recovery_threshold=2):
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_threshold = max(1, int(recovery_threshold))
        self.active_kind = None
        self.active_start = None
        self.active_details = ""
        self.active_metrics = None
        self.pending_kind = None
        self.pending_streak = 0
        self.pending_since = None

    @property
    def active(self):
        return self.active_kind is not None

    @property
    def pending_needed(self):
        if self.pending_kind is None:
            return 0
        if self.pending_kind == HEALTH_NORMAL:
            return self.recovery_threshold
        return self.failure_threshold

    def update(self, level, now, details="", metrics=None):
        level = level or HEALTH_NORMAL

        if level == self.active_kind:
            self._reset_pending()
            return []

        if self.pending_kind != level:
            self.pending_kind = level
            self.pending_streak = 1
            self.pending_since = now
        else:
            self.pending_streak += 1

        if self.pending_streak < self.pending_needed:
            return []

        actions = []
        if self.active_kind is not None:
            duration = max(0, int((now - self.active_start).total_seconds()))
            actions.append(("end", self.active_kind, self.active_start, now, duration))
            self.active_kind = None
            self.active_start = None
            self.active_details = ""
            self.active_metrics = None

        if level != HEALTH_NORMAL:
            # 事件起始时刻用「首次观察到该状态」的时间，不是确认那一刻，否则时长虚短
            start = self.pending_since or now
            self.active_kind = level
            self.active_start = start
            self.active_details = details
            self.active_metrics = metrics
            actions.append(("start", level, start, details, metrics))

        self._reset_pending()
        return actions

    def _reset_pending(self):
        self.pending_kind = None
        self.pending_streak = 0
        self.pending_since = None


class OutageTracker(HealthTracker):
    """向后兼容包装：健康布尔值 → outage / normal 两级。

    保留旧接口（update 返回单个动作，暴露 fail_streak / ok_streak /
    outage_start / outage_details），既有调用方与测试无需改动。
    """

    def __init__(self, failure_threshold=3, recovery_threshold=2):
        super().__init__(failure_threshold, recovery_threshold)

    @property
    def fail_streak(self):
        return self.pending_streak if self.pending_kind == HEALTH_OUTAGE else 0

    @property
    def ok_streak(self):
        return self.pending_streak if self.pending_kind == HEALTH_NORMAL else 0

    @property
    def outage_start(self):
        return self.active_start

    @property
    def outage_details(self):
        return self.active_details

    def update(self, healthy, now, details=""):
        actions = super().update(
            HEALTH_NORMAL if healthy else HEALTH_OUTAGE, now, details
        )
        if not actions:
            return None
        action = actions[0]
        if action[0] == "start":
            return ("start", action[2])
        return ("end", action[2], action[3], action[4])


# --------------------------------------------------------------------------
# 监控线程与采样线程共享的运行时状态
# --------------------------------------------------------------------------

class RuntimeState:
    """线程安全的共享状态：采样线程写指标，监控循环写健康等级 / 告警队列。"""

    def __init__(self):
        self._lock = threading.RLock()
        self._health = HEALTH_NORMAL
        self._metrics = None
        self._sites = []
        self._speed = None
        self._pending = []
        self._status = None

    def _set(self, name, value):
        with self._lock:
            setattr(self, "_" + name, value)

    def _get(self, name):
        with self._lock:
            return getattr(self, "_" + name)

    def set_health(self, level):
        self._set("health", level)

    def get_health(self):
        return self._get("health")

    def set_metrics(self, metrics):
        self._set("metrics", metrics)

    def get_metrics(self):
        return self._get("metrics")

    def set_sites(self, sites):
        self._set("sites", list(sites or []))

    def get_sites(self):
        return list(self._get("sites") or [])

    def set_speed(self, speed):
        self._set("speed", speed)

    def get_speed(self):
        return self._get("speed")

    # -- 最近一轮探测结果（看板要读实时状态，不能只靠 DB） ---------------

    def set_status(self, status):
        self._set("status", status)

    def get_status(self):
        return self._get("status")

    # -- 离线告警队列（断网期间攒着，恢复后补发） ----------------------

    def add_pending(self, subject, body):
        with self._lock:
            if len(self._pending) >= MAX_PENDING_NOTIFICATIONS:
                self._pending.pop(0)
            self._pending.append((subject, body))
            return len(self._pending)

    def take_pending(self):
        with self._lock:
            items = list(self._pending)
            self._pending = []
            return items

    def pending_count(self):
        with self._lock:
            return len(self._pending)

    def snapshot(self):
        with self._lock:
            return {
                "health": self._health,
                "metrics": self._metrics,
                "sites": list(self._sites or []),
                "speed": self._speed,
                "pending": len(self._pending),
                "status": self._status,
            }


class _PeriodicTask:
    """一个「到期就跑、跑完才算下一轮」的周期任务。

    每个任务在**自己的线程**里执行：量化指标要 4.2s、站点只要 0.3s，
    如果串在一个线程里排队，站点数据就会被指标拖到 4.5s 才更新，
    「实时」就无从谈起。用一个 running 标志防止同一个任务重入即可。

    `deferred` 用于「已到期、但当前不方便跑」的任务（例如测速遇到带宽被占用）：
    记下来，等条件允许时立刻补上，而不是白白错过这个周期。
    """

    def __init__(self, name, interval, func):
        self.name = name
        self.interval = max(1, int(interval or 60))
        self.func = func
        self.last_started = None
        self.running = False
        self.deferred = False

    def due(self, first=False):
        if self.running:
            return False
        if first or self.deferred or self.last_started is None:
            return True
        return time.monotonic() - self.last_started >= self.interval

    def defer(self):
        self.deferred = True

    def run(self, on_done=None):
        self.running = True
        self.deferred = False
        self.last_started = time.monotonic()

        def worker():
            try:
                self.func()
            except Exception:
                pass
            finally:
                self.running = False
                if on_done is not None:
                    try:
                        on_done()
                    except Exception:
                        pass

        threading.Thread(target=worker, name=f"sampler-{self.name}", daemon=True).start()


class BackgroundSampler(threading.Thread):
    """后台采样线程：量化指标 / 站点可用性 / 吞吐测速。

    为什么必须在后台：`ping -n 5` 实测耗时 4.2 秒，放进主循环会直接把报警延迟
    从 2 秒拖到 6 秒以上。主循环只读取最近一次快照，因此延迟零影响。

    测速会占满带宽：它运行时让其它采样让路，否则测出来的 RTT/抖动是假的。
    """

    # 调度间隔要**明显小于**任务之间的空隙。
    # 实测教训：质量采样 5 秒一轮、本身耗时 4.2 秒，空闲窗口只有 0.8 秒；
    # 若调度器 1 秒才 tick 一次，就永远踩不到那个窗口，测速会被活活饿死
    # （现象是 speed_tests 表始终为空）。0.25 秒 + deferred 标记双保险。
    TICK_SECONDS = 0.25

    def __init__(self, config, stop_event, state, on_update=None):
        super().__init__(name="wifi-sampler", daemon=True)
        self.config = config
        self.stop_event = stop_event
        self.state = state
        self.on_update = on_update
        self._speed_running = False
        self._last_speed = None
        self._tasks = {
            "quality": _PeriodicTask(
                "quality", config.get("quality_interval_seconds", 5), self._sample_quality
            ),
            "sites": _PeriodicTask(
                "sites", config.get("site_interval_seconds", 5), self._sample_sites
            ),
            "speed": _PeriodicTask(
                "speed", config.get("speed_test_interval_seconds", 3600), self._sample_speed
            ),
        }

    # -- 三个采样任务（分别在各自线程里跑） ----------------------------

    def _sample_quality(self):
        count = self.config.get("quality_ping_count", 5)
        timeout_ms = self.config.get("quality_ping_timeout_ms", 1000)
        deadline = self.config.get("quality_deadline_seconds") or quality_deadline(
            count, timeout_ms
        )
        metrics = sample_quality(
            self.config.get("quality_targets"),
            count=count,
            timeout_ms=timeout_ms,
            deadline=deadline,
        )
        if metrics:
            self.state.set_metrics(metrics)
            self._notify("metrics")

    def _sample_sites(self):
        sites = probe_sites(
            self.config.get("sites"),
            great_ms=self.config.get("site_great_ms", 200),
            ok_ms=self.config.get("site_ok_ms", 800),
            cert_warn_days=self.config.get("cert_warn_days", 14),
        )
        if sites:
            self.state.set_sites(sites)
            self._notify("sites")

    def _sample_speed(self):
        if not self.config.get("speed_test_enabled"):
            return
        if self.state.get_health() == HEALTH_OUTAGE:
            # 断网时测速必然失败，跳过
            return
        self._speed_running = True
        try:
            result = run_speed_test(
                self.config.get("speed_test_sources"),
                size_bytes=self.config.get("speed_test_bytes", 1048576),
                timeout=self.config.get("speed_test_timeout_seconds", 20),
            )
            self._last_speed = result
            self.state.set_speed(result)
            self._notify("speed")
        finally:
            self._speed_running = False

    # -- 调度 -----------------------------------------------------------

    def run(self):
        first = True
        while not self.stop_event.is_set():
            try:
                self._tick(first)
            except Exception:
                pass
            first = False
            if self.stop_event.wait(self.TICK_SECONDS):
                break

    def _tick(self, first=False):
        # 测速进行中：让其它采样让路，避免带宽争抢污染指标
        if not self._speed_running:
            for key in ("quality", "sites"):
                task = self._tasks[key]
                if task.due(first):
                    task.run()
        # 测速启动前还要等质量/站点采样空闲：下载会占满带宽，
        # 与 ping 并发会把首个质量样本的 RTT/抖动抬得虚高（实测 rtt_max 冲到 109ms）
        speed_task = self._tasks["speed"]
        noisy = self._speed_running or any(
            self._tasks[key].running for key in ("quality", "sites")
        )
        if not speed_task.due(first):
            return
        if noisy:
            # 到期了但此刻不方便跑 —— 记住，等空闲立刻补上，不要错过这个周期
            speed_task.defer()
            return
        speed_task.run()

    def _notify(self, kind):
        if self.on_update is not None:
            try:
                self.on_update(kind)
            except Exception:
                pass


# --------------------------------------------------------------------------
# 三层探测
# --------------------------------------------------------------------------

class NetworkProbe:
    """网关 / 外网 / DNS 三级探测，三层解耦、各自独立判定。"""

    def __init__(self, config):
        self.config = config
        self.timeout = float(config.get("probe_timeout_seconds") or 2)
        # 单轮探测的总上限：并发执行后，一轮耗时不会超过它
        self.deadline = max(4.0, self.timeout * 3)
        self.gateway = None
        self.gateway_candidates = []
        self._gateway_fail_streak = 0
        self.refresh_gateway()

    def refresh_gateway(self):
        configured = str(self.config.get("gateway") or "").strip()
        if configured and configured.lower() != "auto":
            self.gateway = configured
            self.gateway_candidates = [configured]
            return self.gateway

        candidates = detect_default_gateways()
        self.gateway_candidates = candidates
        for ip in candidates:
            if ping_host(ip, timeout=self.timeout + 2):
                self.gateway = ip
                return self.gateway
        self.gateway = candidates[0] if candidates else DEFAULT_GATEWAY_FALLBACK
        return self.gateway

    def probe_gateway(self):
        if not self.gateway:
            self.refresh_gateway()
        if not self.gateway:
            return False

        ok = ping_host(self.gateway, timeout=self.timeout + 2)
        if not ok:
            # 部分路由器禁用 ICMP，用本机管理端口兜底（两个端口并发，不串行叠加）
            fallbacks = _run_parallel(
                [
                    (f"tcp{port}", (lambda port=port: tcp_probe(self.gateway, port, timeout=self.timeout)))
                    for port in (80, 443)
                ],
                self.timeout + 1,
            )
            ok = any(bool(value) for value in fallbacks.values())

        if ok:
            self._gateway_fail_streak = 0
            return True

        self._gateway_fail_streak += 1
        if self._gateway_fail_streak >= 3 and len(self.gateway_candidates) > 1:
            self._gateway_fail_streak = 0
            for ip in self.gateway_candidates:
                if ip != self.gateway and ping_host(ip, timeout=self.timeout + 2):
                    self.gateway = ip
                    break
        return False

    def _internet_targets(self):
        targets = []
        for item in self.config.get("internet_targets") or []:
            if isinstance(item, dict) and item.get("host"):
                targets.append((item["host"], int(item.get("port") or 53)))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                targets.append((item[0], int(item[1])))
            elif isinstance(item, str) and item.strip():
                targets.append((item.strip(), 53))
        legacy = str(self.config.get("dns") or "").strip()
        if legacy and legacy.lower() != "auto":
            targets.append((legacy, 53))
        return targets or [(t["host"], t["port"]) for t in DEFAULT_INTERNET_TARGETS]

    def probe_internet(self):
        """TCP 直连 IP，不经过 DNS，因此与 DNS 是否正常完全无关。并发探测所有目标。"""
        targets = self._internet_targets()
        if not targets:
            return False
        tasks = [
            (f"tcp:{index}", (lambda host=host, port=port: tcp_probe(host, port, timeout=self.timeout)))
            for index, (host, port) in enumerate(targets)
        ]
        results = _run_parallel(tasks, self.timeout + 1)
        return any(bool(value) for value in results.values())

    def probe_dns(self):
        hosts = [
            h for h in (self.config.get("dns_probe_hosts") or [])
            if isinstance(h, str) and h.strip()
        ] or DEFAULT_DNS_PROBE_HOSTS
        tasks = [
            (f"dns:{index}", (lambda host=host: dns_probe(host, timeout=self.timeout + 1)))
            for index, host in enumerate(hosts)
        ]
        results = _run_parallel(tasks, self.timeout + 2)
        return any(bool(value) for value in results.values())

    def check_all(self, target_host=None, metrics=None):
        # 四路并发：断网时单轮耗时从「各层超时相加」变成「取最大值」
        outcome = _run_parallel(
            [
                ("gateway", self.probe_gateway),
                ("internet", self.probe_internet),
                ("dns", self.probe_dns),
                ("wifi", check_wifi_signal),
            ],
            self.deadline,
        )
        gateway_ok = bool(outcome.get("gateway"))
        internet_ok = bool(outcome.get("internet"))
        dns_ok = bool(outcome.get("dns"))
        wifi = outcome.get("wifi")
        if not isinstance(wifi, dict):
            wifi = {
                "ssid": None, "signal": None, "signal_percent": None, "rssi": None,
                "rssi_db": None, "state": None, "state_known": False, "connected": None,
            }

        if not internet_ok and target_host:
            internet_ok = ping_host(target_host, timeout=self.timeout + 2)

        signal_text = wifi.get("signal") or "未读取"
        details = (
            f"网关={'OK' if gateway_ok else 'FAIL'}({self.gateway}), "
            f"外网={'OK' if internet_ok else 'FAIL'}, "
            f"DNS={'OK' if dns_ok else 'FAIL'}, "
            f"SSID={wifi.get('ssid') or '未连接'}, 信号={signal_text}"
        )
        if wifi.get("rssi_db") is not None:
            details += f", RSSI={wifi['rssi_db']}dBm"
        if isinstance(metrics, dict) and metrics.get("rtt_avg_ms") is not None:
            details += (
                f", RTT={metrics['rtt_avg_ms']:g}/{metrics.get('rtt_min_ms') or '-'}/"
                f"{metrics.get('rtt_max_ms') or '-'}ms"
            )
            if metrics.get("jitter_ms") is not None:
                details += f", 抖动={metrics['jitter_ms']:g}ms"
            if metrics.get("loss_percent") is not None:
                details += f", 丢包={metrics['loss_percent']:g}%"

        return {
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "gateway_ok": gateway_ok,
            "internet_ok": internet_ok,
            "dns_ok": dns_ok,
            "healthy": bool(gateway_ok and internet_ok and dns_ok),
            "gateway": self.gateway,
            "ssid": wifi.get("ssid"),
            "signal": wifi.get("signal"),
            "signal_percent": wifi.get("signal_percent"),
            "rssi_db": wifi.get("rssi_db"),
            "wifi_state": wifi.get("state"),
            "wifi_connected": wifi.get("connected"),
            "metrics": metrics if isinstance(metrics, dict) else None,
            "details": details,
        }


def check_connection(target_host=None, config=None, probe=None, metrics=None):
    config = config or load_config()
    probe = probe or NetworkProbe(config)
    try:
        status = probe.check_all(target_host, metrics=metrics)
    except TypeError:
        # 兼容只接受 target_host 的旧探针实现
        status = probe.check_all(target_host)
    status["analysis"] = analyze_network_status(status, config)
    return status


# --------------------------------------------------------------------------
# 故障归因
# --------------------------------------------------------------------------

def analyze_network_status(status, config=None):
    """按因果顺序归因：网关 -> 外网 -> DNS -> 信号。

    注意：外网必须排在 DNS 之前。外网不通时 DNS 必然也解析失败，
    先判 DNS 会把「外网出口故障」误报成「DNS 配置问题」。
    """
    config = config or {}
    weak_threshold = int(config.get("weak_signal_threshold") or 50)

    gateway_ok = bool(status.get("gateway_ok", False))
    internet_ok = bool(status.get("internet_ok", False))
    dns_ok = bool(status.get("dns_ok", False))
    signal_percent = status.get("signal_percent")
    if signal_percent is None and status.get("signal") is not None:
        signal_percent = parse_signal_strength(status.get("signal"))
    ssid = status.get("ssid") or "当前网络"
    signal_text = status.get("signal")
    if not signal_text and signal_percent is not None:
        signal_text = f"{signal_percent}%"
    signal_text = signal_text or "未知"
    wifi_connected = status.get("wifi_connected")
    degrade_reasons = metric_degrade_reasons(status.get("metrics"), config)

    if wifi_connected is False and not gateway_ok:
        primary = "wifi_link"
        summary = (
            f"无线网卡当前未连接到任何 WiFi（状态：{status.get('wifi_state') or '未知'}），"
            f"网关 {status.get('gateway') or '未知'} 不可达。请先确认 WiFi 是否已连接。"
        )
        recommendations = [
            "确认无线开关和飞行模式状态",
            "在系统 WiFi 列表中选择并重新连接目标网络",
            "检查是否误连到无信号的网络",
        ]
    elif not gateway_ok:
        primary = "gateway"
        summary = (
            f"{ssid} 的网关 {status.get('gateway') or '未知'} 不可达，说明路由器或本地链路存在问题。"
            f" WiFi 可能仍然连接，但网关没有响应，优先检查路由器和光猫状态。"
        )
        recommendations = [
            "重启路由器或光猫",
            "确认路由器电源和网线连接正常",
            "检查本机是否获取到有效 IP 地址",
        ]
    elif not internet_ok:
        primary = "internet"
        summary = (
            f"{ssid} 的网关可达，但外网 TCP 连接全部失败。"
            f" 这属于运营商出口、光猫或上网策略问题，不是 WiFi 或 DNS 的问题。"
        )
        recommendations = [
            "检查宽带是否欠费或停机",
            "重启光猫 / 运营商设备",
            "确认路由器 WAN 口状态与拨号是否正常",
        ]
    elif not dns_ok:
        primary = "dns"
        summary = (
            f"{ssid} 的网关与外网都正常，但域名解析失败。"
            f" 说明链路通畅，仅 DNS 服务异常。"
        )
        recommendations = [
            "把 DNS 改为 223.5.5.5 / 114.114.114.114",
            "检查本机 DNS 设置和代理软件（部分代理会劫持 DNS）",
            "确认路由器是否禁用了 DNS 转发",
        ]
    elif signal_percent is not None and signal_percent < weak_threshold:
        primary = "wifi"
        summary = (
            f"{ssid} 当前 WiFi 信号较弱（{signal_text}），这会导致断线和丢包。"
            f" 网络仍可通，但很可能是高延迟或间歇性掉线的根因。"
        )
        recommendations = [
            "让设备靠近路由器，减少墙体遮挡",
            "检查微波炉、蓝牙设备等 2.4G 干扰源",
            "考虑切换信道或改用 5G 频段",
        ]
    elif degrade_reasons:
        # 通但很差 —— 布尔值时代测不出这一段，恰是「视频卡但没断网」的根因
        primary = "degraded"
        summary = (
            f"{ssid} 网络可达但质量明显下降（{'、'.join(degrade_reasons)}）。"
            f" 这属于「通了但发虚」：网页能开，但视频通话、游戏会卡顿、掉帧。"
        )
        recommendations = [
            "查看下方站点可用性，判断是整体慢还是某个服务慢",
            "重启路由器 / 光猫后复测，排除设备长时间运行的缓存问题",
            "避开上网高峰时段再测一次，确认是否为运营商拥塞",
            "若丢包持续存在，把监控记录导出发给运营商举证",
        ]
    elif signal_percent is None:
        primary = "healthy"
        summary = (
            f"{ssid} 当前网络状态正常，网关、外网和 DNS 均可达。"
            f" 信号强度无法读取（该网卡可能不是无线网卡，或系统语言未适配）。"
        )
        recommendations = [
            "继续保持监控",
            "如使用有线网络，信号项可忽略",
        ]
    else:
        primary = "healthy"
        summary = (
            f"{ssid} 当前网络状态正常，网关、外网和 DNS 均可达，"
            f" WiFi 信号强度 {signal_text}，未发现明显故障。"
        )
        recommendations = [
            "继续保持监控",
            "如后续出现抖动再检查路由器日志",
        ]

    return {
        "primary_cause": primary,
        "cause_level": derive_cause_level(primary),
        "signal_value": signal_percent,
        "degrade_reasons": degrade_reasons,
        "summary": summary,
        "recommendations": recommendations,
    }


PRIMARY_CAUSE_LABELS = {
    "gateway": "网关不可达",
    "internet": "外网不可达",
    "dns": "DNS 解析失败",
    "wifi": "WiFi 信号弱",
    "wifi_link": "未连接 WiFi",
    "degraded": "网络质量下降",
    "healthy": "正常",
}


# --------------------------------------------------------------------------
# 数据库
# --------------------------------------------------------------------------

def connect_db(db_file):
    conn = sqlite3.connect(db_file, timeout=10)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


# SQLite 在「一个连接收尾关闭 WAL、另一个连接恰好要写」的瞬间会短暂返回
# "attempt to write a readonly database"（也有 locked / i-o error 变体）。
# 这类错误重试就会消失，但直接抛出去会让监控线程把整轮检测判成异常 —— 实测在
# 并发读写场景（GUI 刷新 + 监控写库）下会偶发，所以统一加重试。
_TRANSIENT_DB_ERRORS = (
    "readonly database",
    "database is locked",
    "database table is locked",
    "disk i/o error",
    "unable to open database file",
)
DB_RETRY_ATTEMPTS = 5
DB_RETRY_BASE_DELAY = 0.08


def with_db_retry(func):
    """只吞瞬时错误并重试；真正的错误（权限、语法等）照常抛出。"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        last_error = None
        for attempt in range(DB_RETRY_ATTEMPTS):
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if not any(token in message for token in _TRANSIENT_DB_ERRORS):
                    raise
                last_error = exc
                if attempt == DB_RETRY_ATTEMPTS - 1:
                    break
                time.sleep(DB_RETRY_BASE_DELAY * (attempt + 1))
        raise last_error

    return wrapper


@with_db_retry
def init_db(db_path):
    conn = connect_db(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT,
                end_time TEXT,
                duration_seconds INTEGER,
                status TEXT,
                details TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                gateway_ok INTEGER,
                internet_ok INTEGER,
                dns_ok INTEGER,
                details TEXT
            )
            """
        )
        # 站点级可用性采样（含证书到期）
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS site_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                name TEXT,
                host TEXT,
                ok INTEGER,
                tcp_ms REAL,
                tls_ms REAL,
                total_ms REAL,
                verdict TEXT,
                cert_expires TEXT,
                cert_days_left INTEGER,
                error TEXT
            )
            """
        )
        # 吞吐测速采样
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS speed_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                ok INTEGER,
                mbps REAL,
                seconds REAL,
                bytes INTEGER,
                source TEXT,
                error TEXT
            )
            """
        )

        # 兼容旧库：逐列补齐新增字段
        event_columns = {
            "recovery_details": "TEXT",
            "updated_at": "TEXT",
            "kind": "TEXT",            # outage / degraded
            "cause_level": "TEXT",     # local / isp / upstream / dns / wifi / unknown
            "evidence": "TEXT",        # 逐跳 + WLAN 事件取证文本
            "metrics_json": "TEXT",    # 事件发生时的指标快照
        }
        existing_events = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        for name, column_type in event_columns.items():
            if name not in existing_events:
                conn.execute(f"ALTER TABLE events ADD COLUMN {name} {column_type}")

        check_columns = {
            "health": "TEXT",          # normal / degraded / outage
            "cause_level": "TEXT",
            "rtt_avg_ms": "REAL",
            "rtt_min_ms": "REAL",
            "rtt_max_ms": "REAL",
            "jitter_ms": "REAL",
            "loss_percent": "REAL",
        }
        existing_checks = {row[1] for row in conn.execute("PRAGMA table_info(checks)")}
        for name, column_type in check_columns.items():
            if name not in existing_checks:
                conn.execute(f"ALTER TABLE checks ADD COLUMN {name} {column_type}")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_start ON events(start_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_site_checks_ts ON site_checks(ts)")
        conn.commit()
    finally:
        conn.close()


@with_db_retry
def record_check(db_file, gateway_ok, internet_ok, dns_ok, details, checked_at=None,
                 health=None, cause_level=None, metrics=None):
    """写入一条检测记录，附带本轮健康等级与量化指标。"""
    ts = checked_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    metrics = metrics if isinstance(metrics, dict) else {}
    conn = connect_db(db_file)
    try:
        conn.execute(
            """
            INSERT INTO checks
                (ts, gateway_ok, internet_ok, dns_ok, details, health, cause_level,
                 rtt_avg_ms, rtt_min_ms, rtt_max_ms, jitter_ms, loss_percent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, 1 if gateway_ok else 0, 1 if internet_ok else 0, 1 if dns_ok else 0,
                details, health, cause_level,
                metrics.get("rtt_avg_ms"), metrics.get("rtt_min_ms"),
                metrics.get("rtt_max_ms"), metrics.get("jitter_ms"),
                metrics.get("loss_percent"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


@with_db_retry
def record_site_checks(db_file, sites, checked_at=None):
    ts = checked_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = [item for item in (sites or []) if isinstance(item, dict)]
    if not rows:
        return 0
    conn = connect_db(db_file)
    try:
        conn.executemany(
            """
            INSERT INTO site_checks
                (ts, name, host, ok, tcp_ms, tls_ms, total_ms, verdict,
                 cert_expires, cert_days_left, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ts, item.get("name"), item.get("host"), 1 if item.get("ok") else 0,
                    item.get("tcp_ms"), item.get("tls_ms"), item.get("total_ms"),
                    item.get("verdict"), item.get("cert_expires"),
                    item.get("cert_days_left"), item.get("error"),
                )
                for item in rows
            ],
        )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


@with_db_retry
def record_speed_test(db_file, result, tested_at=None):
    if not isinstance(result, dict):
        return None
    ts = tested_at or result.get("sampled_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = connect_db(db_file)
    try:
        cursor = conn.execute(
            """
            INSERT INTO speed_tests (ts, ok, mbps, seconds, bytes, source, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, 1 if result.get("ok") else 0, result.get("mbps"),
                result.get("seconds"), result.get("bytes"), result.get("url"),
                result.get("error"),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


@with_db_retry
def get_speed_baseline(db_file, limit=20):
    """取历史测速中位数作为基线，用于判断当前速度是否异常。"""
    conn = connect_db(db_file)
    try:
        rows = conn.execute(
            "SELECT mbps FROM speed_tests WHERE ok = 1 AND mbps IS NOT NULL "
            "ORDER BY id DESC LIMIT ?",
            (max(2, int(limit)),),
        ).fetchall()
    finally:
        conn.close()
    values = [row[0] for row in rows if row[0]]
    if len(values) < 2:
        return None
    return round(statistics.median(values), 2)


@with_db_retry
def add_event(db_file, start_time, end_time, duration, status, details, recovery_details=None,
              kind=HEALTH_OUTAGE, cause_level=None, metrics=None):
    """通用写入（保留旧签名，兼容既有调用方与测试）。"""
    conn = connect_db(db_file)
    try:
        cursor = conn.execute(
            """
            INSERT INTO events
                (start_time, end_time, duration_seconds, status, details,
                 recovery_details, updated_at, kind, cause_level, metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                start_time, end_time, duration, status, details, recovery_details,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), kind, cause_level,
                json.dumps(metrics, ensure_ascii=False) if isinstance(metrics, dict) else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def open_outage(db_file, start_time, details, kind=HEALTH_OUTAGE, cause_level=None, metrics=None):
    """事件一发生就落库，避免程序退出/崩溃导致记录丢失。返回事件 id。"""
    return add_event(
        db_file, start_time, None, 0, "ongoing", details,
        kind=kind, cause_level=cause_level, metrics=metrics,
    )


@with_db_retry
def update_event_evidence(db_file, event_id, evidence=None, cause_level=None):
    """取证结果异步回填（tracert 要跑约 9 秒，不能阻塞监控循环）。"""
    if event_id is None:
        return
    conn = connect_db(db_file)
    try:
        if evidence is not None and cause_level is not None:
            conn.execute(
                "UPDATE events SET evidence = ?, cause_level = ?, updated_at = ? WHERE id = ?",
                (evidence, cause_level, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_id),
            )
        elif evidence is not None:
            conn.execute(
                "UPDATE events SET evidence = ?, updated_at = ? WHERE id = ?",
                (evidence, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_id),
            )
        elif cause_level is not None:
            conn.execute(
                "UPDATE events SET cause_level = ?, updated_at = ? WHERE id = ?",
                (cause_level, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_id),
            )
        conn.commit()
    finally:
        conn.close()


@with_db_retry
def close_outage(db_file, event_id, end_time, duration, status, recovery_details=None):
    conn = connect_db(db_file)
    try:
        conn.execute(
            """
            UPDATE events
               SET end_time = ?, duration_seconds = ?, status = ?, recovery_details = ?, updated_at = ?
             WHERE id = ?
            """,
            (
                end_time, duration, status, recovery_details,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@with_db_retry
def mark_stale_ongoing(db_file, now=None):
    """启动时收敛上次异常退出留下的 ongoing 事件（用最后一条检测记录作为结束时间）。"""
    conn = connect_db(db_file)
    try:
        stale = conn.execute(
            "SELECT id, start_time FROM events WHERE status = 'ongoing'"
        ).fetchall()
    finally:
        conn.close()

    for event_id, start_time in stale:
        start = parse_ts(start_time)
        if start is None:
            continue
        conn = connect_db(db_file)
        try:
            row = conn.execute(
                "SELECT MAX(ts) FROM checks WHERE ts >= ?", (start_time,)
            ).fetchone()
            last_ts = row[0] if row else None
        finally:
            conn.close()
        end = parse_ts(last_ts) or start
        if end < start:
            end = start
        duration = int((end - start).total_seconds())
        close_outage(
            db_file, event_id,
            end.strftime("%Y-%m-%d %H:%M:%S"), duration, "interrupted",
            "程序在上次运行时被中断，未确认恢复",
        )
    return len(stale)


def parse_ts(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    return None


@with_db_retry
def get_daily_outage_summary(db_file, now=None):
    """按天统计事件次数与时长；跨天事件会按实际占用时长拆到各天。

    outage_count / total_duration_seconds 保持旧语义（只统计断网），
    另外给出 degraded_count / degraded_duration_seconds，便于区分「断了」和「很差」。
    """
    now = now or datetime.now()
    conn = connect_db(db_file)
    try:
        rows = conn.execute(
            """
            SELECT start_time, end_time, duration_seconds, status, kind
              FROM events
             WHERE status IN ('recovered', 'interrupted', 'ongoing')
             ORDER BY start_time ASC
            """
        ).fetchall()
    finally:
        conn.close()

    per_day = {}

    def bucket_for(day_key):
        return per_day.setdefault(
            day_key,
            {
                "outage_count": 0, "total_duration_seconds": 0.0,
                "degraded_count": 0, "degraded_duration_seconds": 0.0,
                "incident_count": 0,
            },
        )

    for start_text, end_text, _duration, _status, kind in rows:
        start = parse_ts(start_text)
        if start is None:
            continue
        end = parse_ts(end_text) or now
        if end < start:
            end = start

        is_degraded = kind == HEALTH_DEGRADED
        cursor = start
        guard = 0
        while cursor.date() <= end.date() and guard < 400:
            guard += 1
            next_midnight = datetime.combine(cursor.date() + timedelta(days=1), dtime.min)
            segment_end = min(end, next_midnight)
            seconds = max(0.0, (segment_end - cursor).total_seconds())
            bucket = bucket_for(cursor.strftime("%Y-%m-%d"))
            if is_degraded:
                bucket["degraded_count"] += 1
                bucket["degraded_duration_seconds"] += seconds
            else:
                bucket["outage_count"] += 1
                bucket["total_duration_seconds"] += seconds
            if next_midnight <= cursor:
                break
            cursor = next_midnight

    summary = []
    for day_key in sorted(per_day):
        bucket = per_day[day_key]
        seconds = bucket["total_duration_seconds"]
        degraded_seconds = bucket["degraded_duration_seconds"]
        summary.append(
            {
                "date": day_key,
                "outage_count": int(bucket["outage_count"]),
                "total_duration_seconds": int(seconds),
                "total_duration_minutes": round(seconds / 60, 2),
                "total_duration_hours": round(seconds / 3600, 2),
                "total_duration_text": format_duration(seconds),
                "degraded_count": int(bucket["degraded_count"]),
                "degraded_duration_seconds": int(degraded_seconds),
                "degraded_duration_text": format_duration(degraded_seconds),
                "event_count": int(bucket["outage_count"] + bucket["degraded_count"]),
            }
        )
    return summary


def build_incidents(rows, gap_minutes=30):
    """把碎片事件合并成「事故」。

    rows: [(start_text, end_text, duration, status, kind, cause_level)]
    相邻两条间隔 ≤ gap_minutes 视为同一次事故。给 ISP 举证时，
    「今天 3 次事故、累计 22 分钟」比「今天断了 47 次」有说服力得多。
    """
    gap = timedelta(minutes=max(1, int(gap_minutes)))
    incidents = []
    current = None

    for start_text, end_text, duration, status, kind, cause_level in rows:
        start = parse_ts(start_text)
        if start is None:
            continue
        end = parse_ts(end_text) or datetime.now()
        if end < start:
            end = start
        record = {
            "start": start, "end": end, "seconds": max(0, int(duration or 0)),
            "kinds": [kind or HEALTH_OUTAGE], "causes": [cause_level] if cause_level else [],
            "event_count": 1, "statuses": [status],
        }
        if current is not None and start - current["end"] <= gap:
            current["end"] = max(current["end"], end)
            current["seconds"] += record["seconds"]
            current["event_count"] += 1
            current["kinds"].extend(record["kinds"])
            current["causes"].extend(record["causes"])
            current["statuses"].extend(record["statuses"])
        else:
            if current is not None:
                incidents.append(current)
            current = record

    if current is not None:
        incidents.append(current)

    for incident in incidents:
        incident["kinds"] = sorted(set(incident["kinds"]))
        incident["causes"] = sorted({value for value in incident["causes"] if value})
        incident["kind"] = (
            HEALTH_OUTAGE if HEALTH_OUTAGE in incident["kinds"] else HEALTH_DEGRADED
        )
        incident["start_text"] = incident["start"].strftime("%Y-%m-%d %H:%M:%S")
        incident["end_text"] = incident["end"].strftime("%Y-%m-%d %H:%M:%S")
        incident["duration_text"] = format_duration(incident["seconds"])
        incident["date"] = incident["start"].strftime("%Y-%m-%d")
    return incidents


@with_db_retry
def get_incidents(db_file, gap_minutes=30, since_days=None, now=None):
    """读取事件并聚合成事故列表（最近的在前）。"""
    now = now or datetime.now()
    sql = (
        "SELECT start_time, end_time, duration_seconds, status, kind, cause_level "
        "FROM events WHERE status IN ('recovered', 'interrupted', 'ongoing')"
    )
    params = []
    if since_days:
        since = (now - timedelta(days=int(since_days))).strftime("%Y-%m-%d %H:%M:%S")
        sql += " AND start_time >= ?"
        params.append(since)
    sql += " ORDER BY start_time ASC"

    conn = connect_db(db_file)
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    incidents = build_incidents(rows, gap_minutes=gap_minutes)
    incidents.reverse()
    return incidents


@with_db_retry
def get_recent_events(db_file, limit=12):
    """界面用：最近的事件记录（含分级与归因）。"""
    conn = connect_db(db_file)
    try:
        return conn.execute(
            """
            SELECT start_time, end_time, duration_seconds, status, kind,
                   cause_level, details
              FROM events ORDER BY id DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()


def format_event_line(row):
    """把一条事件记录格式化成界面显示的一行。"""
    start, end, duration, status, kind, cause_level, _details = row
    state_labels = {"recovered": "已恢复", "ongoing": "进行中", "interrupted": "未确认恢复"}
    kind_label = "退化" if kind == HEALTH_DEGRADED else "断网"
    cause_label = CAUSE_LEVEL_LABELS.get(cause_level or "", "")
    state = state_labels.get(status, status)
    suffix = f" · {cause_label}" if cause_label else ""
    return f"[{kind_label}] {start} → {end or '—'} | {state} | {format_duration(duration)}{suffix}"


@with_db_retry
def prune_old_data(db_file, retention_days=30, now=None):
    """按保留策略清理高频采样表；事件表永久保留（那是举证材料）。"""
    now = now or datetime.now()
    cutoff = (now - timedelta(days=max(1, int(retention_days)))).strftime("%Y-%m-%d %H:%M:%S")
    removed = {}
    conn = connect_db(db_file)
    try:
        for table in ("checks", "site_checks"):
            cursor = conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            removed[table] = cursor.rowcount
        # 测速采样频率低，留更久
        speed_cutoff = (now - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute("DELETE FROM speed_tests WHERE ts < ?", (speed_cutoff,))
        removed["speed_tests"] = cursor.rowcount
        conn.commit()
    finally:
        conn.close()
    return removed


# --------------------------------------------------------------------------
# 报表
# --------------------------------------------------------------------------

def format_duration(seconds):
    seconds = float(seconds or 0)
    if seconds < 1:
        return "0秒"
    if seconds < 60:
        return f"{seconds:.0f}秒"
    if seconds < 3600:
        return f"{seconds / 60:.1f}分"
    return f"{seconds / 3600:.1f}时"


@with_db_retry
def get_quality_summary(db_file, since_days=1, now=None):
    """统计最近一段时间的网络质量。

    可用率的定义：非断网检测数 / 总检测数。退化不等于不可用，
    所以退化单独统计，不压进可用率里 —— 否则「网通但很差」会被算成断网。
    """
    now = now or datetime.now()
    since = (now - timedelta(days=max(1, int(since_days)))).strftime("%Y-%m-%d %H:%M:%S")
    conn = connect_db(db_file)
    try:
        row = conn.execute(
            """
            SELECT COUNT(*),
                   SUM(CASE WHEN gateway_ok = 1 AND internet_ok = 1 AND dns_ok = 1 THEN 0 ELSE 1 END),
                   SUM(CASE WHEN health = 'degraded' THEN 1 ELSE 0 END),
                   AVG(rtt_avg_ms), AVG(rtt_min_ms), AVG(rtt_max_ms),
                   AVG(jitter_ms), AVG(loss_percent)
              FROM checks WHERE ts >= ?
            """,
            (since,),
        ).fetchone()
    finally:
        conn.close()

    total = int(row[0] or 0)
    outages = int(row[1] or 0)
    degraded = int(row[2] or 0)

    def _round(value, digits=1):
        return round(value, digits) if value is not None else None

    return {
        "total_checks": total,
        "outage_checks": outages,
        "degraded_checks": degraded,
        "healthy_checks": max(0, total - outages),
        "availability_percent": round(100.0 * (total - outages) / total, 3) if total else None,
        "avg_rtt_ms": _round(row[3]),
        "avg_rtt_min_ms": _round(row[4]),
        "avg_rtt_max_ms": _round(row[5]),
        "avg_jitter_ms": _round(row[6]),
        "avg_loss_percent": _round(row[7], 2),
        "since_days": int(since_days),
    }


@with_db_retry
def get_site_summary(db_file, since_days=1, now=None):
    """每个站点的可用率与平均耗时（按站点聚合）。"""
    now = now or datetime.now()
    since = (now - timedelta(days=max(1, int(since_days)))).strftime("%Y-%m-%d %H:%M:%S")
    conn = connect_db(db_file)
    try:
        rows = conn.execute(
            """
            SELECT name, COUNT(*), SUM(CASE WHEN ok = 1 THEN 0 ELSE 1 END),
                   AVG(total_ms), MAX(total_ms), MIN(cert_expires)
              FROM site_checks WHERE ts >= ?
             GROUP BY name ORDER BY name
            """,
            (since,),
        ).fetchall()
    finally:
        conn.close()

    summary = []
    for name, total, failures, avg_ms, worst_ms, cert_expires in rows:
        total = int(total or 0)
        failures = int(failures or 0)
        summary.append(
            {
                "name": name,
                "samples": total,
                "failures": failures,
                "availability_percent": round(100.0 * (total - failures) / total, 2) if total else None,
                "avg_ms": round(avg_ms, 1) if avg_ms is not None else None,
                "worst_ms": round(worst_ms, 1) if worst_ms is not None else None,
                "cert_expires": cert_expires,
            }
        )
    return summary


@with_db_retry
def get_speed_history(db_file, limit=10):
    conn = connect_db(db_file)
    try:
        return conn.execute(
            "SELECT ts, mbps, seconds, source FROM speed_tests WHERE ok = 1 "
            "ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()


def build_daily_chart_svg(summary, output_path, max_bars=30):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if not summary:
        placeholder = (
            "<svg xmlns='http://www.w3.org/2000/svg' width='900' height='360' "
            "viewBox='0 0 900 360'>"
            "<rect width='900' height='360' fill='#0f172a'/>"
            "<text x='450' y='186' fill='#e5e7eb' font-size='26' text-anchor='middle'>"
            "暂无断网记录</text>"
            "</svg>"
        )
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(placeholder)
        return output_path

    charted = summary[-max_bars:]
    truncated = len(summary) - len(charted)

    width, height = 900, 360
    margin_left, margin_right = 90, 40
    margin_top, margin_bottom = 48, 76
    chart_width = width - margin_left - margin_right
    chart_height = height - margin_top - margin_bottom
    baseline_y = margin_top + chart_height          # 零线：柱子与刻度共用同一基准
    axis_right = width - margin_right

    max_value = max(item["total_duration_seconds"] for item in charted) or 1
    max_value = max_value * 1.08                    # 顶部留白，避免柱子顶到轴线

    title = "每日断网时长统计"
    if truncated > 0:
        title += f"（最近 {len(charted)} 天）"

    def y_of(value):
        return baseline_y - (value / max_value) * chart_height

    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
        f"viewBox='0 0 {width} {height}'>",
        "<rect width='100%' height='100%' fill='#0f172a' />",
        f"<text x='{width / 2:.0f}' y='26' text-anchor='middle' fill='#f9fafb' "
        f"font-size='20' font-family='Segoe UI, Microsoft YaHei, Arial'>{title}</text>",
        f"<line x1='{margin_left}' y1='{baseline_y}' x2='{axis_right}' y2='{baseline_y}' "
        f"stroke='#94a3b8' stroke-width='1.5' />",
        f"<line x1='{margin_left}' y1='{margin_top}' x2='{margin_left}' y2='{baseline_y}' "
        f"stroke='#94a3b8' stroke-width='1.5' />",
    ]

    tick_count = 4
    for index in range(tick_count + 1):
        value = max_value * (tick_count - index) / tick_count
        y = y_of(value)
        parts.append(
            f"<line x1='{margin_left}' y1='{y:.1f}' x2='{axis_right}' y2='{y:.1f}' "
            f"stroke='#1e293b' stroke-width='1' />"
        )
        label = format_duration(value) if index < tick_count else "0"
        parts.append(
            f"<text x='{margin_left - 10}' y='{y + 4:.1f}' fill='#cbd5e1' font-size='12' "
            f"text-anchor='end' font-family='Segoe UI, Microsoft YaHei, Arial'>{label}</text>"
        )

    step = chart_width / max(len(charted), 1)
    bar_width = min(64.0, max(4.0, step * 0.62))
    label_every = max(1, int(len(charted) / 12) + 1)

    for index, item in enumerate(charted):
        seconds = item["total_duration_seconds"]
        top_y = y_of(seconds)
        bar_height = max(2.0, baseline_y - top_y)
        x = margin_left + index * step + (step - bar_width) / 2
        if item["outage_count"] <= 2:
            color = "#34d399"
        elif item["outage_count"] <= 4:
            color = "#fbbf24"
        else:
            color = "#f87171"
        parts.append(
            f"<rect x='{x:.1f}' y='{top_y:.1f}' width='{bar_width:.1f}' height='{bar_height:.1f}' "
            f"fill='{color}' rx='4' />"
        )
        if index % label_every == 0:
            parts.append(
                f"<text x='{x + bar_width / 2:.1f}' y='{baseline_y + 18}' fill='#e5e7eb' "
                f"font-size='11' text-anchor='middle' "
                f"font-family='Segoe UI, Microsoft YaHei, Arial'>{item['date'][-5:]}</text>"
            )
        parts.append(
            f"<text x='{x + bar_width / 2:.1f}' y='{max(12.0, top_y - 6):.1f}' fill='#e5e7eb' "
            f"font-size='11' text-anchor='middle' "
            f"font-family='Segoe UI, Microsoft YaHei, Arial'>{item['outage_count']}次</text>"
        )

    parts.append("</svg>")
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(parts))
    return output_path


def _report_html(summary, svg_text, incidents=None, quality=None, sites=None, speed_history=None):
    incidents = incidents or []
    quality = quality or {}
    sites = sites or []
    speed_history = speed_history or []

    total_count = sum(item["outage_count"] for item in summary)
    total_seconds = sum(item["total_duration_seconds"] for item in summary)
    degraded_seconds = sum(item.get("degraded_duration_seconds", 0) for item in summary)

    rows = "\n".join(
        "<tr>"
        f"<td>{item['date']}</td>"
        f"<td>{item['outage_count']}</td>"
        f"<td>{item['total_duration_text']}</td>"
        f"<td>{item.get('degraded_count', 0)}</td>"
        f"<td>{item.get('degraded_duration_text', '0秒')}</td>"
        f"<td>{item['total_duration_seconds']}</td>"
        f"<td>{item['total_duration_minutes']}</td>"
        "</tr>"
        for item in summary
    ) or "<tr><td colspan='7'>暂无记录</td></tr>"

    # 事故列表（30 分钟窗口内的事件已合并）
    incident_rows = "\n".join(
        "<tr>"
        f"<td>{item['start_text']}</td>"
        f"<td>{item['end_text']}</td>"
        f"<td>{item['duration_text']}</td>"
        f"<td>{'断网' if item['kind'] == HEALTH_OUTAGE else '退化'}</td>"
        f"<td>{item['event_count']}</td>"
        f"<td>{'、'.join(CAUSE_LEVEL_LABELS.get(c, c) for c in item['causes']) or '—'}</td>"
        "</tr>"
        for item in incidents[:40]
    ) or "<tr><td colspan='6'>暂无事故</td></tr>"

    site_rows = "\n".join(
        "<tr>"
        f"<td>{item['name']}</td>"
        f"<td>{item['samples']}</td>"
        f"<td>{item['failures']}</td>"
        f"<td>{item['availability_percent'] if item['availability_percent'] is not None else '—'}%</td>"
        f"<td>{item['avg_ms'] if item['avg_ms'] is not None else '—'}</td>"
        f"<td>{item['worst_ms'] if item['worst_ms'] is not None else '—'}</td>"
        f"<td>{item['cert_expires'] or '—'}</td>"
        "</tr>"
        for item in sites
    ) or "<tr><td colspan='7'>暂无站点数据</td></tr>"

    speed_rows = "\n".join(
        f"<tr><td>{ts}</td><td>{mbps:.1f}</td><td>{seconds}</td>"
        f"<td>{os.path.basename(source or '')}</td></tr>"
        for ts, mbps, seconds, source in speed_history
    ) or "<tr><td colspan='4'>暂无测速记录</td></tr>"

    def card(label, value):
        return f"<div class='card'>{label}<b>{value}</b></div>"

    availability = quality.get("availability_percent")
    cards = [
        card("统计天数", len(summary)),
        card("断网总次数", total_count),
        card("断网总时长", format_duration(total_seconds)),
        card("退化总时长", format_duration(degraded_seconds)),
        card("事故数", len(incidents)),
    ]
    if availability is not None:
        cards.append(card("可用率", f"{availability}%"))
    if quality.get("avg_rtt_ms") is not None:
        cards.append(card("平均延迟", f"{quality['avg_rtt_ms']}ms"))
    if quality.get("avg_jitter_ms") is not None:
        cards.append(card("平均抖动", f"{quality['avg_jitter_ms']}ms"))
    if quality.get("avg_loss_percent") is not None:
        cards.append(card("平均丢包", f"{quality['avg_loss_percent']}%"))

    return (
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<title>WiFi 网络质量报表</title>"
        "<style>"
        "body{font-family:'Segoe UI','Microsoft YaHei',Arial;background:#0f172a;"
        "color:#e5e7eb;padding:24px;}"
        "h2{margin:0 0 6px;} h3{margin:26px 0 8px;font-size:15px;color:#f9fafb;}"
        ".sub{color:#94a3b8;font-size:13px;margin-bottom:18px;}"
        ".cards{display:flex;gap:12px;margin-bottom:18px;flex-wrap:wrap;}"
        ".card{background:#1e293b;border-radius:10px;padding:10px 16px;min-width:132px;"
        "color:#94a3b8;font-size:12px;}"
        ".card b{display:block;font-size:20px;color:#f9fafb;margin-top:4px;}"
        "table{border-collapse:collapse;width:100%;max-width:900px;background:#111827;}"
        "th,td{border:1px solid #334155;padding:8px 10px;text-align:left;font-size:13px;}"
        "th{background:#1e293b;color:#f9fafb;}"
        ".chart{max-width:940px;margin-bottom:20px;}"
        ".chart svg{width:100%;height:auto;border:1px solid #334155;border-radius:8px;}"
        ".note{color:#94a3b8;font-size:12px;margin:6px 0 0;}"
        "</style></head><body>"
        "<h2>WiFi 网络质量报表</h2>"
        f"<div class='sub'>生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        f"　·　统计范围 {quality.get('since_days', 1)} 天</div>"
        f"<div class='cards'>{''.join(cards)}</div>"
        f"<div class='chart'>{svg_text}</div>"
        "<div class='note'>柱高表示当天断网累计时长，颜色按当天断网次数：绿≤2 次、黄≤4 次、红&gt;4 次。</div>"
        "<h3>每日统计</h3>"
        "<table><tr><th>日期</th><th>断网次数</th><th>断网时长</th>"
        "<th>退化次数</th><th>退化时长</th><th>秒</th><th>分钟</th></tr>"
        f"{rows}</table>"
        "<h3>事故列表（相邻 30 分钟内的事件已合并）</h3>"
        "<table><tr><th>开始</th><th>结束</th><th>持续</th><th>类型</th>"
        "<th>包含事件数</th><th>归因</th></tr>"
        f"{incident_rows}</table>"
        "<div class='note'>给运营商举证时用这张表："
        "「发生 N 次事故」比「断了 M 次」更准确，也更难被推诿。</div>"
        "<h3>站点可用性</h3>"
        "<table><tr><th>站点</th><th>采样数</th><th>失败数</th><th>可用率</th>"
        "<th>平均耗时(ms)</th><th>最差(ms)</th><th>证书到期</th></tr>"
        f"{site_rows}</table>"
        "<h3>最近测速</h3>"
        "<table><tr><th>时间</th><th>Mbps</th><th>耗时(s)</th><th>源</th></tr>"
        f"{speed_rows}</table>"
        "</body></html>"
    )


def export_daily_report(db_file=None, output_dir=None, now=None, incident_gap_minutes=30,
                        quality_days=1):
    if db_file is None:
        db_file = load_config()["db_file"]
    if output_dir is None:
        output_dir = REPORTS_DIR

    os.makedirs(output_dir, exist_ok=True)
    summary = get_daily_outage_summary(db_file, now=now)
    incidents = get_incidents(db_file, gap_minutes=incident_gap_minutes)
    quality = get_quality_summary(db_file, since_days=quality_days, now=now)
    sites = get_site_summary(db_file, since_days=quality_days, now=now)
    speed_history = get_speed_history(db_file, limit=10)

    csv_path = os.path.join(output_dir, "daily_wifi_report.csv")
    # utf-8-sig 让 Excel 正确识别中文
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            ["date", "outage_count", "total_duration_seconds",
             "total_duration_minutes", "total_duration_hours", "total_duration_text",
             "degraded_count", "degraded_duration_seconds", "degraded_duration_text"]
        )
        for item in summary:
            writer.writerow(
                [
                    item["date"],
                    item["outage_count"],
                    item["total_duration_seconds"],
                    item["total_duration_minutes"],
                    item["total_duration_hours"],
                    item["total_duration_text"],
                    item.get("degraded_count", 0),
                    item.get("degraded_duration_seconds", 0),
                    item.get("degraded_duration_text", "0秒"),
                ]
            )

    incidents_csv = os.path.join(output_dir, "incidents.csv")
    with open(incidents_csv, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            ["start_time", "end_time", "duration_seconds", "kind", "event_count", "causes"]
        )
        for item in incidents:
            writer.writerow(
                [
                    item["start_text"], item["end_text"], item["seconds"],
                    "outage" if item["kind"] == HEALTH_OUTAGE else "degraded",
                    item["event_count"], "|".join(item["causes"]),
                ]
            )

    chart_path = os.path.join(output_dir, "daily_wifi_report.svg")
    build_daily_chart_svg(summary, chart_path)
    with open(chart_path, "r", encoding="utf-8") as handle:
        svg_text = handle.read()

    html_path = os.path.join(output_dir, "daily_wifi_report.html")
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write(
            _report_html(summary, svg_text, incidents, quality, sites, speed_history)
        )

    return {
        "summary": summary,
        "incidents": incidents,
        "quality": quality,
        "sites": sites,
        "csv_path": csv_path,
        "incidents_csv_path": incidents_csv,
        "chart_path": chart_path,
        "html_path": html_path,
    }


# --------------------------------------------------------------------------
# 通知
# --------------------------------------------------------------------------

def log_message(msg, log_file):
    if not log_file:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _LOG_LOCK:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            try:
                if LOG_MAX_BYTES > 0 and os.path.getsize(log_file) >= LOG_MAX_BYTES:
                    # 轮转：旧日志留一代备份，避免 7×24 运行把磁盘写满
                    os.replace(log_file, log_file + ".1")
            except OSError:
                pass
            with open(log_file, "a", encoding="utf-8") as handle:
                handle.write(f"[{ts}] {msg}\n")
        except OSError:
            pass


def send_email(subject, body, config):
    notify = config.get("notify") or {}
    if not notify.get("email_enabled"):
        return False

    try:
        smtp_server = notify.get("smtp_server")
        smtp_port = int(notify.get("smtp_port") or 587)
        smtp_user = notify.get("smtp_user")
        password_env = (notify.get("password_env") or "").strip()
        smtp_password = os.environ.get(password_env) if password_env else None
        smtp_password = smtp_password or notify.get("smtp_password")
        to_email = notify.get("to_email")
        timeout = float(notify.get("timeout_seconds") or 10)

        if not all([smtp_server, smtp_user, smtp_password, to_email]):
            log_message("Email skipped: incomplete smtp settings.", config.get("log_file"))
            return False

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = smtp_user
        msg["To"] = to_email

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=timeout)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=timeout)

        with server:
            if smtp_port != 465:
                server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        log_message("Email sent successfully.", config.get("log_file"))
        return True
    except Exception as exc:
        log_message(f"Email send failed: {exc}", config.get("log_file"))
        return False


def _send_or_queue(state, subject, body, config):
    """异步发通知；失败说明当前发不出去（多半是断网），入队等恢复后补发。

    这是「告警悖论」的解法：断网时邮件本身就走不通（SMTP 要经过外网），
    所以必须先把告警攒在本地，而不是让它悄悄失败。
    发送必须在独立线程，否则 SMTP 挂起会拖死监控循环。
    """
    notify = config.get("notify") or {}
    if not notify.get("email_enabled"):
        return False

    def worker():
        try:
            sent = send_email(subject, body, config)
        except Exception:
            sent = False
        if not sent and state is not None:
            state.add_pending(subject, body)
            log_message(
                "通知发送失败，已入队等待网络恢复后补发。", config.get("log_file")
            )

    threading.Thread(target=worker, name="wifi-notify", daemon=True).start()
    return True


# --------------------------------------------------------------------------
# 监控循环
# --------------------------------------------------------------------------

def _notify_app(app, method, *args):
    """调用界面方法，方法不存在或出错都不影响监控线程。"""
    handler = getattr(app, method, None)
    if handler is None:
        return
    try:
        handler(*args)
    except Exception:
        pass


def create_sampler(config, stop_event, state, on_update=None):
    """按配置创建后台采样线程；关闭采样时返回 None。"""
    if not config.get("sampling_enabled", True):
        return None
    try:
        return BackgroundSampler(config, stop_event, state, on_update)
    except Exception:
        return None


def collect_evidence_async(config, status, db_file, event_id, app=None):
    """异步取证：tracert 约 9 秒、WLAN 事件日志约 1 秒，绝不能阻塞监控循环。"""

    def worker():
        try:
            evidence = collect_evidence(config, status)
            update_event_evidence(
                db_file, event_id, evidence["text"], evidence["segment"]
            )
            segment = evidence["segment"]
            label = {
                "local": "本地网络侧", "isp": "运营商侧", "upstream": "上游站点侧"
            }.get(segment, segment)
            _notify_app(app, "safe_append_log", f"取证完成（{label}），已写入事件记录")
            _notify_app(app, "safe_refresh_events")
        except Exception as exc:
            log_message(f"取证失败: {exc}", config.get("log_file"))

    thread = threading.Thread(target=worker, name="wifi-evidence", daemon=True)
    thread.start()
    return thread


def flush_pending_notifications(state, config):
    """网络恢复后补发断网期间攒下的告警。

    断网时 SMTP 本身就走不通（邮件要经过外网），所以告警必须先入队、
    等网络回来再补发 —— 否则最需要通知的时刻恰好通知失效。
    """
    if not config.get("notify", {}).get("queue_when_offline", True):
        return 0
    pending = state.take_pending()
    sent = 0
    for subject, body in pending:
        if send_email(subject, body, config):
            sent += 1
        else:
            state.add_pending(subject, body)
            break
    if sent:
        log_message(f"已补发 {sent} 条离线期间积压的告警。", config.get("log_file"))
    return sent


def monitor_loop(stop_event, app, state=None, sampler_factory=None):
    """监控主循环。任何单轮异常都不会让线程静默退出。"""
    try:
        config = load_config()
        ensure_paths(config)
        init_db(config["db_file"])
        mark_stale_ongoing(config["db_file"])
    except Exception as exc:
        log_message(f"Monitor init failed: {exc}", os.path.join(BASE_DIR, "logs", "wifi_monitor.log"))
        app.safe_set_state("启动失败")
        app.safe_append_log(f"初始化失败：{exc}")
        app.safe_set_stopped(threading.current_thread())
        return

    log_file = config["log_file"]
    db_file = config["db_file"]
    configure_log_rotation(config.get("log_max_bytes"))
    interval = max(MIN_CHECK_INTERVAL_SECONDS, int(config.get("check_interval_seconds") or 10))
    # 发现异常后不再等满一个正常周期，而是用短间隔快速确认，
    # 这样「拔网线」到报警只需十几秒，而不是等 threshold × 整个周期
    confirm_interval = max(1, int(config.get("confirm_interval_seconds") or 3))
    heartbeat_interval = max(60, int(config.get("heartbeat_interval_seconds") or 300))
    tracker = HealthTracker(
        config.get("failure_threshold", 2), config.get("recovery_threshold", 2)
    )
    try:
        probe = NetworkProbe(config)
    except Exception as exc:
        log_message(f"Probe init failed: {exc}", log_file)
        app.safe_append_log(f"网络探测初始化失败：{exc}")
        app.safe_set_stopped(threading.current_thread())
        return

    state = state or RuntimeState()
    sampler_factory = sampler_factory or create_sampler
    sampler = sampler_factory(
        config, stop_event, state, lambda _kind: _notify_app(app, "safe_refresh_samples")
    )
    if sampler is not None:
        sampler.start()

    # 保留策略：只在启动时清理一次
    try:
        prune_old_data(db_file, config.get("retention_days", 30))
    except Exception as exc:
        log_message(f"清理历史数据失败: {exc}", log_file)

    _notify_app(app, "safe_append_log",
                f"监控已启动：网关={probe.gateway}，正常间隔={interval}s，"
                f"确认间隔={confirm_interval}s，"
                f"连续 {tracker.failure_threshold} 次异常判定为故障。"
                f"后台采样{'已开启（指标/站点/测速）' if sampler else '未开启'}。")

    error_streak = 0
    current_event_id = None
    check_count = 0
    last_heartbeat = time.monotonic()
    last_reported_streak = 0
    last_evidence_at = 0.0
    last_sites_stamp = None
    last_speed_stamp = None
    # 落库节流：探测很密（2s），但写库不必那么密，否则 checks 表会迅速膨胀
    record_interval = max(1, int(config.get("record_check_interval_seconds") or 10))
    site_record_interval = max(5, int(config.get("site_record_interval_seconds") or 60))
    last_check_record = time.monotonic()
    last_site_record = time.monotonic()
    last_health = None
    last_site_verdicts = {}

    while not stop_event.is_set():
        try:
            snapshot = state.snapshot()
            metrics = snapshot.get("metrics")
            sites = snapshot.get("sites") or []
            speed = snapshot.get("speed")

            status = check_connection(config=config, probe=probe, metrics=metrics)
            health_info = evaluate_health(status, metrics, config)
            level = health_info["level"]
            state.set_health(level)

            check_count += 1
            status["check_count"] = check_count
            status["health"] = level
            status["degrade_reasons"] = health_info["reasons"]
            status["sites"] = sites
            status["speed"] = speed
            cause_key = status["analysis"]["primary_cause"]
            cause_level = status["analysis"].get("cause_level")
            state.set_status(status)

            app.safe_update_status(status)

            now_mono = time.monotonic()
            # 首轮（last_health 为 None）与健康等级变化时必须立刻落库，
            # 事件与统计都依赖它；其余按节流间隔写，避免 checks 表迅速膨胀
            if level != last_health or now_mono - last_check_record >= record_interval:
                record_check(
                    db_file, status["gateway_ok"], status["internet_ok"], status["dns_ok"],
                    status["details"], status["checked_at"],
                    health=level, cause_level=cause_level, metrics=metrics,
                )
                last_check_record = now_mono
            last_health = level

            # 站点结果：判定变化时立刻写，否则按节流间隔写
            if sites and sites[0].get("sampled_at") != last_sites_stamp:
                last_sites_stamp = sites[0].get("sampled_at")
                verdicts = {item.get("name"): item.get("verdict") for item in sites}
                changed = verdicts != last_site_verdicts
                if changed or now_mono - last_site_record >= site_record_interval:
                    record_site_checks(db_file, sites, last_sites_stamp)
                    last_site_record = now_mono
                last_site_verdicts = verdicts
            if speed and speed.get("sampled_at") != last_speed_stamp:
                last_speed_stamp = speed.get("sampled_at")
                record_speed_test(db_file, speed)

            actions = tracker.update(level, datetime.now(), status["details"], metrics)
            error_streak = 0
            # 网络恢复后补发断网期间积压的告警
            if level == HEALTH_NORMAL and state.pending_count():
                flush_pending_notifications(state, config)
        except Exception as exc:
            error_streak += 1
            message = f"本轮检测异常（第 {error_streak} 次）：{exc}"
            log_message(message, log_file)
            app.safe_append_log(message)
            app.safe_set_state("监控异常")
            backoff = min(60, interval * min(error_streak, 3))
            if stop_event.wait(backoff):
                break
            continue

        cause = PRIMARY_CAUSE_LABELS.get(cause_key, cause_key)

        # 异常确认过程中的即时反馈：不能让用户觉得程序没在动
        if not tracker.active and tracker.pending_kind not in (None, HEALTH_NORMAL):
            if tracker.pending_streak == 1:
                text = (
                    f"检测异常（{cause}），正在确认 1/{tracker.pending_needed}："
                    f"{status['details']}"
                )
                log_message(text, log_file)
                app.safe_append_log(text)
                app.safe_set_state("异常")
            elif tracker.pending_streak > last_reported_streak:
                text = f"异常持续（{cause}），确认 {tracker.pending_streak}/{tracker.pending_needed}"
                log_message(text, log_file)
                app.safe_append_log(text)
            last_reported_streak = tracker.pending_streak
        elif tracker.pending_kind == HEALTH_NORMAL and tracker.active:
            if tracker.pending_streak == 1:
                text = (
                    f"网络已恢复，正在确认 1/{tracker.pending_needed}：{status['details']}"
                )
                log_message(text, log_file)
                app.safe_append_log(text)
        else:
            last_reported_streak = 0

        for action in actions:
            if action[0] == "start":
                _kind, start_dt, action_details, action_metrics = action[1:5]
                start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
                if _kind == HEALTH_OUTAGE:
                    headline = f"检测到断网（{cause}）"
                else:
                    headline = f"检测到网络质量下降（{'、'.join(health_info['reasons']) or cause}）"
                text = f"{headline}：{action_details}"
                try:
                    current_event_id = open_outage(
                        db_file, start_time, action_details,
                        kind=_kind, cause_level=cause_level, metrics=action_metrics,
                    )
                except Exception as exc:
                    current_event_id = None
                    log_message(f"写入事件失败: {exc}", log_file)
                log_message(text, log_file)
                app.safe_append_log(text)
                app.safe_set_state("异常" if _kind == HEALTH_OUTAGE else "退化")
                body = f"{text}\n开始时间：{start_time}\n归因：{CAUSE_LEVEL_LABELS.get(cause_level, cause_level)}"
                _send_or_queue(state, f"WiFi {'断网' if _kind == HEALTH_OUTAGE else '质量下降'}告警 - {cause}", body, config)
                if (config.get("notify") or {}).get("local_alert_enabled", True):
                    _notify_app(app, "safe_alert", _kind, text)

                # 取证：断网必做，退化做（有冷却），避免频繁跑 tracert
                if config.get("evidence_enabled", True) and current_event_id is not None:
                    now_mono = time.monotonic()
                    cooldown = EVIDENCE_COOLDOWN_SECONDS if _kind != HEALTH_OUTAGE else 0
                    if now_mono - last_evidence_at >= cooldown:
                        last_evidence_at = now_mono
                        app.safe_append_log("正在后台取证（逐跳 + WLAN 断开原因）…")
                        collect_evidence_async(config, status, db_file, current_event_id, app)

            elif action[0] == "end":
                _kind, start_dt, end_dt, duration = action[1:5]
                start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
                end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")
                label = "断网" if _kind == HEALTH_OUTAGE else "网络质量下降"
                text = f"{label}已结束（持续 {format_duration(duration)}）：{status['details']}"
                try:
                    if current_event_id is None:
                        current_event_id = open_outage(
                            db_file, start_time, tracker.active_details or "unknown",
                            kind=_kind, cause_level=cause_level,
                        )
                    close_outage(
                        db_file, current_event_id, end_time, duration, "recovered",
                        status["details"],
                    )
                except Exception as exc:
                    log_message(f"更新事件失败: {exc}", log_file)
                current_event_id = None
                log_message(text, log_file)
                app.safe_append_log(text)
                app.safe_set_state("监控中")
                _notify_app(app, "safe_refresh_events")
                if _kind == HEALTH_OUTAGE:
                    _send_or_queue(state, "WiFi 已恢复", f"{text}\n恢复时间：{end_time}", config)

        # 定期心跳写入文件日志，证明监控在持续运行
        if time.monotonic() - last_heartbeat >= heartbeat_interval:
            last_heartbeat = time.monotonic()
            log_message(
                f"心跳：已连续检测 {check_count} 次，当前状态"
                f"{HEALTH_LABELS.get(level, level)}（{status['details']}）",
                log_file,
            )

        # 异常/确认中时用短间隔快速复检
        busy = tracker.active or tracker.pending_kind not in (None, HEALTH_NORMAL)
        wait_seconds = confirm_interval if busy else interval
        if stop_event.wait(wait_seconds):
            break

    # 退出前把进行中的事件落库，避免记录丢失
    if tracker.active and tracker.active_start is not None:
        end = datetime.now()
        start_time = tracker.active_start.strftime("%Y-%m-%d %H:%M:%S")
        duration = max(0, int((end - tracker.active_start).total_seconds()))
        try:
            if current_event_id is None:
                current_event_id = open_outage(
                    db_file, start_time, tracker.active_details or "unknown",
                    kind=tracker.active_kind,
                )
            close_outage(
                db_file, current_event_id, end.strftime("%Y-%m-%d %H:%M:%S"), duration,
                "interrupted", "监控停止时故障仍未恢复",
            )
            log_message(
                f"监控停止，未恢复的{HEALTH_LABELS.get(tracker.active_kind, '故障')}"
                f"已记录（持续 {format_duration(duration)}）", log_file
            )
        except Exception as exc:
            log_message(f"记录未恢复事件失败: {exc}", log_file)

    if sampler is not None:
        sampler.join(timeout=3)
    app.safe_set_stopped(threading.current_thread())


# --------------------------------------------------------------------------
# 实时看板（本地 HTTP 服务，纯标准库，零新增依赖）
# --------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi 实时看板</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0f172a;color:#e5e7eb;
 font-family:'Segoe UI','Microsoft YaHei',Arial;padding:18px;font-size:14px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;
 flex-wrap:wrap;margin-bottom:16px}
h1{font-size:19px;margin:0;font-weight:600}
h2{font-size:13px;margin:22px 0 8px;color:#94a3b8;font-weight:500;
 text-transform:none;letter-spacing:0}
.meta{display:flex;align-items:center;gap:14px;font-size:12px;color:#94a3b8}
.badge{padding:5px 12px;border-radius:999px;font-weight:600;font-size:13px;
 background:#1e293b;color:#e5e7eb}
.badge.normal{background:#064e3b;color:#6ee7b7}
.badge.degraded{background:#78350f;color:#fcd34d}
.badge.outage{background:#7f1d1d;color:#fca5a5}
.dot{width:8px;height:8px;border-radius:50%;background:#34d399;display:inline-block;
 margin-right:6px;vertical-align:middle}
.dot.off{background:#f87171}
.cards{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}
.card{background:#1e293b;border-radius:12px;padding:13px 16px}
.card .k{color:#94a3b8;font-size:12px;margin-bottom:6px}
.card .v{font-size:22px;font-weight:600;color:#f9fafb;line-height:1.25}
.card .v small{font-size:12px;font-weight:400;color:#94a3b8;margin-left:4px}
.green{color:#6ee7b7!important}.amber{color:#fcd34d!important}.red{color:#fca5a5!important}
.grey{color:#94a3b8!important}
table{border-collapse:collapse;width:100%;background:#111827;border-radius:10px;
 overflow:hidden}
th,td{border-bottom:1px solid #1f2937;padding:9px 12px;text-align:left;font-size:13px}
th{background:#1e293b;color:#94a3b8;font-weight:500}
tr:last-child td{border-bottom:none}
.verdict{font-weight:600}
.trend{background:#111827;border-radius:10px;padding:12px}
svg{display:block;width:100%;height:96px;overflow:visible}
.events{list-style:none;margin:0;padding:0}
.events li{padding:8px 12px;border-bottom:1px solid #1f2937;
 font-family:Consolas,monospace;font-size:12.5px}
.events li:last-child{border-bottom:none}
.events .outage{color:#fca5a5}.events .degraded{color:#fcd34d}
.summary{background:#111827;border-radius:10px;padding:13px 16px;line-height:1.65;
 color:#cbd5e1;font-size:13px}
.empty{color:#64748b;padding:12px;font-size:13px}
footer{margin-top:26px;color:#475569;font-size:11.5px;line-height:1.7}
</style></head>
<body>
<header>
  <div>
    <h1>WiFi 实时看板</h1>
    <div class="meta" style="margin-top:6px">
      <span id="ssid">—</span>
      <span id="details">—</span>
    </div>
  </div>
  <div class="meta">
    <span class="badge" id="healthBadge">连接中…</span>
    <span><span class="dot" id="connDot"></span><span id="connText">正在连接</span></span>
  </div>
</header>

<div class="cards">
  <div class="card"><div class="k">可用率（今日）</div><div class="v" id="cAvail">—</div></div>
  <div class="card"><div class="k">延迟 avg / min / max</div><div class="v" id="cRtt">—</div></div>
  <div class="card"><div class="k">抖动</div><div class="v" id="cJitter">—</div></div>
  <div class="card"><div class="k">丢包</div><div class="v" id="cLoss">—</div></div>
  <div class="card"><div class="k">下载速度</div><div class="v" id="cSpeed">—</div></div>
  <div class="card"><div class="k">今日断网</div><div class="v" id="cOutage">—</div></div>
  <div class="card"><div class="k">今日事故</div><div class="v" id="cIncident">—</div></div>
  <div class="card"><div class="k">检测轮次</div><div class="v" id="cCount">—</div></div>
</div>

<h2>三层探测</h2>
<table>
  <tr><th>层</th><th>状态</th><th>目标</th></tr>
  <tr><td>网关</td><td id="fGateway">—</td><td id="tGateway">—</td></tr>
  <tr><td>外网</td><td id="fInternet">—</td><td>TCP 直连（不经 DNS）</td></tr>
  <tr><td>DNS</td><td id="fDns">—</td><td>域名解析</td></tr>
  <tr><td>无线信号</td><td id="fSignal">—</td><td id="tSignal">—</td></tr>
</table>

<h2>延迟与丢包趋势（最近 60 次采样）</h2>
<div class="trend"><svg id="spark" viewBox="0 0 600 96" preserveAspectRatio="none"></svg></div>

<h2>站点可用性</h2>
<table id="siteTable"><tr><th>站点</th><th>结论</th><th>耗时</th><th>证书到期</th></tr></table>

<h2>当前分析</h2>
<div class="summary" id="analysis">—</div>

<h2>最近事件</h2>
<ul class="events" id="events"></ul>

<footer>
  实时看板 · 数据每 <span id="refreshHint">1</span> 秒刷新 ·
  探测在后台线程，不影响报警速度<br>
  只读接口，仅在监听地址内可访问
</footer>

<script>
var FAILS = 0;
function $(id){ return document.getElementById(id); }
function setText(id, text){ var el = $(id); if (el) el.textContent = text; }
function num(v, digits, suffix){
  if (v === null || v === undefined || v === '') return '—';
  return Number(v).toFixed(digits === undefined ? 0 : digits) + (suffix || '');
}
function okHtml(ok){
  return ok ? '<span class="green">可达</span>' : '<span class="red">不可达</span>';
}
function verdictClass(v){
  if (v === 'DOWN') return 'red';
  if (v === 'SLOW') return 'amber';
  if (v === 'GREAT' || v === 'OK') return 'green';
  return 'grey';
}
function renderSpark(trend){
  var rtt = (trend && trend.rtt) || [];
  var svg = $('spark');
  if (rtt.length < 2){
    svg.innerHTML = '<text x="12" y="50" fill="#64748b" font-size="12">暂无足够采样</text>';
    return;
  }
  var pad = 6, w = 600 - pad * 2, h = 96 - pad * 2;
  var max = Math.max.apply(null, rtt), min = Math.min.apply(null, rtt);
  var span = Math.max(1, max - min);
  var pts = rtt.map(function(v, i){
    var x = pad + (i / (rtt.length - 1)) * w;
    var y = pad + (1 - (v - min) / span) * h;
    return x.toFixed(1) + ',' + y.toFixed(1);
  });
  var parts = [];
  parts.push('<polyline fill="none" stroke="#38bdf8" stroke-width="2" points="' + pts.join(' ') + '"/>');
  parts.push('<text x="' + (pad + 2) + '" y="12" fill="#64748b" font-size="11">max ' + max.toFixed(0) + 'ms</text>');
  parts.push('<text x="' + (pad + 2) + '" y="' + (96 - 4) + '" fill="#64748b" font-size="11">min ' + min.toFixed(0) + 'ms</text>');
  svg.innerHTML = parts.join('');
}
function renderSites(sites){
  var html = '<tr><th>站点</th><th>结论</th><th>耗时</th><th>证书到期</th></tr>';
  if (!sites || !sites.length){
    html += '<tr><td colspan="4" class="empty">等待采样…</td></tr>';
  } else {
    sites.forEach(function(s){
      var cert = s.cert_expires || '—';
      if (s.cert_warning) cert += ' ⚠';
      html += '<tr><td>' + s.name + '</td>'
            + '<td class="verdict ' + verdictClass(s.verdict) + '">' + (s.verdict || '—') + '</td>'
            + '<td>' + num(s.total_ms, 0, 'ms') + '</td>'
            + '<td>' + cert + '</td></tr>';
    });
  }
  $('siteTable').innerHTML = html;
}
function renderEvents(events){
  var el = $('events');
  if (!events || !events.length){
    el.innerHTML = '<li class="empty">暂无事件</li>';
    return;
  }
  el.innerHTML = events.map(function(e){
    return '<li class="' + (e.kind || '') + '">' + e.text + '</li>';
  }).join('');
}
function render(d){
  var badge = $('healthBadge');
  badge.className = 'badge ' + (d.health || '');
  badge.textContent = d.health_label || d.health || '—';

  setText('ssid', d.ssid || '未连接');
  setText('details', d.details || '');

  var q = d.today || {};
  setText('cAvail', d.availability_percent === null ? '—' : num(d.availability_percent, 1, '%'));
  var m = d.metrics || {};
  setText('cRtt', m.rtt_avg_ms === null || m.rtt_avg_ms === undefined ? '—'
    : num(m.rtt_avg_ms, 0) + ' / ' + num(m.rtt_min_ms, 0) + ' / ' + num(m.rtt_max_ms, 0));
  setText('cJitter', num(m.jitter_ms, 1, 'ms'));
  setText('cLoss', num(m.loss_percent, 1, '%'));
  var s = d.speed || {};
  setText('cSpeed', s.ok ? num(s.mbps, 1, ' Mbps') : '—');
  setText('cOutage', (q.outage_count || 0) + ' 次 · ' + (q.total_duration_text || '0秒'));
  setText('cIncident', (d.incident_count || 0) + ' 起');
  setText('cCount', d.check_count || 0);

  $('fGateway').innerHTML = okHtml(d.flags && d.flags.gateway);
  setText('tGateway', d.gateway || '—');
  $('fInternet').innerHTML = okHtml(d.flags && d.flags.internet);
  $('fDns').innerHTML = okHtml(d.flags && d.flags.dns);
  var sp = d.signal_percent;
  $('fSignal').innerHTML = (sp === null || sp === undefined)
    ? '<span class="grey">未读取</span>'
    : '<span class="' + (sp < 50 ? 'amber' : 'green') + '">' + sp + '%</span>';
  setText('tSignal', d.rssi_db ? d.rssi_db + ' dBm' : '—');

  setText('analysis', d.summary || '—');
  setText('refreshHint', Math.round((d.refresh_ms || 1000) / 1000 * 10) / 10);

  renderSpark(d.trend);
  renderSites(d.sites);
  renderEvents(d.events);
}
async function tick(){
  try {
    var r = await fetch('/api/live', {cache: 'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    render(await r.json());
    FAILS = 0;
    $('connDot').className = 'dot';
    setText('connText', '已连接');
  } catch (e) {
    FAILS += 1;
    if (FAILS >= 3){
      $('connDot').className = 'dot off';
      setText('connText', '连接已断开（监控可能已停止）');
    }
  }
}
tick();
setInterval(tick, 1000);
</script>
</body></html>
"""


class _TtlCache:
    """短 TTL 缓存：看板每秒轮询，但统计类查询不必每秒都打数据库。"""

    def __init__(self, ttl=5.0):
        self.ttl = ttl
        self._value = None
        self._at = 0.0

    def get(self, producer):
        now = time.monotonic()
        if self._value is None or now - self._at >= self.ttl:
            try:
                self._value = producer()
            except Exception:
                if self._value is None:
                    self._value = {}
            self._at = now
        return self._value


def _dashboard_db_data(db_file, config):
    """看板里依赖数据库的部分（带缓存调用）。"""
    today = datetime.now().strftime("%Y-%m-%d")
    summary = [item for item in get_daily_outage_summary(db_file) if item["date"] == today]
    today_summary = summary[0] if summary else {}
    gap = config.get("incident_gap_minutes", 30)
    incidents = get_incidents(db_file, gap_minutes=gap, since_days=1)
    conn = connect_db(db_file)
    try:
        trend_rows = conn.execute(
            "SELECT rtt_avg_ms, loss_percent FROM checks "
            "WHERE rtt_avg_ms IS NOT NULL ORDER BY id DESC LIMIT 60"
        ).fetchall()
    finally:
        conn.close()
    trend_rows.reverse()
    return {
        "today": today_summary,
        "incident_count": len(incidents),
        "incidents": incidents[:8],
        "availability_percent": get_quality_summary(db_file, 1).get("availability_percent"),
        "speed_baseline": get_speed_baseline(db_file),
        "trend": {"rtt": [row[0] for row in trend_rows]},
        "events": [
            {"kind": row[4] or HEALTH_OUTAGE, "text": format_event_line(row)}
            for row in get_recent_events(db_file, 10)
        ],
    }


def build_live_payload(state, config=None, db_file=None, cache=None, status=None):
    """组装看板 JSON。实时部分直接读共享状态，统计部分走短 TTL 缓存。"""
    config = config or {}
    state = state or RuntimeState()
    snapshot = state.snapshot()
    metrics = snapshot.get("metrics") or {}
    sites = snapshot.get("sites") or []
    speed = snapshot.get("speed") or {}
    health = snapshot.get("health") or HEALTH_NORMAL
    current = status if isinstance(status, dict) else (state.get_status() or {})

    payload = {
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "refresh_ms": int(config.get("dashboard_refresh_ms") or 1000),
        "health": health,
        "health_label": HEALTH_LABELS.get(health, health),
        "ssid": current.get("ssid"),
        "details": current.get("details") or "等待首轮检测…",
        "check_count": current.get("check_count"),
        "gateway": current.get("gateway"),
        "flags": {
            "gateway": current.get("gateway_ok"),
            "internet": current.get("internet_ok"),
            "dns": current.get("dns_ok"),
        },
        "signal_percent": current.get("signal_percent"),
        "rssi_db": current.get("rssi_db"),
        "summary": (current.get("analysis") or {}).get("summary"),
        "cause_level": (current.get("analysis") or {}).get("cause_level"),
        "metrics": metrics,
        "sites": sites,
        "speed": speed,
        "speed_baseline": None,
        "today": {},
        "incident_count": 0,
        "availability_percent": None,
        "trend": {"rtt": []},
        "events": [],
        "last_sampled": metrics.get("sampled_at"),
    }

    if db_file and os.path.exists(db_file):
        cache = cache or _TtlCache(5.0)
        payload.update(cache.get(lambda: _dashboard_db_data(db_file, config)))
    return payload


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "WifiMonitorDashboard"
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, content_type):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        provider = getattr(self.server, "payload_provider", None)
        if path in ("/", "/index.html"):
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
        elif path == "/api/live":
            payload = {}
            if provider is not None:
                try:
                    payload = provider()
                except Exception as exc:
                    payload = {"error": str(exc)}
            self._send(200, json.dumps(payload, ensure_ascii=False, default=str),
                       "application/json; charset=utf-8")
        elif path == "/api/health":
            self._send(200, json.dumps({"ok": True}), "application/json; charset=utf-8")
        else:
            self._send(404, json.dumps({"error": "not found"}), "application/json; charset=utf-8")

    def log_message(self, *args):
        """静音：每秒一次轮询会把控制台刷爆。"""


class _DashboardServer(ThreadingHTTPServer):
    """看板用的 HTTP 服务。

    必须显式关掉 `allow_reuse_address`：Windows 上 SO_REUSEADDR 的语义与 Linux 不同，
    设了之后**绑定一个已被占用的端口也会成功**（实测），后果是端口顺延逻辑永远不触发，
    还可能悄悄抢用别的程序正在用的端口。
    """

    allow_reuse_address = False
    daemon_threads = True


class LiveDashboard:
    """本地实时看板服务。端口被占用时自动顺延，最多试 10 个。"""

    def __init__(self, config, state, status_provider=None):
        self.config = config
        self.state = state
        self.status_provider = status_provider
        self.host = str(config.get("dashboard_host") or "127.0.0.1")
        self.port = int(config.get("dashboard_port") or 8777)
        self.db_file = config.get("db_file")
        self._cache = _TtlCache(5.0)
        self._server = None
        self._thread = None

    def payload(self):
        status = None
        if self.status_provider is not None:
            try:
                status = self.status_provider()
            except Exception:
                status = None
        return build_live_payload(self.state, self.config, self.db_file, self._cache, status)

    def start(self):
        if self._server is not None:
            return True
        last_error = None
        for offset in range(10):
            port = self.port + offset
            try:
                server = _DashboardServer((self.host, port), DashboardHandler)
            except OSError as exc:
                last_error = exc
                continue
            server.daemon_threads = True
            server.payload_provider = self.payload
            self._server = server
            # 端口传 0 时由系统分配，以实际绑定结果为准
            self.port = server.server_address[1] or port
            self._thread = threading.Thread(
                target=server.serve_forever, name="wifi-dashboard", daemon=True
            )
            self._thread.start()
            log_message(f"实时看板已启动: {self.url}", self.config.get("log_file"))
            return True
        log_message(f"看板启动失败（端口 {self.port} 起 10 个都被占用）: {last_error}",
                    self.config.get("log_file"))
        return False

    def stop(self):
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
        self._server = None

    @property
    def running(self):
        return self._server is not None

    @property
    def url(self):
        host = self.host
        if host in ("0.0.0.0", "", "::"):
            host = local_ip_address() or "127.0.0.1"
        return f"http://{host}:{self.port}/"


def local_ip_address():
    """取本机在局域网里的 IP（供「手机同网访问」提示用）。"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("223.5.5.5", 80))   # 不会真的发包，只为选出出接口
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class HeadlessApp:
    """无界面模式下的 app 替身，让 monitor_loop 不依赖 tkinter。"""

    def __init__(self, on_log=None):
        self.on_log = on_log or console_log
        self.state = RuntimeState()
        self.last_status = None

    def safe_update_status(self, status):
        self.last_status = status

    def safe_append_log(self, message):
        self.on_log(message)

    def safe_set_state(self, value):
        self.on_log(f"[状态] {value}")

    def safe_set_stopped(self, thread):
        self.on_log("[状态] 监控已停止")

    def safe_refresh_events(self):
        pass

    def safe_refresh_samples(self):
        pass

    def safe_alert(self, kind, message):
        self.on_log(f"[{HEALTH_LABELS.get(kind, kind)}] {message}")


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------

class WifiMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WiFi Network Monitor")
        self.geometry("780x900")
        self.minsize(700, 720)
        self.configure(bg="#111827")
        self.stop_event = None
        self.monitor_thread = None
        self.ui_queue = queue.Queue()
        self._closing = False
        self.state = RuntimeState()
        self._apply_window_icon()
        # 响铃开关只读一次：监控运行期间不会改配置
        self.beep_on_outage = True
        try:
            self.beep_on_outage = bool(
                (load_config().get("notify") or {}).get("beep_on_outage", True)
            )
        except Exception:
            pass

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#111827")
        self.style.configure("TLabel", background="#111827", foreground="#e5e7eb")
        self.style.configure("TButton", padding=8)
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#f9fafb")
        self.style.configure("Metric.TLabel", font=("Segoe UI", 11), foreground="#d1d5db")

        self.main = ttk.Frame(self, padding=18)
        self.main.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(self.main)
        header.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(header, text="WiFi 网络监控", style="Header.TLabel").pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="空闲")
        self.status_label = ttk.Label(
            header, textvariable=self.status_var, foreground="#34d399",
            font=("Segoe UI", 11, "bold"),
        )
        self.status_label.pack(side=tk.RIGHT)

        actions = ttk.Frame(self.main)
        actions.pack(fill=tk.X, pady=(0, 12))
        self.start_btn = ttk.Button(actions, text="开始监控", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn = ttk.Button(actions, text="停止监控", command=self.stop_monitoring)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.refresh_btn = ttk.Button(actions, text="刷新记录", command=self.load_recent_events)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.report_btn = ttk.Button(actions, text="生成报表", command=self.generate_report)
        self.report_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.speed_btn = ttk.Button(actions, text="立即测速", command=self.run_speed_test_now)
        self.speed_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.evidence_btn = ttk.Button(actions, text="取证", command=self.run_evidence_now)
        self.evidence_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.dashboard_btn = ttk.Button(actions, text="打开看板", command=self.open_dashboard)
        self.dashboard_btn.pack(side=tk.LEFT)

        metrics = ttk.Frame(self.main)
        metrics.pack(fill=tk.X, pady=(0, 12))
        self.gateway_var = tk.StringVar(value="--")
        self.internet_var = tk.StringVar(value="--")
        self.dns_var = tk.StringVar(value="--")
        self.signal_var = tk.StringVar(value="--")
        self.quality_var = tk.StringVar(value="--")
        self.speed_var = tk.StringVar(value="--")
        self.heartbeat_var = tk.StringVar(value="尚未开始检测")

        for row_index, (label_text, variable) in enumerate(
            [
                ("网关", self.gateway_var),
                ("外网", self.internet_var),
                ("DNS", self.dns_var),
                ("信号", self.signal_var),
                ("质量", self.quality_var),
                ("测速", self.speed_var),
                ("运行", self.heartbeat_var),
            ]
        ):
            frame = ttk.Frame(metrics, padding=(0, 2))
            frame.grid(row=row_index, column=0, sticky="w")
            ttk.Label(frame, text=f"{label_text}:", style="Metric.TLabel").pack(side=tk.LEFT)
            ttk.Label(
                frame, textvariable=variable, style="Metric.TLabel", foreground="#f3f4f6"
            ).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(self.main, text="网络分析", style="Header.TLabel").pack(anchor="w", pady=(8, 6))
        self.analysis_box = scrolledtext.ScrolledText(
            self.main, wrap=tk.WORD, height=8, bg="#0f172a", fg="#e5e7eb", insertbackground="#fff"
        )
        self.analysis_box.pack(fill=tk.X, expand=False)
        self.analysis_box.insert(tk.END, "等待网络分析结果...\n")
        self.analysis_box.configure(state=tk.DISABLED)

        ttk.Label(self.main, text="站点可用性", style="Header.TLabel").pack(anchor="w", pady=(8, 4))
        self.site_box = tk.Listbox(
            self.main, height=4, bg="#0f172a", fg="#e5e7eb", bd=0, highlightthickness=0,
            font=("Consolas", 9),
        )
        self.site_box.pack(fill=tk.X, expand=False)
        self.site_box.insert(tk.END, "等待采样...")

        ttk.Label(self.main, text="日志", style="Header.TLabel").pack(anchor="w", pady=(8, 6))
        self.log_box = scrolledtext.ScrolledText(
            self.main, wrap=tk.WORD, height=9, bg="#0f172a", fg="#e5e7eb", insertbackground="#fff"
        )
        self.log_box.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.main, text="最近事件", style="Header.TLabel").pack(anchor="w", pady=(8, 6))
        self.history_box = tk.Listbox(
            self.main, height=6, bg="#0f172a", fg="#e5e7eb", bd=0, highlightthickness=0,
            selectbackground="#1d4ed8",
        )
        self.history_box.pack(fill=tk.BOTH, expand=False)

        self._ui_handlers = {
            "status": self.apply_status_update,
            "log": self._append_log,
            "state": self._apply_state,
            "stopped": self._apply_stopped,
            "refresh": lambda _payload: self.load_recent_events(),
            "samples": lambda _payload: self.apply_samples(
                self.state.get_sites(), self.state.get_speed()
            ),
            "alert": self._apply_alert,
            "speed_done": lambda _payload: self.speed_btn.configure(state=tk.NORMAL),
            "evidence_done": lambda _payload: self.evidence_btn.configure(state=tk.NORMAL),
        }

        self.load_recent_events()
        self._append_log("程序已启动。点击“开始监控”开始检测。")
        # 实时看板：本地网页，零依赖，界面关掉也不影响命令行模式
        self.dashboard = None
        self._start_dashboard()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(120, self._drain_ui_queue)

    def _apply_window_icon(self):
        """窗口图标。打包后图标随程序分发在临时解包目录里，用 resource_path 定位。"""
        for name in ("app.ico", os.path.join("assets", "app.ico")):
            path = resource_path(name)
            if os.path.exists(path):
                try:
                    self.iconbitmap(path)
                    return
                except Exception:
                    continue

    def _start_dashboard(self):
        try:
            config = load_config()
        except Exception as exc:
            self._append_log(f"看板启动失败（读取配置出错）：{exc}")
            return
        if not config.get("dashboard_enabled", True):
            self._append_log("实时看板已在配置中关闭（dashboard_enabled=false）。")
            return
        try:
            dashboard = LiveDashboard(
                config, self.state, status_provider=self.state.get_status
            )
            if dashboard.start():
                self.dashboard = dashboard
                self._append_log(f"实时看板已启动：{dashboard.url}　（点“打开看板”用浏览器查看）")
            else:
                self._append_log("实时看板启动失败：端口可能被占用。")
        except Exception as exc:
            self._append_log(f"实时看板启动失败：{exc}")

    def open_dashboard(self):
        if self.dashboard is None:
            self._start_dashboard()
        if self.dashboard is None:
            messagebox.showwarning("看板不可用", "实时看板未启动，请查看日志中的原因。")
            return
        url = self.dashboard.url
        self._append_log(f"打开实时看板：{url}")
        try:
            webbrowser.open(url)
        except Exception as exc:
            messagebox.showinfo("实时看板", f"请在浏览器中打开：\n{url}\n\n（自动打开失败：{exc}）")

    # -- 线程安全的界面更新（队列 + 主线程轮询，避免跨线程调用 Tk） ----------

    def post(self, kind, payload=None):
        if self._closing:
            return
        try:
            self.ui_queue.put_nowait((kind, payload))
        except Exception:
            pass

    def _drain_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                handler = self._ui_handlers.get(kind)
                if handler is not None:
                    try:
                        handler(payload)
                    except Exception:
                        pass
        except queue.Empty:
            pass
        except Exception:
            pass
        finally:
            if not self._closing:
                try:
                    self.after(120, self._drain_ui_queue)
                except Exception:
                    pass

    def safe_update_status(self, status):
        self.post("status", status)

    def safe_append_log(self, message):
        self.post("log", message)

    def safe_set_state(self, value):
        self.post("state", value)

    def safe_set_stopped(self, thread):
        self.post("stopped", thread)

    def safe_refresh_events(self):
        self.post("refresh")

    def safe_refresh_samples(self):
        self.post("samples")

    def safe_alert(self, kind, message):
        self.post("alert", (kind, message))

    # -- 界面更新实现 ---------------------------------------------------

    def _apply_state(self, value):
        self.status_var.set(value)
        colors = {
            "监控中": "#34d399", "异常": "#f87171", "退化": "#fbbf24",
            "监控异常": "#fbbf24", "空闲": "#e5e7eb",
        }
        self.status_label.configure(foreground=colors.get(value, "#e5e7eb"))

    def _apply_alert(self, payload):
        """本地告警：断网时任何云端通知都发不出去，界面提示 + 声音是唯一可靠的通道。"""
        kind, message = payload
        # 只有断网才响铃；退化是「通了但差」，反复响会变成噪音
        if kind == HEALTH_OUTAGE and self.beep_on_outage:
            try:
                self.bell()
            except Exception:
                pass
        self._apply_state("异常" if kind == HEALTH_OUTAGE else "退化")
        self._append_log(">>> 本地告警：" + message)

    def _apply_stopped(self, thread):
        # 只有「当前」监控线程才有权改写状态，避免旧的残留线程覆盖新线程
        if thread is not None and self.monitor_thread is not None and thread is not self.monitor_thread:
            return
        self._apply_state("已停止")
        self._append_log("监控已停止。")
        self.load_recent_events()

    def apply_samples(self, sites, speed):
        # 指标采样一落地就刷新，不必等下一轮检测（否则最多要等一个探测周期）
        self._apply_metrics_text(self.state.get_metrics())
        if sites:
            self.site_box.delete(0, tk.END)
            rank = {"DOWN": 0, "SLOW": 1, "OK": 2, "GREAT": 3}
            ordered = sorted(sites, key=lambda item: rank.get(item.get("verdict"), 4))
            for item in ordered:
                timing = f"{item['total_ms']:.0f}ms" if item.get("total_ms") is not None else "—"
                cert = ""
                if item.get("cert_expires"):
                    cert = f"  证书至 {item['cert_expires']}"
                    if item.get("cert_warning"):
                        cert += " ⚠"
                self.site_box.insert(
                    tk.END, f"{item['name']:<8} {item.get('verdict'):<6} {timing:>7}{cert}"
                )
                if item.get("verdict") == "DOWN":
                    self.site_box.itemconfig(tk.END, foreground="#f87171")
                elif item.get("verdict") == "SLOW":
                    self.site_box.itemconfig(tk.END, foreground="#fbbf24")
                else:
                    self.site_box.itemconfig(tk.END, foreground="#6ee7b7")
        if speed:
            self._set_speed_text(speed)

    def _apply_metrics_text(self, metrics):
        if isinstance(metrics, dict) and metrics.get("rtt_avg_ms") is not None:
            text = (
                f"{metrics['rtt_avg_ms']:g}ms"
                f"（{metrics.get('rtt_min_ms') or '-'}~{metrics.get('rtt_max_ms') or '-'}）"
            )
            if metrics.get("jitter_ms") is not None:
                text += f" · 抖动 {metrics['jitter_ms']:g}ms"
            if metrics.get("loss_percent") is not None:
                text += f" · 丢包 {metrics['loss_percent']:g}%"
            stamp = (metrics.get("sampled_at") or "")[-8:]
            self.quality_var.set(f"{text} · {stamp}" if stamp else text)
        else:
            self.quality_var.set("等待采样...")

    def _set_speed_text(self, speed):
        if not speed:
            return
        stamp = (speed.get("sampled_at") or "")[-8:]
        if speed.get("ok"):
            self.speed_var.set(f"{speed['mbps']:.1f} Mbps · {speed['seconds']}s · {stamp}")
        else:
            self.speed_var.set(f"失败（{speed.get('error') or '未知原因'}） · {stamp}")

    def apply_status_update(self, status):
        analysis = status.get("analysis") or analyze_network_status(status)
        self.gateway_var.set(
            f"{'OK' if status['gateway_ok'] else 'FAIL'} ({status.get('gateway') or '-'})"
        )
        self.internet_var.set("OK" if status["internet_ok"] else "FAIL")
        self.dns_var.set("OK" if status["dns_ok"] else "FAIL")
        signal = status.get("signal")
        self.signal_var.set(signal if signal else "未读取")

        metrics = status.get("metrics")
        self._apply_metrics_text(metrics)

        if status.get("speed"):
            self._set_speed_text(status["speed"])

        count = status.get("check_count")
        checked_at = status.get("checked_at") or "-"
        self.heartbeat_var.set(f"第 {count} 次检测 · {checked_at}" if count else checked_at)

        health = status.get("health") or HEALTH_NORMAL
        if health == HEALTH_OUTAGE:
            self._apply_state("异常")
        elif health == HEALTH_DEGRADED:
            self._apply_state("退化")
        else:
            self._apply_state("监控中")

        cause = PRIMARY_CAUSE_LABELS.get(analysis["primary_cause"], analysis["primary_cause"])
        cause_level = analysis.get("cause_level")
        level_text = CAUSE_LEVEL_LABELS.get(cause_level, "")
        self.analysis_box.configure(state=tk.NORMAL)
        self.analysis_box.delete("1.0", tk.END)
        self.analysis_box.insert(
            tk.END,
            f"【{HEALTH_LABELS.get(health, health)} · {cause}】"
            + (f" 归因：{level_text}\n" if level_text else "\n"),
        )
        self.analysis_box.insert(tk.END, f"{analysis['summary']}\n\n建议：\n")
        for item in analysis["recommendations"]:
            self.analysis_box.insert(tk.END, f"- {item}\n")
        self.analysis_box.insert(tk.END, f"\n原始状态：{status.get('details') or '-'}\n")
        self.analysis_box.configure(state=tk.DISABLED)

    def _append_log(self, message):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {message}\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    # -- 操作 -----------------------------------------------------------

    def start_monitoring(self):
        if self.monitor_thread is not None and self.monitor_thread.is_alive():
            if self.stop_event is not None and self.stop_event.is_set():
                # 旧线程仍在收尾，稍后重试，绝不与它并行写库
                self.after(200, self.start_monitoring)
            return
        self.stop_event = threading.Event()
        self.monitor_thread = threading.Thread(
            target=monitor_loop, args=(self.stop_event, self), kwargs={"state": self.state},
            daemon=True, name="wifi-monitor",
        )
        self.monitor_thread.start()
        self._append_log("监控线程已启动。")
        self._apply_state("监控中")

    def stop_monitoring(self):
        if self.stop_event is not None:
            self.stop_event.set()
            self._append_log("正在停止监控...")
        else:
            self._apply_state("已停止")

    def load_recent_events(self):
        try:
            config = load_config()
            init_db(config["db_file"])
            rows = get_recent_events(config["db_file"], limit=12)
            self.history_box.delete(0, tk.END)
            if not rows:
                self.history_box.insert(tk.END, "暂无事件记录")
                return
            for row in rows:
                text = format_event_line(row)
                self.history_box.insert(tk.END, text)
                kind = row[4]
                cause = row[5]
                if kind == HEALTH_DEGRADED or cause == "quality":
                    self.history_box.itemconfig(tk.END, foreground="#fbbf24")
        except Exception as exc:
            self.history_box.delete(0, tk.END)
            self.history_box.insert(tk.END, f"读取失败: {exc}")

    # -- 手动操作 -------------------------------------------------------

    def run_speed_test_now(self):
        """手动触发一次测速（独立线程，不阻塞界面）。"""
        self._append_log("开始手动测速（拉取 1MB 计时）…")
        self.speed_btn.configure(state=tk.DISABLED)

        def worker():
            try:
                config = load_config()
                ensure_paths(config)
                init_db(config["db_file"])
                result = run_speed_test(
                    config.get("speed_test_sources"),
                    size_bytes=config.get("speed_test_bytes", 1048576),
                    timeout=config.get("speed_test_timeout_seconds", 20),
                )
                record_speed_test(config["db_file"], result)
                self.state.set_speed(result)
                self.post("samples", None)
                if result.get("ok"):
                    baseline = get_speed_baseline(config["db_file"])
                    text = f"测速完成：{result['mbps']:.1f} Mbps（{result['seconds']}s）"
                    if baseline:
                        text += f"，历史基线 {baseline:.1f} Mbps"
                    self.post("log", text)
                else:
                    self.post("log", f"测速失败：{result.get('error')}")
            except Exception as exc:
                self.post("log", f"测速异常：{exc}")
            finally:
                self.post("speed_done")

        threading.Thread(target=worker, name="manual-speedtest", daemon=True).start()

    def run_evidence_now(self):
        """手动取证：逐跳 + WLAN 断开原因码（断网时用得上）。"""
        self._append_log("开始取证（逐跳 + WLAN 事件日志）…")
        self.evidence_btn.configure(state=tk.DISABLED)

        def worker():
            try:
                config = load_config()
                probe = NetworkProbe(config)
                status = {
                    "gateway": probe.gateway,
                    "gateway_ok": probe.probe_gateway(),
                    "internet_ok": probe.probe_internet(),
                }
                evidence = collect_evidence(config, status)
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.post("log", f"取证完成（结论段：{evidence['segment']}）")
                for line in evidence["text"].splitlines():
                    self.post("log", "  " + line)
                out_path = os.path.join(config["reports_dir"], "evidence.txt")
                with open(out_path, "a", encoding="utf-8") as handle:
                    handle.write(f"\n===== {stamp} =====\n{evidence['text']}\n")
                self.post("log", f"取证结果已追加到 {out_path}")
            except Exception as exc:
                self.post("log", f"取证失败：{exc}")
            finally:
                self.post("evidence_done")

        threading.Thread(target=worker, name="manual-evidence", daemon=True).start()

    def generate_report(self):
        try:
            config = load_config()
            report = export_daily_report(
                config["db_file"], config["reports_dir"],
                incident_gap_minutes=config.get("incident_gap_minutes", 30),
            )
            summary_text = "\n".join(
                f"{item['date']}: 断网 {item['outage_count']} 次 / {item['total_duration_text']}"
                + (f"，退化 {item['degraded_count']} 次" if item.get("degraded_count") else "")
                for item in report["summary"]
            ) or "暂无记录"
            quality = report.get("quality") or {}
            if quality.get("availability_percent") is not None:
                summary_text += (
                    f"\n\n可用率 {quality['availability_percent']}%"
                    f"，平均延迟 {quality.get('avg_rtt_ms') or '-'}ms"
                    f"，平均丢包 {quality.get('avg_loss_percent') or '-'}%"
                )
            summary_text += f"\n事故数（30 分钟窗口合并）：{len(report.get('incidents') or [])}"
            self._append_log(f"报表已生成: {report['html_path']}")
            messagebox.showinfo(
                "报表生成成功",
                f"HTML: {report['html_path']}\n"
                f"事故清单: {report['incidents_csv_path']}\n"
                f"SVG: {report['chart_path']}\nCSV: {report['csv_path']}\n\n{summary_text}",
            )
        except Exception as exc:
            messagebox.showerror("报表生成失败", str(exc))

    def on_close(self):
        self._closing = True
        if self.stop_event is not None:
            self.stop_event.set()
        thread = self.monitor_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        dashboard = getattr(self, "dashboard", None)
        if dashboard is not None:
            dashboard.stop()
        try:
            self.destroy()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def _show_startup_error(title, message, console=False):
    """启动错误提示。

    `--serve` 是无界面模式，弹 GUI 对话框没有意义；而且打包成 --noconsole 后
    在某些环境下 Tk 也不可用，所以都要能退回控制台输出。
    """
    if console:
        console_log(f"[启动失败] {title}：{message}")
        return
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        console_log(f"[启动失败] {title}：{message}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="WiFi 网络监控工具（默认启动图形界面 + 本地实时看板）"
    )
    parser.add_argument(
        "--serve", action="store_true",
        help="无界面模式：不开窗口，只跑监控 + 实时看板（适合常驻后台）",
    )
    parser.add_argument("--host", help="看板监听地址（默认取 config.json；0.0.0.0 可让同网段手机访问）")
    parser.add_argument("--port", type=int, help="看板端口（默认取 config.json，被占用自动顺延）")
    parser.add_argument("--no-dashboard", action="store_true", help="不启动实时看板")
    parser.add_argument("--open", action="store_true", help="启动后自动用浏览器打开看板")
    return parser.parse_args(argv)


def run_headless(config, args):
    """无界面运行：监控循环 + 看板服务，Ctrl+C 退出。"""
    if args.host:
        config["dashboard_host"] = args.host
    if args.port:
        config["dashboard_port"] = args.port
    if args.no_dashboard:
        config["dashboard_enabled"] = False

    state = RuntimeState()
    stop_event = threading.Event()
    app = HeadlessApp(
        lambda message: console_log(f"[{datetime.now():%H:%M:%S}] {message}")
    )

    dashboard = None
    if config.get("dashboard_enabled", True):
        dashboard = LiveDashboard(config, state, status_provider=state.get_status)
        if dashboard.start():
            console_log(f"实时看板：{dashboard.url}")
            if config.get("dashboard_host") in ("0.0.0.0", "", "::"):
                lan = local_ip_address()
                if lan:
                    console_log(f"同网段可访问：http://{lan}:{dashboard.port}/")
            if args.open:
                try:
                    webbrowser.open(dashboard.url)
                except Exception:
                    pass
        else:
            console_log("实时看板启动失败（端口可能被占用）")

    monitor = threading.Thread(
        target=monitor_loop, args=(stop_event, app), kwargs={"state": state},
        daemon=True, name="wifi-monitor",
    )
    monitor.start()
    console_log("监控已启动，按 Ctrl+C 退出。")
    try:
        while monitor.is_alive():
            monitor.join(1)
    except KeyboardInterrupt:
        console_log("\n正在停止…")
    finally:
        stop_event.set()
        monitor.join(timeout=6)
        if dashboard is not None:
            dashboard.stop()
    console_log("已退出。")


def main(argv=None):
    args = parse_args(argv)
    try:
        created = ensure_config(CONFIG_PATH)
        config = load_config()
        ensure_paths(config)
        init_db(config["db_file"])
    except FileNotFoundError:
        _show_startup_error("配置文件缺失", f"未找到配置文件：\n{CONFIG_PATH}", console=args.serve)
        return 1
    except json.JSONDecodeError as exc:
        _show_startup_error(
            "配置文件格式错误", f"config.json 不是合法 JSON：\n{exc}", console=args.serve
        )
        return 1
    except Exception as exc:
        _show_startup_error("启动失败", f"初始化时发生错误：\n{exc}", console=args.serve)
        return 1

    if created:
        log_message(f"未找到配置文件，已生成默认配置：{CONFIG_PATH}", config.get("log_file"))
        console_log(f"已生成默认配置文件：{CONFIG_PATH}")

    if args.serve:
        run_headless(config, args)
        return 0

    app = WifiMonitorApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
