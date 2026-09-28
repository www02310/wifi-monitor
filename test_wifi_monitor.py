"""wifi_monitor 单元测试

全部测试均为离线可跑：网络探测层通过 mock 注入，不依赖真实网关/外网/DNS，
也不依赖具体路由器地址，换机器不会失败。
"""

import io
import json
import os
import re
import shutil
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from unittest import mock

import wifi_monitor


# 本机真实的中文 netsh 输出（来自 Intel AX211 / Windows 中文版）
NETSH_ZH_CONNECTED = """
系统上有 1 个接口: 

    名称                   : WLAN
    说明            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : a1a9ed11-578a-4e2d-b368-5a6c9ec09c28
    物理地址       : 60:45:2e:2d:1b:a3
    界面类型         : 主要
    状态                  : 已连接
    SSID                   : TP-LINK_5G_D3DA
    AP BSSID               : 58:41:20:c4:d3:dc
    波段                   : 5 GHz
    通道                : 157
    网络类型               : 结构
    无线电类型             : 802.11ac
    身份验证               : WPA2 - 个人
    密码                 : CCMP
    连接模式        : 自动连接
    接收速率(Mbps)         : 390
    传输速率 (Mbps)        : 260
    信号                   : 80%
    Rssi                   : -64
    配置文件               : TP-LINK_5G_D3DA 
"""

NETSH_EN_CONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wireless-AC 9560
    GUID                   : 11111111-2222-3333-4444-555555555555
    Physical address       : 11:22:33:44:55:66
    State                  : connected
    SSID                   : HomeWifi
    AP BSSID               : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ac
    Signal                 : 42%
    Rssi                   : -75
"""

NETSH_ZH_DISCONNECTED = """
系统上有 1 个接口: 

    名称                   : WLAN
    说明            : Intel(R) Wi-Fi 6E AX211 160MHz
    状态                  : 未连接
"""


class TempDirMixin(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="wifi_monitor_test_")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def db_path(self, name="events.db"):
        return os.path.join(self.tmpdir, name)


# --------------------------------------------------------------------------
# 编码与命令
# --------------------------------------------------------------------------

class EncodingTests(unittest.TestCase):
    def test_decode_gbk_output(self):
        # ipconfig 在中文 Windows 输出 GBK（实测）
        raw = "   默认网关. . . . . . . . . . . . . : 192.168.1.1".encode("gbk")
        self.assertIn("192.168.1.1", wifi_monitor.decode_output(raw))
        self.assertIn("默认网关", wifi_monitor.decode_output(raw))

    def test_decode_utf8_output(self):
        # netsh 在同一台机器上输出 UTF-8（实测）
        raw = "    信号                   : 80%".encode("utf-8")
        self.assertEqual("    信号                   : 80%", wifi_monitor.decode_output(raw))

    def test_decode_passthrough_and_empty(self):
        self.assertEqual("abc", wifi_monitor.decode_output("abc"))
        self.assertEqual("", wifi_monitor.decode_output(None))
        self.assertEqual("", wifi_monitor.decode_output(b""))

    def test_decode_invalid_bytes_does_not_raise(self):
        wifi_monitor.decode_output(b"\xff\xfe\x00\x81\x40")

    def test_gateway_regex_does_not_cross_lines(self):
        text = (
            "   默认网关. . . . . . . . . . . . . : \n"
            "   IPv4 地址 . . . . . . . . . . . . : 10.0.0.5\n"
            "   默认网关. . . . . . . . . . . . . : 192.168.1.1\n"
        )
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, text)):
            self.assertEqual(["192.168.1.1"], wifi_monitor.detect_default_gateways())

    def test_detect_gateway_skips_empty_and_dedupes(self):
        text = (
            "   默认网关. . . . . . : 0.0.0.0\n"
            "   默认网关. . . . . . : 192.168.1.1\n"
            "   Default Gateway . . : 192.168.1.1\n"
        )
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, text)):
            self.assertEqual(["192.168.1.1"], wifi_monitor.detect_default_gateways())

    def test_gateway_on_continuation_line(self):
        """本机真实格式：IPv4 网关写在 IPv6 网关的下一行续行里。"""
        text = (
            "无线局域网适配器 WLAN:\n"
            "\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.1.6\n"
            "   子网掩码  . . . . . . . . . . . . : 255.255.255.0\n"
            "   默认网关. . . . . . . . . . . . . : fe80::1%16\n"
            "                                       192.168.1.1\n"
            "\n"
        )
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, text)):
            self.assertEqual(["192.168.1.1"], wifi_monitor.detect_default_gateways())

    def test_gateway_skips_disconnected_adapters(self):
        """虚拟网卡/断开适配器的空网关不能被当成网关。"""
        text = (
            "以太网适配器 VMware Network Adapter VMnet1:\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.40.1\n"
            "   默认网关. . . . . . . . . . . . . : \n"
            "\n"
            "以太网适配器 VMware Network Adapter VMnet8:\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.234.1\n"
            "   默认网关. . . . . . . . . . . . . : \n"
            "\n"
            "无线局域网适配器 WLAN:\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.1.6\n"
            "   默认网关. . . . . . . . . . . . . : fe80::1%16\n"
            "                                       192.168.1.1\n"
        )
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, text)):
            self.assertEqual(["192.168.1.1"], wifi_monitor.detect_default_gateways())


# --------------------------------------------------------------------------
# 无线信号解析（P0 回归）
# --------------------------------------------------------------------------

class WlanParseTests(unittest.TestCase):
    def test_chinese_output_parses_signal(self):
        """中文系统 '信号 : 80%' 必须能解析出来（旧版恒为 None）。"""
        blocks = wifi_monitor.parse_wlan_output(NETSH_ZH_CONNECTED)
        self.assertEqual(1, len(blocks))
        block = blocks[0]
        self.assertEqual("TP-LINK_5G_D3DA", block["ssid"])
        self.assertEqual(80, block["signal_percent"])
        self.assertEqual("80%", block["signal"])
        self.assertEqual(-64, block["rssi_db"])
        self.assertTrue(block["connected"])

    def test_chinese_bssid_not_confused_with_ssid(self):
        block = wifi_monitor.parse_wlan_output(NETSH_ZH_CONNECTED)[0]
        self.assertEqual("TP-LINK_5G_D3DA", block["ssid"])
        self.assertNotIn("58:41:20", block["ssid"])

    def test_english_output_still_works(self):
        block = wifi_monitor.parse_wlan_output(NETSH_EN_CONNECTED)[0]
        self.assertEqual("HomeWifi", block["ssid"])
        self.assertEqual(42, block["signal_percent"])
        self.assertTrue(block["connected"])

    def test_disconnected_interface(self):
        block = wifi_monitor.parse_wlan_output(NETSH_ZH_DISCONNECTED)[0]
        self.assertFalse(block["connected"])
        self.assertIsNone(block["ssid"])
        self.assertIsNone(block["signal_percent"])

    def test_signal_derived_from_rssi_when_percent_missing(self):
        text = "    名称 : WLAN\n    状态 : 已连接\n    SSID : X\n    Rssi : -70\n"
        block = wifi_monitor.parse_wlan_output(text)[0]
        self.assertEqual(60, block["signal_percent"])

    def test_check_wifi_signal_picks_connected_block(self):
        two = NETSH_ZH_DISCONNECTED + NETSH_ZH_CONNECTED
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, two)):
            status = wifi_monitor.check_wifi_signal()
        self.assertEqual("TP-LINK_5G_D3DA", status["ssid"])
        self.assertEqual(80, status["signal_percent"])

    def test_check_wifi_signal_handles_empty_output(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(1, "")):
            status = wifi_monitor.check_wifi_signal()
        self.assertIsNone(status["ssid"])
        self.assertIsNone(status["signal_percent"])
        self.assertIsNone(status["connected"])


# --------------------------------------------------------------------------
# 故障归因（P0 回归：外网故障不能再误报成 DNS）
# --------------------------------------------------------------------------

class AnalysisTests(unittest.TestCase):
    def test_internet_down_is_not_reported_as_dns(self):
        """网关通、外网不通、DNS 也不通时，应归因为外网，而不是 DNS。"""
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": True, "internet_ok": False, "dns_ok": False,
             "signal_percent": 80, "ssid": "X"}
        )
        self.assertEqual("internet", diagnosis["primary_cause"])
        self.assertIn("外网", diagnosis["summary"])
        self.assertNotIn("DNS 解析失败", diagnosis["summary"])

    def test_dns_only_failure_is_reported_as_dns(self):
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": True, "internet_ok": True, "dns_ok": False,
             "signal_percent": 80, "ssid": "X"}
        )
        self.assertEqual("dns", diagnosis["primary_cause"])
        self.assertIn("DNS", diagnosis["summary"])
        self.assertNotIn("8.8.8.8", " ".join(diagnosis["recommendations"]))

    def test_gateway_down(self):
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": False, "internet_ok": False, "dns_ok": False,
             "signal_percent": 30, "ssid": "MyWiFi", "gateway": "192.168.1.1"}
        )
        self.assertEqual("gateway", diagnosis["primary_cause"])
        self.assertIn("192.168.1.1", diagnosis["summary"])

    def test_wifi_disconnected_lowest_layer(self):
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": False, "internet_ok": False, "dns_ok": False,
             "wifi_connected": False, "wifi_state": "未连接", "gateway": "192.168.1.1"}
        )
        self.assertEqual("wifi_link", diagnosis["primary_cause"])

    def test_healthy_with_strong_signal(self):
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": True, "internet_ok": True, "dns_ok": True,
             "signal_percent": 80, "ssid": "X"}
        )
        self.assertEqual("healthy", diagnosis["primary_cause"])

    def test_healthy_with_weak_signal(self):
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": True, "internet_ok": True, "dns_ok": True,
             "signal_percent": 20, "signal": "20%", "ssid": "X"}
        )
        self.assertEqual("wifi", diagnosis["primary_cause"])

    def test_unknown_signal_must_not_be_reported_as_weak(self):
        """信号读不到时必须报正常，不能像旧版那样恒报『信号较弱（0%）』。"""
        diagnosis = wifi_monitor.analyze_network_status(
            {"gateway_ok": True, "internet_ok": True, "dns_ok": True,
             "signal_percent": None, "signal": None, "ssid": "X"}
        )
        self.assertEqual("healthy", diagnosis["primary_cause"])
        self.assertNotIn("信号较弱", diagnosis["summary"])

    def test_weak_threshold_from_config(self):
        status = {"gateway_ok": True, "internet_ok": True, "dns_ok": True,
                  "signal_percent": 60, "signal": "60%", "ssid": "X"}
        self.assertEqual("healthy", wifi_monitor.analyze_network_status(status, {})["primary_cause"])
        self.assertEqual(
            "wifi",
            wifi_monitor.analyze_network_status(status, {"weak_signal_threshold": 70})["primary_cause"],
        )


# --------------------------------------------------------------------------
# 三层探测解耦（P0 回归）
# --------------------------------------------------------------------------

class ProbeIndependenceTests(unittest.TestCase):
    def _config(self):
        return {
            "gateway": "10.0.0.1",
            "probe_timeout_seconds": 1,
            "internet_targets": [{"host": "223.5.5.5", "port": 443}],
            "dns_probe_hosts": ["www.baidu.com"],
        }

    @staticmethod
    def _wifi():
        return {"ssid": "X", "signal": "80%", "signal_percent": 80, "rssi_db": -50,
                "state": "已连接", "connected": True}

    def test_internet_and_dns_are_independent(self):
        """外网通、DNS 挂：internet_ok=True 且 dns_ok=False。"""
        with mock.patch.object(wifi_monitor, "ping_host", return_value=True), \
             mock.patch.object(wifi_monitor, "tcp_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "dns_probe", return_value=False), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", return_value=self._wifi()):
            status = wifi_monitor.check_connection(config=self._config())
        self.assertTrue(status["internet_ok"])
        self.assertFalse(status["dns_ok"])
        self.assertEqual("dns", status["analysis"]["primary_cause"])

    def test_internet_down_while_gateway_up(self):
        """DNS 探测返回 True 也救不了外网：internet 由 TCP 结果决定。"""
        with mock.patch.object(wifi_monitor, "ping_host", return_value=True), \
             mock.patch.object(wifi_monitor, "tcp_probe", return_value=False), \
             mock.patch.object(wifi_monitor, "dns_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", return_value=self._wifi()):
            status = wifi_monitor.check_connection(config=self._config())
        self.assertTrue(status["gateway_ok"])
        self.assertFalse(status["internet_ok"])
        self.assertEqual("internet", status["analysis"]["primary_cause"])

    def test_gateway_tcp_fallback_when_icmp_blocked(self):
        """路由器禁 ICMP 时，用 TCP 兜底判定网关可达。"""
        with mock.patch.object(wifi_monitor, "ping_host", return_value=False), \
             mock.patch.object(wifi_monitor, "tcp_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "dns_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", return_value=self._wifi()), \
             mock.patch.object(wifi_monitor, "detect_default_gateways", return_value=["10.0.0.1"]):
            probe = wifi_monitor.NetworkProbe(self._config())
            self.assertTrue(probe.probe_gateway())

    def test_details_include_signal_and_gateway(self):
        with mock.patch.object(wifi_monitor, "ping_host", return_value=True), \
             mock.patch.object(wifi_monitor, "tcp_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "dns_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", return_value=self._wifi()):
            status = wifi_monitor.check_connection(config=self._config())
        self.assertIn("80%", status["details"])
        self.assertIn("10.0.0.1", status["details"])
        self.assertIn("-50dBm", status["details"])


# --------------------------------------------------------------------------
# 防抖状态机（P0 回归：failure_threshold 必须生效）
# --------------------------------------------------------------------------

class OutageTrackerTests(unittest.TestCase):
    def setUp(self):
        self.t0 = datetime(2026, 9, 28, 10, 0, 0)

    def _at(self, seconds):
        return self.t0 + timedelta(seconds=seconds)

    def test_single_failure_does_not_start_outage(self):
        tracker = wifi_monitor.OutageTracker(failure_threshold=3, recovery_threshold=2)
        self.assertIsNone(tracker.update(False, self.t0))
        self.assertIsNone(tracker.update(False, self._at(20)))
        self.assertFalse(tracker.active)

    def test_third_failure_starts_outage_at_first_failure_time(self):
        tracker = wifi_monitor.OutageTracker(failure_threshold=3, recovery_threshold=2)
        first = self.t0
        tracker.update(False, first)
        tracker.update(False, self._at(20))
        action = tracker.update(False, self._at(40))
        self.assertIsNotNone(action)
        self.assertEqual("start", action[0])
        # 起始时间必须是「第一次失败」的时刻，而不是达到阈值的那一次
        self.assertEqual(first, action[1])
        self.assertTrue(tracker.active)

    def test_flapping_does_not_create_outage(self):
        """失败-成功交替的抖动，不应产生任何断网事件。"""
        tracker = wifi_monitor.OutageTracker(failure_threshold=3, recovery_threshold=2)
        actions = []
        for index in range(10):
            action = tracker.update(index % 2 == 1, self._at(index * 20))
            if action:
                actions.append(action)
        self.assertEqual([], actions)

    def test_recovery_needs_consecutive_successes(self):
        tracker = wifi_monitor.OutageTracker(failure_threshold=2, recovery_threshold=3)
        tracker.update(False, self.t0)
        tracker.update(False, self._at(20))
        self.assertTrue(tracker.active)
        self.assertIsNone(tracker.update(True, self._at(40)))
        self.assertIsNone(tracker.update(True, self._at(60)))
        action = tracker.update(True, self._at(80))
        self.assertEqual("end", action[0])
        self.assertEqual(80, action[3])
        self.assertFalse(tracker.active)

    def test_single_success_in_middle_does_not_end_outage(self):
        tracker = wifi_monitor.OutageTracker(failure_threshold=1, recovery_threshold=2)
        tracker.update(False, self.t0)
        tracker.update(True, self._at(20))
        self.assertIsNone(tracker.update(False, self._at(40)))
        self.assertTrue(tracker.active)


# --------------------------------------------------------------------------
# 数据库与事件生命周期
# --------------------------------------------------------------------------

class DatabaseTests(TempDirMixin):
    def test_migration_adds_new_columns(self):
        """老库（无 recovery_details / updated_at）必须能自动升级。"""
        path = self.db_path("legacy.db")
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TEXT, "
            "end_time TEXT, duration_seconds INTEGER, status TEXT, details TEXT)"
        )
        conn.commit()
        conn.close()

        wifi_monitor.init_db(path)
        conn = sqlite3.connect(path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        conn.close()
        self.assertIn("recovery_details", columns)
        self.assertIn("updated_at", columns)

    def test_open_and_close_outage(self):
        path = self.db_path()
        wifi_monitor.init_db(path)
        event_id = wifi_monitor.open_outage(path, "2026-09-20 10:00:00", "gateway=True, internet=False")
        conn = sqlite3.connect(path)
        row = conn.execute("SELECT status, end_time FROM events WHERE id = ?", (event_id,)).fetchone()
        conn.close()
        self.assertEqual("ongoing", row[0])
        self.assertIsNone(row[1])

        wifi_monitor.close_outage(path, event_id, "2026-09-20 10:05:00", 300, "recovered", "all ok")
        summary = wifi_monitor.get_daily_outage_summary(path)
        self.assertEqual("2026-09-20", summary[0]["date"])
        self.assertEqual(1, summary[0]["outage_count"])
        self.assertEqual(300, summary[0]["total_duration_seconds"])

    def test_daily_summary_aggregates_same_day(self):
        path = self.db_path()
        wifi_monitor.init_db(path)
        wifi_monitor.add_event(path, "2026-09-20 10:00:00", "2026-09-20 10:05:00", 300, "recovered", "one")
        wifi_monitor.add_event(path, "2026-09-20 18:00:00", "2026-09-20 18:03:00", 180, "recovered", "two")
        wifi_monitor.add_event(path, "2026-09-21 06:00:00", "2026-09-21 06:10:00", 600, "recovered", "three")

        summary = wifi_monitor.get_daily_outage_summary(path)
        self.assertEqual("2026-09-20", summary[0]["date"])
        self.assertEqual(2, summary[0]["outage_count"])
        self.assertEqual(480, summary[0]["total_duration_seconds"])
        self.assertEqual("2026-09-21", summary[1]["date"])
        self.assertEqual(1, summary[1]["outage_count"])
        self.assertEqual(600, summary[1]["total_duration_seconds"])

    def test_cross_midnight_outage_is_split_by_day(self):
        """23:50 → 次日 00:20 必须拆成 600s + 1200s，而不是全算在前一天。"""
        path = self.db_path()
        wifi_monitor.init_db(path)
        wifi_monitor.add_event(
            path, "2026-09-20 23:50:00", "2026-09-21 00:20:00", 1800, "recovered", "cross"
        )
        summary = wifi_monitor.get_daily_outage_summary(path)
        by_day = {item["date"]: item for item in summary}
        self.assertEqual(600, by_day["2026-09-20"]["total_duration_seconds"])
        self.assertEqual(1200, by_day["2026-09-21"]["total_duration_seconds"])
        self.assertEqual(1800, sum(item["total_duration_seconds"] for item in summary))
        self.assertEqual(1, by_day["2026-09-20"]["outage_count"])
        self.assertEqual(1, by_day["2026-09-21"]["outage_count"])

    def test_multi_day_outage_distributes_by_actual_overlap(self):
        path = self.db_path()
        wifi_monitor.init_db(path)
        # 09-20 12:00 → 09-23 12:00，正好 3 天
        wifi_monitor.add_event(
            path, "2026-09-20 12:00:00", "2026-09-23 12:00:00", 259200, "recovered", "long"
        )
        summary = wifi_monitor.get_daily_outage_summary(path)
        self.assertEqual(4, len(summary))
        self.assertEqual(259200, sum(item["total_duration_seconds"] for item in summary))
        self.assertEqual(43200, summary[0]["total_duration_seconds"])   # 12 小时
        self.assertEqual(86400, summary[1]["total_duration_seconds"])   # 24 小时
        self.assertEqual(86400, summary[2]["total_duration_seconds"])
        self.assertEqual(43200, summary[3]["total_duration_seconds"])

    def test_mark_stale_ongoing_uses_last_check(self):
        """上次崩溃留下的 ongoing 事件，用最后一条检测记录收敛。"""
        path = self.db_path()
        wifi_monitor.init_db(path)
        event_id = wifi_monitor.open_outage(path, "2026-09-20 10:00:00", "boom")
        wifi_monitor.record_check(path, False, False, False, "down", "2026-09-20 10:03:00")

        wifi_monitor.mark_stale_ongoing(path)
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT status, end_time, duration_seconds FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        conn.close()
        self.assertEqual("interrupted", row[0])
        self.assertEqual("2026-09-20 10:03:00", row[1])
        self.assertEqual(180, row[2])

    def test_record_check_writes_row(self):
        path = self.db_path()
        wifi_monitor.init_db(path)
        wifi_monitor.record_check(path, True, False, True, "detail", "2026-09-20 10:00:00")
        conn = sqlite3.connect(path)
        row = conn.execute("SELECT ts, gateway_ok, internet_ok, dns_ok FROM checks").fetchone()
        conn.close()
        self.assertEqual(("2026-09-20 10:00:00", 1, 0, 1), row)


# --------------------------------------------------------------------------
# 报表
# --------------------------------------------------------------------------

class ReportTests(TempDirMixin):
    def test_export_creates_all_files(self):
        db = self.db_path()
        out = os.path.join(self.tmpdir, "reports")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-20 10:00:00", "2026-09-20 10:05:00", 300, "recovered", "t")

        report = wifi_monitor.export_daily_report(db, out)
        self.assertTrue(os.path.exists(report["csv_path"]))
        self.assertTrue(os.path.exists(report["chart_path"]))
        self.assertTrue(os.path.exists(report["html_path"]))
        self.assertGreaterEqual(report["summary"][0]["outage_count"], 1)

    def test_csv_is_excel_friendly(self):
        db = self.db_path()
        out = os.path.join(self.tmpdir, "reports")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-20 10:00:00", "2026-09-20 10:05:00", 300, "recovered", "t")
        report = wifi_monitor.export_daily_report(db, out)
        with open(report["csv_path"], "rb") as handle:
            head = handle.read(3)
        self.assertEqual(b"\xef\xbb\xbf", head)   # utf-8-sig BOM

    def test_svg_axis_labels_are_meaningful(self):
        """总时长 41 秒时，Y 轴刻度不能像旧版那样全是『0分钟』。"""
        db = self.db_path()
        out = os.path.join(self.tmpdir, "reports")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-20 10:00:00", "2026-09-20 10:00:41", 41, "recovered", "t")
        report = wifi_monitor.export_daily_report(db, out)

        with open(report["chart_path"], "r", encoding="utf-8") as handle:
            svg = handle.read()
        self.assertNotIn("0分钟", svg)
        ticks = re.findall(r"text-anchor='end'[^>]*>([^<]*)</text>", svg)
        self.assertGreater(len(ticks), 1)
        self.assertGreater(len(set(ticks)), 1, f"Y 轴刻度重复：{ticks}")

    def test_svg_bars_stay_inside_axis(self):
        """柱子不能超出最上方刻度线（旧版坐标错位 20px）。"""
        db = self.db_path()
        out = os.path.join(self.tmpdir, "reports")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-20 10:00:00", "2026-09-20 10:00:41", 41, "recovered", "t")
        report = wifi_monitor.export_daily_report(db, out)
        with open(report["chart_path"], "r", encoding="utf-8") as handle:
            svg = handle.read()

        grid_ys = [float(v) for v in re.findall(r"<line x1='90' y1='([\d.]+)'", svg)]
        bar_ys = [float(v) for v in re.findall(r"<rect x='[\d.]+' y='([\d.]+)'", svg)]
        self.assertTrue(grid_ys and bar_ys)
        self.assertGreaterEqual(min(bar_ys), min(grid_ys) - 0.01)

    def test_svg_placeholder_has_viewbox(self):
        path = os.path.join(self.tmpdir, "empty.svg")
        wifi_monitor.build_daily_chart_svg([], path)
        with open(path, "r", encoding="utf-8") as handle:
            svg = handle.read()
        self.assertIn("viewBox", svg)
        self.assertIn("暂无断网记录", svg)

    def test_svg_limits_bar_count(self):
        summary = [
            {"date": f"2026-08-{day:02d}", "outage_count": 1, "total_duration_seconds": 60,
             "total_duration_minutes": 1.0, "total_duration_hours": 0.02,
             "total_duration_text": "1.0分"}
            for day in range(1, 29)
        ]
        summary += [
            {"date": f"2026-09-{day:02d}", "outage_count": 1, "total_duration_seconds": 60,
             "total_duration_minutes": 1.0, "total_duration_hours": 0.02,
             "total_duration_text": "1.0分"}
            for day in range(1, 16)
        ]
        path = os.path.join(self.tmpdir, "many.svg")
        wifi_monitor.build_daily_chart_svg(summary, path, max_bars=30)
        with open(path, "r", encoding="utf-8") as handle:
            svg = handle.read()
        self.assertEqual(30, svg.count("<rect x="))
        self.assertIn("最近 30 天", svg)

    def test_html_embeds_chart(self):
        db = self.db_path()
        out = os.path.join(self.tmpdir, "reports")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-20 10:00:00", "2026-09-20 10:05:00", 300, "recovered", "t")
        report = wifi_monitor.export_daily_report(db, out)
        with open(report["html_path"], "r", encoding="utf-8") as handle:
            html = handle.read()
        self.assertIn("<svg", html)
        self.assertIn("断网总次数", html)

    def test_format_duration(self):
        self.assertEqual("0秒", wifi_monitor.format_duration(0))
        self.assertEqual("41秒", wifi_monitor.format_duration(41))
        self.assertEqual("1.5分", wifi_monitor.format_duration(90))
        self.assertEqual("2.0时", wifi_monitor.format_duration(7200))


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------

class ConfigTests(TempDirMixin):
    def _write_config(self, payload):
        path = os.path.join(self.tmpdir, "config.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        return path

    def test_paths_are_resolved_against_config_dir(self):
        path = self._write_config(
            {"gateway": "10.1.1.1", "log_file": "logs\\a.log", "db_file": "data\\b.db"}
        )
        config = wifi_monitor.load_config(path)
        self.assertTrue(os.path.isabs(config["log_file"]))
        self.assertTrue(os.path.isabs(config["db_file"]))
        self.assertEqual(os.path.join(self.tmpdir, "logs"), os.path.dirname(config["log_file"]))
        self.assertEqual(os.path.join(self.tmpdir, "data"), os.path.dirname(config["db_file"]))

    def test_missing_keys_fall_back_to_defaults(self):
        """旧配置只有 gateway，不应抛 KeyError。"""
        path = self._write_config({"gateway": "192.168.1.1"})
        config = wifi_monitor.load_config(path)
        # 实时刷新默认值：探测 2 秒一轮、3 次确认、1 秒快检
        self.assertEqual(3, config["failure_threshold"])
        self.assertEqual(3, config["recovery_threshold"])
        self.assertEqual(2, config["check_interval_seconds"])
        self.assertEqual(1, config["confirm_interval_seconds"])
        self.assertIn("heartbeat_interval_seconds", config)
        self.assertIn("internet_targets", config)
        self.assertIn("dns_probe_hosts", config)
        self.assertIn("dashboard_port", config)
        self.assertIn("record_check_interval_seconds", config)

    def test_old_config_still_loads(self):
        """旧版 config.json（带 dns 键、无新键）必须能直接跑起来。"""
        path = self._write_config({
            "gateway": "192.168.1.1", "dns": "8.8.8.8",
            "check_interval_seconds": 20, "failure_threshold": 3,
        })
        config = wifi_monitor.load_config(path)
        probe = wifi_monitor.NetworkProbe(config)
        self.assertEqual("192.168.1.1", probe.gateway)
        targets = [host for host, _port in probe._internet_targets()]
        self.assertIn("8.8.8.8", targets)      # 旧 dns 键仍被当作外网目标
        self.assertEqual(3, wifi_monitor.OutageTracker(config["failure_threshold"]).failure_threshold)

    def test_legacy_dns_key_is_tolerated(self):
        path = self._write_config({"gateway": "auto", "dns": "8.8.8.8"})
        config = wifi_monitor.load_config(path)
        self.assertEqual("8.8.8.8", config["dns"])

    def test_notify_block_merges_with_defaults(self):
        path = self._write_config({"notify": {"email_enabled": True}})
        config = wifi_monitor.load_config(path)
        self.assertTrue(config["notify"]["email_enabled"])
        self.assertIn("smtp_server", config["notify"])   # 默认值仍在

    def test_real_config_file_is_valid(self):
        config = wifi_monitor.load_config(wifi_monitor.CONFIG_PATH)
        self.assertEqual("auto", config["gateway"])
        self.assertNotIn("8.8.8.8", json.dumps(config["internet_targets"]))

    def test_missing_config_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            wifi_monitor.load_config(os.path.join(self.tmpdir, "nope.json"))

    def test_broken_json_raises_decode_error(self):
        path = os.path.join(self.tmpdir, "bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ this is not json ")
        with self.assertRaises(json.JSONDecodeError):
            wifi_monitor.load_config(path)


# --------------------------------------------------------------------------
# 邮件
# --------------------------------------------------------------------------

class EmailTests(unittest.TestCase):
    def _config(self, **notify_overrides):
        notify = {
            "email_enabled": True, "smtp_server": "smtp.test", "smtp_port": 587,
            "smtp_user": "u@test", "smtp_password": "p", "to_email": "t@test",
        }
        notify.update(notify_overrides)
        return {"log_file": None, "notify": notify}

    def test_disabled_email_is_noop(self):
        self.assertFalse(wifi_monitor.send_email("s", "b", {"notify": {"email_enabled": False}}))
        with mock.patch("wifi_monitor.smtplib.SMTP") as smtp_cls:
            wifi_monitor.send_email("s", "b", {"notify": {"email_enabled": False}})
            smtp_cls.assert_not_called()

    def test_starttls_used_for_587_with_timeout(self):
        with mock.patch("wifi_monitor.smtplib.SMTP") as smtp_cls:
            instance = smtp_cls.return_value
            self.assertTrue(wifi_monitor.send_email("主题", "内容", self._config()))
            instance.starttls.assert_called_once()
            instance.login.assert_called_once_with("u@test", "p")
            self.assertEqual(10, smtp_cls.call_args.kwargs.get("timeout"))

    def test_ssl_used_for_465_and_no_starttls(self):
        with mock.patch("wifi_monitor.smtplib.SMTP_SSL") as ssl_cls, \
             mock.patch("wifi_monitor.smtplib.SMTP") as plain_cls:
            instance = ssl_cls.return_value
            self.assertTrue(wifi_monitor.send_email("s", "b", self._config(smtp_port=465)))
            ssl_cls.assert_called_once()
            plain_cls.assert_not_called()
            instance.starttls.assert_not_called()

    def test_password_from_env_overrides_plaintext(self):
        config = self._config(password_env="MY_SECRET", smtp_password="plain")
        with mock.patch.dict(os.environ, {"MY_SECRET": "from-env"}), \
             mock.patch("wifi_monitor.smtplib.SMTP") as smtp_cls:
            instance = smtp_cls.return_value
            wifi_monitor.send_email("s", "b", config)
            instance.login.assert_called_once_with("u@test", "from-env")

    def test_smtp_failure_is_swallowed(self):
        with mock.patch("wifi_monitor.smtplib.SMTP", side_effect=OSError("no route")):
            self.assertFalse(wifi_monitor.send_email("s", "b", self._config()))

    def test_incomplete_settings_returns_false(self):
        config = {"log_file": None, "notify": {"email_enabled": True, "smtp_server": "x"}}
        self.assertFalse(wifi_monitor.send_email("s", "b", config))


# --------------------------------------------------------------------------
# 并发探测（P0 回归：断网时不能逐层串行累加超时）
# --------------------------------------------------------------------------

class ParallelProbeTests(unittest.TestCase):
    def test_run_parallel_collects_all_results(self):
        results = wifi_monitor._run_parallel([("a", lambda: 1), ("b", lambda: False)], 2)
        self.assertEqual({"a": 1, "b": False}, results)

    def test_run_parallel_marks_stragglers_as_none(self):
        def slow():
            time.sleep(1.5)
            return True

        started = time.monotonic()
        results = wifi_monitor._run_parallel([("slow", slow)], 0.2)
        elapsed = time.monotonic() - started
        self.assertIsNone(results["slow"])
        self.assertLess(elapsed, 1.0, f"没有遵守超时上限: {elapsed:.2f}s")

    def test_run_parallel_swallows_exceptions(self):
        def boom():
            raise RuntimeError("probe exploded")

        self.assertIsNone(wifi_monitor._run_parallel([("boom", boom)], 1)["boom"])

    def test_layers_run_concurrently(self):
        """四层各睡 0.5s：串行要 ~3s，并发应在 ~1s 内完成。"""
        config = {
            "gateway": "10.0.0.1", "probe_timeout_seconds": 1,
            "internet_targets": [{"host": "1.1.1.1", "port": 443}],
            "dns_probe_hosts": ["x.invalid"],
        }

        def slow_false(*_args, **_kwargs):
            time.sleep(0.5)
            return False

        with mock.patch.object(wifi_monitor, "ping_host", side_effect=slow_false), \
             mock.patch.object(wifi_monitor, "tcp_probe", side_effect=slow_false), \
             mock.patch.object(wifi_monitor, "dns_probe", side_effect=slow_false), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", side_effect=slow_false):
            probe = wifi_monitor.NetworkProbe(config)
            started = time.monotonic()
            status = probe.check_all()
            elapsed = time.monotonic() - started

        self.assertFalse(status["healthy"])
        self.assertLess(elapsed, 1.8, f"三层没有并发，耗时 {elapsed:.2f}s")

    def test_check_all_survives_wifi_read_failure(self):
        config = {
            "gateway": "10.0.0.1", "probe_timeout_seconds": 1,
            "internet_targets": [{"host": "1.1.1.1", "port": 443}],
            "dns_probe_hosts": ["x.invalid"],
        }
        with mock.patch.object(wifi_monitor, "ping_host", return_value=True), \
             mock.patch.object(wifi_monitor, "tcp_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "dns_probe", return_value=True), \
             mock.patch.object(wifi_monitor, "check_wifi_signal", return_value=False):
            probe = wifi_monitor.NetworkProbe(config)
            status = probe.check_all()
        self.assertTrue(status["healthy"])
        self.assertIsNone(status["signal_percent"])


# --------------------------------------------------------------------------
# ping 与 DNS 探测的健壮性
# --------------------------------------------------------------------------

class PingAndDnsTests(unittest.TestCase):
    def test_ping_accepts_real_reply(self):
        out = "来自 192.168.1.1 的回复: 字节=32 时间=4ms TTL=64\n"
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, out)):
            self.assertTrue(wifi_monitor.ping_host("192.168.1.1"))

    def test_ping_rejects_unreachable_reply_with_zero_exit_code(self):
        """中间设备回「无法访问目标主机」时退出码仍是 0，不能算通。"""
        out = (
            "正在 Ping 10.0.0.1 具有 32 字节的数据:\n"
            "来自 192.168.1.1 的回复: 无法访问目标主机。\n"
        )
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, out)):
            self.assertFalse(wifi_monitor.ping_host("10.0.0.1"))

    def test_ping_rejects_timeout_exit_code(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(1, "请求超时。\n")):
            self.assertFalse(wifi_monitor.ping_host("10.0.0.1"))

    def test_dns_pool_is_bounded_and_reused(self):
        """getaddrinfo 是阻塞调用，必须用有上限的线程池兜住，否则断网时线程无限堆积。"""
        pool = wifi_monitor._dns_pool()
        self.assertIs(pool, wifi_monitor._dns_pool())
        self.assertEqual(2, pool._max_workers)

    def test_dns_probe_reports_failure_without_raising(self):
        with mock.patch.object(wifi_monitor.socket, "getaddrinfo", side_effect=OSError("no dns")):
            self.assertFalse(wifi_monitor.dns_probe("nope.invalid", timeout=1))
        self.assertFalse(wifi_monitor.dns_probe("", timeout=1))

    def test_dns_probe_honours_timeout(self):
        def blocks(*_args, **_kwargs):
            time.sleep(3)
            return []

        with mock.patch.object(wifi_monitor.socket, "getaddrinfo", side_effect=blocks):
            started = time.monotonic()
            result = wifi_monitor.dns_probe("slow.invalid", timeout=0.3)
            elapsed = time.monotonic() - started
        self.assertFalse(result)
        self.assertLess(elapsed, 1.5, f"DNS 探测没有遵守超时: {elapsed:.2f}s")


# --------------------------------------------------------------------------
# 监控循环响应速度（用户反馈：断网后没有反应）
# --------------------------------------------------------------------------

class DownProbe:
    def __init__(self, config):
        self.gateway = config.get("gateway") or "10.0.0.1"

    def check_all(self, target_host=None, metrics=None):
        return {
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "gateway_ok": False, "internet_ok": False, "dns_ok": False, "healthy": False,
            "gateway": self.gateway, "ssid": "FakeWiFi", "signal": "80%",
            "signal_percent": 80, "rssi_db": -60, "wifi_state": "已连接",
            "wifi_connected": True, "details": "网关=FAIL(10.0.0.1), 外网=FAIL, DNS=FAIL",
        }


class FakeApp:
    def __init__(self):
        self.logs = []
        self.states = []
        self.statuses = []

    def safe_update_status(self, status):
        self.statuses.append(status)

    def safe_append_log(self, message):
        self.logs.append(message)

    def safe_set_state(self, value):
        self.states.append(value)

    def safe_set_stopped(self, thread):
        pass

    def safe_refresh_events(self):
        pass


class MonitorLoopResponsivenessTests(TempDirMixin):
    """断网必须被「很快」发现，而不是等 threshold × 整个正常周期。"""

    def _run(self, probe_cls, wait_seconds=8):
        config_path = os.path.join(self.tmpdir, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump({
                "gateway": "10.0.0.1",
                "check_interval_seconds": 60,      # 正常间隔故意设得极长
                "confirm_interval_seconds": 1,     # 确认间隔很短
                "failure_threshold": 2,
                "recovery_threshold": 2,
                "heartbeat_interval_seconds": 60,
                "probe_timeout_seconds": 1,
                # 测试必须完全离线：关掉后台采样与自动取证
                "sampling_enabled": False,
                "evidence_enabled": False,
                "log_file": "logs\\wifi_monitor.log",
                "db_file": "data\\wifi_events.db",
                "notify": {"email_enabled": False},
            }, handle)

        self.addCleanup(setattr, wifi_monitor, "CONFIG_PATH", wifi_monitor.CONFIG_PATH)
        self.addCleanup(
            setattr, wifi_monitor, "MIN_CHECK_INTERVAL_SECONDS",
            wifi_monitor.MIN_CHECK_INTERVAL_SECONDS,
        )
        wifi_monitor.CONFIG_PATH = config_path
        wifi_monitor.MIN_CHECK_INTERVAL_SECONDS = 1

        app = FakeApp()
        stop = threading.Event()
        db_path = os.path.join(self.tmpdir, "data", "wifi_events.db")

        with mock.patch.object(wifi_monitor, "NetworkProbe", probe_cls):
            thread = threading.Thread(
                target=wifi_monitor.monitor_loop, args=(stop, app), daemon=True
            )
            started = time.monotonic()
            thread.start()
            detected_at = None
            while time.monotonic() - started < wait_seconds:
                time.sleep(0.1)
                if os.path.exists(db_path):
                    conn = sqlite3.connect(db_path)
                    try:
                        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    finally:
                        conn.close()
                    if count:
                        detected_at = time.monotonic() - started
                        break
            stop.set()
            thread.join(timeout=10)

        return detected_at, app, db_path

    def test_outage_detected_quickly_after_disconnect(self):
        detected_at, app, _db = self._run(DownProbe)
        self.assertIsNotNone(detected_at, "断网后 8 秒内没有生成任何断网事件")
        self.assertLess(detected_at, 5.0, f"报警太慢：{detected_at:.2f}s")
        self.assertTrue(app.statuses, "界面没有收到任何状态更新")
        self.assertIn("异常", app.states)

    def test_user_sees_confirmation_progress(self):
        """第一次失败就要给出「正在确认」提示，不能等确认完成才吭声。"""
        _detected, app, _db = self._run(DownProbe)
        self.assertTrue(
            any("正在确认" in message for message in app.logs),
            f"缺少确认过程提示：{app.logs}",
        )
        self.assertTrue(any("检测到断网" in message for message in app.logs))
        self.assertIn("异常", app.states)

    def test_check_counter_is_reported(self):
        _detected, app, _db = self._run(DownProbe)
        counts = [status.get("check_count") for status in app.statuses]
        self.assertTrue(counts and counts[0] == 1, f"检测计数异常：{counts}")
        self.assertGreaterEqual(max(counts), 2)

    def test_heartbeat_written_to_log_file(self):
        _detected, app, _db = self._run(DownProbe, wait_seconds=3)
        log_path = os.path.join(self.tmpdir, "logs", "wifi_monitor.log")
        self.assertTrue(os.path.exists(log_path))
        with open(log_path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("检测到断网", content)


# --------------------------------------------------------------------------
# 量化指标：RTT / 抖动 / 丢包
# --------------------------------------------------------------------------

PING_CN_HEALTHY = """
正在 Ping 223.5.5.5 具有 32 字节的数据:
来自 223.5.5.5 的回复: 字节=32 时间=32ms TTL=52
来自 223.5.5.5 的回复: 字节=32 时间=28ms TTL=52
来自 223.5.5.5 的回复: 字节=32 时间=28ms TTL=52
来自 223.5.5.5 的回复: 字节=32 时间=33ms TTL=52
来自 223.5.5.5 的回复: 字节=32 时间=29ms TTL=52

223.5.5.5 的 Ping 统计信息:
    数据包: 已发送 = 5，已接收 = 5，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 28ms，最长 = 33ms，平均 = 30ms
"""

PING_CN_PARTIAL = """
来自 223.5.5.5 的回复: 字节=32 时间=42ms TTL=52
请求超时。
来自 223.5.5.5 的回复: 字节=32 时间=310ms TTL=52
请求超时。

    数据包: 已发送 = 5，已接收 = 3，丢失 = 2 (40% 丢失)，
    最短 = 42ms，最长 = 310ms，平均 = 176ms
"""

PING_CN_ZERO = """
正在 Ping 10.255.255.99 具有 32 字节的数据:
请求超时。
请求超时。
请求超时。

    数据包: 已发送 = 3，已接收 = 0，丢失 = 3 (100% 丢失)，
"""

PING_EN_HEALTHY = """
Pinging 223.5.5.5 with 32 bytes of data:
Reply from 223.5.5.5: bytes=32 time=30ms TTL=52
Reply from 223.5.5.5: bytes=32 time=31ms TTL=52

Ping statistics for 223.5.5.5:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 30ms, Maximum = 31ms, Average = 30ms
"""

UNREACHABLE_CN = """
来自 192.168.1.1 的回复: 无法访问目标主机。
    数据包: 已发送 = 3，已接收 = 3，丢失 = 0 (0% 丢失)，
"""


class PingMetricsTests(unittest.TestCase):
    def test_parse_chinese_healthy_output(self):
        parsed = wifi_monitor.parse_ping_output(PING_CN_HEALTHY)
        self.assertEqual([32.0, 28.0, 28.0, 33.0, 29.0], parsed["rtts"])
        self.assertEqual(28.0, parsed["rtt_min_ms"])
        self.assertEqual(30.0, parsed["rtt_avg_ms"])
        self.assertEqual(33.0, parsed["rtt_max_ms"])
        self.assertEqual(0.0, parsed["loss_percent"])
        self.assertEqual(5, parsed["sent"])
        self.assertEqual(5, parsed["received"])

    def test_jitter_is_population_stddev(self):
        parsed = wifi_monitor.parse_ping_output(PING_CN_HEALTHY)
        expected = statistics.pstdev([32.0, 28.0, 28.0, 33.0, 29.0])
        self.assertAlmostEqual(expected, parsed["jitter_ms"], places=2)

    def test_parse_partial_loss(self):
        parsed = wifi_monitor.parse_ping_output(PING_CN_PARTIAL)
        self.assertEqual(40.0, parsed["loss_percent"])
        self.assertEqual(2, parsed["sent"] - parsed["received"])
        self.assertIsNotNone(parsed["jitter_ms"])

    def test_parse_total_loss(self):
        parsed = wifi_monitor.parse_ping_output(PING_CN_ZERO)
        self.assertEqual(100.0, parsed["loss_percent"])
        self.assertEqual([], parsed["rtts"])
        self.assertIsNone(parsed["rtt_avg_ms"])

    def test_parse_english_output(self):
        parsed = wifi_monitor.parse_ping_output(PING_EN_HEALTHY)
        self.assertEqual(30.0, parsed["rtt_avg_ms"])
        self.assertEqual(0.0, parsed["loss_percent"])

    def test_parse_empty_output_is_safe(self):
        parsed = wifi_monitor.parse_ping_output("")
        self.assertEqual([], parsed["rtts"])
        self.assertIsNone(parsed["loss_percent"])

    def test_ping_stats_marks_unreachable_as_not_ok(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, UNREACHABLE_CN)):
            result = wifi_monitor.ping_stats("192.168.1.222", count=3)
        self.assertFalse(result["ok"])

    def test_ping_stats_ok_on_partial_loss(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, PING_CN_PARTIAL)):
            result = wifi_monitor.ping_stats("223.5.5.5", count=5)
        self.assertTrue(result["ok"], "部分丢包仍应算可达")
        self.assertEqual(40.0, result["loss_percent"])

    def test_sample_quality_picks_lowest_loss(self):
        def fake_ping(host, count=5, timeout_ms=1000):
            if host == "good":
                return {"host": host, "ok": True, "loss_percent": 0.0,
                        "jitter_ms": 5.0, "rtt_avg_ms": 30.0}
            return {"host": host, "ok": True, "loss_percent": 40.0,
                    "jitter_ms": 90.0, "rtt_avg_ms": 400.0}

        with mock.patch.object(wifi_monitor, "ping_stats", side_effect=fake_ping):
            best = wifi_monitor.sample_quality(["bad", "good"])
        self.assertEqual("good", best["host"])
        self.assertEqual(0.0, best["loss_percent"])
        self.assertTrue(best.get("sampled_at"))

    def test_sample_quality_returns_none_without_targets(self):
        self.assertIsNone(wifi_monitor.sample_quality([]))
        self.assertIsNone(wifi_monitor.sample_quality(None))

    def test_quality_deadline_formula(self):
        # 5 包 × 0.85s + 1s 超时 + 1.5s 余量
        self.assertAlmostEqual(6.75, wifi_monitor.quality_deadline(5, 1000), places=2)
        self.assertGreaterEqual(wifi_monitor.quality_deadline(1, 200), 3.0)

    def test_slow_target_is_dropped_so_metrics_publish_on_time(self):
        """实测 114.114.114.114 完全屏蔽 ICMP、耗时 8.8s，不能让它拖住整次采样。"""
        def fake_ping(host, count=5, timeout_ms=1000):
            if host == "dead":
                time.sleep(1.2)
                return None
            return {"host": host, "ok": True, "loss_percent": 0.0,
                    "jitter_ms": 2.0, "rtt_avg_ms": 25.0}

        started = time.monotonic()
        with mock.patch.object(wifi_monitor, "ping_stats", side_effect=fake_ping):
            best = wifi_monitor.sample_quality(["dead", "fast"], deadline=0.4)
        elapsed = time.monotonic() - started
        self.assertEqual("fast", best["host"])
        self.assertLess(elapsed, 1.0, "坏目标不该拖住采样发布")

    def test_all_targets_timeout_yields_full_loss(self):
        """全超时必须给出「100% 丢包」，否则指标会冻结在最后一次健康值上。"""
        with mock.patch.object(wifi_monitor, "ping_stats", return_value=None):
            best = wifi_monitor.sample_quality(["a", "b"], count=3, deadline=0.3)
        self.assertIsNotNone(best)
        self.assertFalse(best["ok"])
        self.assertEqual(100.0, best["loss_percent"])
        self.assertEqual(0, best["received"])
        self.assertTrue(best["timed_out"])

    def test_sample_quality_uses_auto_deadline(self):
        with mock.patch.object(wifi_monitor, "ping_stats",
                               return_value={"host": "x", "ok": True, "loss_percent": 0.0,
                                             "jitter_ms": 1.0, "rtt_avg_ms": 10.0}):
            best = wifi_monitor.sample_quality(["x"], count=5, timeout_ms=1000)
        self.assertEqual(wifi_monitor.quality_deadline(5, 1000), best["deadline_seconds"])


# --------------------------------------------------------------------------
# 健康等级（退化态）
# --------------------------------------------------------------------------

class HealthEvaluationTests(unittest.TestCase):
    def _status(self, **kwargs):
        base = {
            "gateway_ok": True, "internet_ok": True, "dns_ok": True,
            "signal_percent": 80,
        }
        base.update(kwargs)
        return base

    def test_unreachable_is_outage(self):
        result = wifi_monitor.evaluate_health(
            self._status(internet_ok=False), None, {}
        )
        self.assertEqual("outage", result["level"])

    def test_healthy_when_all_good(self):
        metrics = {"loss_percent": 0.0, "jitter_ms": 3.0, "rtt_avg_ms": 25.0}
        result = wifi_monitor.evaluate_health(self._status(), metrics, {})
        self.assertEqual("normal", result["level"])

    def test_high_loss_is_degraded(self):
        metrics = {"loss_percent": 25.0, "jitter_ms": 3.0, "rtt_avg_ms": 30.0}
        result = wifi_monitor.evaluate_health(self._status(), metrics, {})
        self.assertEqual("degraded", result["level"])
        self.assertTrue(any("丢包" in reason for reason in result["reasons"]))

    def test_high_jitter_is_degraded(self):
        metrics = {"loss_percent": 0.0, "jitter_ms": 120.0, "rtt_avg_ms": 30.0}
        result = wifi_monitor.evaluate_health(self._status(), metrics, {})
        self.assertEqual("degraded", result["level"])
        self.assertTrue(any("抖动" in reason for reason in result["reasons"]))

    def test_high_rtt_is_degraded(self):
        metrics = {"loss_percent": 0.0, "jitter_ms": 3.0, "rtt_avg_ms": 800.0}
        result = wifi_monitor.evaluate_health(self._status(), metrics, {})
        self.assertEqual("degraded", result["level"])

    def test_weak_signal_alone_is_degraded(self):
        """信号弱也属于「通了但很差」，不能算正常。"""
        metrics = {"loss_percent": 0.0, "jitter_ms": 1.0, "rtt_avg_ms": 20.0}
        result = wifi_monitor.evaluate_health(self._status(signal_percent=20), metrics, {})
        self.assertEqual("degraded", result["level"])

    def test_decided_by_config_thresholds(self):
        metrics = {"loss_percent": 8.0, "jitter_ms": 1.0, "rtt_avg_ms": 20.0}
        strict = {"degrade_loss_percent": 5.0}
        loose = {"degrade_loss_percent": 10.0}
        self.assertEqual(
            "degraded", wifi_monitor.evaluate_health(self._status(), metrics, strict)["level"]
        )
        self.assertEqual(
            "normal", wifi_monitor.evaluate_health(self._status(), metrics, loose)["level"]
        )

    def test_degraded_cause_is_reported_in_analysis(self):
        status = self._status()
        status["metrics"] = {"loss_percent": 30.0, "jitter_ms": 2.0, "rtt_avg_ms": 25.0}
        analysis = wifi_monitor.analyze_network_status(status, {"weak_signal_threshold": 50})
        self.assertEqual("degraded", analysis["primary_cause"])
        self.assertEqual("quality", analysis["cause_level"])
        self.assertIn("30", analysis["summary"])

    def test_cause_level_mapping(self):
        self.assertEqual("local", wifi_monitor.derive_cause_level("gateway"))
        self.assertEqual("local", wifi_monitor.derive_cause_level("wifi_link"))
        self.assertEqual("isp", wifi_monitor.derive_cause_level("internet"))
        self.assertEqual("dns", wifi_monitor.derive_cause_level("dns"))
        self.assertEqual("normal", wifi_monitor.derive_cause_level("healthy"))
        # 逐跳取证能把「外网不通」细化成上游问题
        self.assertEqual("upstream", wifi_monitor.derive_cause_level("internet", "upstream"))
        self.assertEqual("local", wifi_monitor.derive_cause_level("internet", "local"))


class HealthTrackerTests(unittest.TestCase):
    def setUp(self):
        self.t0 = datetime(2026, 9, 28, 10, 0, 0)

    def _at(self, seconds):
        return self.t0 + timedelta(seconds=seconds)

    def test_degraded_opens_event_after_threshold(self):
        tracker = wifi_monitor.HealthTracker(failure_threshold=2, recovery_threshold=2)
        self.assertEqual([], tracker.update("degraded", self.t0))
        actions = tracker.update("degraded", self._at(3))
        self.assertEqual("start", actions[0][0])
        self.assertEqual("degraded", actions[0][1])
        self.assertEqual(self.t0, actions[0][2], "起始时间应为首次观察到退化的时刻")
        self.assertTrue(tracker.active)

    def test_switch_from_degraded_to_outage_ends_then_starts(self):
        tracker = wifi_monitor.HealthTracker(failure_threshold=1, recovery_threshold=1)
        tracker.update("degraded", self.t0)
        self.assertEqual("degraded", tracker.active_kind)
        actions = tracker.update("outage", self._at(10))
        self.assertEqual("end", actions[0][0])
        self.assertEqual("degraded", actions[0][1])
        self.assertEqual("start", actions[1][0])
        self.assertEqual("outage", actions[1][1])
        self.assertEqual("outage", tracker.active_kind)

    def test_recovery_needs_confirmation(self):
        tracker = wifi_monitor.HealthTracker(failure_threshold=1, recovery_threshold=3)
        tracker.update("outage", self.t0)
        self.assertEqual([], tracker.update("normal", self._at(10)))
        self.assertEqual([], tracker.update("normal", self._at(20)))
        actions = tracker.update("normal", self._at(30))
        self.assertEqual("end", actions[0][0])
        self.assertFalse(tracker.active)

    def test_pending_progress_is_exposed(self):
        tracker = wifi_monitor.HealthTracker(failure_threshold=3, recovery_threshold=2)
        tracker.update("outage", self.t0)
        self.assertEqual("outage", tracker.pending_kind)
        self.assertEqual(1, tracker.pending_streak)
        self.assertEqual(3, tracker.pending_needed)
        tracker.update("outage", self._at(3))
        self.assertEqual(2, tracker.pending_streak)

    def test_degraded_then_normal_closes_event(self):
        tracker = wifi_monitor.HealthTracker(failure_threshold=2, recovery_threshold=2)
        tracker.update("degraded", self.t0)
        tracker.update("degraded", self._at(10))
        self.assertTrue(tracker.active)
        tracker.update("normal", self._at(20))
        actions = tracker.update("normal", self._at(30))
        self.assertEqual("end", actions[0][0])
        # 起始取「首次观察到期化」，结束取「确认恢复」的时刻（与既有断网行为一致）
        self.assertEqual(self.t0, actions[0][2])
        self.assertEqual(self._at(30), actions[0][3])
        self.assertEqual(30, actions[0][4])

    def test_legacy_outage_tracker_still_uses_bool(self):
        """旧接口必须保持可用：外部只传 True/False。"""
        tracker = wifi_monitor.OutageTracker(failure_threshold=1, recovery_threshold=2)
        action = tracker.update(False, self.t0)
        self.assertEqual(("start", self.t0), action)
        self.assertEqual(0, tracker.fail_streak)
        self.assertTrue(tracker.active)
        self.assertEqual(self.t0, tracker.outage_start)


# --------------------------------------------------------------------------
# 站点可用性
# --------------------------------------------------------------------------

class SiteProbeTests(unittest.TestCase):
    def test_verdict_thresholds(self):
        self.assertEqual("GREAT", wifi_monitor.site_verdict(120, True, 200, 800))
        self.assertEqual("OK", wifi_monitor.site_verdict(500, True, 200, 800))
        self.assertEqual("SLOW", wifi_monitor.site_verdict(1500, True, 200, 800))
        self.assertEqual("DOWN", wifi_monitor.site_verdict(None, False, 200, 800))
        self.assertEqual("DOWN", wifi_monitor.site_verdict(100, False, 200, 800))

    def test_probe_site_success_with_certificate(self):
        cert = {"notAfter": "Sep 28 12:00:00 2027 GMT"}
        fake_socket = mock.MagicMock()
        fake_tls = mock.MagicMock()
        fake_tls.getpeercert.return_value = cert
        context = mock.MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = fake_tls

        with mock.patch.object(wifi_monitor.socket, "create_connection", return_value=fake_socket), \
             mock.patch.object(wifi_monitor.ssl, "create_default_context", return_value=context):
            result = wifi_monitor.probe_site("微信", "weixin.qq.com", 443, 4, 14, 200, 800)

        self.assertTrue(result["ok"])
        self.assertEqual("2027-09-28", result["cert_expires"])
        self.assertGreater(result["cert_days_left"], 300)
        self.assertFalse(result["cert_warning"])

    def test_probe_site_cert_warning_when_expiring(self):
        cert = {"notAfter": "Oct 01 12:00:00 2026 GMT"}
        fake_socket = mock.MagicMock()
        fake_tls = mock.MagicMock()
        fake_tls.getpeercert.return_value = cert
        context = mock.MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = fake_tls

        with mock.patch.object(wifi_monitor.socket, "create_connection", return_value=fake_socket), \
             mock.patch.object(wifi_monitor.ssl, "create_default_context", return_value=context):
            result = wifi_monitor.probe_site(
                "站点", "example.com", 443, 4, 14, 200, 800,
            )
        self.assertTrue(result["cert_warning"], "证书 3 天内到期应告警")

    def test_probe_site_tcp_failure(self):
        with mock.patch.object(
            wifi_monitor.socket, "create_connection", side_effect=OSError("refused")
        ):
            result = wifi_monitor.probe_site("站点", "down.example.com", 443)
        self.assertFalse(result["ok"])
        self.assertEqual("DOWN", result["verdict"])
        self.assertIn("refused", result["error"])

    def test_probe_sites_keeps_config_order(self):
        def fake_probe(name, host, port=443, timeout=4, cert_warn_days=14,
                       great_ms=200, ok_ms=800):
            return {"name": name, "host": host, "ok": True, "total_ms": 10.0,
                    "verdict": "GREAT", "cert_expires": None, "cert_warning": False}

        sites = [{"name": "A", "host": "a.com"}, {"name": "B", "host": "b.com"}]
        with mock.patch.object(wifi_monitor, "probe_site", side_effect=fake_probe):
            results = wifi_monitor.probe_sites(sites)
        self.assertEqual(["A", "B"], [item["name"] for item in results])
        self.assertTrue(all(item.get("sampled_at") for item in results))

    def test_site_summary_puts_worst_first(self):
        sites = [
            {"name": "好", "verdict": "GREAT", "total_ms": 30.0},
            {"name": "坏", "verdict": "DOWN", "total_ms": None},
        ]
        text = wifi_monitor.site_summary(sites)
        self.assertTrue(text.startswith("站点：坏"), text)


# --------------------------------------------------------------------------
# 测速 / 吞吐
# --------------------------------------------------------------------------

class SpeedTestTests(unittest.TestCase):
    class _Response:
        def __init__(self, payload):
            self.payload = payload

        def read(self, size):
            return self.payload[:size]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_measure_throughput_computes_mbps(self):
        payload = b"x" * (256 * 1024)
        with mock.patch.object(
            wifi_monitor.urllib.request, "urlopen", return_value=self._Response(payload)
        ):
            result = wifi_monitor.measure_throughput("https://example.com/f", 256 * 1024)
        self.assertTrue(result["ok"])
        self.assertEqual(len(payload), result["bytes"])
        self.assertGreater(result["mbps"], 0)

    def test_measure_throughput_handles_failure(self):
        with mock.patch.object(
            wifi_monitor.urllib.request, "urlopen",
            side_effect=wifi_monitor.urllib.error.URLError("no route"),
        ):
            result = wifi_monitor.measure_throughput("https://example.com/f")
        self.assertFalse(result["ok"])
        self.assertIn("no route", result["error"])

    def test_run_speed_test_falls_back_to_second_source(self):
        calls = []

        def fake_measure(url, size_bytes=1048576, timeout=20):
            calls.append(url)
            if url == "bad":
                return {"url": url, "ok": False, "mbps": None, "error": "fail"}
            return {"url": url, "ok": True, "mbps": 25.0, "bytes": 100, "seconds": 0.3}

        with mock.patch.object(wifi_monitor, "measure_throughput", side_effect=fake_measure):
            result = wifi_monitor.run_speed_test(["bad", "good"])
        self.assertTrue(result["ok"])
        self.assertEqual(["bad", "good"], calls, "必须串行尝试，且失败后换下一个源")

    def test_run_speed_test_without_sources(self):
        result = wifi_monitor.run_speed_test([])
        self.assertFalse(result["ok"])

    def test_default_sources_are_domestic(self):
        """绝不能用 speed.cloudflare.com：实测国内只有 0.3 Mbps。"""
        joined = " ".join(wifi_monitor.DEFAULT_SPEED_SOURCES)
        self.assertNotIn("cloudflare", joined)
        self.assertIn("aliyun", joined)


# --------------------------------------------------------------------------
# 断网自动取证
# --------------------------------------------------------------------------

TRACERT_CN = """
通过最多 30 个跃点跟踪到 223.5.5.5 的路由

  1    15 ms     3 ms     1 ms  192.168.1.1
  2     6 ms     6 ms     9 ms  100.64.0.1
  3     9 ms    10 ms     9 ms  218.5.181.77
  4    11 ms     9 ms     *     61.154.71.33
  5     *       26 ms    25 ms  202.97.13.165
  6     *        *        *     请求超时。
  7     *       27 ms    30 ms  101.95.209.222
  8     *        *        *     请求超时。

跟踪完成。
"""

TRACERT_ALL_TIMEOUT = """
  1     *        *        *     请求超时。
  2     *        *        *     请求超时。
跟踪完成。
"""

TRACERT_REACHED_TARGET = """
  1     2 ms     1 ms     1 ms  192.168.1.1
  2    20 ms    18 ms    19 ms  223.5.5.5
跟踪完成。
"""


class TracertTests(unittest.TestCase):
    def test_tracert_hops_parses_output(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, TRACERT_CN)):
            hops, _raw = wifi_monitor.tracert_hops("223.5.5.5")
        self.assertEqual(8, len(hops))
        self.assertTrue(hops[0]["responded"])
        self.assertEqual(["192.168.1.1"], hops[0]["ips"])
        self.assertFalse(hops[5]["responded"], "全是 * 的跳不该算响应")
        self.assertTrue(hops[6]["responded"], "有一列有 ms 就算响应")

    def test_summarize_local_when_first_hop_fails(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, TRACERT_ALL_TIMEOUT)):
            hops, _raw = wifi_monitor.tracert_hops("10.0.0.1")
        segment, text = wifi_monitor.summarize_tracert(hops, gateway="10.0.0.1")
        self.assertEqual("local", segment)
        self.assertIn("第 1 跳", text)

    def test_summarize_isp_when_gateway_ok_but_next_fails(self):
        output = "  1     2 ms     1 ms     1 ms  192.168.1.1\n  2     *        *        *     请求超时。\n"
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, output)):
            hops, _raw = wifi_monitor.tracert_hops("223.5.5.5")
        segment, text = wifi_monitor.summarize_tracert(hops, gateway="192.168.1.1")
        self.assertEqual("isp", segment)
        self.assertIn("运营商上行", text)

    def test_summary_never_asserts_a_hop_is_broken(self):
        """实测网络完全正常时末跳也可能无响应，所以措辞不能断言故障位置。"""
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, TRACERT_CN)):
            hops, _raw = wifi_monitor.tracert_hops("223.5.5.5")
        _segment, text = wifi_monitor.summarize_tracert(hops, gateway="192.168.1.1")
        self.assertIn("无响应", text)
        self.assertIn("ICMP", text, "必须带上「ICMP 可能被屏蔽」的说明")
        self.assertNotIn("故障在运营商上行链路", text)

    def test_summarize_upstream_when_target_reached(self):
        with mock.patch.object(wifi_monitor, "run_cmd", return_value=(0, TRACERT_REACHED_TARGET)):
            hops, _raw = wifi_monitor.tracert_hops("223.5.5.5")
        segment, text = wifi_monitor.summarize_tracert(
            hops, gateway="192.168.1.1", target="223.5.5.5"
        )
        self.assertEqual("upstream", segment)
        self.assertIn("链路正常", text)

    def test_summarize_empty_hops(self):
        segment, _text = wifi_monitor.summarize_tracert([])
        self.assertEqual("unknown", segment)


class WlanEventTests(unittest.TestCase):
    def test_event_ids_are_mapped_without_parsing_message_text(self):
        """实测 PowerShell 重定向后消息会变英文，所以只能按 ID 判定。"""
        lines = [
            "2026-09-28 10:14:02|8001|WLAN AutoConfig service has successfully connected",
            "2026-09-28 10:13:40|8003|WLAN AutoConfig service has successfully disconnected",
            "2026-09-28 10:13:30|11002|Association failed",
        ]
        now = datetime(2026, 9, 28, 10, 20, 0)
        events = wifi_monitor.parse_wlan_event_lines(lines, lookback_minutes=30, now=now)
        self.assertEqual(3, len(events))
        self.assertEqual("已成功连接无线网络", events[0]["label"])
        self.assertFalse(events[0]["abnormal"])
        self.assertTrue(events[2]["abnormal"])

    def test_old_events_are_filtered_out(self):
        lines = [
            "2026-09-28 09:00:00|8003|x",
            "2026-09-28 10:10:00|8001|x",
        ]
        now = datetime(2026, 9, 28, 10, 20, 0)
        events = wifi_monitor.parse_wlan_event_lines(lines, lookback_minutes=30, now=now)
        self.assertEqual(1, len(events))
        self.assertEqual("8001", events[0]["id"])

    def test_malformed_lines_are_skipped(self):
        events = wifi_monitor.parse_wlan_event_lines(
            ["garbage", "no|pipe|but|ok", ""], now=datetime(2026, 9, 28, 10, 20, 0)
        )
        self.assertEqual(1, len(events))

    def test_collect_evidence_combines_sources(self):
        config = {
            "internet_targets": [{"host": "223.5.5.5", "port": 443}],
            "evidence_tracert_max_hops": 8,
            "evidence_tracert_timeout_ms": 800,
            "evidence_wlan_lookback_minutes": 30,
        }
        status = {"gateway": "192.168.1.1", "gateway_ok": False, "internet_ok": False}
        fake_events = [{"time": "2026-09-28 10:13:40", "id": "8003",
                        "label": "已断开无线网络", "abnormal": False, "raw": ""}]
        with mock.patch.object(wifi_monitor, "tracert_hops", return_value=([], "")), \
             mock.patch.object(wifi_monitor, "read_wlan_events", return_value=fake_events):
            evidence = wifi_monitor.collect_evidence(config, status)
        self.assertIn("【逐跳】", evidence["text"])
        self.assertIn("已断开无线网络", evidence["text"])
        self.assertEqual("unknown", evidence["segment"])


# --------------------------------------------------------------------------
# 事件聚合（事故）与数据保留
# --------------------------------------------------------------------------

class IncidentAggregationTests(unittest.TestCase):
    def test_events_within_gap_merge_into_one_incident(self):
        rows = [
            ("2026-09-28 10:00:00", "2026-09-28 10:01:00", 60, "recovered", "outage", "isp"),
            ("2026-09-28 10:20:00", "2026-09-28 10:21:00", 60, "recovered", "outage", "isp"),
            ("2026-09-28 12:00:00", "2026-09-28 12:05:00", 300, "recovered", "outage", "local"),
        ]
        incidents = wifi_monitor.build_incidents(rows, gap_minutes=30)
        self.assertEqual(2, len(incidents), "10:00 与 10:20 间隔 19 分钟应合并")
        self.assertEqual(2, incidents[0]["event_count"])
        self.assertEqual(120, incidents[0]["seconds"])
        self.assertEqual("2026-09-28 10:00:00", incidents[0]["start_text"])
        self.assertEqual(1, incidents[1]["event_count"])

    def test_incident_takes_worst_kind(self):
        rows = [
            ("2026-09-28 10:00:00", "2026-09-28 10:01:00", 60, "recovered", "degraded", "quality"),
            ("2026-09-28 10:05:00", "2026-09-28 10:06:00", 60, "recovered", "outage", "isp"),
        ]
        incidents = wifi_monitor.build_incidents(rows, gap_minutes=30)
        self.assertEqual(1, len(incidents))
        self.assertEqual("outage", incidents[0]["kind"])
        self.assertEqual(["isp", "quality"], incidents[0]["causes"])

    def test_ongoing_event_uses_now_as_end(self):
        now = datetime(2026, 9, 28, 10, 30, 0)
        rows = [("2026-09-28 10:00:00", None, 0, "ongoing", "outage", None)]
        with mock.patch.object(wifi_monitor, "datetime") as fake_datetime:
            fake_datetime.now.return_value = now
            fake_datetime.strptime = datetime.strptime
            incidents = wifi_monitor.build_incidents(rows, gap_minutes=30)
        self.assertEqual(1, len(incidents))
        self.assertEqual("2026-09-28 10:30:00", incidents[0]["end_text"])

    def test_get_incidents_reads_db(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_incident_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        wifi_monitor.add_event(db, "2026-09-28 10:00:00", "2026-09-28 10:01:00", 60,
                               "recovered", "d", kind="outage", cause_level="isp")
        wifi_monitor.add_event(db, "2026-09-28 10:20:00", "2026-09-28 10:21:00", 60,
                               "recovered", "d", kind="degraded", cause_level="quality")
        incidents = wifi_monitor.get_incidents(db, gap_minutes=30)
        self.assertEqual(1, len(incidents))
        self.assertEqual(2, incidents[0]["event_count"])


class RetentionTests(unittest.TestCase):
    def test_prune_removes_old_samples_but_keeps_events(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_prune_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)

        old = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        wifi_monitor.record_check(db, True, True, True, "old", old)
        wifi_monitor.record_check(db, True, True, True, "new", None)
        wifi_monitor.record_site_checks(
            db, [{"name": "A", "host": "a", "ok": True, "verdict": "GREAT"}], old
        )
        wifi_monitor.add_event(db, old, None, 0, "ongoing", "old event")

        removed = wifi_monitor.prune_old_data(db, retention_days=30)
        self.assertEqual(1, removed["checks"])
        self.assertEqual(1, removed["site_checks"])

        conn = wifi_monitor.connect_db(db)
        try:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0])
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            conn.close()


class DatabaseRetryTests(unittest.TestCase):
    def test_transient_error_is_retried_then_succeeds(self):
        calls = {"n": 0}

        @wifi_monitor.with_db_retry
        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise sqlite3.OperationalError("attempt to write a readonly database")
            return "ok"

        self.assertEqual("ok", flaky())
        self.assertEqual(3, calls["n"])

    def test_non_transient_error_is_not_retried(self):
        calls = {"n": 0}

        @wifi_monitor.with_db_retry
        def broken():
            calls["n"] += 1
            raise sqlite3.OperationalError("no such table: nope")

        with self.assertRaises(sqlite3.OperationalError):
            broken()
        self.assertEqual(1, calls["n"])

    def test_gives_up_after_max_attempts(self):
        calls = {"n": 0}

        @wifi_monitor.with_db_retry
        def always_locked():
            calls["n"] += 1
            raise sqlite3.OperationalError("database is locked")

        with self.assertRaises(sqlite3.OperationalError):
            always_locked()
        self.assertEqual(wifi_monitor.DB_RETRY_ATTEMPTS, calls["n"])


class SchemaMigrationTests(unittest.TestCase):
    def test_new_columns_and_tables_created(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_schema_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        conn = wifi_monitor.connect_db(db)
        try:
            event_cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            check_cols = {row[1] for row in conn.execute("PRAGMA table_info(checks)")}
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
        finally:
            conn.close()
        for column in ("kind", "cause_level", "evidence", "metrics_json"):
            self.assertIn(column, event_cols)
        for column in ("health", "rtt_avg_ms", "jitter_ms", "loss_percent"):
            self.assertIn(column, check_cols)
        self.assertIn("site_checks", tables)
        self.assertIn("speed_tests", tables)

    def test_legacy_events_count_as_outage(self):
        """旧库里的记录没有 kind 列，必须按断网统计而不是被漏掉。"""
        tmpdir = tempfile.mkdtemp(prefix="wifi_legacy_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        conn = wifi_monitor.connect_db(db)
        try:
            conn.execute(
                "INSERT INTO events (start_time, end_time, duration_seconds, status, details) "
                "VALUES ('2026-09-20 10:00:00', '2026-09-20 10:05:00', 300, 'recovered', 'legacy')"
            )
            conn.commit()
        finally:
            conn.close()
        summary = wifi_monitor.get_daily_outage_summary(db)
        self.assertEqual(1, summary[0]["outage_count"])
        self.assertEqual(300, summary[0]["total_duration_seconds"])


class QualitySummaryTests(unittest.TestCase):
    def test_availability_and_averages(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_quality_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        wifi_monitor.record_check(db, True, True, True, "a", None, health="normal",
                                  metrics={"rtt_avg_ms": 20.0, "jitter_ms": 2.0, "loss_percent": 0.0})
        wifi_monitor.record_check(db, False, False, False, "b", None, health="outage")
        wifi_monitor.record_check(db, True, True, True, "c", None, health="degraded",
                                  metrics={"rtt_avg_ms": 40.0, "jitter_ms": 80.0, "loss_percent": 10.0})

        quality = wifi_monitor.get_quality_summary(db, since_days=1)
        self.assertEqual(3, quality["total_checks"])
        self.assertEqual(1, quality["outage_checks"])
        self.assertEqual(1, quality["degraded_checks"])
        self.assertAlmostEqual(66.667, quality["availability_percent"], places=2)
        self.assertEqual(30.0, quality["avg_rtt_ms"])
        self.assertEqual(5.0, quality["avg_loss_percent"])

    def test_site_summary_counts_failures(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_site_sum_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        wifi_monitor.record_site_checks(db, [
            {"name": "A", "host": "a", "ok": True, "total_ms": 100.0, "verdict": "GREAT",
             "cert_expires": "2027-01-01"},
            {"name": "A", "host": "a", "ok": False, "total_ms": None, "verdict": "DOWN"},
        ])
        summary = wifi_monitor.get_site_summary(db, since_days=1)
        self.assertEqual(1, len(summary))
        self.assertEqual(2, summary[0]["samples"])
        self.assertEqual(1, summary[0]["failures"])
        self.assertEqual(50.0, summary[0]["availability_percent"])
        self.assertEqual("2027-01-01", summary[0]["cert_expires"])


class RuntimeStateTests(unittest.TestCase):
    def test_pending_queue_is_bounded(self):
        state = wifi_monitor.RuntimeState()
        for index in range(wifi_monitor.MAX_PENDING_NOTIFICATIONS + 5):
            state.add_pending(f"s{index}", "b")
        self.assertEqual(wifi_monitor.MAX_PENDING_NOTIFICATIONS, state.pending_count())
        items = state.take_pending()
        self.assertEqual(0, state.pending_count())
        self.assertEqual(f"s{5}", items[0][0], "超出上限时应丢掉最旧的")

    def test_settle_or_queue_enqueues_when_email_fails(self):
        state = wifi_monitor.RuntimeState()
        config = {"notify": {"email_enabled": True}, "log_file": None}
        with mock.patch.object(wifi_monitor, "send_email", return_value=False):
            wifi_monitor._send_or_queue(state, "主题", "内容", config)
            for _ in range(50):
                if state.pending_count():
                    break
                time.sleep(0.02)
        self.assertEqual(1, state.pending_count())

    def test_flush_resends_and_drains_queue(self):
        state = wifi_monitor.RuntimeState()
        state.add_pending("s", "b")
        config = {"notify": {"email_enabled": True}, "log_file": None}
        with mock.patch.object(wifi_monitor, "send_email", return_value=True):
            self.assertEqual(1, wifi_monitor.flush_pending_notifications(state, config))
        self.assertEqual(0, state.pending_count())

    def test_flush_keeps_unsent_items(self):
        state = wifi_monitor.RuntimeState()
        state.add_pending("s", "b")
        config = {"notify": {"email_enabled": True}, "log_file": None}
        with mock.patch.object(wifi_monitor, "send_email", return_value=False):
            self.assertEqual(0, wifi_monitor.flush_pending_notifications(state, config))
        self.assertEqual(1, state.pending_count())

    def test_snapshot_reports_health_and_metrics(self):
        state = wifi_monitor.RuntimeState()
        state.set_health("degraded")
        state.set_metrics({"rtt_avg_ms": 30.0})
        snap = state.snapshot()
        self.assertEqual("degraded", snap["health"])
        self.assertEqual(30.0, snap["metrics"]["rtt_avg_ms"])


class SamplerTests(unittest.TestCase):
    def test_create_sampler_respects_config_flag(self):
        state = wifi_monitor.RuntimeState()
        self.assertIsNone(
            wifi_monitor.create_sampler({"sampling_enabled": False}, threading.Event(), state)
        )
        sampler = wifi_monitor.create_sampler({"sampling_enabled": True}, threading.Event(), state)
        self.assertIsInstance(sampler, wifi_monitor.BackgroundSampler)
        self.assertFalse(sampler.is_alive(), "创建时不应自动启动")

    def test_sampler_fills_state_without_touching_loop(self):
        state = wifi_monitor.RuntimeState()
        stop = threading.Event()
        config = {
            "sampling_enabled": True,
            "quality_targets": ["10.255.255.99"],
            "site_interval_seconds": 3600,
            "sites": [],
            "speed_test_enabled": False,
        }
        sampler = wifi_monitor.BackgroundSampler(config, stop, state)
        with mock.patch.object(
            wifi_monitor, "sample_quality",
            return_value={"host": "10.255.255.99", "ok": True, "loss_percent": 0.0,
                          "jitter_ms": 1.0, "rtt_avg_ms": 5.0},
        ):
            sampler._tick(first=True)
        self.assertEqual(5.0, state.get_metrics()["rtt_avg_ms"])

    def test_sampler_skips_work_while_speed_test_running(self):
        state = wifi_monitor.RuntimeState()
        config = {"quality_targets": ["x"], "sites": [], "speed_test_enabled": False}
        sampler = wifi_monitor.BackgroundSampler(config, threading.Event(), state)
        sampler._speed_running = True
        with mock.patch.object(wifi_monitor, "sample_quality") as mocked:
            sampler._tick(first=True)
        mocked.assert_not_called()


class EventLineFormatTests(unittest.TestCase):
    def test_outage_line(self):
        row = ("2026-09-28 10:00:00", "2026-09-28 10:01:00", 60, "recovered", "outage", "isp", "d")
        text = wifi_monitor.format_event_line(row)
        self.assertIn("[断网]", text)
        self.assertIn("已恢复", text)
        self.assertIn("运营商", text)

    def test_degraded_line(self):
        row = ("2026-09-28 10:00:00", None, 0, "ongoing", "degraded", "quality", "d")
        text = wifi_monitor.format_event_line(row)
        self.assertIn("[退化]", text)
        self.assertIn("进行中", text)


# --------------------------------------------------------------------------
# 实时看板
# --------------------------------------------------------------------------

class TtlCacheTests(unittest.TestCase):
    def test_value_is_reused_within_ttl(self):
        cache = wifi_monitor._TtlCache(ttl=60)
        calls = {"n": 0}

        def producer():
            calls["n"] += 1
            return {"v": calls["n"]}

        self.assertEqual(1, cache.get(producer)["v"])
        self.assertEqual(1, cache.get(producer)["v"])
        self.assertEqual(1, calls["n"])

    def test_expired_value_is_refreshed(self):
        cache = wifi_monitor._TtlCache(ttl=0)
        calls = {"n": 0}

        def producer():
            calls["n"] += 1
            return {"v": calls["n"]}

        cache.get(producer)
        cache.get(producer)
        self.assertEqual(2, calls["n"])

    def test_producer_error_does_not_break_polling(self):
        cache = wifi_monitor._TtlCache(ttl=0)

        def broken():
            raise RuntimeError("db gone")

        self.assertEqual({}, cache.get(broken))


class LivePayloadTests(unittest.TestCase):
    def test_payload_without_database(self):
        state = wifi_monitor.RuntimeState()
        state.set_health("degraded")
        state.set_metrics({"rtt_avg_ms": 30.0, "jitter_ms": 5.0, "loss_percent": 0.0})
        state.set_sites([{"name": "微信", "verdict": "GREAT", "total_ms": 100.0}])
        state.set_status({
            "ssid": "MyWiFi", "details": "网关=OK", "check_count": 7,
            "gateway": "192.168.1.1",
            "gateway_ok": True, "internet_ok": True, "dns_ok": False,
            "signal_percent": 77, "rssi_db": -58,
            "analysis": {"summary": "测试结论", "cause_level": "local"},
        })
        payload = wifi_monitor.build_live_payload(
            state, {"dashboard_refresh_ms": 1000}, db_file=None
        )
        self.assertEqual("degraded", payload["health"])
        self.assertEqual("网络退化", payload["health_label"])
        self.assertEqual("MyWiFi", payload["ssid"])
        self.assertEqual(30.0, payload["metrics"]["rtt_avg_ms"])
        self.assertEqual(1, len(payload["sites"]))
        self.assertEqual({"gateway": True, "internet": True, "dns": False}, payload["flags"])
        self.assertEqual("测试结论", payload["summary"])
        self.assertEqual(7, payload["check_count"])
        self.assertEqual(1000, payload["refresh_ms"])

    def test_payload_without_any_status_is_safe(self):
        payload = wifi_monitor.build_live_payload(wifi_monitor.RuntimeState(), {}, db_file=None)
        self.assertEqual("normal", payload["health"])
        self.assertIsNone(payload["ssid"])
        self.assertEqual({}, payload["metrics"])
        self.assertEqual([], payload["sites"])
        self.assertIn("等待首轮检测", payload["details"])

    def test_payload_includes_db_statistics(self):
        tmpdir = tempfile.mkdtemp(prefix="wifi_dash_")
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "e.db")
        wifi_monitor.init_db(db)
        now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        wifi_monitor.record_check(db, True, True, True, "ok", now_text, health="normal",
                                  metrics={"rtt_avg_ms": 22.0, "loss_percent": 0.0})
        wifi_monitor.add_event(db, now_text, now_text, 30, "recovered", "d",
                               kind="outage", cause_level="isp")

        state = wifi_monitor.RuntimeState()
        payload = wifi_monitor.build_live_payload(state, {}, db_file=db)
        self.assertEqual(1, payload["incident_count"])
        self.assertEqual(1, len(payload["events"]))
        self.assertIn("[断网]", payload["events"][0]["text"])
        self.assertEqual([22.0], payload["trend"]["rtt"])


class _FakeAppStub:
    def __init__(self):
        self.logs = []
        self.statuses = []

    def safe_update_status(self, status):
        self.statuses.append(status)

    def safe_append_log(self, message):
        self.logs.append(message)

    def safe_set_state(self, value):
        pass

    def safe_set_stopped(self, thread):
        pass

    def safe_refresh_events(self):
        pass

    def safe_refresh_samples(self):
        pass

    def safe_alert(self, kind, message):
        self.logs.append(f"ALERT {kind} {message}")


class DashboardServerTests(TempDirMixin):
    """真起一个 HTTP 服务并请求，确认看板闭环可用。"""

    def _config(self):
        return {
            "dashboard_host": "127.0.0.1",
            "dashboard_port": 0,          # 交给系统分配空闲端口，避免测试互相抢端口
            "dashboard_refresh_ms": 1000,
            "incident_gap_minutes": 30,
            "log_file": os.path.join(self.tmpdir, "logs", "wifi_monitor.log"),
            "db_file": self.db_path("dash.db"),
        }

    def _start(self):
        config = self._config()
        wifi_monitor.init_db(config["db_file"])
        state = wifi_monitor.RuntimeState()
        state.set_status({
            "ssid": "TestWiFi", "details": "d", "check_count": 3,
            "gateway": "192.168.1.1", "gateway_ok": True,
            "internet_ok": True, "dns_ok": True, "signal_percent": 60,
            "analysis": {"summary": "一切正常", "cause_level": "normal"},
        })
        dashboard = wifi_monitor.LiveDashboard(config, state)
        self.assertTrue(dashboard.start(), "看板应能启动")
        self.addCleanup(dashboard.stop)
        return dashboard

    def _get(self, url):
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read().decode("utf-8")

    def test_serves_index_html(self):
        dashboard = self._start()
        status, body = self._get(dashboard.url)
        self.assertEqual(200, status)
        self.assertIn("WiFi 实时看板", body)
        self.assertIn("/api/live", body)

    def test_live_api_returns_json(self):
        dashboard = self._start()
        status, body = self._get(dashboard.url + "api/live")
        self.assertEqual(200, status)
        payload = json.loads(body)
        self.assertEqual("TestWiFi", payload["ssid"])
        self.assertEqual("一切正常", payload["summary"])
        self.assertIn("flags", payload)
        self.assertIn("sites", payload)

    def test_health_endpoint(self):
        dashboard = self._start()
        status, body = self._get(dashboard.url + "api/health")
        self.assertEqual(200, status)
        self.assertTrue(json.loads(body)["ok"])

    def test_unknown_path_returns_404(self):
        dashboard = self._start()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get(dashboard.url + "nope")
        self.assertEqual(404, ctx.exception.code)

    def test_stop_is_idempotent(self):
        dashboard = self._start()
        self.assertTrue(dashboard.running)
        dashboard.stop()
        self.assertFalse(dashboard.running)
        dashboard.stop()
        self.assertFalse(dashboard.running)

    def test_port_conflict_auto_shifts(self):
        """端口被占用时必须自动顺延，而不是启动失败。"""
        import http.server as http_server

        blocker = http_server.ThreadingHTTPServer(("127.0.0.1", 0), http_server.BaseHTTPRequestHandler)
        self.addCleanup(blocker.server_close)
        taken = blocker.server_address[1]

        config = self._config()
        config["dashboard_port"] = taken
        wifi_monitor.init_db(config["db_file"])
        dashboard = wifi_monitor.LiveDashboard(config, wifi_monitor.RuntimeState())
        self.addCleanup(dashboard.stop)
        self.assertTrue(dashboard.start())
        self.assertNotEqual(taken, dashboard.port)


class LocalIpTests(unittest.TestCase):
    def test_returns_ipv4_or_none(self):
        value = wifi_monitor.local_ip_address()
        self.assertTrue(value is None or isinstance(value, str))


class HeadlessAppTests(unittest.TestCase):
    def test_implements_the_app_interface_used_by_monitor_loop(self):
        logs = []
        app = wifi_monitor.HeadlessApp(on_log=logs.append)
        for name in ("safe_update_status", "safe_append_log", "safe_set_state",
                     "safe_set_stopped", "safe_refresh_events", "safe_refresh_samples",
                     "safe_alert"):
            self.assertTrue(callable(getattr(app, name)), f"缺少 {name}")
        app.safe_append_log("hello")
        app.safe_alert("outage", "断了")
        self.assertTrue(any("hello" in line for line in logs))
        self.assertTrue(any("断网" in line for line in logs))


class ArgsTests(unittest.TestCase):
    def test_defaults(self):
        args = wifi_monitor.parse_args([])
        self.assertFalse(args.serve)
        self.assertIsNone(args.host)
        self.assertIsNone(args.port)

    def test_serve_flags(self):
        args = wifi_monitor.parse_args(["--serve", "--host", "0.0.0.0", "--port", "9000", "--open"])
        self.assertTrue(args.serve)
        self.assertEqual("0.0.0.0", args.host)
        self.assertEqual(9000, args.port)
        self.assertTrue(args.open)


class PeriodicTaskTests(unittest.TestCase):
    def test_first_run_is_due(self):
        task = wifi_monitor._PeriodicTask("t", 60, lambda: None)
        self.assertTrue(task.due(first=True))

    def test_not_due_before_interval(self):
        task = wifi_monitor._PeriodicTask("t", 60, lambda: None)
        self.assertTrue(task.due(first=True))
        task.last_started = time.monotonic()
        self.assertFalse(task.due())

    def test_due_after_interval(self):
        task = wifi_monitor._PeriodicTask("t", 1, lambda: None)
        task.last_started = time.monotonic() - 5
        self.assertTrue(task.due())

    def test_running_task_is_not_started_again(self):
        task = wifi_monitor._PeriodicTask("t", 1, lambda: None)
        task.running = True
        task.last_started = time.monotonic() - 100
        self.assertFalse(task.due(), "同一任务不能重入")


class SamplerConcurrencyTests(unittest.TestCase):
    def test_slow_quality_does_not_block_sites(self):
        """量化指标要 4.2s、站点只要 0.3s，串行排队会让站点数据永远慢一拍。"""
        config = {
            "quality_targets": ["x"],
            "quality_interval_seconds": 1,
            "site_interval_seconds": 1,
            "sites": [{"name": "A", "host": "a"}],
            "speed_test_enabled": False,
        }
        state = wifi_monitor.RuntimeState()
        sampler = wifi_monitor.BackgroundSampler(config, threading.Event(), state)

        released = threading.Event()
        sites_done = threading.Event()

        def slow_quality():
            released.wait(timeout=5)

        def quick_sites():
            state.set_sites([{"name": "A", "verdict": "GREAT", "total_ms": 10.0}])
            sites_done.set()

        sampler._tasks["quality"].func = slow_quality
        sampler._tasks["sites"].func = quick_sites

        sampler._tick(first=True)
        self.assertTrue(
            sites_done.wait(timeout=3),
            "站点采样被指标采样阻塞了 —— 两者必须在各自线程里跑",
        )
        released.set()

    def test_speed_test_makes_others_wait(self):
        """测速占满带宽时，其它采样必须让路，否则测出来的 RTT 是假的。"""
        config = {
            "quality_targets": ["x"],
            "sites": [{"name": "A", "host": "a"}],
            "speed_test_enabled": True,
        }
        sampler = wifi_monitor.BackgroundSampler(config, threading.Event(),
                                                 wifi_monitor.RuntimeState())
        sampler._speed_running = True
        calls = []
        sampler._tasks["quality"].func = lambda: calls.append("quality")
        sampler._tasks["sites"].func = lambda: calls.append("sites")
        sampler._tick(first=True)
        self.assertEqual([], calls)

    def test_speed_skipped_during_outage(self):
        config = {
            "speed_test_enabled": True,
            "speed_test_sources": ["https://example.com/x"],
            "quality_targets": [],
            "sites": [],
        }
        state = wifi_monitor.RuntimeState()
        state.set_health("outage")
        sampler = wifi_monitor.BackgroundSampler(config, threading.Event(), state)
        with mock.patch.object(wifi_monitor, "run_speed_test") as mocked:
            sampler._sample_speed()
        mocked.assert_not_called()

    def test_speed_skipped_when_disabled(self):
        state = wifi_monitor.RuntimeState()
        sampler = wifi_monitor.BackgroundSampler(
            {"speed_test_enabled": False}, threading.Event(), state
        )
        with mock.patch.object(wifi_monitor, "run_speed_test") as mocked:
            sampler._sample_speed()
        mocked.assert_not_called()


class RecordThrottleTests(TempDirMixin):
    """探测很密（2 秒），但写库要节流，否则 checks 表会迅速膨胀。"""

    def _run(self, rounds=6):
        config_path = os.path.join(self.tmpdir, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump({
                "gateway": "10.0.0.1",
                "check_interval_seconds": 1,
                "confirm_interval_seconds": 1,
                "failure_threshold": 3,
                "recovery_threshold": 3,
                "probe_timeout_seconds": 1,
                "record_check_interval_seconds": 3600,   # 远大于测试时长
                "sampling_enabled": False,
                "evidence_enabled": False,
                "log_file": "logs\\wifi_monitor.log",
                "db_file": "data\\wifi_events.db",
                "notify": {"email_enabled": False},
            }, handle)

        self.addCleanup(setattr, wifi_monitor, "CONFIG_PATH", wifi_monitor.CONFIG_PATH)
        self.addCleanup(setattr, wifi_monitor, "MIN_CHECK_INTERVAL_SECONDS",
                        wifi_monitor.MIN_CHECK_INTERVAL_SECONDS)
        wifi_monitor.CONFIG_PATH = config_path
        wifi_monitor.MIN_CHECK_INTERVAL_SECONDS = 1

        app = _FakeAppStub()
        stop = threading.Event()
        db_path = os.path.join(self.tmpdir, "data", "wifi_events.db")

        with mock.patch.object(wifi_monitor, "NetworkProbe", DownProbe):
            thread = threading.Thread(
                target=wifi_monitor.monitor_loop, args=(stop, app), daemon=True
            )
            thread.start()
            while len(app.statuses) < rounds and thread.is_alive():
                time.sleep(0.1)
            stop.set()
            thread.join(timeout=10)
        return app, db_path

    def test_detection_runs_every_round_but_db_is_throttled(self):
        app, db_path = self._run(rounds=6)
        self.assertGreaterEqual(len(app.statuses), 6, "界面必须每轮都刷新（实时）")

        conn = sqlite3.connect(db_path)
        try:
            checks = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(1, checks, f"写库应被节流成 1 条，实际 {checks} 条")

    def test_health_change_forces_immediate_record(self):
        """健康等级一变必须立刻落库，否则事件与统计会失真。"""
        app, db_path = self._run(rounds=6)
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute("SELECT health FROM checks ORDER BY id").fetchall()
        finally:
            conn.close()
        self.assertTrue(rows)
        self.assertEqual("outage", rows[0][0], "首次判定为断网时应立即写入")


# --------------------------------------------------------------------------
# 打包相关：路径解析、配置自动生成、无控制台输出
# --------------------------------------------------------------------------

class PackagingPathTests(unittest.TestCase):
    def test_source_mode_uses_module_dir(self):
        with mock.patch.object(sys, "frozen", False, create=True):
            self.assertEqual(
                os.path.dirname(os.path.abspath(wifi_monitor.__file__)),
                wifi_monitor._app_dir(),
            )

    def test_frozen_mode_uses_exe_dir_not_meipass(self):
        """单文件 exe 下 __file__ 在临时解包目录里，数据写那儿退出就丢光了。"""
        fake_exe = r"C:\Program Files\WiFiMonitor\WiFiMonitor.exe"
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "executable", fake_exe):
            self.assertEqual(
                r"C:\Program Files\WiFiMonitor", wifi_monitor._app_dir()
            )

    def test_resource_path_prefers_meipass(self):
        with mock.patch.object(sys, "_MEIPASS", r"C:\tmp\_MEI123", create=True):
            self.assertTrue(
                wifi_monitor.resource_path("app.ico").startswith(r"C:\tmp\_MEI123")
            )

    def test_resource_path_falls_back_to_module_dir(self):
        with mock.patch.object(sys, "_MEIPASS", None, create=True):
            self.assertEqual(
                os.path.join(os.path.dirname(os.path.abspath(wifi_monitor.__file__)), "app.ico"),
                wifi_monitor.resource_path("app.ico"),
            )


class EnsureConfigTests(TempDirMixin):
    def test_creates_valid_config_when_missing(self):
        path = os.path.join(self.tmpdir, "sub", "config.json")
        self.assertTrue(wifi_monitor.ensure_config(path))
        self.assertTrue(os.path.exists(path))
        config = wifi_monitor.load_config(path)
        self.assertEqual("auto", config["gateway"])
        self.assertIn("dashboard_port", config)

    def test_does_not_overwrite_existing(self):
        path = os.path.join(self.tmpdir, "config.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"gateway": "10.1.2.3"}, handle)
        self.assertFalse(wifi_monitor.ensure_config(path))
        self.assertEqual("10.1.2.3", wifi_monitor.load_config(path)["gateway"])


class ConsoleLogTests(unittest.TestCase):
    def test_silent_when_no_console(self):
        """打包成 --noconsole 后 sys.stdout 是 None，print 会抛异常。"""
        with mock.patch.object(sys, "stdout", None):
            wifi_monitor.console_log("不该炸")      # 不抛就算过

    def test_writes_when_console_present(self):
        stream = io.StringIO()
        with mock.patch.object(sys, "stdout", stream):
            wifi_monitor.console_log("hello")
        self.assertIn("hello", stream.getvalue())

    def test_startup_error_in_serve_mode_does_not_touch_tk(self):
        stream = io.StringIO()
        with mock.patch.object(sys, "stdout", stream), \
             mock.patch.object(wifi_monitor.tk, "Tk") as tk_cls:
            wifi_monitor._show_startup_error("标题", "内容", console=True)
        tk_cls.assert_not_called()
        self.assertIn("内容", stream.getvalue())


class MainEntryTests(TempDirMixin):
    def test_serve_mode_creates_config_and_does_not_raise(self):
        """打包后首次运行没有 config.json，必须自动生成而不是弹错误框退出。"""
        config_path = os.path.join(self.tmpdir, "config.json")
        self.addCleanup(setattr, wifi_monitor, "CONFIG_PATH", wifi_monitor.CONFIG_PATH)
        wifi_monitor.CONFIG_PATH = config_path

        started = {"n": 0}

        def fake_run_headless(config, args):
            started["n"] += 1

        with mock.patch.object(wifi_monitor, "run_headless", side_effect=fake_run_headless), \
             mock.patch.object(wifi_monitor, "local_ip_address", return_value=None), \
             mock.patch.object(sys, "stdout", io.StringIO()):
            code = wifi_monitor.main(["--serve", "--no-dashboard"])

        self.assertEqual(0, code)
        self.assertTrue(os.path.exists(config_path), "应自动生成 config.json")
        self.assertEqual(1, started["n"], "应进入无界面模式")


class SamplerBandwidthTests(unittest.TestCase):
    def _sampler(self):
        config = {
            "quality_targets": ["x"],
            "sites": [],
            "speed_test_enabled": True,
            "speed_test_sources": ["https://example.com/x"],
        }
        sampler = wifi_monitor.BackgroundSampler(
            config, threading.Event(), wifi_monitor.RuntimeState()
        )
        # 让质量/站点本 tick 不到期，单独考察测速的启动条件
        now = time.monotonic()
        for key in ("quality", "sites"):
            sampler._tasks[key].last_started = now
        return sampler

    def test_speed_waits_until_quality_and_sites_are_idle(self):
        """下载会占满带宽，与 ping 并发会把首个质量样本的 RTT 抬得虚高。"""
        sampler = self._sampler()
        sampler._tasks["quality"].running = True     # 模拟质量采样还在跑
        with mock.patch.object(wifi_monitor, "run_speed_test") as mocked:
            sampler._tick(first=False)
            time.sleep(0.15)
        mocked.assert_not_called()
        self.assertFalse(sampler._tasks["speed"].running)

    def test_speed_starts_after_samples_finish(self):
        sampler = self._sampler()
        with mock.patch.object(wifi_monitor, "run_speed_test",
                               return_value={"ok": True, "mbps": 10.0}) as mocked:
            sampler._tick(first=False)
            for _ in range(60):
                if mocked.called:
                    break
                time.sleep(0.02)
        self.assertTrue(mocked.called, "质量/站点空闲后测速应当启动")

    def test_first_tick_defers_speed_until_samples_done(self):
        """首次 tick 会先启动质量/站点采样，测速应顺延而不是抢带宽。"""
        config = {
            "quality_targets": ["x"],
            "sites": [],
            "speed_test_enabled": True,
            "speed_test_sources": ["https://example.com/x"],
        }
        sampler = wifi_monitor.BackgroundSampler(
            config, threading.Event(), wifi_monitor.RuntimeState()
        )
        released = threading.Event()

        def slow_quality():
            released.wait(timeout=5)      # 模拟 ping -n 5 的 4.2 秒

        sampler._tasks["quality"].func = slow_quality
        with mock.patch.object(wifi_monitor, "run_speed_test") as mocked:
            sampler._tick(first=True)
            time.sleep(0.2)
            mocked.assert_not_called()
            self.assertTrue(sampler._tasks["quality"].running)
            released.set()
            # 质量采样结束后，测速应当能启动
            for _ in range(80):
                sampler._tick(first=False)
                if mocked.called:
                    break
                time.sleep(0.02)
        self.assertTrue(mocked.called, "采样结束后测速应启动")

    def test_speed_is_not_starved_by_long_quality_samples(self):
        """回归：质量采样 5s 一轮、本身耗时 4.2s，空闲窗口只有 0.8s。

        调度器若只按固定 1 秒 tick，就永远踩不到那个窗口，测速会被活活饿死 ——
        实测现象是 speed_tests 表始终为空。到期被挡住的任务必须记下来、等空闲补上。
        """
        sampler = self._sampler()
        sampler._tasks["quality"].running = True     # 质量采样长期占用
        with mock.patch.object(wifi_monitor, "run_speed_test") as mocked:
            for _ in range(10):
                sampler._tick(first=False)
                time.sleep(0.01)
            mocked.assert_not_called()
            self.assertTrue(
                sampler._tasks["speed"].deferred,
                "到期却被带宽占用挡住时，应标记 deferred 等空闲补跑",
            )
            sampler._tasks["quality"].running = False
            for _ in range(60):
                sampler._tick(first=False)
                if mocked.called:
                    break
                time.sleep(0.02)
        self.assertTrue(mocked.called, "空闲后测速必须补上，不能被饿死")

    def test_defer_flag_clears_after_run(self):
        task = wifi_monitor._PeriodicTask("t", 60, lambda: None)
        task.defer()
        self.assertTrue(task.due())
        task.run()
        self.assertFalse(task.deferred)
        self.assertIsNotNone(task.last_started)


# --------------------------------------------------------------------------
# 日志轮转
# --------------------------------------------------------------------------

class LogRotationTests(TempDirMixin):
    def test_rotates_when_over_threshold(self):
        """7×24 常驻运行必须有上限，否则日志会一直涨到把磁盘写满。"""
        log_file = os.path.join(self.tmpdir, "logs", "a.log")
        self.addCleanup(setattr, wifi_monitor, "LOG_MAX_BYTES", wifi_monitor.LOG_MAX_BYTES)
        wifi_monitor.LOG_MAX_BYTES = 200

        for index in range(30):
            wifi_monitor.log_message(f"第 {index} 条日志" * 3, log_file)

        self.assertTrue(os.path.exists(log_file))
        self.assertTrue(os.path.exists(log_file + ".1"), "应轮转出 .1 备份")
        # 注意：连续轮转时 .1 保存的是「上一次轮转前」的内容（只保留一代），
        # 所以不能断言最旧的日志还在 —— 只能断言备份非空、新日志在正文里
        self.assertGreater(os.path.getsize(log_file + ".1"), 0)
        self.assertLess(os.path.getsize(log_file), 200 + 400)
        with open(log_file, encoding="utf-8") as handle:
            self.assertIn("第 29 条日志", handle.read(), "最新日志应在正文里")

    def test_configure_log_rotation_accepts_valid_value_only(self):
        self.addCleanup(setattr, wifi_monitor, "LOG_MAX_BYTES", wifi_monitor.LOG_MAX_BYTES)
        original = wifi_monitor.LOG_MAX_BYTES
        wifi_monitor.configure_log_rotation(1024)
        self.assertEqual(1024, wifi_monitor.LOG_MAX_BYTES)
        wifi_monitor.configure_log_rotation("abc")
        self.assertEqual(1024, wifi_monitor.LOG_MAX_BYTES, "非法值应被忽略")
        wifi_monitor.configure_log_rotation(0)
        self.assertEqual(1024, wifi_monitor.LOG_MAX_BYTES)   # 0 表示不限制，不覆盖
        wifi_monitor.configure_log_rotation(None)
        self.assertEqual(1024, wifi_monitor.LOG_MAX_BYTES)
        wifi_monitor.LOG_MAX_BYTES = original

    def test_no_log_file_is_silent(self):
        wifi_monitor.log_message("x", None)      # 不抛就算过


if __name__ == "__main__":
    unittest.main()
