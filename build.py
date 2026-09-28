"""一键打包脚本：生成图标 → PyInstaller 打包 → 把配套文件放进 dist。

用法：
    python build.py                # 打包（默认单文件、无控制台窗口）
    python build.py --shortcut     # 打包后额外创建桌面快捷方式
    python build.py --console      # 保留控制台窗口（调试用）

产物：dist/WiFiMonitor.exe（图标已内嵌，可直接拷走单文件运行）
"""

import argparse
import os
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "dist")
BUILD_DIR = os.path.join(BASE_DIR, "build")
ICON_PATH = os.path.join(BASE_DIR, "app.ico")
ENTRY = os.path.join(BASE_DIR, "wifi_monitor.py")
APP_NAME = "WiFiMonitor"

# 本项目只用标准库 + tkinter；显式排除常见的「被意外拖进来」的重型依赖，
# 否则打包体积会莫名其妙涨几十 MB。
EXCLUDES = [
    "numpy", "pandas", "matplotlib", "scipy", "PIL",
    "IPython", "notebook", "pytest", "docutils",
]


def run(cmd, **kwargs):
    print("$", " ".join(str(part) for part in cmd), flush=True)
    return subprocess.run(cmd, **kwargs)


def step_icon():
    print("\n[1/4] 生成图标", flush=True)
    result = run([sys.executable, os.path.join(BASE_DIR, "make_icon.py"), ICON_PATH])
    if result.returncode != 0 or not os.path.exists(ICON_PATH):
        raise SystemExit("图标生成失败")
    print("       -> %s (%d 字节)" % (ICON_PATH, os.path.getsize(ICON_PATH)), flush=True)


def step_pyinstaller(console):
    print("\n[2/4] PyInstaller 打包", flush=True)
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",
        "--console" if console else "--windowed",
        "--name", APP_NAME,
        "--icon", ICON_PATH,
        # 图标随包分发，程序运行时用它设置窗口图标（打包后在 _MEIPASS 里）
        "--add-data", "%s%s." % (ICON_PATH, os.pathsep),
        "--distpath", DIST_DIR,
        "--workpath", BUILD_DIR,
        "--specpath", BUILD_DIR,
    ]
    for name in EXCLUDES:
        cmd += ["--exclude-module", name]
    cmd.append(ENTRY)
    result = run(cmd)
    if result.returncode != 0:
        raise SystemExit("PyInstaller 打包失败")

    exe = os.path.join(DIST_DIR, APP_NAME + (".exe" if os.name == "nt" else ""))
    if not os.path.exists(exe):
        raise SystemExit("未找到生成的 exe：%s" % exe)
    size_mb = os.path.getsize(exe) / 1024 / 1024
    print("       -> %s (%.1f MB)" % (exe, size_mb), flush=True)
    return exe


def step_companions():
    print("\n[3/4] 复制配套文件到 dist", flush=True)
    for name in ("config.json", "app.ico"):
        source = os.path.join(BASE_DIR, name)
        if os.path.exists(source):
            shutil.copy2(source, os.path.join(DIST_DIR, name))
            print("       -> %s" % name, flush=True)

    readme = os.path.join(DIST_DIR, "使用说明.txt")
    with open(readme, "w", encoding="utf-8") as handle:
        handle.write(README_TEXT)
    print("       -> 使用说明.txt", flush=True)


def step_shortcut(exe, desktop=True):
    print("\n[4/4] 创建快捷方式", flush=True)
    targets = []
    if desktop:
        desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
        if os.path.isdir(desktop_dir):
            targets.append(os.path.join(desktop_dir, "WiFi 网络监控.lnk"))
    targets.append(os.path.join(DIST_DIR, "WiFi 网络监控.lnk"))

    for lnk in targets:
        script = (
            "$ws = New-Object -ComObject WScript.Shell; "
            "$s = $ws.CreateShortcut('%s'); "
            "$s.TargetPath = '%s'; "
            "$s.WorkingDirectory = '%s'; "
            "$s.IconLocation = '%s'; "
            "$s.Description = 'WiFi 网络监控 - 实时监控网络质量并留下举证记录'; "
            "$s.Save()" % (lnk, exe, DIST_DIR, ICON_PATH)
        )
        result = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
        )
        if result.returncode == 0 and os.path.exists(lnk):
            print("       -> %s" % lnk, flush=True)
        else:
            print("       !! 创建失败：%s" % lnk, flush=True)


README_TEXT = """WiFi 网络监控 —— 使用说明
========================================

【直接运行】
双击 WiFiMonitor.exe 即可打开监控界面。
界面右上角会显示实时看板地址（默认 http://127.0.0.1:8777/），
点「打开看板」用浏览器查看实时数据。

【无界面常驻（适合长期挂机）】
在命令行里运行：
    WiFiMonitor.exe --serve
    WiFiMonitor.exe --serve --open          启动后自动打开浏览器
    WiFiMonitor.exe --serve --host 0.0.0.0  允许同网段手机访问看板
按 Ctrl+C 退出。

【文件说明】
    config.json     配置文件，改完重启程序生效
    app.ico         图标
    data\\           断网事件数据库（wifi_events.db，请勿删除）
    logs\\           运行日志
    reports\\        生成的报表、事故清单、取证记录

【重要】
1. 首次运行会自动生成 config.json。
2. 想恢复默认配置，删掉 config.json 再启动即可。
3. 断网记录永久保留，只自动清理高频采样数据（默认 30 天）。
4. 拿去找运营商举证时，用「生成报表」得到的 reports\\incidents.csv，
   里面是按 30 分钟窗口合并后的「事故」清单，比按次数统计更有说服力。
5. 启动可能慢几秒：单文件 exe 需要先解包，属正常现象。

【常用配置】
    check_interval_seconds        探测间隔（默认 2 秒）
    failure_threshold             连续几次异常才报警（默认 3）
    dashboard_host                改成 "0.0.0.0" 可让手机访问看板
    notify.email_enabled          开启邮件通知（断网时邮件发不出去，
                                  程序会自动入队、等网络恢复后补发）
"""


def main():
    parser = argparse.ArgumentParser(description="打包 WiFi 网络监控")
    parser.add_argument("--console", action="store_true", help="保留控制台窗口（调试用）")
    parser.add_argument("--shortcut", action="store_true", help="打包后创建桌面快捷方式")
    parser.add_argument("--no-clean", action="store_true", help="不清空旧 build 目录")
    args = parser.parse_args()

    if args.no_clean and os.path.isdir(BUILD_DIR):
        pass
    elif os.path.isdir(BUILD_DIR):
        shutil.rmtree(BUILD_DIR, ignore_errors=True)

    step_icon()
    exe = step_pyinstaller(args.console)
    step_companions()
    step_shortcut(exe, desktop=args.shortcut)

    print("\n打包完成：%s" % exe, flush=True)
    print("提示：把 WiFiMonitor.exe 单独拷到任何位置都能运行，", flush=True)
    print("      首次启动会在同级目录自动生成 config.json / data / logs / reports。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
