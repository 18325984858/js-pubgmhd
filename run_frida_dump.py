# -*- coding: utf-8 -*-
"""
UE4.18 Dump Launcher — 通过 Frida 注入 JS 脚本，文件直接写入设备
目标: com.tencent.tmgp.pubgmhd (PUBG Mobile)

使用方法:
  1. 确保设备已连接, adb 可用, frida-server 已在设备上运行
  2. 方式 A — 附加到已运行的游戏 (推荐, 等游戏加载到主界面后执行):
       python run_frida_dump.py
  3. 方式 B — 通过 Frida spawn 启动游戏:
       python run_frida_dump.py --spawn
  4. dump 完成后可选 --pull 自动 adb pull 文件到本地:
       python run_frida_dump.py --pull

设备端输出路径: /data/data/com.tencent.tmgp.pubgmhd/files/
  - NamesDump.txt    所有 FName 索引 → 字符串
  - ObjectsDump.txt  所有 UObject [索引] 类名 完整路径
  - GWorldInfo.txt   当前 GWorld 信息

依赖:
  pip install frida frida-tools
"""

import frida
import sys
import os
import argparse
import subprocess
import time
import threading

PACKAGE = "com.tencent.tmgp.pubgmhd"
JS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_ue4_dump.js")
JS_SDK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_ue4_sdk_dump.js")
JS_MONITOR_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_match_monitor.js")
DEVICE_OUTPUT_DIR = "/data/data/" + PACKAGE + "/cache/ue4_dump/"
LOCAL_PULL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dump_output")
INIT_DELAY = 60  # 等待引擎初始化的秒数

done_event = threading.Event()
script_ref = None  # 全局引用，用于发送消息


def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        msg_type = payload.get("type", "")

        if msg_type in ("info", "phase"):
            print(f"[*] {payload['msg']}")
        elif msg_type == "error":
            print(f"[!] {payload['msg']}")
        elif msg_type == "ready":
            print(f"[*] {payload['msg']}")
        elif msg_type == "done":
            print(f"[*] {payload['msg']}")
            done_event.set()
        elif msg_type == "heartbeat":
            print(f"    {payload['msg']}")
        elif msg_type == "state_change":
            print(f"\n>>> {payload['msg']}\n")

    elif message["type"] == "error":
        print(f"[ERROR] {message.get('description', '')}")
        if "stack" in message:
            print(message["stack"])


def pull_files(local_dir, file_list=None):
    """通过 su cp 将 app 私有目录的文件逐个复制到 /sdcard/ 再 adb pull"""
    os.makedirs(local_dir, exist_ok=True)
    TMP_DIR = "/sdcard/ue4_dump_tmp/"
    subprocess.run(["adb", "shell", "su", "-c", "mkdir -p " + TMP_DIR], capture_output=True)
    if file_list is None:
        file_list = ["NamesDump.txt", "ObjectsDump.txt", "GWorldInfo.txt"]
    for fname in file_list:
        src = DEVICE_OUTPUT_DIR + fname
        dst_remote = TMP_DIR + fname
        local = os.path.join(local_dir, fname)
        # 逐个文件 cp + chmod
        cp_ret = subprocess.run(
            ["adb", "shell", "su", "-c", f"cp '{src}' '{dst_remote}' && chmod 644 '{dst_remote}'"],
            capture_output=True, text=True
        )
        if cp_ret.returncode != 0:
            print(f"[*] adb pull {dst_remote} → {local}")
            print(f"     FAILED (cp): {cp_ret.stderr.strip()}")
            continue
        print(f"[*] adb pull {dst_remote} → {local}")
        ret = subprocess.run(["adb", "pull", dst_remote, local], capture_output=True, text=True)
        if ret.returncode == 0:
            size = os.path.getsize(local) if os.path.isfile(local) else 0
            print(f"     OK ({size:,} bytes)")
        else:
            print(f"     FAILED: {ret.stderr.strip()}")
    # 清理临时目录
    subprocess.run(["adb", "shell", "su", "-c", "rm -rf " + TMP_DIR], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description="UE4 Frida Dumper for PUBG Mobile")
    parser.add_argument("--spawn", action="store_true", help="Spawn 方式启动游戏")
    parser.add_argument("--sdk", action="store_true", help="生成 SDK 风格 dump.cs (包含类/结构体/字段/函数)")
    parser.add_argument("--monitor", action="store_true", help="实时监控对局状态")
    parser.add_argument("--package", default=PACKAGE, help=f"目标包名")
    parser.add_argument("--js", default=None, help="Frida JS 脚本路径")
    parser.add_argument("--pull", action="store_true", help="dump 完成后自动 adb pull")
    parser.add_argument("--pull-dir", default=LOCAL_PULL_DIR, help="adb pull 本地目标目录")
    args = parser.parse_args()

    # 确定 JS 脚本
    if args.js:
        js_path = args.js
    elif args.monitor:
        js_path = JS_MONITOR_FILE
    elif args.sdk:
        js_path = JS_SDK_FILE
    else:
        js_path = JS_FILE

    # 加载 JS 脚本
    if not os.path.isfile(js_path):
        print(f"[!] JS 脚本未找到: {js_path}")
        sys.exit(1)

    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    print("[*] 正在连接 USB 设备...")
    try:
        device = frida.get_usb_device(timeout=10)
    except frida.TimedOutError:
        print("[!] 未找到 USB 设备，请确保 adb 已连接且 frida-server 正在运行")
        sys.exit(1)

    print(f"[*] 设备: {device.name}")

    session = None
    pid = None

    if args.spawn:
        print(f"[*] Spawn 启动: {args.package}")
        pid = device.spawn([args.package])
        session = device.attach(pid)
    else:
        print(f"[*] 正在附加到: {args.package}")
        try:
            session = device.attach(args.package)
        except frida.ProcessNotFoundError:
            print(f"[!] 进程 {args.package} 未找到，请先启动游戏或使用 --spawn 参数")
            sys.exit(1)

    # 注入前先在设备上创建输出目录
    subprocess.run(["adb", "shell", "mkdir", "-p", DEVICE_OUTPUT_DIR], capture_output=True)

    # 注入脚本
    script = session.create_script(js_code)
    script.on("message", on_message)
    script.load()

    if args.spawn and pid is not None:
        print(f"[*] 恢复进程 PID={pid}")
        device.resume(pid)

    print(f"[*] 脚本已注入，文件将写入设备: {DEVICE_OUTPUT_DIR}")

    # 等待引擎初始化
    print(f"[*] 等待 {INIT_DELAY} 秒让引擎完成初始化...")
    for remaining in range(INIT_DELAY, 0, -1):
        if remaining % 10 == 0:
            print(f"[*] {remaining}s remaining...")
        time.sleep(1)

    # 发送 start 指令给 JS 端
    print("[*] 发送 start 信号，开始 dump...")
    script.post({"type": "start"})

    print("[*] 等待 dump 完成...")
    print("[*] 按 Ctrl+C 可提前中断\n")

    try:
        done_event.wait(timeout=600)
        if not done_event.is_set():
            print("\n[!] 超时，dump 可能未完成")
    except KeyboardInterrupt:
        print("\n[*] 用户中断")
    finally:
        try:
            session.detach()
        except Exception:
            pass

    # 可选自动拉取
    if args.pull:
        print(f"\n[*] 正在从设备拉取文件到 {args.pull_dir} ...")
        if args.sdk:
            pull_files(args.pull_dir, ["dump.cs"])
        else:
            pull_files(args.pull_dir)
    else:
        print(f"\n[*] dump 文件已存储在设备: {DEVICE_OUTPUT_DIR}")


if __name__ == "__main__":
    main()
