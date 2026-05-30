#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Force socket to resolve IPv4 only.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

import vpn_utils
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "960"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "960"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
NODE_PROBE_TIMEOUT_SECONDS = int(os.environ.get("NODE_PROBE_TIMEOUT_SECONDS", "5"))
MAX_BATCH_TEST_NODES = int(os.environ.get("MAX_BATCH_TEST_NODES", "24"))
NODE_PROBE_WORKERS = int(os.environ.get("NODE_PROBE_WORKERS", "16"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
CHANNEL_COUNT = max(1, int(os.environ.get("CHANNEL_COUNT", "6")))
PROXY_BASE_PORT = int(os.environ.get("PROXY_BASE_PORT", str(LOCAL_PROXY_PORT)))
UI_HOST = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0
channels: dict[int, dict[str, Any]] = {}

def channel_device(index: int) -> str:
    return f"tun{index}"

def channel_port(index: int) -> int:
    return PROXY_BASE_PORT + index

def channel_table(index: int) -> int:
    return 100 + index

def get_channel(index: int) -> dict[str, Any]:
    if index < 0 or index >= CHANNEL_COUNT:
        raise ValueError(f"Invalid channel index: {index}")
    with lock:
        channel = channels.get(index)
        if channel is None:
            channel = {
                "index": index,
                "node_id": "",
                "process": None,
                "is_connecting": False,
                "last_ping_time": 0.0,
                "last_latency": 0,
                "auto_switch": True,
                "country_lock": "",
                "asn_lock": "",
                "last_message": "未连接",
                "proxy_ok": None,
                "proxy_ip": "-",
                "proxy_latency_ms": 0,
                "proxy_error": "",
            }
            channels[index] = channel
        return channel

def init_channels() -> None:
    for idx in range(CHANNEL_COUNT):
        get_channel(idx)

def sync_legacy_channel0() -> None:
    global active_openvpn_process, active_openvpn_node_id, is_connecting, last_active_ping_time, last_active_latency
    channel = get_channel(0)
    active_openvpn_process = channel.get("process")
    active_openvpn_node_id = str(channel.get("node_id") or "")
    is_connecting = any(bool(get_channel(idx).get("is_connecting")) for idx in range(CHANNEL_COUNT))
    last_active_ping_time = float(channel.get("last_ping_time") or 0.0)
    last_active_latency = int(channel.get("last_latency") or 0)

def active_channel_map() -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for idx in range(CHANNEL_COUNT):
        node_id = str(get_channel(idx).get("node_id") or "")
        if node_id:
            result.setdefault(node_id, []).append(idx)
    return result

def normalize_asn_locks(value: Any) -> list[str]:
    if isinstance(value, list):
        raw_values = value
    elif isinstance(value, str):
        raw_values = [part for part in re.split(r"[,\\s]+", value) if part]
    else:
        raw_values = []
    result: list[str] = []
    seen: set[str] = set()
    for item in raw_values:
        asn = str(item or "").strip()
        if asn and asn not in seen:
            seen.add(asn)
            result.append(asn)
    return result

def serialize_channels(nodes: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    node_map = {str(n.get("id")): n for n in (nodes or read_json(NODES_FILE, []))}
    data = []
    for idx in range(CHANNEL_COUNT):
        channel = get_channel(idx)
        node_id = str(channel.get("node_id") or "")
        process = channel.get("process")
        running = process is not None and process.poll() is None
        node = dict(node_map.get(node_id, {}))
        node.pop("config_text", None)
        data.append(
            {
                "index": idx,
                "port": channel_port(idx),
                "device": channel_device(idx),
                "table": channel_table(idx),
                "node_id": node_id,
                "is_connecting": bool(channel.get("is_connecting")),
                "running": running,
                "auto_switch": bool(channel.get("auto_switch", True)),
                "country_lock": channel.get("country_lock", ""),
                "asn_lock": normalize_asn_locks(channel.get("asn_lock")),
                "last_message": channel.get("last_message", ""),
                "latency_ms": int(channel.get("last_latency") or node.get("latency_ms") or 0),
                "proxy_ok": channel.get("proxy_ok"),
                "proxy_ip": channel.get("proxy_ip", "-"),
                "proxy_latency_ms": int(channel.get("proxy_latency_ms") or 0),
                "proxy_error": channel.get("proxy_error", ""),
                "node": node,
            }
        )
    return data

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import ipaddress
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def cleanup_old_logs(logs_dir: Path) -> None:
    try:
        now = time.time()
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    sync_legacy_channel0()
    state = read_json(STATE_FILE, {})
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state["channel_count"] = CHANNEL_COUNT
    state["proxy_base_port"] = PROXY_BASE_PORT
    state["channels"] = serialize_channels()
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("local_proxy", f"http://{LOCAL_PROXY_HOST}:{PROXY_BASE_PORT}")
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def fetch_api_text() -> str:
    request = urllib.request.Request(
        API_URL,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def is_ipv4_literal(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).version == 4
    except ValueError:
        return False

def clean_openvpn_config(config_text: str) -> str:
    blocked_directives = {"route-ipv6", "ifconfig-ipv6", "tun-ipv6", "redirect-gateway-ipv6"}
    cleaned_lines = []
    for raw_line in config_text.splitlines():
        directive = raw_line.strip().split(maxsplit=1)[0].lower() if raw_line.strip() else ""
        if directive in blocked_directives:
            continue
        cleaned_lines.append(raw_line)
    return "\n".join(cleaned_lines)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any] | None:
    config_text = clean_openvpn_config(config_text)
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    if not is_ipv4_literal(ip) or (remote_host and not is_ipv4_literal(remote_host)):
        return None
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    
    # 检查本地是否有节点缓存，以确定最大重试尝试次数
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    
    log_to_json("INFO", "Main", f"开始拉取官方 API 节点列表 (最大尝试次数: {max_attempts})...")
    for i in range(max_attempts):
        if i > 0:
            time.sleep(1.5)
        try:
            api_text = fetch_api_text()
            rows = parse_vpngate_rows(api_text)
            for row in rows[:MAX_SCAN_ROWS]:
                ip = row.get("IP", "")
                if not ip or ip in seen_ips:
                    continue
                encoded = row.get("OpenVPN_ConfigData_Base64", "")
                if not encoded:
                    continue
                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
                if not node:
                    continue
                candidates.append(node)
                seen_ips.add(ip)
        except Exception as e:
            print(f"[fetch_candidates] Fetch {i+1} failed: {e}", flush=True)
            log_to_json("WARNING", "Main", f"第 {i+1} 次拉取 API 节点失败: {e}")
            if i == max_attempts - 1 and not candidates:
                log_to_json("ERROR", "Main", f"获取官方 API 节点失败: {e}")
                raise
                
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        # Terminate existing openvpn processes managing tun0 or using our vpngate configuration
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
        print("[Cleanup] Terminated existing AimiliVPN OpenVPN processes.", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "openvpn command not found", None
    except OSError as exc:
        return False, f"openvpn start failed: {exc}", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not startup_done[0]:
                lines.put(line.rstrip())
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line.rstrip()}", flush=True)
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-8:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    if not ok and tail:
        message = tail[-1][-220:]
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0", table_id: int = 100) -> None:
    try:
        subprocess.run(["ip", "rule", "del", "oif", interface, "table", str(table_id)], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", str(table_id)], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", str(table_id)], check=True, timeout=2)
            print(f"[policy_routing] Enabled policy routing for interface {interface} table {table_id} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[policy_routing] Failed to enable policy routing after 3 attempts", flush=True)

def cleanup_policy_routing(interface: str = "tun0", table_id: int = 100) -> None:
    try:
        subprocess.run(["ip", "rule", "del", "oif", interface, "table", str(table_id)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True, timeout=2)
        print(f"[policy_routing] Cleared policy routing table {table_id} for {interface}", flush=True)
    except Exception:
        pass

def stop_channel_openvpn(channel_index: int) -> None:
    channel = get_channel(channel_index)
    cleanup_policy_routing(channel_device(channel_index), channel_table(channel_index))
    stop_process(channel.get("process"))
    channel["process"] = None
    channel["node_id"] = ""
    channel["is_connecting"] = False
    channel["last_ping_time"] = 0.0
    channel["last_latency"] = 0
    channel["last_message"] = "已断开"
    channel["proxy_ok"] = None
    channel["proxy_ip"] = "-"
    channel["proxy_latency_ms"] = 0
    channel["proxy_error"] = ""

    with lock:
        nodes = read_json(NODES_FILE, [])
        changed = False
        for item in nodes:
            active_indexes = [idx for idx in item.get("active_channels", []) if idx != channel_index]
            if item.get("active_channels") != active_indexes:
                item["active_channels"] = active_indexes
                changed = True
            if channel_index == 0 and item.get("active"):
                item["active"] = False
                changed = True
        if changed:
            write_json(NODES_FILE, nodes)
    sync_legacy_channel0()

def channel_running(channel_index: int) -> bool:
    process = get_channel(channel_index).get("process")
    return process is not None and process.poll() is None

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_channel_openvpn(0)
    active_openvpn_process = None
    active_openvpn_node_id = ""

def active_openvpn_running() -> bool:
    return channel_running(0)

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score")))
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        return 99

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_file = str(node["config_file"])
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = Path(config_file)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = get_free_test_index()
    try:
        ok, message, _ = run_openvpn_until_ready(config_file, keep_alive=False, route_nopull=True, timeout=NODE_PROBE_TIMEOUT_SECONDS, dev=f"tun{idx}")
    finally:
        release_test_index(idx)
    
    try:
        if temp_path.exists():
            temp_path.unlink()
    except Exception:
        pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        limited_ids = set(node_ids[:MAX_BATCH_TEST_NODES])
        to_test = [n for n in nodes if n.get("id") in limited_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_file = n_info["config_file"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = Path(config_file)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception:
            pass
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        test_idx = get_free_test_index()
        try:
            ok, message, _ = run_openvpn_until_ready(config_file, keep_alive=False, route_nopull=True, timeout=NODE_PROBE_TIMEOUT_SECONDS, dev=f"tun{test_idx}")
        finally:
            release_test_index(test_idx)
        
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass
            
        temp_node = {
            "id": node_id,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        if ok:
            ip_to_enrich = {
                "ip": n_info.get("ip"),
                "remote_host": h,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            vpn_utils.enrich_ip_info([ip_to_enrich])
            temp_node.update(ip_to_enrich)
        return temp_node

    updated_nodes_map = {}
    max_workers = max(1, min(NODE_PROBE_WORKERS, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
                
    with lock:
        current_nodes = read_json(NODES_FILE, [])
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def test_nodes_in_batches(node_ids: list[str]) -> list[dict[str, Any]]:
    all_results: list[dict[str, Any]] = []
    if not node_ids:
        return all_results
    batches = [
        node_ids[i : i + MAX_BATCH_TEST_NODES]
        for i in range(0, len(node_ids), MAX_BATCH_TEST_NODES)
    ]
    for batch_index, batch_ids in enumerate(batches, start=1):
        set_state(
            is_connecting=True,
            last_check_message=f"正在全量检测节点可用性 {batch_index}/{len(batches)}，本批 {len(batch_ids)} 个..."
        )
        all_results.extend(test_multiple_nodes(batch_ids))
    return all_results

def auto_switch_node(attempt: int = 0, channel_index: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return

    next_node = best_node_for_channel(channel_index)
    if next_node:
        msg = f"通道 {channel_index} 当前连接已失效或代理连通性检测失败，正在按锁定条件切换至最低延迟可用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_channel_node(channel_index, next_node["id"])
        except Exception as e:
            err_msg = f"通道 {channel_index} 切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1, channel_index)
    else:
        msg = f"通道 {channel_index} 没有符合锁定条件的可用备选节点，将自动断开并在后台异步获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_channel_openvpn(channel_index)
        with lock:
            nodes = read_json(NODES_FILE, [])
            for item in nodes:
                active_indexes = [idx for idx in item.get("active_channels", []) if idx != channel_index]
                item["active_channels"] = active_indexes
                item["active"] = 0 in active_indexes
            write_json(NODES_FILE, nodes)
        if channel_index == 0:
            set_state(active_openvpn_node_id="", last_check_message="没有符合锁定条件的可用备选节点，已断开")
        
        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False)
                auto_switch_node(0, channel_index)
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def best_node_for_channel(channel_index: int) -> dict[str, Any] | None:
    channel = get_channel(channel_index)
    country_lock = str(channel.get("country_lock") or "")
    asn_locks = set(normalize_asn_locks(channel.get("asn_lock")))
    active_ids = {str(get_channel(idx).get("node_id") or "") for idx in range(CHANNEL_COUNT)}
    nodes = read_json(NODES_FILE, [])
    def matches_locks(n: dict[str, Any]) -> bool:
        if country_lock and n.get("country") != country_lock and n.get("country_short") != country_lock:
            return False
        if asn_locks and str(n.get("asn") or "") not in asn_locks:
            return False
        return True
    candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and n.get("id") not in active_ids
        and matches_locks(n)
    ]
    candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
    return candidates[0] if candidates else None

def auto_connect_channel(channel_index: int) -> str:
    node = best_node_for_channel(channel_index)
    if not node:
        raise RuntimeError("没有找到符合条件的可用节点")
    return connect_channel_node(channel_index, str(node["id"]))

def connect_channel_node(channel_index: int, node_id: str) -> str:
    channel = get_channel(channel_index)
    device = channel_device(channel_index)
    proxy_port = channel_port(channel_index)
    table_id = channel_table(channel_index)
    with lock:
        if channel.get("is_connecting"):
            print(f"[连接] 通道 {channel_index} 正在建立连接中，跳过此请求", flush=True)
            return "Already connecting"
        channel["is_connecting"] = True
        channel["node_id"] = node_id
        channel["last_message"] = "正在初始化连接配置..."
        sync_legacy_channel0()
        if channel_index == 0:
            set_state(active_openvpn_node_id=node_id, is_connecting=True, active_node_latency="正在连接", last_check_message="正在初始化连接配置...")

    try:
        log_to_json("INFO", "VPN", f"通道 {channel_index} 开始连接节点: {node_id}")
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        channel["last_message"] = "正在关闭与清理旧的 VPN 连接及网卡..."
        if channel_index == 0:
            set_state(active_node_latency="清理连接", last_check_message=channel["last_message"])
        stop_channel_openvpn(channel_index)
        channel["is_connecting"] = True
        channel["node_id"] = node_id

        channel["last_message"] = "正在写入 OpenVPN 节点配置文件..."
        if channel_index == 0:
            set_state(active_node_latency="写入配置", last_check_message=channel["last_message"])
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        channel["last_message"] = "正在启动 OpenVPN Core 核心服务并建立连接..."
        if channel_index == 0:
            set_state(active_node_latency="启动核心", last_check_message=channel["last_message"])
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True, dev=device)
        if not ok or process is None:
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                active_indexes = [idx for idx in item.get("active_channels", []) if idx != channel_index]
                item["active_channels"] = active_indexes
                if channel_index == 0:
                    item["active"] = False
            write_json(NODES_FILE, nodes)
            channel["process"] = None
            channel["node_id"] = ""
            channel["is_connecting"] = False
            channel["last_message"] = f"连接失败: {message}"
            log_to_json("ERROR", "VPN", f"通道 {channel_index} 连接节点 {node_id} 失败: {message}")
            sync_legacy_channel0()
            if channel_index == 0:
                set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=channel["last_message"])
            raise RuntimeError(message)

        channel["process"] = process
        channel["node_id"] = node_id

        channel["last_message"] = "正在配置策略路由规则与流量转发..."
        if channel_index == 0:
            set_state(active_node_latency="配置路由", last_check_message=channel["last_message"])
        setup_policy_routing(device, table_id)

        channel["last_ping_time"] = time.time()
        channel["last_latency"] = 0
        channel["last_message"] = "正在直连测试代理出口延迟与可用性..."
        if channel_index == 0:
            set_state(active_node_latency="测试延迟", last_check_message=channel["last_message"])
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                channel["last_latency"] = latency
        except Exception:
            pass

        for item in nodes:
            active_indexes = [idx for idx in item.get("active_channels", []) if idx != channel_index]
            if item.get("id") == node_id and channel_index not in active_indexes:
                active_indexes.append(channel_index)
            item["active_channels"] = sorted(active_indexes)
            item["active"] = 0 in active_indexes
            if channel_index in active_indexes:
                item["probe_message"] = f"Active on channel {channel_index}. HTTP proxy: http://{LOCAL_PROXY_HOST}:{proxy_port}"
        write_json(NODES_FILE, nodes)

        channel["last_message"] = "正在测试本地代理出站联通性与出口 IP..."
        if channel_index == 0:
            set_state(last_check_message=channel["last_message"])
        res = check_proxy_health(port=proxy_port, interface=device)
        channel["proxy_ok"] = bool(res.get("ok"))
        channel["proxy_ip"] = res.get("ip", "-") if res.get("ok") else "-"
        channel["proxy_latency_ms"] = parse_int(res.get("latency_ms"))
        channel["proxy_error"] = "" if res.get("ok") else res.get("error", "未知错误")
        if channel_index == 0:
            set_state(
                proxy_ok=channel["proxy_ok"],
                proxy_ip=channel["proxy_ip"],
                proxy_latency_ms=channel["proxy_latency_ms"],
                proxy_error=channel["proxy_error"],
            )

        latency_str = f"{channel['last_latency']} ms" if channel["last_latency"] > 0 else "检测超时"
        channel["last_message"] = f"Connected {node_id}"
        channel["is_connecting"] = False
        sync_legacy_channel0()
        if channel_index == 0:
            set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=channel["last_message"], active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"通道 {channel_index} 节点 {node_id} 连接成功，出口网卡 {device} 已启用")
        return f"Connected channel {channel_index} -> {node_id}"
    finally:
        channel["is_connecting"] = False
        sync_legacy_channel0()

def connect_node(node_id: str) -> str:
    return connect_channel_node(0, node_id)

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            has_active_id = False
            with lock:
                if active_openvpn_node_id:
                    has_active_id = True
                    stop_active_openvpn()
            if has_active_id:
                print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                is_connecting = False
                auto_switch_node()
                is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            candidates = []

        if not candidates:
            is_connecting = False
            return "没有拉取到新节点"

        with lock:
            active_nodes: list[dict[str, Any]] = []
            active_ids = {str(get_channel(idx).get("node_id") or "") for idx in range(CHANNEL_COUNT)}
            active_ids.discard("")
            if active_ids:
                current_nodes = read_json(NODES_FILE, [])
                active_nodes = [n for n in current_nodes if n.get("id") in active_ids]
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            for active_node in active_nodes:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # Test all non-active nodes in bounded batches so the refreshed pool is fully classified.
        with lock:
            current_nodes = read_json(NODES_FILE, [])
            active_ids = {str(get_channel(idx).get("node_id") or "") for idx in range(CHANNEL_COUNT)}
            active_ids.discard("")
            to_test = [n for n in current_nodes if str(n.get("id") or "") not in active_ids]
            to_test_ids = [n["id"] for n in to_test]
            
        print(f"[维护线程] 正在全量检测新获取列表的 {len(to_test_ids)} 个节点", flush=True)
        set_state(is_connecting=True, last_check_message=f"正在全量检测 {len(to_test_ids)} 个节点可用性...")
        tested_nodes = test_nodes_in_batches(to_test_ids)
        
        is_connecting = False
        
        with lock:
            merged = read_json(NODES_FILE, [])
            if not active_openvpn_running():
                available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                if available_candidates:
                    auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(tested_nodes)} nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        is_connecting = False
        raise e


def collector_loop() -> None:
    while True:
        success = False
        try:
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">安全登录</h2>
      <p class="login-subtitle">请输入管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value;
      const pwd = document.getElementById("password").value;
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>多通道管理</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      display: none;
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      align-items: center;
      gap: 8px;
      max-width: min(760px, 52vw);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    .toolbar {
      background: rgba(13, 22, 36, 0.74);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 8px 8px 0 0;
      border-bottom: 0;
      padding: 12px;
      margin-bottom: 0;
      display: grid;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      gap: 10px;
      align-items: center;
    }

    .toolbar select {
      width: 100%;
      height: 38px;
      background: rgba(15, 23, 42, 0.78);
      border: 1px solid rgba(126, 146, 178, 0.16);
      border-radius: 6px;
      padding: 0 10px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 13px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: max-content;
      min-width: 100%;
      border-collapse: collapse;
      text-align: left;
      table-layout: auto;
    }

    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--border-color);
      font-size: 13px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 6px;
      align-items: center;
      flex-wrap: nowrap;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 10px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .asn-cell {
      display: inline-block;
      max-width: 260px;
      line-height: 1.35;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      color: #cbd5e1;
      font-size: 12px;
      font-weight: 500;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;
      vertical-align: middle;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button {
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    body {
      background: #080d17;
      background-image: linear-gradient(180deg, rgba(8, 13, 23, 1) 0%, rgba(7, 17, 24, 1) 100%);
    }

    header {
      padding: 18px 30px 16px;
      background: rgba(8, 13, 23, 0.86);
    }

    h1 {
      font-size: 19px;
      background: none;
      -webkit-text-fill-color: unset;
      color: #a8b5ff;
      letter-spacing: 0;
    }

    main {
      max-width: 1560px;
      padding: 22px 24px 28px;
    }

    .dashboard-toolbar {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      align-items: center;
    }

    @media (min-width: 1600px) {
      header {
        padding-left: calc((100vw - 1560px) / 2 + 24px);
        padding-right: calc((100vw - 1560px) / 2 + 24px);
      }
    }

    .channels-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(360px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }

    .channel-card {
      position: relative;
      overflow: visible;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      background: rgba(13, 22, 37, 0.9);
      box-shadow: none;
      padding: 14px;
      min-height: 0;
    }

    .channel-card.active {
      background: var(--active-row-bg);
      border: 2px solid var(--success);
      box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.08);
      padding: 13px;
    }

    .channel-card.connecting {
      border-color: rgba(245, 158, 11, 0.48);
      background: rgba(37, 29, 15, 0.74);
    }

    .channel-card.offline {
      border-color: rgba(82, 103, 132, 0.28);
      background: rgba(13, 22, 37, 0.72);
    }

    .channel-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 8px;
    }

    .channel-head-actions {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      flex-shrink: 0;
    }

    .channel-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      font-weight: 800;
      color: var(--text-primary);
    }

    .port-pill,
    .node-pill,
    .mini-pill {
      display: inline-flex;
      align-items: center;
      height: 20px;
      padding: 0 7px;
      border-radius: 6px;
      background: rgba(83, 104, 139, 0.22);
      border: 1px solid rgba(128, 147, 178, 0.12);
      color: #aebbd0;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11px;
      font-weight: 700;
    }

    .channel-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      height: 22px;
      padding: 0 9px;
      border-radius: 999px;
      color: #34d399;
      background: rgba(16, 185, 129, 0.12);
      box-shadow: none;
      font-size: 12px;
      font-weight: 700;
    }

    .channel-status.offline {
      color: #94a3b8;
      background: rgba(148, 163, 184, 0.12);
      box-shadow: none;
    }

    .channel-status.connecting {
      color: #fbbf24;
      background: rgba(245, 158, 11, 0.13);
    }

    .channel-status::before {
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 10px currentColor;
    }

    .channel-metrics {
      display: grid;
      grid-template-columns: minmax(120px, 0.85fr) minmax(260px, 1.75fr) minmax(80px, 0.55fr) minmax(80px, 0.55fr);
      gap: 8px;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
      background: rgba(17, 24, 39, 0.4);
      margin-bottom: 10px;
    }

    .metric-label {
      display: block;
      color: var(--text-secondary);
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .metric-value {
      display: block;
      color: var(--text-primary);
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      font-weight: 800;
      min-height: 16px;
      word-break: break-all;
    }

    .metric-value.text {
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;
      font-weight: 700;
      line-height: 1.25;
      min-height: 32px;
      overflow-wrap: anywhere;
      word-break: break-word;
      overflow: hidden;
      white-space: normal;
    }

    .channel-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      align-items: center;
      min-height: 24px;
      margin-bottom: 8px;
    }

    .mini-pill.good {
      color: #34d399;
      background: rgba(16, 185, 129, 0.1);
      border-color: rgba(16, 185, 129, 0.18);
    }

    .mini-pill.bad {
      color: #fb7185;
      background: rgba(244, 63, 94, 0.1);
      border-color: rgba(244, 63, 94, 0.2);
    }

    .channel-actions {
      display: grid;
      grid-template-columns: 1fr;
      gap: 8px;
      align-items: center;
      margin-bottom: 8px;
    }

    .channel-info-pill {
      min-width: 0;
      height: 30px;
      border-radius: 6px;
      border: 1px solid rgba(126, 146, 178, 0.12);
      background: rgba(13, 25, 40, 0.7);
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 0 10px;
      font-size: 12px;
      font-weight: 800;
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
    }

    .channel-info-pill.asn {
      justify-content: center;
      color: #dbeafe;
    }

    .channel-disconnect-btn {
      height: 24px;
      padding: 0 9px;
      border-radius: 999px;
      border: 1px solid rgba(244, 63, 94, 0.26);
      background: rgba(244, 63, 94, 0.12);
      color: #fb7185;
      font-size: 12px;
      font-weight: 800;
      cursor: pointer;
    }

    .channel-disconnect-btn:disabled {
      opacity: 0.38;
      cursor: not-allowed;
    }

    .channel-options {
      display: grid;
      grid-template-columns: minmax(110px, 1fr) minmax(110px, 1fr);
      gap: 8px;
      align-items: center;
      margin-top: 8px;
    }

    .lock-menu {
      position: relative;
      min-width: 0;
    }

    .lock-mode-btn {
      width: 100%;
      height: 34px;
      border-radius: 6px;
      border: 1px solid rgba(126, 146, 178, 0.18);
      background: linear-gradient(180deg, rgba(22, 35, 56, 0.95), rgba(10, 22, 36, 0.92));
      color: #e5edf7;
      font-size: 12px;
      font-weight: 700;
      padding: 0 30px 0 10px;
      text-align: left;
      cursor: pointer;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
      transition: border-color 0.18s ease, background 0.18s ease, transform 0.18s ease;
    }

    .lock-mode-btn:hover {
      border-color: rgba(16, 185, 129, 0.36);
      background: linear-gradient(180deg, rgba(25, 43, 66, 0.98), rgba(12, 28, 43, 0.96));
      transform: translateY(-1px);
    }

    .lock-mode-btn::after {
      content: "";
      position: absolute;
      right: 11px;
      top: 50%;
      width: 7px;
      height: 7px;
      border-right: 2px solid rgba(203, 213, 225, 0.75);
      border-bottom: 2px solid rgba(203, 213, 225, 0.75);
      transform: translateY(-65%) rotate(45deg);
      pointer-events: none;
    }

    .lock-select {
      display: none;
      position: absolute;
      left: 0;
      right: 0;
      top: 34px;
      z-index: 20;
      height: 30px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      background: rgba(15, 23, 42, 0.72);
      color: var(--text-primary);
      font-size: 12px;
      padding: 0 8px;
      min-width: 0;
    }

    .lock-select.open {
      display: block;
    }

    .lock-list-menu,
    .asn-check-menu {
      display: none;
      position: absolute;
      left: 0;
      right: 0;
      top: 34px;
      z-index: 25;
      max-height: 180px;
      overflow-y: auto;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      background: rgba(13, 24, 40, 0.98);
      padding: 6px;
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.28);
      scrollbar-width: none;
    }

    .lock-list-menu::-webkit-scrollbar,
    .asn-check-menu::-webkit-scrollbar {
      width: 0;
      height: 0;
      display: none;
    }

    .lock-list-menu.open,
    .asn-check-menu.open {
      display: block;
    }

    .country-lock-option,
    .asn-check-option {
      display: flex;
      align-items: center;
      gap: 7px;
      min-height: 28px;
      padding: 4px 6px;
      border-radius: 5px;
      color: #dbeafe;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }

    .country-lock-option {
      width: 100%;
      border: 0;
      background: transparent;
      text-align: left;
      font-family: inherit;
    }

    .country-lock-option.active {
      background: rgba(16, 185, 129, 0.12);
      color: #6ee7b7;
    }

    .country-lock-option:hover,
    .asn-check-option:hover {
      background: rgba(56, 189, 248, 0.08);
      color: #e0f2fe;
    }

    .asn-check-option input {
      width: 14px;
      height: 14px;
      accent-color: #10b981;
    }

    .node-channel-select {
      display: inline-block;
      position: static;
      height: 30px;
      width: 74px;
      min-width: 74px;
      border-radius: 6px;
      border: 1px solid rgba(56, 189, 248, 0.38);
      background: rgba(8, 24, 38, 0.72);
      color: #7dd3fc;
      font-size: 12px;
      font-weight: 600;
      padding: 0 6px;
      text-align: center;
      text-align-last: center;
      appearance: none;
      -webkit-appearance: none;
      background-image: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .node-channel-select:hover,
    .node-channel-select:focus {
      border-color: rgba(56, 189, 248, 0.72);
      background: rgba(14, 34, 52, 0.9);
      color: #bae6fd;
      outline: none;
      box-shadow: 0 4px 10px rgba(56, 189, 248, 0.14);
    }

    .channel-actions button,
    .nodes-actions button {
      height: 30px;
      min-width: 0;
      padding: 0 10px;
      border-radius: 6px;
      font-size: 12px;
      white-space: nowrap;
    }

    .btn-green {
      background: linear-gradient(135deg, #10b981 0%, #059669 100%);
      border: 0;
      color: #fff;
    }

    .btn-rose {
      height: 36px;
      border-radius: 8px;
      background: rgba(244, 63, 94, 0.12);
      border: 1px solid rgba(244, 63, 94, 0.34);
      color: #fb7185;
      font-weight: 700;
      box-shadow: none;
    }

    .btn-rose:hover {
      background: rgba(244, 63, 94, 0.2);
      border-color: rgba(244, 63, 94, 0.52);
      color: #fecdd3;
    }

    .btn-dark {
      height: 36px;
      border-radius: 8px;
      background: rgba(8, 24, 38, 0.72);
      border: 1px solid rgba(56, 189, 248, 0.32);
      color: #bae6fd;
      font-weight: 700;
      box-shadow: none;
    }

    .btn-dark:hover {
      background: rgba(14, 34, 52, 0.9);
      border-color: rgba(56, 189, 248, 0.58);
      color: #e0f2fe;
    }

    .nodes-panel-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin: 6px 0 12px;
    }

    .active-node-section,
    .stats,
    .proxy-test-section {
      display: none !important;
    }

    .nodes-panel-title h2 {
      margin: 0;
      font-size: 16px;
      color: #f8fafc;
    }

    .nodes-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }

    .toolbar {
      margin-bottom: 12px;
      padding: 12px;
      border-radius: 8px;
      background: rgba(19, 29, 46, 0.82);
      display: grid;
      grid-template-columns: repeat(5, minmax(118px, 1fr));
      gap: 9px;
    }

    .toolbar select {
      width: 100%;
      min-width: 0;
      height: 36px;
      border-radius: 6px;
      font-size: 13px;
      box-sizing: border-box;
    }

    .table-wrapper {
      border-radius: 8px;
      background: rgba(13, 22, 37, 0.9);
    }

    th,
    td {
      padding: 10px 12px;
      font-size: 13px;
    }

    th {
      text-transform: none;
      letter-spacing: 0;
      background: rgba(12, 18, 32, 0.95);
    }

    .row-check {
      width: 16px;
      height: 16px;
      accent-color: #10b981;
    }

    .country-cell {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      white-space: nowrap;
    }

    td:nth-child(7),
    th:nth-child(7) {
      min-width: 112px;
      white-space: nowrap;
      word-break: keep-all;
    }

    td:nth-child(6),
    th:nth-child(6) {
      min-width: 240px;
    }

    @media (max-width: 1100px) {
      .channels-grid {
        grid-template-columns: 1fr;
      }
      .toolbar {
        grid-template-columns: 1fr 1fr;
      }
      .channel-actions {
        grid-template-columns: repeat(3, minmax(0, 1fr));
      }
    }

    @media (max-width: 680px) {
      body {
        min-width: 0;
      }

      header {
        position: static;
        padding: 14px 14px 12px;
        align-items: stretch;
      }

      .brand {
        width: 100%;
      }

      h1 {
        font-size: 17px;
      }

      .status {
        align-items: flex-start;
        line-height: 1.45;
        word-break: break-word;
      }

      .dashboard-toolbar {
        width: 100%;
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
      }

      .dashboard-toolbar > * {
        width: 100%;
      }

      .dashboard-toolbar button {
        height: 36px;
        justify-content: center;
        padding: 0 10px;
      }

      .dashboard-toolbar .dropdown button {
        width: 100%;
      }

      main {
        padding: 12px;
      }

      .channels-grid {
        grid-template-columns: minmax(0, 1fr);
        gap: 10px;
      }

      .toolbar {
        grid-template-columns: 1fr;
        gap: 8px;
        padding: 10px;
      }

      .channel-card {
        padding: 11px;
        min-height: 0;
      }

      .channel-top {
        margin-bottom: 10px;
      }

      .channel-title {
        min-width: 0;
        flex-wrap: wrap;
      }

      .channel-metrics {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 9px;
        padding: 10px;
      }

      .metric-value {
        font-size: 12px;
      }

      .channel-actions {
        grid-template-columns: 1fr;
        gap: 6px;
      }

      .channel-options {
        grid-template-columns: 1fr;
      }

      .channel-actions button,
      .nodes-actions button {
        width: 100%;
        padding: 0 6px;
      }

      .channel-head-actions {
        gap: 6px;
      }

      .nodes-panel-title {
        align-items: stretch;
        flex-direction: column;
      }

      .nodes-actions {
        display: grid;
        grid-template-columns: 1fr 1fr;
      }

      .table-wrapper {
        margin-left: -2px;
        margin-right: -2px;
      }

      .pagination-container {
        align-items: stretch !important;
      }

      .pagination-container > div:last-child {
        width: 100%;
        display: grid !important;
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .pagination-container span {
        grid-column: 1 / -1;
        text-align: center;
      }

      th,
      td {
        font-size: 12px;
        padding: 9px 10px;
      }

      .mono,
      .asn-cell {
        font-size: 11px;
      }
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      多通道管理
    </h1>
    <div id="status" class="status"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="dashboard-toolbar">
    <button id="refresh" class="btn-dark">
      刷新节点
    </button>
    <button id="logout_btn" class="btn-rose" onclick="logoutAdmin()">退出登录</button>
  </div>
</header>
<main>
  <section class="channels-grid" id="channels_grid"></section>

  <section class="nodes-panel-title">
    <h2>节点池</h2>
  </section>

  <!-- 当前连接活动节点卡片 -->
  <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
    <!-- Rendered dynamically by render() -->
  </section>

  <section class="stats">
    <div class="stat">
      <div class="stat-info">
        <strong id="legacy_total">0</strong>
        <span>可用节点池</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="legacy_target">3</strong>
        <span>目标储备数</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="legacy_active">0</strong>
        <span>已激活连接</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
      </div>
    </div>
  </section>

  <section class="proxy-test-section" style="margin-bottom: 24px;">
    <div class="stat" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary);"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
        </div>
        <div>
          <h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">本地代理出口检测 (Port 7928)</h3>
          <p style="margin: 0; font-size: 13px; color: var(--text-secondary);">
            测试本地 HTTP/SOCKS5 代理是否成功通过当前 VPN 节点出站，并获取实际出口公网 IP 和延迟。
          </p>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-left: auto;">
        <div id="proxy_test_result" style="text-align: right;">
          <div style="font-size: 14px; font-weight: 500; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 8px;"></span>
          </div>
        </div>
        <button id="btn_test_proxy" class="btn-primary" style="height: 40px; padding: 0 16px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          测试代理
        </button>
      </div>
    </div>
  </section>

  <section class="toolbar">
    <select id="status_filter">
      <option value="">全部状态</option>
      <option value="available">可用</option>
      <option value="not_checked">待检测</option>
      <option value="unavailable">不可用</option>
    </select>
    <select id="country_filter">
      <option value="">全部国家</option>
    </select>
    <select id="type_filter">
      <option value="">全部类型</option>
      <option value="residential">住宅 IP</option>
      <option value="hosting">机房 IP</option>
      <option value="mobile">移动网</option>
      <option value="proxy">代理 IP</option>
    </select>
    <select id="asn_filter">
      <option value="">全部 ASN</option>
    </select>
    <select id="page_size">
      <option value="25">每页 25</option>
      <option value="50">每页 50</option>
      <option value="100" selected>每页 100</option>
    </select>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 82px;">状态</th>
            <th style="width: 110px;">国家</th>
            <th style="width: 150px;">IP</th>
            <th style="width: 82px;">类型</th>
            <th style="width: 70px;">延迟</th>
            <th style="width: 260px;">ASN</th>
            <th style="width: 150px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set(), testingChannelIds = new Set();
let selectedManualChannels = {};
let currentPage = 1;
let pageSize = 100;
let currentPageNodes = [];
let openLockMenuId = null;

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

function countryFlag(code) {
  const cc = String(code || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  return cc.replace(/./g, char => String.fromCodePoint(127397 + char.charCodeAt(0)));
}

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function asnDisplay(asn, asName) {
  const cleanAsn = String(asn || "").trim();
  const cleanName = String(asName || "").trim().replace(/^AS\d+\s*/i, "");
  const full = [cleanAsn, cleanName].filter(Boolean).join(" ");
  if (!full) return {short: "-", full: "-"};
  return {short: full, full};
}

function nodeAsnLabel(node) {
  if (!node) return "-";
  return asnDisplay(node.asn, node.as_name || node.owner).full;
}

function asnOptionLabel(asn, scopedNodes) {
  const node = scopedNodes.find(n => String(n.asn || "").trim() === asn && (n.as_name || n.owner));
  return asnDisplay(asn, node ? (node.as_name || node.owner) : "").full;
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n.country).filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">全部国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function updateAsnFilter() {
  const select = $("asn_filter");
  if (!select) return;
  const selectedValue = select.value;
  const selectedCountry = $("country_filter") ? $("country_filter").value : "";
  const scopedNodes = selectedCountry ? nodes.filter(n => n.country === selectedCountry) : nodes;
  const asns = Array.from(new Set(scopedNodes.map(n => String(n.asn || "").trim()).filter(Boolean))).sort();

  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(asns) === JSON.stringify(currentOptions)) {
    return;
  }

  select.innerHTML = '<option value="">全部 ASN</option>' +
    asns.map(asn => `<option value="${esc(asn)}">${esc(asnOptionLabel(asn, scopedNodes))}</option>`).join("");

  if (asns.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedAsn = $("asn_filter") ? $("asn_filter").value : "";
  const selectedStatus = $("status_filter") ? $("status_filter").value : "";
  const selectedType = $("type_filter") ? $("type_filter").value : "";
  return nodes.filter(n => {
    if (selectedCountry && n.country !== selectedCountry) {
      return false;
    }
    if (selectedAsn && String(n.asn || "") !== selectedAsn) {
      return false;
    }
    if (selectedStatus && (n.probe_status || "not_checked") !== selectedStatus) {
      return false;
    }
    if (selectedType && String(n.ip_type || "") !== selectedType) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if ((b.score || 0) !== (a.score || 0)) {
      return (b.score || 0) - (a.score || 0);
    }
    return a.id.localeCompare(b.id);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n.active || n.id === activeNodeId);
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  $("total").textContent=nodes.length; 
  $("target").textContent=state.target_valid_nodes||3;
  $("active").textContent=activeNode?1:0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：http://127.0.0.1:7928 | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`;
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        if (state.last_check_message) {
          pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
        } else {
          pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
        }
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>${latencyText}</td>
        <td class="mono">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td>${esc(displayLocation)}</td>
        <td class="mono" style="font-size:12px; color:var(--text-secondary);">${esc(n.asn||"-")}</td>
        <td>${esc(n.owner||n.as_name||"-")}</td>
        <td>${esc(translateQuality(n.quality))}</td>
        <td>${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

function channelStatusMeta(ch) {
  if (ch && ch.is_connecting) return {text: "连接中", cls: "connecting"};
  if (ch && (ch.running || ch.node_id)) return {text: "已连接", cls: ""};
  return {text: "未连接", cls: "offline"};
}

function activeIndexesForNode(node) {
  if (!node) return [];
  if (Array.isArray(node.active_channels)) return node.active_channels;
  if (node.active_channel !== undefined && node.active_channel !== null) return [node.active_channel];
  if (node.active) return [0];
  return [];
}

function countryLockOptions(channel, currentValue) {
  const countries = Array.from(new Set(nodes.map(n => n.country).filter(Boolean))).sort();
  const normalized = currentValue || "";
  const allClass = normalized ? "" : " active";
  const options = [`<button type="button" class="country-lock-option${allClass}" onclick="setChannelCountry(${channel}, '')">全部国家</button>`];
  countries.forEach(country => {
    const active = country === normalized ? " active" : "";
    const sample = nodes.find(n => n.country === country && n.country_short);
    const flag = countryFlag(sample && sample.country_short);
    options.push(`<button type="button" class="country-lock-option${active}" onclick="setChannelCountry(${channel}, decodeURIComponent('${encodeURIComponent(country)}'))">${flag ? `<span>${flag}</span>` : ""}<span>${esc(translateCountry(country))}</span></button>`);
  });
  return options.join("");
}

function normalizeAsnLocks(value) {
  if (Array.isArray(value)) return value.map(v => String(v || "").trim()).filter(Boolean);
  return String(value || "").split(/[,\s]+/).map(v => v.trim()).filter(Boolean);
}

function asnCheckboxOptions(channel, currentValue) {
  const selected = new Set(normalizeAsnLocks(currentValue));
  const channelData = state.channels && state.channels.find(ch => (ch.index || 0) === channel);
  const country = channelData && channelData.country_lock ? channelData.country_lock : "";
  const scopedNodes = country ? nodes.filter(n => n.country === country || n.country_short === country) : nodes;
  const currentAsns = new Set(scopedNodes.map(n => String(n.asn || "").trim()).filter(Boolean));
  const asns = Array.from(new Set([...selected, ...currentAsns])).sort();
  if (!asns.length) return '<div class="asn-check-option" style="color: var(--text-secondary); cursor: default;">暂无 ASN</div>';
  return asns.map(asn => {
    const checked = selected.has(asn) ? "checked" : "";
    const present = currentAsns.has(asn);
    const label = present ? asnOptionLabel(asn, scopedNodes) : `${asn} 暂无节点`;
    return `<label class="asn-check-option${present ? "" : " stale"}"><input type="checkbox" value="${esc(asn)}" ${checked} onchange="setChannelAsn(${channel})"><span>${esc(label)}</span></label>`;
  }).join("");
}

function countryLockLabel(ch) {
  if (!ch || !ch.country_lock) return "全部国家锁定";
  const sample = nodes.find(n => (n.country === ch.country_lock || n.country_short === ch.country_lock) && n.country_short);
  const flag = countryFlag(sample && sample.country_short);
  return `国家锁定：${flag ? flag : ""}${translateCountry(ch.country_lock)}`;
}

function asnLockLabel(ch) {
  const asns = normalizeAsnLocks(ch && ch.asn_lock);
  if (!asns.length) return "全部 ASN 锁定";
  return asns.length === 1 ? `ASN锁定：${asns[0]}` : `ASN锁定：已选 ${asns.length}`;
}

function renderChannelCards() {
  const grid = $("channels_grid");
  if (!grid) return;
  const activeLockMenuId = openLockMenuId;
  const activeLockMenu = activeLockMenuId ? $(activeLockMenuId) : null;
  const activeLockMenuScrollTop = activeLockMenu ? activeLockMenu.scrollTop : 0;
  const count = state.channel_count || 6;
  const channels = state.channels && state.channels.length
    ? state.channels
    : Array.from({length: count}, (_, index) => ({index, port: (state.proxy_base_port || 7928) + index, device: `tun${index}`, auto_switch: true}));

  grid.innerHTML = channels.map(ch => {
    const idx = ch.index || 0;
    const node = (ch.node && ch.node.id) ? ch.node : nodes.find(n => n.id === ch.node_id);
    const meta = channelStatusMeta(ch);
    const cardClass = ch.is_connecting ? "connecting" : (node ? "active" : "offline");
    const ip = node ? (node.ip || node.remote_host || "-") : "-";
    const asnLabel = nodeAsnLabel(node);
    const nodeLatency = ch.latency_ms || (node && node.latency_ms) || 0;
    const nodeLatencyClass = getLatencyClass(nodeLatency);
    const proxyLatency = ch.proxy_latency_ms || 0;
    return `
      <article class="channel-card ${cardClass}">
        <div class="channel-top">
          <div class="channel-title">
            <span>通道 ${idx}</span>
            <span class="port-pill">:${ch.port || ((state.proxy_base_port || 7928) + idx)}</span>
          </div>
          <div class="channel-head-actions">
            <span class="channel-status ${meta.cls}">${meta.text}</span>
            <button class="channel-disconnect-btn" onclick="disconnectChannel(${idx})" ${(!node && !ch.node_id) ? "disabled" : ""}>断开</button>
          </div>
        </div>
        <div class="channel-metrics">
          <div>
            <span class="metric-label">出口IP</span>
            <span class="metric-value">${esc(ip)}</span>
          </div>
          <div>
            <span class="metric-label">ASN</span>
            <span class="metric-value text" title="${esc(asnLabel)}">${esc(asnLabel)}</span>
          </div>
          <div>
            <span class="metric-label">节点延迟</span>
            <span class="metric-value">${nodeLatency ? `<span class="latency-val ${nodeLatencyClass}">${nodeLatency} ms</span>` : "-"}</span>
          </div>
          <div>
            <span class="metric-label">代理延迟</span>
            <span class="metric-value">${proxyLatency ? `${proxyLatency} ms` : "-"}</span>
          </div>
        </div>
        <div class="channel-options">
          <div class="lock-menu">
            <button type="button" class="lock-mode-btn country-lock-btn" onclick="toggleLockMenu('country', ${idx})">${esc(countryLockLabel(ch))}</button>
            <div id="country_select_${idx}" class="lock-list-menu">
              ${countryLockOptions(idx, ch.country_lock || "")}
            </div>
          </div>
          <div class="lock-menu">
            <button type="button" class="lock-mode-btn asn-lock-btn" onclick="toggleLockMenu('asn', ${idx})">${esc(asnLockLabel(ch))}</button>
            <div id="asn_select_${idx}" class="asn-check-menu">
              ${asnCheckboxOptions(idx, ch.asn_lock)}
            </div>
          </div>
        </div>
      </article>
    `;
  }).join("");
  if (activeLockMenuId) {
    const restored = $(activeLockMenuId);
    if (restored) {
      restored.classList.add("open");
      restored.scrollTop = activeLockMenuScrollTop;
    }
  }
}

function render(){
  renderChannelCards();
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  $("status").innerHTML = `<span class="status-dot"></span>代理端口 ${state.proxy_base_port || 7928}-${(state.proxy_base_port || 7928) + (state.channel_count || 6) - 1} | 通道 ${state.channel_count || 6} 个 | ${esc(state.last_check_message || "服务运行中")}`;

  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML = currentPageNodes.map(n => {
      const activeIndexes = activeIndexesForNode(n);
      const isActive = activeIndexes.length > 0;
      const rowClass = isActive ? 'class="active-row"' : '';
      const badgeClass = isActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isActive ? `<span class="badge-pulse"></span>通道 ${activeIndexes.join(",")}` : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const asnLabel = nodeAsnLabel(n);
      const isTesting = testingNodeIds.has(n.id);
      const connectLabel = isActive ? "已连接" : "连接";
      const connectDisabled = state.is_connecting || n.probe_status === "unavailable" ? "disabled" : "";
      const testBtnText = isTesting ? "检测中" : "测试";
      const channelSelect = buildChannelChooser(n.id);
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td><span class="country-cell">${esc(translateCountry(n.country))}</span></td>
        <td class="mono">${esc(n.ip||n.remote_host)}</td>
        <td>${esc(translateIpType(n.ip_type))}</td>
        <td>${latencyText}</td>
        <td><span class="asn-cell" title="${esc(asnLabel)}">${esc(asnLabel)}</span></td>
        <td>
          <div class="table-actions">
            <button class="test-btn" ${isTesting ? "disabled" : ""} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>
            ${channelSelect}
            ${isActive ? `<button class="connect-btn" disabled>${connectLabel}</button>` : `<button class="connect-btn" ${connectDisabled} onclick="connectNodeSmart('${esc(n.id)}')">${connectLabel}</button>`}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;

  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;

}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

let pollInterval = null;
let manualRefreshActive = false;

function setRefreshButtonBusy(text) {
  const btn = $("refresh");
  if (!btn) return;
  manualRefreshActive = true;
  btn.disabled = true;
  btn.textContent = text || "正在全量检测...";
}

function resetRefreshButton() {
  const btn = $("refresh");
  if (!btn) return;
  manualRefreshActive = false;
  btn.disabled = false;
  btn.textContent = "刷新节点";
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = data.nodes || [];
      state = data.state || {};
      stableSortNodes();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        if (manualRefreshActive) resetRefreshButton();
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      if (manualRefreshActive) resetRefreshButton();
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}

function firstAvailableChannel() {
  const channels = state.channels || [];
  const idle = channels.find(ch => !ch.node_id && !ch.running && !ch.is_connecting);
  if (idle) return idle.index || 0;
  return 0;
}

function buildChannelChooser(nodeId) {
  const channels = state.channels || [];
  const count = state.channel_count || 6;
  const list = channels.length ? channels : Array.from({length: count}, (_, index) => ({index}));
  const current = Number.isInteger(selectedManualChannels[nodeId]) ? selectedManualChannels[nodeId] : null;
  const options = list.map(ch => {
    const idx = ch.index || 0;
    const selected = idx === current ? "selected" : "";
    return `<option value="${idx}" ${selected}>通道 ${idx}</option>`;
  }).join("");
  return `<select class="node-channel-select" onchange="selectedManualChannels['${esc(nodeId)}']=this.value === '' ? null : parseInt(this.value, 10);">
    <option value="" ${current === null ? "selected" : ""}>选择通道</option>
    ${options}
  </select>`;
}

function toggleLockMenu(kind, channel) {
  const targetId = `${kind}_select_${channel}`;
  document.querySelectorAll(".lock-select.open, .lock-list-menu.open, .asn-check-menu.open").forEach(select => {
    if (select.id !== targetId) select.classList.remove("open");
  });
  const select = $(targetId);
  if (!select) return;
  select.classList.toggle("open");
  openLockMenuId = select.classList.contains("open") ? targetId : null;
}

async function connectNodeSmart(id) {
  const channels = state.channels || [];
  const selectedManualChannel = selectedManualChannels[id];
  const selected = channels.find(ch => (ch.index || 0) === selectedManualChannel);
  if (!selected) {
    alert("请先选择要连接的通道");
    return;
  }
  const channel = selectedManualChannel;
  await connectNodeToChannel(channel, id);
}

async function connectNodeToChannel(channel, id) {
  state.is_connecting = true;
  render();
  startConnectionPolling();
  try {
    const r = await fetch("./api/channel/connect", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel, id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("连接请求错误");
  } finally {
    await load();
  }
}

async function autoConnectChannel(channel) {
  state.is_connecting = true;
  render();
  startConnectionPolling();
  try {
    const r = await fetch("./api/channel/auto_connect", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("自动切换失败: " + (result.error || "没有可用节点"));
    }
  } catch (e) {
    alert("自动切换请求错误");
  } finally {
    await load();
  }
}

async function disconnectChannel(channel) {
  if (!confirm(`确定要断开通道 ${channel} 吗？`)) return;
  try {
    await fetch("./api/channel/disconnect", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel})
    });
  } catch (e) {
    alert("断开通道失败");
  } finally {
    await load();
  }
}

async function testChannelProxy(channel) {
  testingChannelIds.add(channel);
  render();
  try {
    const response = await fetch("./api/channel/test_proxy", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel})
    });
    const result = await response.json();
    if (!result.ok) {
      console.warn(result.error || "通道出口测试失败");
    }
  } catch (e) {
  } finally {
    testingChannelIds.delete(channel);
    await load();
  }
}

async function setChannelCountry(channel, country) {
  try {
    await fetch("./api/channel/country_lock", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel, country: String(country || "").trim()})
    });
    const select = $(`country_select_${channel}`);
    if (select) select.classList.remove("open");
    if (openLockMenuId === `country_select_${channel}`) openLockMenuId = null;
  } catch (e) {
    alert("国家锁定保存失败");
  } finally {
    await load();
  }
}

async function setChannelAsn(channel) {
  const menu = $(`asn_select_${channel}`);
  const asns = menu
    ? Array.from(menu.querySelectorAll('input[type="checkbox"]:checked')).map(input => input.value)
    : [];
  const currentChannel = state.channels && state.channels.find(ch => (ch.index || 0) === channel);
  if (currentChannel) currentChannel.asn_lock = asns;
  render();
  try {
    const response = await fetch("./api/channel/asn_lock", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({channel, asns})
    });
    if (!response.ok) throw new Error("save failed");
  } catch (e) {
    alert("ASN锁定保存失败");
    await load();
  }
}

async function load(){
  const r=await fetch("./api/nodes"); 
  const d=await r.json(); 
  nodes=d.nodes||[]; 
  state=d.state||{}; 
  
  stableSortNodes();
  updateCountryFilter();
  updateAsnFilter();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}

$("country_filter").onchange=()=>{ currentPage = 1; updateAsnFilter(); render(); };
if ($("status_filter")) $("status_filter").onchange=()=>{ currentPage = 1; render(); };
if ($("asn_filter")) $("asn_filter").onchange=()=>{ currentPage = 1; render(); };
if ($("type_filter")) $("type_filter").onchange=()=>{ currentPage = 1; render(); };
if ($("page_size")) $("page_size").onchange=()=>{ pageSize = parseInt($("page_size").value, 10) || 100; currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  setRefreshButtonBusy("正在全量检测...");
  state.is_connecting = true;
  state.last_check_message = "正在手动刷新节点并全量检测可用性...";
  render();
  try{
    const response = await fetch("./api/refresh_nodes",{method:"POST"});
    if (!response.ok) throw new Error("refresh failed");
    startConnectionPolling();
  } 
  catch(e){
    resetRefreshButton();
    await load();
  }
};
if ($("btn_test_proxy")) $("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && !openLockMenuId && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      updateAsnFilter();
      render();
    } catch(e) {}
  }
}, 10000);
</script>
</body></html>"""

def check_proxy_health(port: int | None = None, interface: str = "tun0") -> dict[str, Any]:
    port = port or LOCAL_PROXY_PORT
    # 1. 检测代理服务端口是否在监听
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
    except Exception as e:
        return {
            "ok": False,
            "error": f"代理服务未运行 (端口 {port} 连接失败，原因: {e})"
        }

    # 2. 检测虚拟网卡是否存在 (Linux 下)
    tun_path = Path(f"/sys/class/net/{interface}")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": f"VPN 虚拟网卡 ({interface}) 未启用，请确保当前通道已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    cmd = [
        "curl", "-4", "-s",
        "-w", "\n%{time_total} %{http_code}",
        "-x", f"socks5h://127.0.0.1:{port}",
        "http://ip.sb",
        "--max-time", "5"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
        
        # 如果 ip.sb 失败，使用备用地址 http://api.ipify.org
        cmd[7] = "http://api.ipify.org"
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
                        
        return {"ok": False, "error": f"出口连接测试失败 (curl 返回码: {res.returncode}, stderr: {res.stderr.strip()})"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    time.sleep(2)
    while True:
        try:
            if is_connecting:
                time.sleep(5)
                continue

            for idx in range(CHANNEL_COUNT):
                channel = get_channel(idx)
                node_id = str(channel.get("node_id") or "")
                if not node_id:
                    channel["proxy_ok"] = None
                    channel["proxy_ip"] = "-"
                    channel["proxy_latency_ms"] = 0
                    channel["proxy_error"] = ""
                    if idx == 0:
                        set_state(proxy_ok=None, proxy_ip="-", proxy_latency_ms=0, proxy_error="")
                    continue

                res = check_proxy_health(port=channel_port(idx), interface=channel_device(idx))
                if res["ok"]:
                    channel["proxy_ok"] = True
                    channel["proxy_ip"] = res["ip"]
                    channel["proxy_latency_ms"] = res["latency_ms"]
                    channel["proxy_error"] = ""
                    if idx == 0:
                        set_state(proxy_ok=True, proxy_ip=res["ip"], proxy_latency_ms=res["latency_ms"], proxy_error="")
                    log_to_json("INFO", "Proxy", f"通道 {idx} 代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
                else:
                    error_msg = res.get("error", "未知错误")
                    channel["proxy_ok"] = False
                    channel["proxy_ip"] = "-"
                    channel["proxy_latency_ms"] = 0
                    channel["proxy_error"] = error_msg
                    print(f"[警告] 通道 {idx} 端口 {channel_port(idx)} 本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"通道 {idx} 代理不可用: {error_msg}")
                    if idx == 0:
                        set_state(proxy_ok=False, proxy_ip="-", proxy_latency_ms=0, proxy_error=error_msg)

                    with lock:
                        nodes = read_json(NODES_FILE, [])
                        active_node = next((n for n in nodes if n.get("id") == node_id), None)
                        if active_node:
                            mark_blacklisted(active_node, f"通道 {idx} 代理连通性检测失败: {error_msg}")
                            active_node["probe_status"] = "unavailable"
                            write_json(NODES_FILE, nodes)
                    try:
                        auto_connect_channel(idx)
                    except Exception as switch_error:
                        log_to_json("WARNING", "Proxy", f"通道 {idx} 自动切换失败: {switch_error}")
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global active_openvpn_node_id, is_connecting
    while True:
        try:
            nodes = read_json(NODES_FILE, [])
            for idx in range(CHANNEL_COUNT):
                channel = get_channel(idx)
                node_id = str(channel.get("node_id") or "")
                if not channel_running(idx) or not node_id:
                    if channel.get("is_connecting"):
                        channel["last_message"] = "测试中..."
                    elif not channel.get("is_connecting"):
                        channel["last_latency"] = 0
                    continue
                node = next((n for n in nodes if n.get("id") == node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            channel["last_latency"] = latency
                            channel["last_ping_time"] = time.time()
                            if idx == 0:
                                set_state(active_node_latency=f"{latency} ms")
                        else:
                            channel["last_latency"] = 0
                            if idx == 0:
                                set_state(active_node_latency="检测超时")
                    else:
                        channel["last_latency"] = 0
                        if idx == 0:
                            set_state(active_node_latency="检测超时")
                else:
                    channel["last_latency"] = 0
                    if idx == 0:
                        set_state(active_node_latency="检测超时")
            sync_legacy_channel0()
            if not active_openvpn_running() and is_connecting:
                set_state(active_node_latency="测试中...")
            elif not active_openvpn_running():
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        auth_file = DATA_DIR / "ui_auth.json"
        if not auth_file.exists():
            try:
                DATA_DIR.mkdir(exist_ok=True)
                auth_file.write_text(json.dumps({"secret_path": "EJsW2EeBo9lY"}), encoding="utf-8")
            except Exception:
                pass
            return "EJsW2EeBo9lY"
        try:
            creds = json.loads(auth_file.read_text(encoding="utf-8"))
            if "secret_path" in creds:
                return creds["secret_path"]
            elif "password" in creds:
                secret_path = creds["password"]
                try:
                    auth_file.write_text(json.dumps({"secret_path": secret_path}), encoding="utf-8")
                except Exception:
                    pass
                return secret_path
            return "EJsW2EeBo9lY"
        except Exception:
            return "EJsW2EeBo9lY"

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            return True
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        if not secret_path:
            return self.path
        if self.path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if self.path.startswith(prefix):
            return "/" + self.path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            sync_legacy_channel0()
            nodes = read_json(NODES_FILE, [])
            active_map = active_channel_map()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                active_indexes = active_map.get(str(n.get("id")), [])
                n["active_channels"] = active_indexes
                n["active_channel"] = active_indexes[0] if active_indexes else None
                n["active"] = 0 in active_indexes
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                
                curr_username = str(payload.get("curr_username") or "")
                curr_password = str(payload.get("curr_password") or "")
                
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                new_username = str(payload.get("new_username") or "").strip()
                new_password = str(payload.get("new_password") or "").strip()
                
                if not curr_username or not curr_password:
                    self.send_json({"ok": False, "error": "请输入当前账号和密码进行安全验证"}, HTTPStatus.FORBIDDEN)
                    return
                
                ui_cfg = load_ui_config()
                expected_uname = ui_cfg.get("username", "admin")
                expected_pwd = ui_cfg.get("password", "")
                
                if curr_username != expected_uname or curr_password != expected_pwd:
                    self.send_json({"ok": False, "error": "当前账号或密码不正确"}, HTTPStatus.FORBIDDEN)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                if new_username:
                    ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "配置更新成功，系统将在 2 秒内重启..."})
                
                def restart_server():
                    time.sleep(2)
                    print("[系统] 管理后台配置更新，进程即将退出以触发自动重启...", flush=True)
                    os._exit(0)
                
                threading.Thread(target=restart_server, daemon=True).start()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/channel/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel_index = parse_int(payload.get("channel"))
                node_id = str(payload.get("id") or "")
                self.send_json({"ok": True, "message": connect_channel_node(channel_index, node_id)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/channel/auto_connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel_index = parse_int(payload.get("channel"))
                self.send_json({"ok": True, "message": auto_connect_channel(channel_index)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/channel/disconnect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel_index = parse_int(payload.get("channel"))
                stop_channel_openvpn(channel_index)
                if channel_index == 0:
                    set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/channel/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel_index = parse_int(payload.get("channel"))
                result = check_proxy_health(port=channel_port(channel_index), interface=channel_device(channel_index))
                channel = get_channel(channel_index)
                channel["proxy_ok"] = bool(result.get("ok"))
                channel["proxy_ip"] = result.get("ip", "-") if result.get("ok") else "-"
                channel["proxy_latency_ms"] = parse_int(result.get("latency_ms"))
                channel["proxy_error"] = "" if result.get("ok") else result.get("error", "未知错误")
                if channel_index == 0:
                    set_state(
                        proxy_ok=channel["proxy_ok"],
                        proxy_ip=channel["proxy_ip"],
                        proxy_latency_ms=channel["proxy_latency_ms"],
                        proxy_error=channel["proxy_error"],
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/channel/country_lock":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel = get_channel(parse_int(payload.get("channel")))
                channel["country_lock"] = str(payload.get("country") or "")
                self.send_json({"ok": True, "country_lock": channel["country_lock"]})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/channel/asn_lock":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                channel = get_channel(parse_int(payload.get("channel")))
                channel["asn_lock"] = normalize_asn_locks(payload.get("asns", payload.get("asn")))
                self.send_json({"ok": True, "asn_lock": channel["asn_lock"]})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动节点刷新与全量可用性检测流程"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                stop_active_openvpn()
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                if length > 0:
                    self.rfile.read(length)
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

def main() -> None:
    ensure_dirs()
    init_channels()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{LOCAL_PROXY_HOST}:{PROXY_BASE_PORT}",
            "channel_count": CHANNEL_COUNT,
            "proxy_base_port": PROXY_BASE_PORT,
            "channels": serialize_channels([]),
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    for idx in range(CHANNEL_COUNT):
        threading.Thread(
            target=proxy_server.start_proxy_server,
            args=(LOCAL_PROXY_HOST, channel_port(idx), channel_device(idx)),
            daemon=True,
        ).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    for _ in range(30):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect((LOCAL_PROXY_HOST, channel_port(0)))
            gateway_ready = True
            break
        except Exception:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except Exception:
                pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = int(ui_cfg.get("port", UI_PORT))
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{PROXY_BASE_PORT}-{channel_port(CHANNEL_COUNT - 1)}", flush=True)
    ThreadingHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
