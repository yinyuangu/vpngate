#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import threading
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "vpngate_data"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"

ip_cache_lock = threading.RLock()

COUNTRY_CODE_TRANSLATIONS = {
    "AD": "安道尔", "AE": "阿联酋", "AF": "阿富汗", "AG": "安提瓜和巴布达", "AI": "安圭拉",
    "AL": "阿尔巴尼亚", "AM": "亚美尼亚", "AO": "安哥拉", "AR": "阿根廷", "AT": "奥地利",
    "AU": "澳大利亚", "AW": "阿鲁巴", "AZ": "阿塞拜疆", "BA": "波黑", "BB": "巴巴多斯",
    "BD": "孟加拉国", "BE": "比利时", "BF": "布基纳法索", "BG": "保加利亚", "BH": "巴林",
    "BI": "布隆迪", "BJ": "贝宁", "BM": "百慕大", "BN": "文莱", "BO": "玻利维亚",
    "BR": "巴西", "BS": "巴哈马", "BT": "不丹", "BW": "博茨瓦纳", "BY": "白俄罗斯",
    "BZ": "伯利兹", "CA": "加拿大", "CD": "刚果（金）", "CF": "中非", "CG": "刚果（布）",
    "CH": "瑞士", "CI": "科特迪瓦", "CL": "智利", "CM": "喀麦隆", "CN": "中国",
    "CO": "哥伦比亚", "CR": "哥斯达黎加", "CU": "古巴", "CV": "佛得角", "CY": "塞浦路斯",
    "CZ": "捷克", "DE": "德国", "DJ": "吉布提", "DK": "丹麦", "DM": "多米尼克",
    "DO": "多米尼加", "DZ": "阿尔及利亚", "EC": "厄瓜多尔", "EE": "爱沙尼亚", "EG": "埃及",
    "ES": "西班牙", "ET": "埃塞俄比亚", "EU": "欧盟", "FI": "芬兰", "FJ": "斐济",
    "FK": "福克兰群岛", "FM": "密克罗尼西亚", "FO": "法罗群岛", "FR": "法国", "GA": "加蓬",
    "GB": "英国", "GD": "格林纳达", "GE": "格鲁吉亚", "GF": "法属圭亚那", "GH": "加纳",
    "GI": "直布罗陀", "GL": "格陵兰", "GM": "冈比亚", "GN": "几内亚", "GP": "瓜德罗普",
    "GQ": "赤道几内亚", "GR": "希腊", "GT": "危地马拉", "GU": "关岛", "GW": "几内亚比绍",
    "GY": "圭亚那", "HK": "香港", "HN": "洪都拉斯", "HR": "克罗地亚", "HT": "海地",
    "HU": "匈牙利", "ID": "印度尼西亚", "IE": "爱尔兰", "IL": "以色列", "IN": "印度",
    "IQ": "伊拉克", "IR": "伊朗", "IS": "冰岛", "IT": "意大利", "JM": "牙买加",
    "JO": "约旦", "JP": "日本", "KE": "肯尼亚", "KG": "吉尔吉斯斯坦", "KH": "柬埔寨",
    "KI": "基里巴斯", "KM": "科摩罗", "KN": "圣基茨和尼维斯", "KP": "朝鲜", "KR": "韩国",
    "KW": "科威特", "KY": "开曼群岛", "KZ": "哈萨克斯坦", "LA": "老挝", "LB": "黎巴嫩",
    "LC": "圣卢西亚", "LI": "列支敦士登", "LK": "斯里兰卡", "LR": "利比里亚", "LS": "莱索托",
    "LT": "立陶宛", "LU": "卢森堡", "LV": "拉脱维亚", "LY": "利比亚", "MA": "摩洛哥",
    "MC": "摩纳哥", "MD": "摩尔多瓦", "ME": "黑山", "MG": "马达加斯加", "MK": "北马其顿",
    "ML": "马里", "MM": "缅甸", "MN": "蒙古", "MO": "澳门", "MQ": "马提尼克",
    "MR": "毛里塔尼亚", "MT": "马耳他", "MU": "毛里求斯", "MV": "马尔代夫", "MW": "马拉维",
    "MX": "墨西哥", "MY": "马来西亚", "MZ": "莫桑比克", "NA": "纳米比亚", "NC": "新喀里多尼亚",
    "NE": "尼日尔", "NG": "尼日利亚", "NI": "尼加拉瓜", "NL": "荷兰", "NO": "挪威",
    "NP": "尼泊尔", "NR": "瑙鲁", "NZ": "新西兰", "OM": "阿曼", "PA": "巴拿马",
    "PE": "秘鲁", "PF": "法属波利尼西亚", "PG": "巴布亚新几内亚", "PH": "菲律宾", "PK": "巴基斯坦",
    "PL": "波兰", "PR": "波多黎各", "PT": "葡萄牙", "PW": "帕劳", "PY": "巴拉圭",
    "QA": "卡塔尔", "RE": "留尼汪", "RO": "罗马尼亚", "RS": "塞尔维亚", "RU": "俄罗斯",
    "RW": "卢旺达", "SA": "沙特阿拉伯", "SB": "所罗门群岛", "SC": "塞舌尔", "SD": "苏丹",
    "SE": "瑞典", "SG": "新加坡", "SI": "斯洛文尼亚", "SK": "斯洛伐克", "SL": "塞拉利昂",
    "SM": "圣马力诺", "SN": "塞内加尔", "SO": "索马里", "SR": "苏里南", "ST": "圣多美和普林西比",
    "SV": "萨尔瓦多", "SY": "叙利亚", "SZ": "斯威士兰", "TC": "特克斯和凯科斯群岛", "TD": "乍得",
    "TG": "多哥", "TH": "泰国", "TJ": "塔吉克斯坦", "TL": "东帝汶", "TM": "土库曼斯坦",
    "TN": "突尼斯", "TO": "汤加", "TR": "土耳其", "TT": "特立尼达和多巴哥", "TW": "台湾",
    "TZ": "坦桑尼亚", "UA": "乌克兰", "UG": "乌干达", "US": "美国", "UY": "乌拉圭",
    "UZ": "乌兹别克斯坦", "VA": "梵蒂冈", "VC": "圣文森特和格林纳丁斯", "VE": "委内瑞拉", "VG": "英属维尔京群岛",
    "VI": "美属维尔京群岛", "VN": "越南", "VU": "瓦努阿图", "WS": "萨摩亚", "YE": "也门",
    "YT": "马约特", "ZA": "南非", "ZM": "赞比亚", "ZW": "津巴布韦",
}

COUNTRY_TRANSLATIONS = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Russia": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "Laos": "老挝",
    "Lao People's Democratic Republic": "老挝",
    "Lao PDR": "老挝",
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
    "Peru": "秘鲁",
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
    "European Union": "欧盟",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡",
}

def translate_country(country: str, country_short: str = "") -> str:
    code = str(country_short or "").strip().upper()
    if code and code in COUNTRY_CODE_TRANSLATIONS:
        return COUNTRY_CODE_TRANSLATIONS[code]
    clean_country = str(country or "").strip()
    if not clean_country:
        return ""
    return COUNTRY_TRANSLATIONS.get(clean_country, clean_country)

def get_upstream_proxy() -> tuple[str | None, str | None, int | None]:
    """
    Returns (proxy_type, host, port) from environment variables.
    proxy_type is 'socks' or 'http'.
    """
    socks_env = os.environ.get("OPENVPN_UPSTREAM_SOCKS")
    if socks_env:
        if "://" in socks_env:
            parsed = urllib.parse.urlsplit(socks_env)
            if parsed.hostname and parsed.port:
                return "socks", parsed.hostname, parsed.port
        else:
            parts = socks_env.split(":")
            if len(parts) == 2:
                return "socks", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "socks", parts[0], 10808

    http_env = os.environ.get("OPENVPN_UPSTREAM_HTTP")
    if http_env:
        if "://" in http_env:
            parsed = urllib.parse.urlsplit(http_env)
            if parsed.hostname and parsed.port:
                return "http", parsed.hostname, parsed.port
        else:
            parts = http_env.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "http", parts[0], 10808

    for env_name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"]:
        val = os.environ.get(env_name)
        if not val:
            continue
        if "://" in val:
            parsed = urllib.parse.urlsplit(val)
            ptype = "socks" if parsed.scheme.startswith("socks") else "http"
            if parsed.hostname and parsed.port:
                return ptype, parsed.hostname, parsed.port
        else:
            parts = val.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
    return None, None, None

def is_config_tcp(config_text: str) -> bool:
    try:
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            parts = line.split()
            if parts[0].lower() == "proto" and len(parts) >= 2:
                if "tcp" in parts[1].lower():
                    return True
            elif parts[0].lower() == "remote" and len(parts) >= 4:
                if "tcp" in parts[3].lower():
                    return True
    except Exception:
        pass
    return False

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host = fallback_ip
    remote_port = 0
    proto = "unknown"
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
    return remote_host, remote_port, proto

def get_physical_interface() -> str | None:
    try:
        res = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            routes = []
            for line in res.stdout.splitlines():
                if line.startswith("default via"):
                    parts = line.split()
                    try:
                        gw = parts[2]
                        dev = parts[parts.index("dev") + 1]
                        metric = 0
                        if "metric" in parts:
                            metric = int(parts[parts.index("metric") + 1])
                        routes.append((gw, dev, metric))
                    except (ValueError, IndexError):
                        continue
            if routes:
                routes.sort(key=lambda x: x[2], reverse=True)
                for gw, dev, metric in routes:
                    if not dev.startswith(("tun", "tap", "wg", "ppp")):
                        return dev
                return routes[0][1]
    except Exception:
        pass
    return None

def tcp_latency_ms(host: str, port: int, dev: str | None = None) -> int:
    started = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode("utf-8"))
            except OSError:
                pass
        s.connect((host, port))
        return max(1, int((time.time() - started) * 1000))
    except OSError:
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass

def ping_latency_ms(host: str, port: int, fallback_ping: int = 0) -> int:
    dev = get_physical_interface()
    # 1. Try ping with interface binding
    if dev:
        try:
            cmd = ["ping", "-c", "1", "-W", "2", "-I", dev, host]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            if res.returncode == 0:
                match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
                if match:
                    val = int(float(match.group(1)))
                    if val > 0:
                        return val
        except Exception:
            pass

    # 2. Try ping without interface binding
    try:
        cmd = ["ping", "-c", "1", "-W", "2", host]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if res.returncode == 0:
            match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if match:
                val = int(float(match.group(1)))
                if val > 0:
                    return val
    except Exception:
        pass

    # 3. Try TCP latency check
    tcp_val = tcp_latency_ms(host, port, dev)
    if tcp_val > 0:
        return tcp_val

    # 4. Fallback
    if fallback_ping > 0:
        return fallback_ping
    return 0

def check_and_fix_dns() -> None:
    """
    Checks if DNS resolution is broken in WSL.
    If names fail but direct IP connections work, appends public DNS nameservers to /etc/resolv.conf.
    """
    try:
        socket.gethostbyname("www.vpngate.net")
        return
    except socket.gaierror:
        pass

    network_ok = False
    for ip in ["8.8.8.8", "1.1.1.1"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(2)
            s.connect((ip, 53))
            network_ok = True
            break
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    if not network_ok:
        return

    resolv_file = Path("/etc/resolv.conf")
    if resolv_file.exists():
        try:
            content = resolv_file.read_text(encoding="utf-8", errors="replace")
            if "nameserver 1.1.1.1" not in content and "nameserver 8.8.8.8" not in content:
                print("[dns_heal] Resolving names failed, but IP network is OK. Appending public DNS to /etc/resolv.conf...", flush=True)
                with open("/etc/resolv.conf", "a", encoding="utf-8") as f:
                    f.write("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        except Exception as e:
            print(f"[dns_heal] Failed to write DNS fallback: {e}", flush=True)

def load_ip_cache() -> dict[str, dict[str, Any]]:
    with ip_cache_lock:
        try:
            if IP_CACHE_FILE.exists():
                return json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

def save_ip_cache(cache: dict[str, dict[str, Any]]) -> None:
    with ip_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True)
            IP_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

IP_INFO_FIELDS = "status,message,query,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile"

def _build_ip_info_entry(item: dict[str, Any], cached_at: float) -> dict[str, Any] | None:
    if item.get("status") != "success":
        return None
    query_ip = item.get("query")
    if not query_ip:
        return None

    ip_type = "residential"
    if item.get("mobile"):
        ip_type = "mobile"
    elif item.get("proxy"):
        ip_type = "proxy"
    elif item.get("hosting"):
        ip_type = "hosting"

    quality = "normal"
    if item.get("proxy"):
        quality = "proxy"
    elif item.get("hosting"):
        quality = "datacenter"
    elif item.get("mobile"):
        quality = "mobile"

    translated_country = translate_country(item.get("country", ""))
    loc = " ".join(part for part in [translated_country, item.get("regionName"), item.get("city")] if part)
    return {
        "owner": item.get("org") or item.get("isp") or "",
        "asn": item.get("as") or "",
        "as_name": item.get("asname") or "",
        "location": loc,
        "ip_type": ip_type,
        "quality": quality,
        "cached_at": cached_at,
    }

def _query_single_ip_info(ip: str, cached_at: float) -> dict[str, Any] | None:
    request = urllib.request.Request(
        f"http://ip-api.com/json/{urllib.parse.quote(ip)}?lang=zh-CN&fields={IP_INFO_FIELDS}",
        headers={"User-Agent": "vpngate-manager/2.2"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            item = json.loads(response.read().decode("utf-8", errors="replace"))
            return _build_ip_info_entry(item, cached_at)
    except Exception as e:
        print(f"[enrich_ip_info] Single query failed for {ip}: {e}", flush=True)
        return None

def enrich_ip_info(nodes: list[dict[str, Any]]) -> None:
    # 1. Read cache thread-safely
    with ip_cache_lock:
        cache = load_ip_cache()

    ips_to_query = []
    now = time.time()

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if not ip:
            continue
        if ip in cache and now - cache[ip].get("cached_at", 0) < 7 * 24 * 3600:
            cached = cache[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")
        else:
            if ip not in ips_to_query:
                ips_to_query.append(ip)

    if not ips_to_query:
        return

    # 2. Perform HTTP query outside lock
    new_entries = {}
    chunk_size = 20
    for i in range(0, len(ips_to_query), chunk_size):
        chunk = ips_to_query[i : i + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        request = urllib.request.Request(
            f"http://ip-api.com/batch?lang=zh-CN&fields={IP_INFO_FIELDS}",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "vpngate-manager/2.2"},
            method="POST",
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    data = json.loads(response.read().decode("utf-8", errors="replace"))
                    for item in data:
                        entry = _build_ip_info_entry(item, now)
                        if not entry:
                            continue
                        query_ip = item.get("query")
                        if query_ip:
                            new_entries[query_ip] = entry
                    break
            except Exception as e:
                if attempt == 2:
                    print(f"[enrich_ip_info] Batch query failed: {e}", flush=True)
                else:
                    time.sleep(0.5 * (attempt + 1))

    unresolved_ips = [ip for ip in ips_to_query if ip not in new_entries]
    for ip in unresolved_ips:
        entry = None
        for attempt in range(2):
            entry = _query_single_ip_info(ip, now)
            if entry:
                break
            time.sleep(0.3 * (attempt + 1))
        if entry:
            new_entries[ip] = entry

    if not new_entries:
        return

    # 3. Save cache thread-safely (reload & update to avoid overwrite of concurrent queries)
    with ip_cache_lock:
        cache = load_ip_cache()
        cache.update(new_entries)
        save_ip_cache(cache)

    # 4. Enrich nodes with newly queried info
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if ip in new_entries:
            cached = new_entries[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")
