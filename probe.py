#!/usr/bin/env python3
"""
全维度浏览器与网络环境指纹探测服务 (Who-Probe)
支持:
  1. 静态前端资源托管 (/, /zh-cn/, /assets/*) + Gzip 压缩
  2. 客户端 IP 归属 / ASN / 机房与代理属性 / PTR 反向解析 (双源容灾 + 内存 TTL 缓存)
  3. Linux 旁路只读抓包解析真实 TCP SYN (TTL / Window / MSS / MTU / TCP Options / JA4T / OS)
     与 TLS ClientHello (JA3 / JA4 / GREASE / ALPN / Cipher & Extension 计数) —— 零侵入 Nginx 443
  4. 无状态 HTTP ETag 缓存追踪探针 (/api/who/etag) 与低开销 RTT 测速 (/api/who/ping)
"""

from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures
import gzip
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import whoprobe_admin_store as admin_store  # noqa: E402
import egress_intel  # noqa: E402
import share_store  # noqa: E402
import visibility  # noqa: E402
import visibility_dns  # noqa: E402

ENABLE_ACTIVE_443 = False
VISIBILITY_VIEW = visibility.View()
DEFAULT_TRUSTED_EDGES = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
TRUSTED_EDGES = DEFAULT_TRUSTED_EDGES
EDGE_WIRE_HEADERS = ("X-Edge-Peer-IP", "X-Edge-Peer-Port", "X-Edge-Local-IP", "X-Edge-Local-Port")
EDGE_PROTOCOL_HEADERS = {
    "httpVersion": "X-HTTP-Version",
    "tlsProtocol": "X-TLS-Protocol",
    "tlsCipher": "X-TLS-Cipher",
    "tlsCurves": "X-TLS-Curves",
    "tlsAlpn": "X-TLS-ALPN",
    "tlsSessionReused": "X-TLS-Reused",
}
WHO_RUN_TOKEN_HEADER = "X-Who-Run-Token"
ACTIVE_PROBE_HEADER = "X-Who-Active-Probe"

SHARE_STORE: share_store.ShareStore | None = None
_SHARE_STORE_LOCK = threading.Lock()
_SHARE_RATE_SALT = secrets.token_hex(16)
ADMIN_AUTH: admin_store.AdminAuth | None = None
ADMIN_STORE: admin_store.AdminStore | None = None


def _ip_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or not value or len(value) > 45 or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _normalized_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    addr = _ip_literal(value)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_trusted_edge(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        if "%" in value:
            raise ValueError("scoped IP unsupported")
        net = ipaddress.ip_network(value)
        if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96:
            mapped = net.network_address.ipv4_mapped
            if mapped is not None:
                return ipaddress.IPv4Network((mapped, net.prefixlen - 96))
        return net
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an IP address or CIDR") from exc


def _is_trusted_edge_ip(peer_ip: str) -> bool:
    addr = _normalized_ip(peer_ip)
    return addr is not None and any(addr in net for net in TRUSTED_EDGES)


TcpConnection = tuple[str, int, str, int]


def _tcp_connection_key(peer_ip: str, peer_port: str | int,
                        local_ip: str, local_port: str | int) -> TcpConnection | None:
    peer, local = _normalized_ip(peer_ip), _normalized_ip(local_ip)
    if peer is None or local is None or peer.version != local.version:
        return None
    if peer.is_unspecified or local.is_unspecified or peer.is_multicast or local.is_multicast:
        return None
    ports = (str(peer_port), str(local_port))
    if any(not re.fullmatch(r"[0-9]{1,5}", p) for p in ports):
        return None
    sport, dport = map(int, ports)
    if not (1 <= sport <= 65535 and 1 <= dport <= 65535):
        return None
    return str(peer), sport, str(local), dport

# RFC 8701 TLS GREASE 值集合
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


class TTLCache:
    """线程安全的轻量级有界 TTL 字典缓存。"""

    def __init__(self, maxsize: int = 2048, ttl_sec: float = 600.0) -> None:
        self.maxsize = maxsize
        self.ttl_sec = ttl_sec
        self._lock = threading.Lock()
        self._data: collections.OrderedDict[object, tuple[float, object]] = collections.OrderedDict()

    def get(self, key: object) -> object | None:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            exp, val = item
            if now > exp:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return val

    def set(self, key: object, val: object, ttl_sec: float | None = None) -> None:
        exp = time.monotonic() + (self.ttl_sec if ttl_sec is None else ttl_sec)
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = (exp, val)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def discard(self, key: object) -> None:
        with self._lock:
            self._data.pop(key, None)


GEO_CACHE = TTLCache(maxsize=2048, ttl_sec=900.0)
PTR_CACHE = TTLCache(maxsize=2048, ttl_sec=900.0)
# 抓包与 TLS 桥共享同一四元组记录，更新时不得混入旧连接的数据。
PACKET_CACHE = TTLCache(maxsize=4096, ttl_sec=180.0)
_WIRE_LOCK = threading.Lock()
TLS_PERM_CACHE = TTLCache(maxsize=4096, ttl_sec=180.0)
_TLS_PERM_LOCK = threading.Lock()
SHARE_RATE_CACHE = TTLCache(maxsize=4096, ttl_sec=60.0)
_GEO_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="geo")
_SERVER_COORDS: list[float] | None = None
_SERVER_COORDS_LOCK = threading.Lock()


def get_share_store(data_dir: str | Path | None = None) -> share_store.ShareStore:
    global SHARE_STORE
    with _SHARE_STORE_LOCK:
        if SHARE_STORE is None:
            SHARE_STORE = share_store.ShareStore(data_dir=data_dir)
        return SHARE_STORE


def record_admin_visit_async(
    *,
    ip: str,
    event: str,
    ua: str = "",
    geo: dict | None = None,
    tcp_os: str = "",
    share_id: str = "",
    target_ip: str = "",
    score: int = 0,
    grade: str = "",
    created_at: int | None = None,
    dedup_sec: float = 4.0,
) -> None:
    store = ADMIN_STORE
    if store is None or not ip:
        return
    if ip in ("127.0.0.1", "::1") and os.environ.get("WHOPROBE_LOG_LOCAL") != "1":
        return

    if geo is not None:
        try:
            store.record_visit(
                ip=ip,
                event=event,
                ua=ua,
                geo=geo,
                tcp_os=tcp_os,
                share_id=share_id,
                target_ip=target_ip,
                score=score,
                grade=grade,
                created_at=created_at,
                dedup_sec=dedup_sec,
            )
        except Exception:
            pass
        return

    def _bg() -> None:
        try:
            g = lookup_ip_geo(ip)
            store.record_visit(
                ip=ip,
                event=event,
                ua=ua,
                geo=g,
                tcp_os=tcp_os,
                share_id=share_id,
                target_ip=target_ip,
                score=score,
                grade=grade,
                created_at=created_at,
                dedup_sec=dedup_sec,
            )
        except Exception:
            pass

    try:
        _GEO_POOL.submit(_bg)
    except Exception:
        pass


def is_private_or_loopback(ip: str) -> bool:
    clean = ip.split("%")[0].strip().lower()
    if clean in ("127.0.0.1", "::1", "localhost", ""):
        return True
    if clean.startswith(("10.", "192.168.", "100.64.", "fe80:", "fc00:", "fd00:")):
        return True
    if clean.startswith("172."):
        parts = clean.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def lookup_ptr(ip: str, timeout: float = 0.75) -> str | None:
    clean = ip.split("%")[0].strip()
    if is_private_or_loopback(clean):
        return None
    cached = PTR_CACHE.get(clean)
    if cached is not None:
        return cached or None

    result: list[str | None] = [None]

    def _worker() -> None:
        try:
            host, _, _ = socket.gethostbyaddr(clean)
            result[0] = host
        except Exception:
            result[0] = None

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    val = result[0]
    PTR_CACHE.set(clean, val or "")
    return val


def _fetch_geo_ipapi(clean_ip: str, priv: bool) -> dict | None:
    fields = (
        "status,message,country,countryCode,regionName,city,lat,lon,"
        "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    url1 = (
        f"http://ip-api.com/json/?fields={fields}"
        if priv
        else f"http://ip-api.com/json/{urllib.parse.quote(clean_ip)}?fields={fields}"
    )
    req = urllib.request.Request(url1, headers={"User-Agent": "WhoProbe/2.0"})
    with urllib.request.urlopen(req, timeout=2.1) as resp:
        raw = json.loads(resp.read().decode("utf-8", errors="replace"))
    if raw.get("status") != "success":
        return None
    asn_str = raw.get("as") or ""
    asn_num = asn_str.split(" ")[0] if asn_str.startswith("AS") else asn_str
    out = {
        "ok": True,
        "source": "ip-api",
        "ip": raw.get("query") or clean_ip,
        "socketIp": clean_ip,
        "isLoopbackFallback": priv,
        "country": raw.get("country") or "",
        "countryCode": (raw.get("countryCode") or "").upper(),
        "region": raw.get("regionName") or "",
        "city": raw.get("city") or "",
        "lat": raw.get("lat"),
        "lon": raw.get("lon"),
        "timezone": raw.get("timezone") or "",
        "isp": raw.get("isp") or "",
        "org": raw.get("org") or "",
        "asn": asn_num,
        "asFull": asn_str,
        "asName": raw.get("asname") or "",
        "ptr": raw.get("reverse") or "",
        "mobile": bool(raw.get("mobile")),
        "proxy": bool(raw.get("proxy")),
        "hosting": bool(raw.get("hosting")),
    }
    out["hostingInferred"] = infer_datacenter(out)
    out["mobile"] = infer_mobile(out)
    return out


def _fetch_geo_ipwhois(clean_ip: str, priv: bool) -> dict | None:
    url2 = "https://ipwho.is/" if priv else f"https://ipwho.is/{urllib.parse.quote(clean_ip)}"
    req2 = urllib.request.Request(url2, headers={"User-Agent": "Mozilla/5.0 WhoProbe/2.0"})
    with urllib.request.urlopen(req2, timeout=2.3) as resp2:
        raw2 = json.loads(resp2.read().decode("utf-8", errors="replace"))
    if raw2.get("success") is False or not raw2.get("ip"):
        return None
    conn = raw2.get("connection") or {}
    tz = raw2.get("timezone") or {}
    asn_val = conn.get("asn")
    asn_str = f"AS{asn_val}" if asn_val else ""
    out = {
        "ok": True,
        "source": "ipwho.is",
        "ip": raw2.get("ip") or clean_ip,
        "socketIp": clean_ip,
        "isLoopbackFallback": priv,
        "country": raw2.get("country") or "",
        "countryCode": (raw2.get("country_code") or "").upper(),
        "region": raw2.get("region") or "",
        "city": raw2.get("city") or "",
        "lat": raw2.get("latitude"),
        "lon": raw2.get("longitude"),
        "timezone": (tz.get("id") if isinstance(tz, dict) else "") or "",
        "isp": conn.get("isp") or "",
        "org": conn.get("org") or "",
        "asn": asn_str,
        "asFull": f"{asn_str} {conn.get('org') or ''}".strip(),
        "asName": conn.get("domain") or "",
        "ptr": "",
        "mobile": False,
        "proxy": False,
        "hosting": False,
    }
    out["hostingInferred"] = infer_datacenter(out)
    out["hosting"] = out["hostingInferred"]
    out["mobile"] = infer_mobile(out)
    return out


def lookup_ip_geo(ip: str) -> dict:
    """并发竞速查询客户端 IP 的归属地、ASN、ISP、机房属性与 PTR（硬上限 ≤ 2.3s，杜绝慢源串联阻塞）。"""
    clean_ip = ip.split("%")[0].strip()
    priv = is_private_or_loopback(clean_ip)
    cache_key = "__self__" if priv else clean_ip

    cached = GEO_CACHE.get(cache_key)
    if isinstance(cached, dict):
        return cached

    f_primary = _GEO_POOL.submit(_fetch_geo_ipapi, clean_ip, priv)
    f_backup = _GEO_POOL.submit(_fetch_geo_ipwhois, clean_ip, priv)
    f_ptr = None if priv else _GEO_POOL.submit(lookup_ptr, clean_ip, 0.75)

    chosen: dict | None = None
    # 优先给包含 hosting/mobile/proxy 原生标记的 ip-api 1.5s 窗口；超时或失败立即采用已就绪的备源
    concurrent.futures.wait([f_primary], timeout=1.5)
    if f_primary.done():
        try:
            chosen = f_primary.result()
        except Exception:
            chosen = None

    if chosen is None:
        pending = [f for f in (f_primary, f_backup) if not f.done()]
        if pending:
            concurrent.futures.wait(pending, timeout=0.9, return_when=concurrent.futures.FIRST_COMPLETED)
        for fut in (f_primary, f_backup):
            if fut.done():
                try:
                    cand = fut.result()
                    if isinstance(cand, dict) and cand.get("ok"):
                        chosen = cand
                        break
                except Exception:
                    continue
        if chosen is None:
            still = [f for f in (f_primary, f_backup) if not f.done()]
            if still:
                concurrent.futures.wait(still, timeout=0.6, return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in still:
                    if fut.done():
                        try:
                            cand = fut.result()
                            if isinstance(cand, dict) and cand.get("ok"):
                                chosen = cand
                                break
                        except Exception:
                            continue

    if isinstance(chosen, dict) and chosen.get("ok"):
        if not chosen.get("ptr") and f_ptr is not None:
            try:
                chosen["ptr"] = f_ptr.result(timeout=0.15) or ""
            except Exception:
                chosen["ptr"] = ""
            chosen["hostingInferred"] = infer_datacenter(chosen)
        GEO_CACHE.set(cache_key, chosen)
        return chosen

    return {"ok": False, "ip": clean_ip, "socketIp": clean_ip, "error": "lookup_failed"}


def get_server_coarse_coords() -> list[float] | None:
    """获取服务端所在城市的粗粒度经纬度（保留 1 位小数，仅用于物理光纤 RTT 下界测算，不暴露服务端 IP）。"""
    global _SERVER_COORDS
    if _SERVER_COORDS is not None:
        return _SERVER_COORDS
    cached = GEO_CACHE.get("__self__")
    if isinstance(cached, dict) and isinstance(cached.get("lat"), (int, float)) and isinstance(cached.get("lon"), (int, float)):
        with _SERVER_COORDS_LOCK:
            _SERVER_COORDS = [round(float(cached["lat"]), 1), round(float(cached["lon"]), 1)]
            return _SERVER_COORDS
    return None


def start_server_geo_prewarmer() -> None:
    def _worker() -> None:
        global _SERVER_COORDS
        try:
            g = lookup_ip_geo("127.0.0.1")
            if isinstance(g.get("lat"), (int, float)) and isinstance(g.get("lon"), (int, float)):
                with _SERVER_COORDS_LOCK:
                    _SERVER_COORDS = [round(float(g["lat"]), 1), round(float(g["lon"]), 1)]
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True, name="srv-geo-prewarm").start()


DATACENTER_KEYWORDS = (
    "amazon", "aws", "ec2", "lightsail", "google cloud", "gcp", "microsoft", "azure",
    "cloudflare", "digitalocean", "linode", "akamai", "vultr", "choopa", "hetzner",
    "ovh", "contabo", "oracle", "alibaba", "aliyun", "tencent", "huawei", "sakura",
    "leaseweb", "psychz", "cogent", "hurricane electric", "m247", "datapacket",
    "datacamp", "cdn77", "zenlayer", "multacom", "racknerd", "dmit", "bandwagon",
    "it7", "frantech", "buyvm", "kamatera", "upcloud", "scaleway", "hostinger",
    "gcore", "fly.io", "fastly", "stackpath", "hosting", "datacenter", "vps", "cloud",
)


def infer_datacenter(geo: dict) -> bool:
    if geo.get("hosting"):
        return True
    hay = " ".join(
        str(geo.get(k) or "") for k in ("isp", "org", "asFull", "asName", "ptr")
    ).lower()
    return any(kw in hay for kw in DATACENTER_KEYWORDS)


MOBILE_KEYWORDS = (
    "5gc", " 5g", "5g ", "4g", "lte", "cellular", "mobile", "wireless",
    "cmnet", "cmiot", "chinamobile", "china mobile", "unicom mobile",
    "t-mobile", "verizon wireless", "at&t mobility", "docomo", "kddi",
    "vodafone", "telefonica",
)


def infer_mobile(geo: dict) -> bool:
    if geo.get("mobile"):
        return True
    hay = " ".join(
        str(geo.get(k) or "") for k in ("isp", "org", "asFull", "asName", "ptr")
    ).lower()
    return any(kw in hay for kw in MOBILE_KEYWORDS)


CLOUDFLARE_NETS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )
)


def is_cloudflare_edge_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0].strip())
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_NETS)


# ============================================================================
# 被动 TCP SYN (JA4T / OS / MTU) 与 TLS ClientHello (JA3 / JA4) 解析器
# ============================================================================

def infer_initial_ttl(ttl: int) -> int:
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def parse_tcp_options(opts_bytes: bytes) -> tuple[list[str], int | None, int | None]:
    names: list[str] = []
    mss: int | None = None
    wscale: int | None = None
    i = 0
    n = len(opts_bytes)
    while i < n:
        kind = opts_bytes[i]
        if kind == 0:  # EOL
            names.append("eol")
            break
        if kind == 1:  # NOP
            names.append("nop")
            i += 1
            continue
        if i + 1 >= n:
            break
        length = opts_bytes[i + 1]
        if length < 2 or i + length > n:
            break
        body = opts_bytes[i + 2 : i + length]
        if kind == 2 and len(body) == 2:
            mss = struct.unpack("!H", body)[0]
            names.append("mss")
        elif kind == 3 and len(body) == 1:
            wscale = body[0]
            names.append("ws")
        elif kind == 4:
            names.append("sok")
        elif kind == 5:
            names.append("sack")
        elif kind == 8:
            names.append("ts")
        elif kind == 34:
            names.append("tfo")
        else:
            names.append(f"opt{kind}")
        i += length
    return names, mss, wscale


def extract_tcp_tsval(opts_bytes: bytes) -> int | None:
    """从原始 TCP Options 字节串提取 Kind=8 (Timestamp) 的 32-bit TSval 计数。"""
    i = 0
    n = len(opts_bytes)
    while i < n:
        kind = opts_bytes[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= n:
            break
        length = opts_bytes[i + 1]
        if length < 2 or i + length > n:
            break
        if kind == 8 and length == 10:
            return struct.unpack("!I", opts_bytes[i + 2 : i + 6])[0]
        i += length
    return None


def guess_tcp_os(init_ttl: int, window: int, opts: list[str]) -> tuple[str, str]:
    opt_sig = ",".join(opts)
    if init_ttl == 128:
        return "Windows (NT 10/11)", "windows"
    if init_ttl == 64:
        # macOS / iOS 典型特征: window=65535 且包含 eol 或 ts 在 sok 前
        if window == 65535 and ("eol" in opts or opt_sig.startswith("mss,nop,ws,nop,nop,ts,sok")):
            return "macOS / iOS (Darwin)", "apple"
        if "sok" in opts and "ts" in opts and opts.index("sok") < opts.index("ts"):
            return "Linux / Android", "linux"
        if window != 65535 and "sok" in opts:
            return "Linux / Android", "linux"
        return "Linux / Unix", "unix"
    if init_ttl == 255:
        return "BSD / 网络设备 (TTL 255)", "unix"
    return f"Unknown (TTL {init_ttl})", "other"


def infer_tunnel_from_mss(mss: int | None, ipv6: bool = False) -> str:
    if not mss:
        return "unknown"
    mtu = mss + (60 if ipv6 else 40)
    if mtu > 1500:
        return "jumbo_cloud"
    if mtu == 1500:
        return "ethernet"
    if mtu in (1492, 1480):
        return "pppoe"
    if mtu in (1420, 1412):
        return "wireguard"
    if 1380 <= mtu < 1420:
        return "ipsec_or_tun"
    if 1280 <= mtu < 1380:
        return "openvpn_or_tun"
    if mtu < 1480:
        return "tunnel"
    return "standard"


def build_ja4t(window: int, opts: list[str], mss: int | None, wscale: int | None) -> str:
    opt_Num_map = {
        "eol": "0", "nop": "1", "mss": "2", "ws": "3", "sok": "4", "sack": "5", "ts": "8", "tfo": "34"
    }
    codes = "-".join(opt_Num_map.get(o, o.replace("opt", "")) for o in opts) or "00"
    return f"{window}_{codes}_{mss or 0}_{wscale if wscale is not None else 0}"


def _quic_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(buf):
        return None
    b0 = buf[pos]
    n = 1 << (b0 >> 6)
    if pos + n > len(buf):
        return None
    val = b0 & 0x3F
    for i in range(1, n):
        val = (val << 8) | buf[pos + i]
    return val, pos + n


QUIC_TP_NAMES: dict[int, str] = {
    0x01: "max_idle_timeout",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x11: "version_information",
    0x20: "max_datagram_frame_size",
    0x2AB2: "grease_quic_bit",
}


def parse_quic_transport_params(edata: bytes) -> dict:
    pos = 0
    end = len(edata)
    params: dict[str, int | bool | str] = {}
    order: list[str] = []
    has_grease_tp = False
    while pos < end and len(order) < 32:
        k_res = _quic_varint(edata, pos)
        if k_res is None:
            break
        tp_id, pos = k_res
        l_res = _quic_varint(edata, pos)
        if l_res is None:
            break
        vlen, pos = l_res
        if pos + vlen > end:
            break
        vbytes = edata[pos : pos + vlen]
        pos += vlen
        # RFC 9000 Section 18.1: 31 * N + 27 为 GREASE 传输参数
        if tp_id >= 27 and (tp_id - 27) % 31 == 0:
            has_grease_tp = True
            continue
        name = QUIC_TP_NAMES.get(tp_id, f"0x{tp_id:x}")
        order.append(name)
        if name == "initial_source_connection_id":
            params[name] = len(vbytes)
        elif vlen == 0:
            params[name] = True
        else:
            iv = _quic_varint(vbytes, 0)
            params[name] = iv[0] if (iv is not None and iv[1] == vlen) else vbytes.hex()[:24]
    return {"params": params, "order": order, "hasGreaseParam": has_grease_tp}


def parse_tls_client_hello(payload: bytes, transport_prefix: str = "t") -> dict | None:
    """解析 TLS Record 中的 ClientHello，计算 JA3、JA4、扩展顺序与可选 QUIC 传输参数。"""
    # TLS Record Header: ContentType(1)=0x16, LegacyVersion(2)=0x0301/0x0303, Length(2)
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    rec_len = struct.unpack("!H", payload[3:5])[0]
    if rec_len > len(payload) - 5:
        return None
    hs = payload[5 : 5 + rec_len]
    # HandshakeType(1)=0x01 (ClientHello), Length(3)
    if len(hs) < 38 or hs[0] != 0x01:
        return None
    hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    if len(hs) < 4 + hs_len:
        return None
    body = hs[4 : 4 + hs_len]
    if len(body) < 34:
        return None

    client_version = struct.unpack("!H", body[0:2])[0]
    hello_id = body[2:14].hex()  # ClientHello.random 前 12B，唯一标识单次 TLS 握手用于多源去重
    pos = 2 + 32  # skip client_version(2) + random(32)
    if pos >= len(body):
        return None

    # Session ID
    sid_len = body[pos]
    pos += 1 + sid_len
    if sid_len > 32 or pos + 2 > len(body):
        return None

    # Cipher Suites
    cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    if cs_len < 2 or cs_len % 2 or pos + cs_len > len(body):
        return None
    raw_ciphers = [
        struct.unpack("!H", body[pos + j : pos + j + 2])[0]
        for j in range(0, cs_len - 1, 2)
    ]
    pos += cs_len

    # Compression Methods
    if pos >= len(body):
        return None
    comp_len = body[pos]
    pos += 1 + comp_len
    if not comp_len or pos > len(body):
        return None

    has_grease = any(c in GREASE_VALUES for c in raw_ciphers)
    ciphers = [c for c in raw_ciphers if c not in GREASE_VALUES]

    raw_exts: list[int] = []
    groups: list[int] = []
    key_share_groups: list[int] = []
    ec_formats: list[int] = []
    sig_algs: list[int] = []
    supported_versions: list[int] = []
    alpn_list: list[str] = []
    cert_comp_algs: list[int] = []
    sni_host = ""
    quic_tp: dict | None = None

    if pos < len(body):
        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end_ext = pos + ext_total
        if end_ext != len(body):
            return None
        while pos < end_ext:
            if pos + 4 > end_ext:
                return None
            etype, elen = struct.unpack("!HH", body[pos : pos + 4])
            pos += 4
            if pos + elen > end_ext:
                return None
            edata = body[pos : pos + elen]
            pos += elen
            if etype in GREASE_VALUES:
                has_grease = True
                continue
            raw_exts.append(etype)

            if etype == 0x0000 and len(edata) >= 5:  # server_name (SNI)
                name_len = struct.unpack("!H", edata[3:5])[0]
                sni_host = edata[5 : 5 + name_len].decode("ascii", errors="ignore")
            elif etype == 0x000A and len(edata) >= 2:  # supported_groups
                glen = struct.unpack("!H", edata[0:2])[0]
                for k in range(2, min(len(edata), 2 + glen) - 1, 2):
                    g = struct.unpack("!H", edata[k : k + 2])[0]
                    if g not in GREASE_VALUES:
                        groups.append(g)
            elif etype == 0x0033 and len(edata) >= 2:  # key_share
                klen = struct.unpack("!H", edata[0:2])[0]
                ki = 2
                kend = min(len(edata), 2 + klen)
                while ki + 4 <= kend:
                    kg, kelen = struct.unpack("!HH", edata[ki : ki + 4])
                    ki += 4 + kelen
                    if kg not in GREASE_VALUES:
                        key_share_groups.append(kg)
            elif etype == 0x001B and len(edata) >= 1:  # compress_certificate
                clen = edata[0]
                for k in range(1, min(len(edata), 1 + clen) - 1, 2):
                    cert_comp_algs.append(struct.unpack("!H", edata[k : k + 2])[0])
            elif etype == 0x000B and len(edata) >= 1:  # ec_point_formats
                flen = edata[0]
                ec_formats.extend(edata[1 : 1 + flen])
            elif etype == 0x000D and len(edata) >= 2:  # signature_algorithms
                slen = struct.unpack("!H", edata[0:2])[0]
                for k in range(2, min(len(edata), 2 + slen) - 1, 2):
                    sig_algs.append(struct.unpack("!H", edata[k : k + 2])[0])
            elif etype == 0x0010 and len(edata) >= 2:  # ALPN
                alen = struct.unpack("!H", edata[0:2])[0]
                idx = 2
                while idx < min(len(edata), 2 + alen):
                    plen = edata[idx]
                    idx += 1
                    alpn_list.append(edata[idx : idx + plen].decode("ascii", errors="ignore"))
                    idx += plen
            elif etype == 0x002B and len(edata) >= 1:  # supported_versions
                vlen = edata[0]
                for k in range(1, min(len(edata), 1 + vlen) - 1, 2):
                    v = struct.unpack("!H", edata[k : k + 2])[0]
                    if v not in GREASE_VALUES:
                        supported_versions.append(v)
            elif etype == 0x0039 and len(edata) >= 2:  # quic_transport_parameters
                quic_tp = parse_quic_transport_params(edata)

    # JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    ja3_str = (
        f"{client_version},"
        f"{'-'.join(str(x) for x in ciphers)},"
        f"{'-'.join(str(x) for x in raw_exts)},"
        f"{'-'.join(str(x) for x in groups)},"
        f"{'-'.join(str(x) for x in ec_formats)}"
    )
    ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

    # JA4: t{ver}{sni}{c_cnt}{e_cnt}{alpn}_{cipher_hash12}_{ext_sig_hash12}
    max_ver = max(supported_versions) if supported_versions else client_version
    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    ver_code = ver_map.get(max_ver, "00")
    sni_code = "d" if sni_host else "i"
    c_cnt = f"{min(len(ciphers), 99):02d}"
    e_cnt = f"{min(len(raw_exts), 99):02d}"
    first_alpn = alpn_list[0] if alpn_list else "00"
    alpn_code = (first_alpn[0] + first_alpn[-1]) if len(first_alpn) >= 2 else "00"

    sorted_ciphers_hex = ",".join(f"{c:04x}" for c in sorted(ciphers))
    c_hash = hashlib.sha256(sorted_ciphers_hex.encode("ascii")).hexdigest()[:12] if ciphers else "000000000000"

    # JA4_c 忽略 SNI(0x0000) 和 ALPN(0x0010) 后排序扩展，并拼接原始顺序 signature_algorithms
    exts_for_ja4 = sorted(e for e in raw_exts if e not in (0x0000, 0x0010))
    ext_hex = ",".join(f"{e:04x}" for e in exts_for_ja4)
    sig_hex = ",".join(f"{s:04x}" for s in sig_algs)
    ja4_c_input = f"{ext_hex}_{sig_hex}" if sig_hex else ext_hex
    e_hash = hashlib.sha256(ja4_c_input.encode("ascii")).hexdigest()[:12] if ja4_c_input else "000000000000"

    ja4 = f"{transport_prefix}{ver_code}{sni_code}{c_cnt}{e_cnt}{alpn_code}_{c_hash}_{e_hash}"

    all_groups = set(groups) | set(key_share_groups)
    pq_name = (
        "X25519MLKEM768"
        if 0x11EC in all_groups
        else ("X25519Kyber768" if 0x6399 in all_groups else ("SecP256r1MLKEM768" if 0x11EB in all_groups else ""))
    )
    group_names_map = {
        0x11EC: "X25519MLKEM768",
        0x11EB: "SecP256r1MLKEM768",
        0x6399: "X25519Kyber768",
        0x001D: "X25519",
        0x0017: "P-256",
        0x0018: "P-384",
        0x0019: "P-521",
        0x0100: "ffdhe2048",
        0x0101: "ffdhe3072",
    }
    key_share_names = [group_names_map.get(g, f"0x{g:04x}") for g in key_share_groups]
    comp_map = {1: "zlib", 2: "brotli", 3: "zstd"}

    return {
        "ja3": ja3_hash,
        "ja4": ja4,
        "helloLength": hs_len + 4,
        "hasGrease": has_grease,
        "cipherCount": len(ciphers),
        "extCount": len(raw_exts),
        "alpn": alpn_list,
        "sni": sni_host,
        "tls13Supported": 0x0304 in supported_versions,
        "pqSupported": bool(pq_name),
        "pqGroup": pq_name,
        "keyShareGroups": key_share_names,
        "echExtension": 0xFE0D in raw_exts,
        "alpsExtension": (0x4469 in raw_exts) or (0x44CD in raw_exts),
        "pskPresent": 0x0029 in raw_exts,
        "helloId": hello_id,
        "extOrder": [e for e in raw_exts if e not in (0x0029, 0x0015)],
        "certCompression": [comp_map.get(a, str(a)) for a in cert_comp_algs],
        "quicTransportParams": quic_tp,
    }


def record_tls_hello_sample(tls_info: dict, run_token: str = "",
                            conn_key: TcpConnection | None = None) -> dict:
    """每轮仅汇总确切归属本轮请求的 ClientHello；没有有效 token 时不保存。"""
    hid = tls_info.get("helloId") or ""
    sample = {
        "conn": conn_key,
        "hid": hid,
        "exts": tuple(tls_info.get("extOrder") or []),
        "psk": bool(tls_info.get("pskPresent")),
        "ja3": tls_info.get("ja3") or "",
    }
    samples = [sample] if hid else []
    if hid and conn_key is not None and re.fullmatch(r"[0-9a-fA-F]{32}", run_token):
        key = hashlib.sha256(bytes.fromhex(run_token)).digest()
        with _TLS_PERM_LOCK:
            now = time.monotonic()
            cur = TLS_PERM_CACHE.get(key)
            if isinstance(cur, tuple):
                deadline, cached_samples = cur
            else:
                deadline, cached_samples = now + TLS_PERM_CACHE.ttl_sec, []
            samples = cached_samples
            if len(samples) < 6 and all(s["hid"] != hid and s["conn"] != conn_key for s in samples):
                samples = [*samples, sample]
                TLS_PERM_CACHE.set(key, (deadline, samples), ttl_sec=deadline - now)

    permuted: bool | None = None
    for i, left in enumerate(samples):
        for right in samples[i + 1:]:
            a, b = left["exts"], right["exts"]
            sa, sb = set(a), set(b)
            common_a = [x for x in a if x in sb]
            common_b = [x for x in b if x in sa]
            if len(common_a) >= 4:
                if common_a != common_b:
                    permuted = True
                    break
                permuted = False
        if permuted is True:
            break
    return {
        "samples": len(samples),
        "permuted": permuted,
        "pskSeen": any(s["psk"] for s in samples),
        "distinctJa3": len({s["ja3"] for s in samples if s["ja3"]}),
    }


def evaluate_tcp_continuity(
    *,
    syn_ttl: int,
    hello_ttl: int,
    syn_had_ts: bool,
    syn_tsval: int | None,
    hello_tsval: int | None,
    dt_sec: float,
) -> tuple[int | None, bool, str | None]:
    """
    校验同一条 TCP 连接 (seq == syn_seq + 1) 上 SYN 与首包 ClientHello 的跨包连续性。
    兼容 5G 蜂窝 UPF/CGNAT 剥离 TSopt (RFC 7323 §3.2)、多核网关微秒级负偏置与 1MHz 高频时钟，
    仅在同连接 TTL 突变 ≥30 或有符号 TSval 断层 (>25,000,000 / <-50,000) 时判定无状态 SYN 改包。
    """
    ttl_jump = abs(int(hello_ttl) - int(syn_ttl))
    if ttl_jump >= 30:
        return None, True, f"ttl_jump_{syn_ttl}_to_{hello_ttl}"

    if syn_tsval is not None and hello_tsval is not None and dt_sec >= 0.008:
        signed_delta = ((hello_tsval - syn_tsval + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        if signed_delta > 25_000_000:
            return None, True, "tsval_discontinuity"
        if signed_delta < -50_000:
            return None, True, "tsval_backward_jump"
        if signed_delta <= 0:
            return None, False, "cgnat_or_subtick_skew"
        ts_hz = round(signed_delta / dt_sec)
        if 10 <= ts_hz <= 2_500_000:
            return ts_hz, False, None
        return None, False, "burst_compressed_rtt"

    if syn_had_ts and hello_tsval is None:
        return None, False, "ts_stripped_by_middlebox"

    return None, False, None


_CAPTURE_BYTES = 4096  # 与既有内核抓包上限一致
_MAX_HELLO_BYTES = 8192
_MAX_IPV6_EXT_HEADERS = 4
_SYN_HELLO_SEC = 10.0
_TCP_SEQUENCE_MASK = 0xFFFFFFFF


def _parse_tcp_frame(frame: bytes, port: int) -> tuple | None:
    """只解析 Ethernet II 上目标端口的未分片 TCP；截短的有效 IP/TCP 头与载荷分别处理。"""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    df = ip_id = None
    if ether_type == 0x0800:
        if len(frame) < 34 or frame[14] >> 4 != 4 or frame[23] != 6:
            return None
        ihl = (frame[14] & 0x0F) * 4
        ip_len, ip_id, frag = struct.unpack_from("!HHH", frame, 16)
        if ihl < 20 or frag & 0x3FFF:  # MF 明确拒绝：首分片也不完整
            return None
        version, traffic_class, limit = 4, frame[15], frame[22]
        df = bool(frag & 0x4000)
        peer_ip = socket.inet_ntop(socket.AF_INET, frame[26:30])
        local_ip = socket.inet_ntop(socket.AF_INET, frame[30:34])
        ip_end, tcp_start = 14 + ip_len, 14 + ihl
    elif ether_type == 0x86DD:
        if len(frame) < 54 or frame[14] >> 4 != 6:
            return None
        payload_len = struct.unpack_from("!H", frame, 18)[0]
        if payload_len == 0:  # 不支持 IPv6 jumbogram
            return None
        version, limit = 6, frame[21]
        traffic_class = ((frame[14] & 0x0F) << 4) | (frame[15] >> 4)
        peer_ip = socket.inet_ntop(socket.AF_INET6, frame[22:38])
        local_ip = socket.inet_ntop(socket.AF_INET6, frame[38:54])
        # IPv6 link-local/ULA 与回环源不参与公网抓包；不将线上 v6 映射地址当另一条 v4 连接。
        if frame[22] & 0xFE == 0xFC or (frame[22] == 0xFE and frame[23] & 0xC0 == 0x80):
            return None
        if frame[22:34] == b"\x00" * 10 + b"\xff\xff" or frame[38:50] == b"\x00" * 10 + b"\xff\xff":
            return None
        ip_end, tcp_start = 54 + payload_len, 54
        frame_end = min(len(frame), ip_end)
        proto = frame[20]
        saw_fragment = False
        for _ in range(_MAX_IPV6_EXT_HEADERS):
            if proto == 6:
                break
            if tcp_start + 8 > frame_end:
                return None
            next_proto, ext_len = frame[tcp_start : tcp_start + 2]
            if proto in (0, 43, 60):  # Hop-by-Hop / Routing / Destination Options
                if (proto == 0 and tcp_start != 54) or (proto == 43 and frame[tcp_start + 3] != 0):
                    return None
                size = (ext_len + 1) * 8
            elif proto == 44:  # 仅原子分片（offset=0 / M=0），不重组 IP
                if saw_fragment or ext_len or frame[tcp_start + 2 : tcp_start + 4] != b"\0\0":
                    return None
                saw_fragment = True
                size = 8
            elif proto == 51 and ext_len >= 1:  # AH
                size = (ext_len + 2) * 4
            else:
                return None  # ESP、无后续头或未知扩展不可作为 TCP 证据
            if tcp_start + size > frame_end:
                return None
            tcp_start += size
            proto = next_proto
        if proto != 6:
            return None
    else:
        return None

    frame_end = min(len(frame), ip_end)
    if tcp_start + 20 > frame_end or is_private_or_loopback(peer_ip):
        return None
    peer_port, local_port, seq = struct.unpack_from("!HHI", frame, tcp_start)
    if local_port != port:
        return None
    key = _tcp_connection_key(peer_ip, peer_port, local_ip, local_port)
    data_offset = (frame[tcp_start + 12] >> 4) * 4
    data_start = tcp_start + data_offset
    if key is None or data_offset < 20 or data_start > frame_end:
        return None
    flags = frame[tcp_start + 13]
    window = struct.unpack_from("!H", frame, tcp_start + 14)[0]
    return (
        key, version, limit, traffic_class, df, ip_id, seq, flags, window,
        frame[tcp_start + 20 : data_start], frame[data_start : frame_end], frame_end == ip_end,
    )


class LinuxPacketSniffer:
    """
    Linux AF_PACKET 只读旁路抓包器。
    挂载内核经典 BPF 过滤器，仅放行目标端口(443)的 TCP SYN 包与 TLS ClientHello 首包，
    业务大流量数据帧在内核态直接丢弃，零 CPU 负担，且完全不介入 Nginx 数据链路。
    """

    SO_ATTACH_FILTER = 26

    def __init__(self, iface: str, port: int = 443) -> None:
        self.iface = iface
        self.port = port
        self.active = False
        self.error: str | None = None
        self._fragments = TTLCache(maxsize=1024, ttl_sec=4.0)

    def start(self) -> None:
        if not sys.platform.startswith("linux"):
            self.error = "non-linux-platform"
            return
        sock = None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.iface, 0))
            self._attach_bpf(sock, self.port)
            self.active = True
            t = threading.Thread(target=self._loop, args=(sock,), daemon=True, name="tls-syn-sniffer")
            t.start()
        except Exception as exc:
            self.error = str(exc)
            self.active = False
            if sock is not None:
                sock.close()

    @staticmethod
    def _bpf_instructions(port: int) -> list[tuple[int, int, int, int]]:
        """cBPF：有界 IPv6 扩展链与 IPv4 共用 TCP 端口/载荷过滤；不退回全量抓包。"""
        code: list[tuple[int, int | str, str, str]] = []
        labels: dict[str, int] = {}

        def mark(name: str) -> None:
            labels[name] = len(code)

        def emit(op: int, k: int | str = 0, yes: str = "", no: str = "") -> None:
            code.append((op, k, yes, no))

        emit(0x28, 12)                    # ldh [12] EtherType
        emit(0x15, 0x0800, "ipv4")
        emit(0x15, 0x86DD, "ipv6", "drop")
        mark("ipv4")
        emit(0x30, 23)                    # ldb [23] protocol
        emit(0x15, 6, no="drop")
        emit(0x28, 20)                    # ldh [20] flags / offset
        emit(0x45, 0x3FFF, "drop")
        emit(0xB1, 14)                    # ldxb 4*([14] & 0xf), X = IPv4 头长
        emit(0x05, "tcp")                 # ja tcp

        mark("ipv6")
        emit(0x01, 40)                    # ldx #40, 相对 IP 起点的偏移
        emit(0x30, 20)                    # ldb [20] Next Header
        for i in range(_MAX_IPV6_EXT_HEADERS):
            frag, ah, opts, advance = (f"{kind}{i}" for kind in ("frag", "ah", "opts", "advance"))
            emit(0x15, 6, "tcp")
            emit(0x15, 44, frag)
            emit(0x15, 51, ah)
            emit(0x15, 0, opts)
            emit(0x15, 43, opts)
            emit(0x15, 60, opts, "drop")
            mark(frag)
            emit(0x48, 16)                # ldh [x + 16] Fragment Offset / M
            emit(0x15, 0, no="drop")
            emit(0x50, 14)                # ldb [x + 14] Next Header
            emit(0x02, 0)                 # st M[0]
            emit(0x00, 8)                 # ld #8
            emit(0x05, advance)
            mark(ah)
            emit(0x50, 14)
            emit(0x02, 0)
            emit(0x50, 15)                # ldb [x + 15] Payload Len
            emit(0x04, 2)                 # add #2
            emit(0x64, 2)                 # lsh #2
            emit(0x05, advance)
            mark(opts)
            emit(0x50, 14)
            emit(0x02, 0)
            emit(0x50, 15)                # ldb [x + 15] Hdr Ext Len
            emit(0x04, 1)
            emit(0x64, 3)
            mark(advance)
            emit(0x0C)                   # add x
            emit(0x07)                   # tax
            emit(0x60, 0)                 # ld M[0] (Next Header)
        emit(0x15, 6, no="drop")

        mark("tcp")
        emit(0x48, 16)                    # ldh [x + 16] TCP dst port
        emit(0x15, port, no="drop")
        emit(0x50, 27)                    # ldb [x + 27] TCP flags
        emit(0x54, 0x3F)
        emit(0x15, 2, "accept")           # SYN，允许 ECE/CWR
        emit(0x50, 26)                    # ldb [x + 26] TCP data offset
        emit(0x74, 2)
        emit(0x54, 0x3C)                   # TCP 头长
        emit(0x0C)
        emit(0x07)
        emit(0x48, 14)                    # ldh [x + 14] payload[0:2]，越界由内核丢弃
        emit(0x15, 0x1703, "drop")        # 排除 TLS Application Data
        mark("accept")
        emit(0x06, _CAPTURE_BYTES)
        mark("drop")
        emit(0x06, 0)

        def offset(label: str, index: int) -> int:
            return labels[label] - index - 1 if label else 0

        return [
            (op, offset(yes, i), offset(no, i), offset(k, i) if isinstance(k, str) else k)
            for i, (op, k, yes, no) in enumerate(code)
        ]

    @classmethod
    def _attach_bpf(cls, sock: socket.socket, port: int) -> None:
        import ctypes

        insns = cls._bpf_instructions(port)
        bpf_buf = b"".join(struct.pack("HBBI", *insn) for insn in insns)
        c_buf = ctypes.create_string_buffer(bpf_buf)
        fprog = struct.pack("@HP", len(insns), ctypes.addressof(c_buf))
        sock.setsockopt(socket.SOL_SOCKET, cls.SO_ATTACH_FILTER, fprog)

    def ingest_frame(self, frame: bytes, now_mono: float | None = None) -> None:
        capture = _parse_tcp_frame(frame, self.port)
        if capture is None:
            return
        (key, version, limit, traffic, df, ip_id, seq, flags, window, opts_raw, payload, complete) = capture
        now = time.monotonic() if now_mono is None else now_mono
        with _WIRE_LOCK:
            existing = PACKET_CACHE.get(key)
            rec = dict(existing) if isinstance(existing, dict) else {}
            syn = rec.get("_syn")
            if (flags & 0x3F) == 0x02:
                if (syn and syn[1] == seq and 0.0 <= now - syn[0] <= _SYN_HELLO_SEC
                        and not rec.get("_passiveHello") and "_bridge" not in rec):
                    if not syn[2]:
                        # 重传不刷新首次时间或用别的 SYN 覆盖指纹。
                        rec["_syn"] = (syn[0], seq, True)
                        PACKET_CACHE.set(key, rec)
                    return
                self._fragments.discard(key)
                opts, mss, wscale = parse_tcp_options(opts_raw)
                initial_limit = infer_initial_ttl(limit)
                os_guess, os_family = guess_tcp_os(initial_limit, window, opts)
                tcp = {
                    "ipVersion": version,
                    "observedTtl": limit,  # 兼容旧读取方，v6 语义为 Hop Limit
                    "initialTtl": initial_limit,
                    "hops": max(0, initial_limit - limit),
                    "window": window,
                    "mss": mss,
                    "mtu": (mss + (60 if version == 6 else 40)) if mss else None,
                    "tunnelGuess": infer_tunnel_from_mss(mss, ipv6=(version == 6)),
                    "wscale": wscale,
                    "options": opts,
                    "ja4t": build_ja4t(window, opts, mss, wscale),
                    "osGuess": os_guess,
                    "osFamily": os_family,
                    "ecn": bool(flags & 0xC0) or bool(traffic & 0x03),
                    "synTsval": extract_tcp_tsval(opts_raw),
                    "tsHz": None,
                    "tsNote": None,
                    "synSpoofSuspect": False,
                    "handshakeRttMs": None,
                    "minHandshakeRttMs": None,
                    "capturedAt": round(time.time(), 2),
                }
                if version == 4:
                    tcp.update(df=df, synIpId=ip_id, helloIpId=None, tos=traffic)
                else:
                    tcp.update(hopLimit=limit, initialHopLimit=initial_limit, trafficClass=traffic)
                # 新 SYN 一定开启新一代，清除同四元组的旧 TLS、H2、协商元数据。
                PACKET_CACHE.set(key, {"tcp": tcp, "_syn": (now, seq, False)})
                return

            if not (payload and (flags & 0x17) == 0x10 and syn and 0.0 <= now - syn[0] <= _SYN_HELLO_SEC):
                return
            if rec.get("_passiveHello"):
                return
            if seq == (syn[1] + 1) & _TCP_SEQUENCE_MASK:
                if not payload.startswith(b"\x16\x03"):
                    return
                pref = b""
                timing = (now, limit, ip_id, extract_tcp_tsval(opts_raw))
            else:
                pending = self._fragments.get(key)
                if not isinstance(pending, tuple) or pending[0] != seq:
                    return  # 不拼接错序、重复或有缺口的片段
                _, pref, timing = pending
            merged = pref + payload[:_MAX_HELLO_BYTES - len(pref)]
            if len(merged) >= 6:
                record_size = 5 + struct.unpack_from("!H", merged, 3)[0]
                if merged[5] != 1 or not (43 <= record_size <= _MAX_HELLO_BYTES):
                    self._fragments.discard(key)
                    return
                if len(merged) >= record_size:
                    self._fragments.discard(key)
                    tls = parse_tls_client_hello(merged)
                    if tls is not None:
                        self._store_hello(key, rec, tls, timing)
                    return
            if complete:
                self._fragments.set(key, ((seq + len(payload)) & _TCP_SEQUENCE_MASK, merged, timing))
            else:  # 抓包截短而不是正常 TCP 分段，缺失字节不可跨段补齐
                self._fragments.discard(key)

    @staticmethod
    def _store_hello(key: TcpConnection, rec: dict, tls: dict, timing: tuple) -> None:
        current = rec.get("tlsClientHello")
        if isinstance(current, dict) and current.get("helloId") != tls["helloId"]:
            return  # 已成功终止的 TLS 桥是更强的来源，不混合冲突的包观测
        rec["tlsClientHello"] = tls
        rec["_passiveHello"] = True
        syn_t, _seq, retransmitted = rec["_syn"]
        hello_t, limit, ip_id, hello_tsval = timing
        dt_sec = hello_t - syn_t
        rtt_ms = round(dt_sec * 1000.0, 1)
        if not retransmitted and 0.2 <= rtt_ms <= 4000.0:
            tcp = dict(rec["tcp"])
            ts_hz, spoof_suspect, ts_note = evaluate_tcp_continuity(
                syn_ttl=tcp["observedTtl"], hello_ttl=limit, syn_had_ts="ts" in tcp["options"],
                syn_tsval=tcp["synTsval"], hello_tsval=hello_tsval, dt_sec=dt_sec,
            )
            tcp.update(handshakeRttMs=rtt_ms, minHandshakeRttMs=rtt_ms, tsHz=ts_hz,
                       tsNote=ts_note, synSpoofSuspect=spoof_suspect)
            if tcp["ipVersion"] == 4:
                tcp["helloIpId"] = ip_id
            rec["tcp"] = tcp
        PACKET_CACHE.set(key, rec)

    def _loop(self, sock: socket.socket) -> None:
        try:
            while self.active:
                self.ingest_frame(sock.recv(_CAPTURE_BYTES))
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.active = False
            sock.close()


SNIFFER: LinuxPacketSniffer | None = None
TLS_BRIDGE: TLSBridgeServer | None = None
QUIC_COLLECTOR: QUICInitialCollector | None = None

# ---------------------------------------------------------------------------
# 零依赖 RFC 9001 QUIC v1/v2 Initial 包解密与多包 CRYPTO ClientHello 重组器
# ---------------------------------------------------------------------------

_AES_SBOX = (
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
)
_AES_XTIME = tuple(((i << 1) ^ 0x1B) & 0xFF if i & 0x80 else (i << 1) for i in range(256))


def _aes128_expand(key: bytes) -> list[list[int]]:
    w = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = [_AES_SBOX[t[1]] ^ rcon, _AES_SBOX[t[2]], _AES_SBOX[t[3]], _AES_SBOX[t[0]]]
            rcon = _AES_XTIME[rcon]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [[w[r * 4 + c][b] for c in range(4) for b in range(4)] for r in range(11)]


def _aes128_enc(rk: list[list[int]], blk: bytes) -> bytes:
    s = [blk[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 10):
        s = [
            _AES_SBOX[s[0]], _AES_SBOX[s[5]], _AES_SBOX[s[10]], _AES_SBOX[s[15]],
            _AES_SBOX[s[4]], _AES_SBOX[s[9]], _AES_SBOX[s[14]], _AES_SBOX[s[3]],
            _AES_SBOX[s[8]], _AES_SBOX[s[13]], _AES_SBOX[s[2]], _AES_SBOX[s[7]],
            _AES_SBOX[s[12]], _AES_SBOX[s[1]], _AES_SBOX[s[6]], _AES_SBOX[s[11]],
        ]
        ns = [0] * 16
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            x = a0 ^ a1 ^ a2 ^ a3
            ns[i] = a0 ^ x ^ _AES_XTIME[a0 ^ a1] ^ rk[r][i]
            ns[i + 1] = a1 ^ x ^ _AES_XTIME[a1 ^ a2] ^ rk[r][i + 1]
            ns[i + 2] = a2 ^ x ^ _AES_XTIME[a2 ^ a3] ^ rk[r][i + 2]
            ns[i + 3] = a3 ^ x ^ _AES_XTIME[a3 ^ a0] ^ rk[r][i + 3]
        s = ns
    s = [
        _AES_SBOX[s[0]], _AES_SBOX[s[5]], _AES_SBOX[s[10]], _AES_SBOX[s[15]],
        _AES_SBOX[s[4]], _AES_SBOX[s[9]], _AES_SBOX[s[14]], _AES_SBOX[s[3]],
        _AES_SBOX[s[8]], _AES_SBOX[s[13]], _AES_SBOX[s[2]], _AES_SBOX[s[7]],
        _AES_SBOX[s[12]], _AES_SBOX[s[1]], _AES_SBOX[s[6]], _AES_SBOX[s[11]],
    ]
    return bytes(s[i] ^ rk[10][i] for i in range(16))


def _gf128_mul(x: int, y: int) -> int:
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        y = ((y >> 1) ^ 0xE1000000000000000000000000000000) if (y & 1) else (y >> 1)
    return z


def _aes128_gcm_open(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes | None:
    if len(ct_and_tag) < 16 or len(ct_and_tag) > 2048:
        return None
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    rk = _aes128_expand(key)
    h_int = int.from_bytes(_aes128_enc(rk, b"\x00" * 16), "big")
    y = 0
    for seg in (
        aad + b"\x00" * ((16 - len(aad) % 16) % 16),
        ct + b"\x00" * ((16 - len(ct) % 16) % 16),
        struct.pack("!QQ", len(aad) * 8, len(ct) * 8),
    ):
        for off in range(0, len(seg), 16):
            y = _gf128_mul(y ^ int.from_bytes(seg[off : off + 16], "big"), h_int)
    j0 = nonce + b"\x00\x00\x00\x01"
    exp_tag = (y ^ int.from_bytes(_aes128_enc(rk, j0), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(exp_tag, tag):
        return None
    out = bytearray(len(ct))
    ctr = int.from_bytes(j0, "big")
    for off in range(0, len(ct), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        ks = _aes128_enc(rk, ctr.to_bytes(16, "big"))
        blk = ct[off : off + 16]
        for j in range(len(blk)):
            out[off + j] = blk[j] ^ ks[j]
    return bytes(out)


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(secret, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


def decrypt_quic_initial_packet(pkt: bytes) -> tuple[bytes, int, list[tuple[int, bytes]]] | None:
    """解密单个 QUIC v1/v2 Client Initial 数据报，返回 (dcid, quic_version, [(crypto_offset, crypto_bytes), ...])。"""
    if len(pkt) < 64 or len(pkt) > 2048 or (pkt[0] & 0xC0) != 0xC0:
        return None
    ver = struct.unpack("!I", pkt[1:5])[0]
    if ver == 0x00000001:
        salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
        lbl_k, lbl_iv, lbl_hp, init_type = b"quic key", b"quic iv", b"quic hp", 0
    elif ver == 0x6B3343CF:
        salt = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
        lbl_k, lbl_iv, lbl_hp, init_type = b"quicv2 key", b"quicv2 iv", b"quicv2 hp", 1
    else:
        return None
    if ((pkt[0] & 0x30) >> 4) != init_type:
        return None
    pos = 5
    dcid_len = pkt[pos]
    pos += 1
    if dcid_len > 20 or pos + dcid_len + 1 > len(pkt):
        return None
    dcid = pkt[pos : pos + dcid_len]
    pos += dcid_len
    scid_len = pkt[pos]
    pos += 1 + scid_len
    tok = _quic_varint(pkt, pos)
    if tok is None:
        return None
    tok_len, pos = tok
    pos += tok_len
    rem = _quic_varint(pkt, pos)
    if rem is None:
        return None
    rem_len, pn_off = rem
    if pn_off + 20 > len(pkt) or pn_off + rem_len > len(pkt):
        return None

    isec = hmac.new(salt, dcid, hashlib.sha256).digest()
    csec = _hkdf_expand_label(isec, b"client in", 32)
    key = _hkdf_expand_label(csec, lbl_k, 16)
    iv = _hkdf_expand_label(csec, lbl_iv, 12)
    hp = _hkdf_expand_label(csec, lbl_hp, 16)

    mask = _aes128_enc(_aes128_expand(hp), pkt[pn_off + 4 : pn_off + 20])
    b0 = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (b0 & 0x03) + 1
    hdr = bytearray(pkt[: pn_off + pn_len])
    hdr[0] = b0
    pn = 0
    for i in range(pn_len):
        hdr[pn_off + i] ^= mask[1 + i]
        pn = (pn << 8) | hdr[pn_off + i]
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    pt = _aes128_gcm_open(key, nonce, pkt[pn_off + pn_len : pn_off + rem_len], bytes(hdr))
    if pt is None:
        return None

    # 提取明文载荷中的 CRYPTO 帧 (0x06)，兼容 Chrome PADDING(0x00)/PING(0x01) 混淆与乱序分片
    p = 0
    end = len(pt)
    segs: list[tuple[int, bytes]] = []
    while p < end and len(segs) < 32:
        ft = pt[p]
        p += 1
        if ft in (0x00, 0x01):
            continue
        if ft == 0x06:
            r_off = _quic_varint(pt, p)
            if r_off is None:
                break
            c_off, p = r_off
            r_ln = _quic_varint(pt, p)
            if r_ln is None:
                break
            c_ln, p = r_ln
            if p + c_ln > end or c_off > 8192:
                break
            segs.append((c_off, pt[p : p + c_ln]))
            p += c_ln
        else:
            break
    return dcid, ver, segs


def guess_quic_stack(tls_info: dict, tp: dict) -> tuple[str, str]:
    params = tp.get("params") or {}
    has_gr_tp = bool(tp.get("hasGreaseParam"))
    has_gr_bit = bool(params.get("grease_quic_bit"))
    init_data = params.get("initial_max_data")
    bidi_loc = params.get("initial_max_stream_data_bidi_local")
    dgram = params.get("max_datagram_frame_size")
    alps = bool(tls_info.get("alpsExtension"))
    cert_comp = tls_info.get("certCompression") or []

    if dgram == 65536 and (has_gr_tp or has_gr_bit) and ("brotli" in cert_comp or alps):
        return "quiche", "Chromium quiche 原生 QUIC 栈"
    if params.get("active_connection_id_limit") == 8 and not alps:
        return "neqo", "Firefox neqo 原生 QUIC 栈"
    if init_data in (2097152, 4194304, 1048576) and not alps and not cert_comp and has_gr_bit:
        return "nw_quic", "Apple WebKit / Network.framework QUIC 栈"
    if not cert_comp and not alps and (params.get("max_udp_payload_size") in (1452, 1280) or bidi_loc == 524288):
        return "quic-go", "Go quic-go 代理传输库 (Sing-box / Mihomo / Hysteria2)"
    return "generic_quic", "标准 QUIC v1 客户端栈"


class QUICInitialCollector:
    """独立 UDP 监听器只解析 QUIC Initial，不完成 H3，也不关联到 HTTP 请求。"""

    def __init__(self, port: int = 443) -> None:
        self.port = port
        self.active = False
        self.error: str | None = None
        self._socks: list[socket.socket] = []
        self._frag_cache = TTLCache(maxsize=1024, ttl_sec=8.0)

    def start(self) -> None:
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s4.bind(("0.0.0.0", self.port))
            self._socks.append(s4)
            try:
                s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s6.bind(("::", self.port))
                self._socks.append(s6)
            except OSError:
                pass
            self.active = True
            for sk in self._socks:
                threading.Thread(target=self._loop, args=(sk,), name="quic-udp", daemon=True).start()
        except Exception as exc:
            self.error = str(exc)
            self.active = False

    def ingest_datagram(self, raw: bytes, peer: tuple) -> dict | None:
        dec = decrypt_quic_initial_packet(raw)
        if dec is None:
            return None
        dcid, ver, new_segs = dec
        if not new_segs:
            return None
        fkey = (peer, ver, dcid)
        prev = self._frag_cache.get(fkey)
        all_segs: list[tuple[int, bytes]] = list(prev) if isinstance(prev, list) else []
        all_segs.extend(new_segs)
        all_segs.sort(key=lambda x: x[0])

        assembled = bytearray()
        for off, chunk in all_segs:
            if off > len(assembled):
                break
            if off + len(chunk) > len(assembled):
                assembled.extend(chunk[len(assembled) - off :])

        if len(assembled) < 4 or assembled[0] != 0x01:
            self._frag_cache.set(fkey, all_segs[:24], ttl_sec=5.0)
            return None
        hs_len = (assembled[1] << 16) | (assembled[2] << 8) | assembled[3]
        if len(assembled) < 4 + hs_len:
            self._frag_cache.set(fkey, all_segs[:24], ttl_sec=5.0)
            return None

        self._frag_cache.discard(fkey)
        if hs_len + 4 > 0xFFFF:
            return None
        hs_bytes = bytes(assembled[: 4 + hs_len])
        tls_rec = b"\x16\x03\x01" + struct.pack("!H", len(hs_bytes)) + hs_bytes
        tls_info = parse_tls_client_hello(tls_rec, transport_prefix="q")
        if not tls_info:
            return None
        tp = tls_info.get("quicTransportParams") or {"params": {}, "order": [], "hasGreaseParam": False}
        fam, label = guess_quic_stack(tls_info, tp)
        out = {
            "quicVersion": "v2" if ver == 0x6B3343CF else "v1",
            "ja4q": tls_info["ja4"],
            "pqSupported": tls_info["pqSupported"],
            "pqGroup": tls_info["pqGroup"],
            "alpn": tls_info["alpn"],
            "stackFamily": fam,
            "stackGuess": label,
            "transportParams": tp.get("params") or {},
            "paramOrder": tp.get("order") or [],
            "hasGreaseParam": bool(tp.get("hasGreaseParam")),
        }
        return out

    def _loop(self, sock: socket.socket) -> None:
        while self.active:
            try:
                data, addr = sock.recvfrom(2048)
                self.ingest_datagram(data, addr)
            except Exception:
                continue

# ---------------------------------------------------------------------------
# HTTP/2 Akamai 原始帧指纹解析器 (RFC 9113 / RFC 7541 HPACK) + 零侵入 TLS 嗅探桥
# ---------------------------------------------------------------------------

H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# RFC 7541 Appendix A 静态表前 15 项（覆盖全部 HTTP/2 伪头部）
HPACK_STATIC_NAMES: dict[int, str] = {
    1: ":authority",
    2: ":method",
    3: ":method",
    4: ":path",
    5: ":path",
    6: ":scheme",
    7: ":scheme",
    8: ":status",
    9: ":status",
    10: ":status",
    11: ":status",
    12: ":status",
    13: ":status",
    14: ":status",
}

PSEUDO_SHORT: dict[str, str] = {
    ":method": "m",
    ":authority": "a",
    ":scheme": "s",
    ":path": "p",
    ":protocol": "proto",
}

# RFC 7541 Appendix B 常用 ASCII 符号 Huffman 表（足以无损还原任意伪头与常见请求头名）
_HPACK_HUFF_PAIRS: tuple[tuple[int, int, int], ...] = (
    (0x1FF8, 13, 48), (0x7FFFD8, 23, 49), (0xFFFFFE2, 28, 50),  # placeholder overridden below
)
# 标准 RFC 7541 Huffman (code, bit_len) 索引 0..127 子集（覆盖全部可见字符与 ':','a'-'z','-','_'）
_RFC7541_HUFFMAN_ASCII: dict[tuple[int, int], str] = {
    (0x0, 5): "0", (0x1, 5): "1", (0x2, 5): "2", (0x3, 6): "a", (0x4, 6): "c",
    (0x5, 6): "e", (0x6, 6): "i", (0x7, 6): "o", (0x8, 6): "s", (0x9, 6): "t",
    (0x14, 6): " ", (0x15, 6): "%", (0x16, 6): "-", (0x17, 6): ".", (0x18, 6): "/",
    (0x19, 6): "3", (0x1A, 6): "4", (0x1B, 6): "5", (0x1C, 6): "6", (0x1D, 6): "7",
    (0x1E, 6): "8", (0x1F, 6): "9", (0x20, 6): "=", (0x21, 6): "A", (0x22, 6): "_",
    (0x23, 6): "b", (0x24, 6): "d", (0x25, 6): "f", (0x26, 6): "g", (0x27, 6): "h",
    (0x28, 6): "l", (0x29, 6): "m", (0x2A, 6): "n", (0x2B, 6): "p", (0x2C, 6): "r",
    (0x2D, 6): "u", (0x5C, 7): ":", (0x5D, 7): "B", (0x5E, 7): "C", (0x5F, 7): "D",
    (0x60, 7): "E", (0x61, 7): "F", (0x62, 7): "G", (0x63, 7): "H", (0x64, 7): "I",
    (0x65, 7): "J", (0x66, 7): "K", (0x67, 7): "L", (0x68, 7): "M", (0x69, 7): "N",
    (0x6A, 7): "O", (0x6B, 7): "P", (0x6C, 7): "Q", (0x6D, 7): "R", (0x6E, 7): "S",
    (0x6F, 7): "T", (0x70, 7): "U", (0x71, 7): "V", (0x72, 7): "W", (0x73, 7): "Y",
    (0x74, 7): "j", (0x75, 7): "k", (0x76, 7): "q", (0x77, 7): "v", (0x78, 7): "w",
    (0x79, 7): "x", (0x7A, 7): "y", (0x7B, 7): "z", (0xF8, 8): "&", (0xF9, 8): "*",
    (0xFA, 8): ",", (0xFB, 8): ";", (0xFC, 8): "X", (0xFD, 8): "Z",
}


def _hpack_huff_decode(data: bytes) -> str:
    acc = 0
    bits = 0
    out: list[str] = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        progressed = True
        while progressed and bits >= 5:
            progressed = False
            for blen in (5, 6, 7, 8):
                if bits < blen:
                    break
                code = (acc >> (bits - blen)) & ((1 << blen) - 1)
                ch = _RFC7541_HUFFMAN_ASCII.get((code, blen))
                if ch is not None:
                    out.append(ch)
                    bits -= blen
                    acc &= (1 << bits) - 1 if bits > 0 else 0
                    progressed = True
                    break
            if not progressed and bits > 24:
                # 罕见高阶符号（非伪头部字符），停止解码字段名
                return "".join(out)
    return "".join(out)


def _hpack_int(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int] | None:
    if pos >= len(buf):
        return None
    mask = (1 << prefix_bits) - 1
    val = buf[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    shift = 0
    while pos < len(buf) and shift <= 28:
        b = buf[pos]
        pos += 1
        val += (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7
    return None


def _hpack_str(buf: bytes, pos: int) -> tuple[str, int] | None:
    if pos >= len(buf):
        return None
    huff = (buf[pos] & 0x80) != 0
    ln_res = _hpack_int(buf, pos, 7)
    if ln_res is None:
        return None
    length, pos = ln_res
    if length < 0 or pos + length > len(buf):
        return None
    raw = buf[pos : pos + length]
    pos += length
    if huff:
        return _hpack_huff_decode(raw), pos
    return raw.decode("latin-1", errors="ignore"), pos


def _decode_hpack_pseudo_order(block: bytes) -> list[str]:
    pos = 0
    end = len(block)
    pseudo: list[str] = []
    dyn_names: list[str] = []
    steps = 0
    while pos < end and steps < 40:
        steps += 1
        b = block[pos]
        if b & 0x80:
            res = _hpack_int(block, pos, 7)
            if res is None:
                break
            idx, pos = res
            name = HPACK_STATIC_NAMES.get(idx) or (dyn_names[idx - 62] if 62 <= idx < 62 + len(dyn_names) else "")
        elif (b & 0xC0) == 0x40:
            res = _hpack_int(block, pos, 6)
            if res is None:
                break
            idx, pos = res
            if idx == 0:
                ns = _hpack_str(block, pos)
                if ns is None:
                    break
                name, pos = ns
            else:
                name = HPACK_STATIC_NAMES.get(idx) or (dyn_names[idx - 62] if 62 <= idx < 62 + len(dyn_names) else "")
            vs = _hpack_str(block, pos)
            if vs is None:
                break
            _, pos = vs
            dyn_names.insert(0, name)
        elif (b & 0xE0) == 0x20:
            res = _hpack_int(block, pos, 5)
            if res is None:
                break
            _, pos = res
            continue
        else:
            res = _hpack_int(block, pos, 4)
            if res is None:
                break
            idx, pos = res
            if idx == 0:
                ns = _hpack_str(block, pos)
                if ns is None:
                    break
                name, pos = ns
            else:
                name = HPACK_STATIC_NAMES.get(idx) or (dyn_names[idx - 62] if 62 <= idx < 62 + len(dyn_names) else "")
            vs = _hpack_str(block, pos)
            if vs is None:
                break
            _, pos = vs

        if name.startswith(":"):
            short = PSEUDO_SHORT.get(name, name.lstrip(":"))
            if short not in pseudo:
                pseudo.append(short)
        elif pseudo:
            # RFC 9113：所有伪头部必须出现在普通头部之前，遇到首个普通头即可结束提取
            break
    return pseudo


def guess_h2_client(
    settings_pairs: list[tuple[int, int]],
    window_update: int,
    priorities: list[str],
    pseudo: list[str],
) -> tuple[str, str]:
    s_map = {k: v for k, v in settings_pairs}
    s_ids = [k for k, _ in settings_pairs]
    p_str = ",".join(pseudo)

    # 1) Chromium (Chrome / Edge / Brave): INITIAL_WINDOW_SIZE=6291456 (6MB), WU=15663105, m,a,s,p
    if (s_map.get(4) == 6291456 or window_update == 15663105) and p_str.startswith("m,a,s,p"):
        return "chromium", "Chromium / Blink 原生 H2 栈"
    # 2) Firefox (Gecko / Necko): INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384, WU=12517377, m,p,a,s
    if (s_map.get(4) == 131072 or window_update == 12517377) and p_str.startswith("m,p,a,s"):
        return "firefox", "Firefox / Necko 原生 H2 栈"
    # 3) Apple WebKit (Safari macOS / iOS): WU=10485760, settings 含 2:0 + 4:2097152/4194304 + 3:100, m,s,p,a 或 m,s,a,p
    if window_update == 10485760 or (p_str in ("m,s,p,a", "m,s,a,p") and s_map.get(4) in (2097152, 4194304)):
        return "webkit", "Safari / Apple WebKit 原生 H2 栈"
    # 4) Go golang.org/x/net/http2 (含基于 utls+net/http2 的客户端): WU=1073741824 (1GB) 或 4:4194304+6:10485760
    if window_update == 1073741824 or (s_map.get(4) == 4194304 and s_map.get(6) == 10485760):
        return "go", "Go x/net/http2 库"
    # 5) curl / nghttp2: settings 以 3:100 开头且 WU=1048510465，或典型 3,4,2 顺序
    if window_update == 1048510465 or s_ids[:3] == [3, 4, 2]:
        return "curl", "curl / nghttp2 库"
    # 6) Python hyper-h2 / httpx / aiohttp 或 Node undici
    if s_map.get(4) == 65535 and window_update == 0:
        return "python", "Python hyper-h2 / httpx 库"
    if p_str == "m,a,s,p":
        return "chromium_like", "类 Chromium H2 栈 (自定义窗口参数)"
    if p_str == "m,p,a,s":
        return "firefox_like", "类 Firefox H2 栈"
    if p_str in ("m,s,p,a", "m,s,a,p"):
        return "webkit_like", "类 WebKit / nghttp2 H2 栈"
    return "unknown", "非标准 / 定制 HTTP/2 客户端"


def parse_h2_client_preface(data: bytes) -> dict | None:
    """解析客户端 HTTP/2 Connection Preface 后的初始帧序列并生成 Akamai 标准指纹。"""
    if not data.startswith(H2_CLIENT_PREFACE):
        return None
    pos = len(H2_CLIENT_PREFACE)
    end = len(data)
    settings_pairs: list[tuple[int, int]] | None = None
    window_update = 0
    priorities: list[str] = []
    pseudo_order: list[str] = []
    headers_priority: str | None = None
    frames_seen = 0

    while pos + 9 <= end and frames_seen < 16:
        length = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
        ftype = data[pos + 3]
        flags = data[pos + 4]
        stream_id = struct.unpack("!I", data[pos + 5 : pos + 9])[0] & 0x7FFFFFFF
        pos += 9
        if pos + length > end:
            break
        payload = data[pos : pos + length]
        pos += length
        frames_seen += 1

        if ftype == 0x04 and (flags & 0x01) == 0 and settings_pairs is None:
            # SETTINGS 帧（仅取首个非 ACK 客户端 SETTINGS，保留非 GREASE 项与 GREASE 标记）
            pairs: list[tuple[int, int]] = []
            grease_setting = False
            for off in range(0, len(payload) - (len(payload) % 6), 6):
                sid, sval = struct.unpack("!HI", payload[off : off + 6])
                if sid in GREASE_VALUES:
                    grease_setting = True
                    continue
                pairs.append((sid, sval))
            settings_pairs = pairs
        elif ftype == 0x08 and stream_id == 0 and len(payload) == 4 and window_update == 0:
            window_update = struct.unpack("!I", payload)[0] & 0x7FFFFFFF
        elif ftype == 0x02 and len(payload) == 5:
            dep_raw, weight = struct.unpack("!IB", payload)
            excl = 1 if (dep_raw & 0x80000000) else 0
            dep = dep_raw & 0x7FFFFFFF
            priorities.append(f"{stream_id}:{excl}:{dep}:{weight + 1}")
        elif ftype == 0x01 and not pseudo_order:
            hblock = payload
            if flags & 0x08:  # PADDED
                if not hblock:
                    break
                pad_len = hblock[0]
                hblock = hblock[1 : len(hblock) - pad_len if pad_len < len(hblock) else 1]
            if flags & 0x20:  # PRIORITY flag inside HEADERS
                if len(hblock) < 5:
                    break
                dep_raw, weight = struct.unpack("!IB", hblock[:5])
                excl = 1 if (dep_raw & 0x80000000) else 0
                dep = dep_raw & 0x7FFFFFFF
                headers_priority = f"{excl}:{dep}:{weight + 1}"
                if not priorities:
                    priorities.append(f"{stream_id}:{headers_priority}")
                hblock = hblock[5:]
            pseudo_order = _decode_hpack_pseudo_order(hblock)
            break

    if settings_pairs is None and not pseudo_order:
        return None

    s_pairs = settings_pairs or []
    settings_str = ";".join(f"{k}:{v}" for k, v in s_pairs)
    prio_str = ",".join(priorities) if priorities else "0"
    pseudo_str = ",".join(pseudo_order)
    akamai = f"{settings_str}|{window_update:02d}|{prio_str}|{pseudo_str}" if window_update == 0 else f"{settings_str}|{window_update}|{prio_str}|{pseudo_str}"
    fam, label = guess_h2_client(s_pairs, window_update, priorities, pseudo_order)
    fp_hash = hashlib.md5(akamai.encode("ascii", errors="ignore")).hexdigest()
    return {
        "h2Used": True,
        "akamai": akamai,
        "akamaiHash": fp_hash,
        "settings": settings_str,
        "windowUpdate": window_update,
        "priority": prio_str,
        "headersPriority": headers_priority,
        "pseudoOrder": pseudo_order,
        "clientFamily": fam,
        "clientGuess": label,
    }


def _socket_connection_key(conn: socket.socket, peer: tuple) -> TcpConnection | None:
    try:
        local = conn.getsockname()
    except OSError:
        return None
    if len(peer) < 2 or not isinstance(local, tuple) or len(local) < 2:
        return None
    return _tcp_connection_key(peer[0], peer[1], local[0], local[1])


def _read_proxy_protocol_v1(conn: socket.socket, *, trusted_peer: bool) -> TcpConnection | None:
    """读取受信 PROXY v1 的原始 TCP 四元组；无头或 UNKNOWN 不推断端点。"""
    peek = conn.recv(108, socket.MSG_PEEK)
    if not peek.startswith(b"P"):
        return None
    if not trusted_peer:
        raise ValueError("untrusted PROXY preface")
    # 已缓冲的完整行只读一次；分段时逐字节读并遵守同一个 deadline，不吞 TLS 数据。
    end = peek.find(b"\r\n")
    first_read = end + 2 if end >= 0 else len(peek)
    line = bytearray()
    timeout = conn.gettimeout()
    deadline = time.monotonic() + (timeout or 8.0)
    try:
        while len(line) < 108 and not line.endswith(b"\r\n"):
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise TimeoutError("incomplete PROXY line")
            conn.settimeout(remain)
            chunk = conn.recv(max(1, first_read - len(line)))
            if not chunk:
                break
            line.extend(chunk)
    finally:
        conn.settimeout(timeout)
    if not line.endswith(b"\r\n"):
        raise ValueError("incomplete PROXY line")
    parts = line[:-2].decode("ascii").split(" ")
    if len(parts) >= 2 and parts[:2] == ["PROXY", "UNKNOWN"]:
        return None
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        raise ValueError("invalid PROXY TCP line")
    _, family, peer_ip, local_ip, peer_port, local_port = parts
    peer, local = _ip_literal(peer_ip), _ip_literal(local_ip)
    version = int(family[-1])
    if peer is None or local is None or peer.version != version or local.version != version:
        raise ValueError("invalid PROXY address family")
    key = _tcp_connection_key(peer_ip, peer_port, local_ip, local_port)
    if key is None:
        raise ValueError("invalid PROXY TCP endpoints")
    return key


def _proxy_v1_line(key: TcpConnection | None) -> bytes:
    if key is None:
        return b"PROXY UNKNOWN\r\n"
    peer, sport, local, dport = key
    family = "TCP6" if ":" in peer else "TCP4"
    return f"PROXY {family} {peer} {local} {sport} {dport}\r\n".encode("ascii")


def _socket_tls_meta(ssock: ssl.SSLSocket) -> dict:
    cipher = ssock.cipher()
    return {
        "tlsProtocol": ssock.version() or "",
        "tlsCipher": cipher[0] if cipher else "",
        "tlsAlpn": ssock.selected_alpn_protocol() or "",
        "tlsSessionReused": "r" if ssock.session_reused else ".",
    }


class TLSBridgeServer:
    """本地回环 TLS 终止 + HTTP/2 原始帧无损旁路嗅探桥（将解密流转发至 Nginx h2c / h1 后端）。"""

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        default_cert: str,
        default_key: str,
        sni_certs: dict[str, tuple[str, str]] | None = None,
        h2c_backend: tuple[str, int] = ("127.0.0.1", 10082),
        h1_backend: tuple[str, int] = ("127.0.0.1", 10081),
        upstream_proxy_protocol: bool = True,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.h2c_backend = h2c_backend
        self.h1_backend = h1_backend
        self.upstream_proxy_protocol = upstream_proxy_protocol
        self.active = False
        self.error: str | None = None
        self._sock: socket.socket | None = None
        self._ctx = self._make_ctx(default_cert, default_key)
        self._sni_map: dict[str, ssl.SSLContext] = {}
        for host_name, (cpath, kpath) in (sni_certs or {}).items():
            self._sni_map[host_name.lower().strip()] = self._make_ctx(cpath, kpath)
        if self._sni_map:
            self._ctx.sni_callback = self._on_sni

    @staticmethod
    def _make_ctx(cert_path: str, key_path: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return ctx

    def _on_sni(self, ssl_sock: ssl.SSLSocket, server_name: str | None, _initial_ctx: ssl.SSLContext) -> None:
        if server_name:
            sub = self._sni_map.get(server_name.lower().strip())
            if sub is not None:
                ssl_sock.context = sub

    def start(self) -> None:
        try:
            family = socket.AF_INET6 if ":" in self.listen_host else socket.AF_INET
            srv = socket.socket(family, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, self.listen_port))
            srv.listen(256)
            self._sock = srv
            self.active = True
            threading.Thread(target=self._accept_loop, name="tls-h2-bridge", daemon=True).start()
        except Exception as exc:
            self.error = str(exc)
            self.active = False

    def stop(self) -> None:
        self.active = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while self.active:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                if not self.active:
                    break
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(8.0)
        ssock: ssl.SSLSocket | None = None
        up: socket.socket | None = None
        key = None
        owner = object()
        try:
            trusted = _is_trusted_edge_ip(addr[0])
            key = _read_proxy_protocol_v1(conn, trusted_peer=trusted)
            if not trusted:
                key = _socket_connection_key(conn, addr)

            # 先无损窥探，TLS 成功前不发布任何观测；缺原始端点时仍正常转发。
            ti = None
            if key is not None:
                ch_peek = conn.recv(_CAPTURE_BYTES, socket.MSG_PEEK)
                if len(ch_peek) >= 5 and ch_peek[0] == 0x16:
                    need = 5 + struct.unpack_from("!H", ch_peek, 3)[0]
                    if len(ch_peek) < need <= _CAPTURE_BYTES:
                        time.sleep(0.012)
                        ch_peek = conn.recv(_CAPTURE_BYTES, socket.MSG_PEEK)
                    ti = parse_tls_client_hello(ch_peek)

            ssock = self._ctx.wrap_socket(conn, server_side=True)
            meta = _socket_tls_meta(ssock)
            alpn = meta["tlsAlpn"]
            if alpn == "h2":
                meta["httpVersion"] = "HTTP/2.0"
            elif alpn == "http/1.1":
                meta["httpVersion"] = "HTTP/1.1"
            if key is not None:
                self._publish_handshake(key, owner, meta, ti)

            target = self.h2c_backend if alpn == "h2" else self.h1_backend
            up = socket.create_connection(target, timeout=5.0)
            if self.upstream_proxy_protocol:
                up.sendall(_proxy_v1_line(key))

            ssock.settimeout(65.0)
            up.settimeout(65.0)

            def _back_to_client() -> None:
                try:
                    while True:
                        data = up.recv(32768)
                        if not data:
                            break
                        ssock.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        ssock.close()
                    except Exception:
                        pass

            t_rev = threading.Thread(target=_back_to_client, daemon=True)
            t_rev.start()

            preface_buf = bytearray()
            done_h2 = alpn != "h2" or key is None
            while True:
                chunk = ssock.recv(16384)
                if not chunk:
                    break
                if not done_h2 and key is not None:
                    take = min(len(chunk), 8192 - len(preface_buf))
                    if take > 0:
                        preface_buf.extend(chunk[:take])
                    parsed = parse_h2_client_preface(bytes(preface_buf))
                    if parsed is not None:
                        # 在转发首个 HTTP 请求前发布，且旧桥任务不能改写新连接。
                        self._publish_h2(key, owner, parsed)
                        if parsed.get("pseudoOrder"):
                            done_h2 = True
                    if done_h2 or len(preface_buf) >= 8192:
                        done_h2 = True
                        preface_buf.clear()
                up.sendall(chunk)
            try:
                up.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            t_rev.join(timeout=5.0)
        except Exception:
            pass
        finally:
            if key is not None:
                with _WIRE_LOCK:
                    rec = PACKET_CACHE.get(key)
                    if isinstance(rec, dict) and rec.get("_bridge") is owner:
                        PACKET_CACHE.discard(key)
            for s in (up, ssock, conn):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

    @staticmethod
    def _publish_handshake(key: TcpConnection, owner: object, meta: dict, tls: dict | None) -> None:
        with _WIRE_LOCK:
            previous = PACKET_CACHE.get(key)
            rec = dict(previous) if isinstance(previous, dict) else {}
            syn = rec.get("_syn")
            captured_hello = rec.get("tlsClientHello")
            if ("_bridge" in rec or not syn or not (0.0 <= time.monotonic() - syn[0] <= _SYN_HELLO_SEC)
                    or (tls and captured_hello and tls["helloId"] != captured_hello["helloId"])):
                # 相同四元组可能被复用；只有本次新 SYN / 一致的旁路 ClientHello 可保留。
                rec = {}
            rec.update(_bridge=owner, connection=meta)
            if tls is not None:
                rec["tlsClientHello"] = tls
            if meta["tlsAlpn"] != "h2":
                rec["http2"] = {"h2Used": False, "alpn": meta["tlsAlpn"]}
            PACKET_CACHE.set(key, rec)

    @staticmethod
    def _publish_h2(key: TcpConnection, owner: object, h2: dict) -> None:
        with _WIRE_LOCK:
            rec = PACKET_CACHE.get(key)
            if isinstance(rec, dict) and rec.get("_bridge") is owner:
                PACKET_CACHE.set(key, {**rec, "http2": h2})


# 浏览器原生从不发送、只会由中间层（HTTPS 解密代理 / 企业网关 / 杀软 Web 防护 / CDN Worker 反代）注入的转发头
PROXY_LEAK_HEADERS = (
    "via", "forwarded", "x-forwarded-host", "x-forwarded-server", "x-forwarded-port", "x-forwarded",
    "forwarded-for", "x-proxy-id", "proxy-connection", "x-bluecoat-via", "client-ip", "true-client-ip",
    "x-client-ip", "x-originating-ip", "x-cluster-client-ip", "x-remote-ip", "x-remote-addr",
    "x-proxyuser-ip", "wl-proxy-client-ip", "proxy-client-ip", "x-coming-from", "x-imforwards",
    "x-iwproxy-nesting", "x-proxymesh-ip", "fastly-client-ip", "akamai-origin-hop", "x-amz-cf-id",
    "cf-worker",
)
CDN_ORIGIN_HEADERS = ("cf-connecting-ip", "cf-ray", "cdn-loop", "cf-ipcountry", "cf-visitor")
_HDR_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")


def detect_proxy_headers(headers, real_ip: str = "", trusted_cf: bool = False) -> dict:
    """识别 TLS 终止后仍出现在 HTTP 请求中的代理转发头（仅返回头名称、跳数与脱敏 Via，不回显任何 IP）。"""
    present = {k.lower() for k in headers.keys()}
    names = [h for h in PROXY_LEAK_HEADERS if h in present]
    if not trusted_cf:
        names += [h for h in CDN_ORIGIN_HEADERS if h in present]
    xff_parts = [p.strip() for p in (headers.get("X-Forwarded-For") or "").split(",") if p.strip()]
    if real_ip:
        # 本机 Nginx 以 $proxy_add_x_forwarded_for 追加了真实对端；可信 CF 边缘再额外贡献 1 跳
        hops = max(0, len(xff_parts) - 1 - (1 if trusted_cf else 0))
    else:
        hops = len(xff_parts)
    via_raw = headers.get("Via") or ""
    via = _HDR_IP_RE.sub("x.x.x.x", " ".join(via_raw.split()))[:80]
    return {"names": names, "xffHops": hops, "via": via, "suspect": bool(names or hops)}


class WhoProbeHandler(BaseHTTPRequestHandler):
    server_version = "WhoProbe/2.0"
    _head_only = False

    def log_message(self, fmt: str, *args) -> None:
        return  # 不记录访问者 IP 日志，保护隐私且保持安静

    def _accepts_gzip(self) -> bool:
        return "gzip" in (self.headers.get("Accept-Encoding") or "").lower()

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        cache_control: str = "no-store",
        status: int = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        use_gzip = len(body) > 512 and self._accepts_gzip()
        out = gzip.compress(body, compresslevel=5) if use_gzip else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if not self._head_only:
            self.wfile.write(out)

    def do_HEAD(self) -> None:
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _send_json(
        self,
        payload: dict,
        cache_control: str = "no-store",
        status: int = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            raw,
            "application/json; charset=utf-8",
            cache_control=cache_control,
            status=status,
            extra_headers=extra_headers,
        )

    def _single_header(self, name: str) -> str:
        values = self.headers.get_all(name, ())
        if len(values) != 1 or len(values[0]) > 1024 or "\n" in values[0] or "\r" in values[0]:
            return ""
        return values[0].strip()

    def _is_trusted_edge(self) -> bool:
        """只检查实际后端 TCP peer，绝不用请求头校验其自身来源。"""
        return _is_trusted_edge_ip(self.client_address[0])

    def _observed_wire_key(self) -> TcpConnection | None:
        """返回访客到观测入口的 (peer IP, peer port, local IP, local port)，仅内部使用。"""
        if self._is_trusted_edge():
            return _tcp_connection_key(*(self._single_header(header) for header in EDGE_WIRE_HEADERS))
        return _socket_connection_key(self.connection, self.client_address)

    def _trusted_real_ip(self) -> str:
        if not self._is_trusted_edge():
            return ""
        key = self._observed_wire_key()
        if key is not None:
            return key[0]
        addr = _normalized_ip(self._single_header("X-Real-IP"))
        return str(addr) if addr is not None and not (addr.is_unspecified or addr.is_multicast) else ""

    def _origin_and_base(self, mounted_under_who: bool) -> tuple[str, str]:
        connection_proto = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
        forwarded = self._single_header("X-Forwarded-Proto") if self._is_trusted_edge() else ""
        proto = forwarded if forwarded in ("http", "https") else connection_proto
        host = (self.headers.get("Host") or "localhost").strip()
        base_href = "/who/" if mounted_under_who else "/"
        origin_prefix = f"{proto}://{host}{'/who' if mounted_under_who else ''}"
        return origin_prefix, base_href

    def _extract_client_ip(self) -> str:
        real_ip = self._trusted_real_ip()
        if real_ip and is_cloudflare_edge_ip(real_ip):
            norm_cf, _ = egress_intel.normalize_public_ip(self._single_header("CF-Connecting-IP"))
            if norm_cf:
                return norm_cf
        addr = _normalized_ip(self.client_address[0])
        return real_ip or (str(addr) if addr is not None else self.client_address[0])

    def _observed_connection(self) -> tuple[dict, dict]:
        """返回当前请求关联的连接协商与包观测；缺测为 null/空串，无 IP 回退。"""
        trusted = self._is_trusted_edge()
        key = self._observed_wire_key()
        ingress_proto = self._single_header("X-HTTP-Version") if trusted else ""
        ingress_alpn = self._single_header("X-TLS-ALPN") if trusted else ""
        # TCP/UDP can reuse the same tuple. A CDN's connection to this origin
        # also must not be reported as the forwarded browser's wire evidence.
        browser_tcp = key is not None and not (ingress_proto.upper().startswith("HTTP/3") or ingress_alpn.startswith("h3"))
        browser_tcp = browser_tcp and (not trusted or self._extract_client_ip() == key[0])
        record = PACKET_CACHE.get(key) if browser_tcp else None
        rec = record if isinstance(record, dict) else {}
        conn = dict.fromkeys(EDGE_PROTOCOL_HEADERS, "")
        conn["source"] = "unknown"
        if key is not None and trusted:
            conn["source"] = "trusted-edge"
            bridge_meta = rec.get("connection") or {}
            for field, header in EDGE_PROTOCOL_HEADERS.items():
                conn[field] = bridge_meta[field] if field in bridge_meta else self._single_header(header)
            conn["httpVersion"] = self._single_header("X-HTTP-Version") or conn["httpVersion"]
        elif key is not None:
            conn["source"] = "direct"
            conn["httpVersion"] = self.request_version
            if isinstance(self.connection, ssl.SSLSocket):
                conn.update(_socket_tls_meta(self.connection))

        tls_hello = rec.get("tlsClientHello")
        return conn, {
            "snifferActive": bool(SNIFFER and SNIFFER.active),
            "tlsBridgeActive": bool(TLS_BRIDGE and TLS_BRIDGE.active),
            "quicCollectorActive": bool(QUIC_COLLECTOR and QUIC_COLLECTOR.active),
            "tcp": rec.get("tcp"),
            "tlsClientHello": tls_hello,
            "tlsPermutation": record_tls_hello_sample(tls_hello, self._single_header(WHO_RUN_TOKEN_HEADER), key)
            if isinstance(tls_hello, dict) else None,
            "http2": rec.get("http2"),
            "quic": None,  # 独立 UDP Initial 解析没有 HTTP 请求归属
        }

    def _check_admin_access(self, qs: dict[str, list[str]] | None = None) -> tuple[bool, str | None]:
        """
        校验 ?k=<token>、X-Admin-Key 或已签发 HttpOnly 会话 Cookie。
        未携带有效凭据时一律伪装返回 404，对扫描器完全隐身管理后台路径。
        返回 (authorized, new_cookie_header_or_None)。
        """
        if ADMIN_AUTH is None or ADMIN_STORE is None:
            return False, None
        client_ip = self._extract_client_ip()
        k_val = ((qs or {}).get("k") or [""])[0].strip() or (self.headers.get("X-Admin-Key") or "").strip()
        if k_val:
            if not ADMIN_AUTH.check_rate_limit(client_ip):
                return False, None
            if not ADMIN_AUTH.verify_password(k_val):
                ADMIN_AUTH.record_failure(client_ip)
                return False, None
            ADMIN_AUTH.clear_failures(client_ip)
            is_https = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower() == "https"
            flags = f"Path=/; HttpOnly; SameSite=Strict{'; Secure' if is_https else ''}"
            tok = ADMIN_AUTH.issue_session_cookie()
            return True, f"{ADMIN_AUTH.COOKIE_NAME}={tok}; Max-Age={ADMIN_AUTH.SESSION_TTL_SEC}; {flags}"

        ok = ADMIN_AUTH.verify_request_headers(
            self.headers.get("Cookie") or "",
            self.headers.get("Authorization") or "",
        )
        return ok, None

    def _require_admin(self, qs: dict[str, list[str]] | None = None) -> bool:
        ok, _ = self._check_admin_access(qs)
        if not ok:
            self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
            return False
        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        mounted_under_who = path == "/who" or path.startswith("/who/")

        # 支持挂载在 /who 子路径后缀下，彻底隔离同域名其他业务
        if path == "/who":
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", "/who/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/who/"):
            path = path[4:]  # "/who/" -> "/", "/who/assets/..." -> "/assets/..."

        if VISIBILITY_VIEW.handle_get(self, path, parsed):
            return

        origin_prefix, base_href = self._origin_and_base(mounted_under_who)

        # 0a) 隐身令牌式管理后台 (/admin?k=<token>)：无有效令牌或 Cookie 时一律返回 404，绝不暴露后台入口
        if path in ("/admin", "/admin/"):
            qs_adm = urllib.parse.parse_qs(parsed.query)
            ok_adm, new_ck = self._check_admin_access(qs_adm)
            if not ok_adm:
                self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                return
            adm_file = STATIC_DIR / "admin.html"
            if not adm_file.is_file():
                self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                return
            raw_adm = adm_file.read_text(encoding="utf-8")
            base_tag = f'  <base href="{share_store.html.escape(base_href, quote=True)}">\n'
            out_adm = raw_adm.replace("<head>", "<head>\n" + base_tag, 1) if "<head>" in raw_adm else (base_tag + raw_adm)
            adm_page_hdrs = {"X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}
            if new_ck:
                adm_page_hdrs["Set-Cookie"] = new_ck
            self._send_bytes(
                out_adm.encode("utf-8"),
                "text/html; charset=utf-8",
                cache_control="no-store, no-cache, must-revalidate",
                extra_headers=adm_page_hdrs,
            )
            return

        if path.startswith("/api/who/admin/"):
            qs = urllib.parse.parse_qs(parsed.query)
            if not self._require_admin(qs):
                return
            assert ADMIN_STORE is not None
            adm_hdrs = {"X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}

            if path == "/api/who/admin/overview":
                try:
                    days = int((qs.get("days") or ["30"])[0])
                except ValueError:
                    days = 30
                ov = ADMIN_STORE.get_overview(days=days, total_shares_in_store=get_share_store().count_active())
                self._send_json({"ok": True, **ov}, cache_control="no-store", extra_headers=adm_hdrs)
                return

            if path == "/api/who/admin/visits":
                day_f = (qs.get("day") or [""])[0].strip()
                ev_f = (qs.get("event") or [""])[0].strip()
                q_f = (qs.get("q") or [""])[0].strip()
                try:
                    lim = int((qs.get("limit") or ["80"])[0])
                    off = int((qs.get("offset") or ["0"])[0])
                except ValueError:
                    lim, off = 80, 0
                total, items = ADMIN_STORE.query_visits(day=day_f, event=ev_f, q=q_f, limit=lim, offset=off)
                sh_cache: dict[str, dict | None] = {}
                sstore = get_share_store()
                for it in items:
                    sid = it.get("shareId") or ""
                    if not sid:
                        continue
                    if sid not in sh_cache:
                        sh_cache[sid] = sstore.get(sid)
                    srec = sh_cache[sid]
                    if srec and isinstance(srec.get("report"), dict):
                        rep = srec["report"]
                        it["shareSummary"] = {
                            "exists": True,
                            "score": rep.get("score"),
                            "grade": rep.get("grade") or "",
                            "exitRegion": ((rep.get("topo") or {}).get("exitRegion") or "")[:36],
                            "verdict": ((rep.get("verdict") or {}).get("text") or rep.get("summary") or "")[:64],
                        }
                    else:
                        it["shareSummary"] = {"exists": False}
                self._send_json(
                    {"ok": True, "total": total, "items": items},
                    cache_control="no-store",
                    extra_headers=adm_hdrs,
                )
                return

            if path == "/api/who/admin/shares":
                q_f = (qs.get("q") or [""])[0].strip().lower().lstrip("#")
                try:
                    lim = int((qs.get("limit") or ["80"])[0])
                    off = int((qs.get("offset") or ["0"])[0])
                except ValueError:
                    lim, off = 80, 0
                sstore = get_share_store()
                recent = sstore.list_recent(limit=200, offset=0)
                meta_map = ADMIN_STORE.get_share_meta_map([r["id"] for r in recent])
                cards: list[dict] = []
                for r in recent:
                    sid = r["id"]
                    rep = r.get("report") if isinstance(r.get("report"), dict) else {}
                    meta = meta_map.get(sid, {})
                    topo = rep.get("topo") if isinstance(rep.get("topo"), dict) else {}
                    vd = rep.get("verdict") if isinstance(rep.get("verdict"), dict) else {}
                    card = {
                        "id": sid,
                        "createdAt": r["createdAt"],
                        "score": rep.get("score"),
                        "grade": rep.get("grade") or "-",
                        "scene": rep.get("scene") or "disguise",
                        "badCnt": rep.get("badCnt", 0),
                        "warnCnt": rep.get("warnCnt", 0),
                        "okCnt": rep.get("okCnt", 0),
                        "exitRegion": topo.get("exitRegion") or "",
                        "exitType": topo.get("exitType") or "",
                        "purityText": topo.get("purityText") or "",
                        "deviceSub": topo.get("deviceSub") or "",
                        "verdictTone": vd.get("tone") or "ok",
                        "verdictText": vd.get("text") or rep.get("summary") or "",
                        "creatorIp": meta.get("creatorIp") or "",
                        "creatorCc": meta.get("creatorCc") or "",
                        "creatorCity": meta.get("creatorCity") or "",
                        "creatorOrg": meta.get("creatorOrg") or "",
                        "viewCount": int(meta.get("viewCount") or 0),
                        "lastViewedAt": int(meta.get("lastViewedAt") or 0),
                        "lastViewerIp": meta.get("lastViewerIp") or "",
                    }
                    if q_f:
                        blob = f"{sid} {card['creatorIp']} {card['creatorCity']} {card['creatorOrg']} {card['exitRegion']} {card['verdictText']} {card['grade']} {card['lastViewerIp']}".lower()
                        if q_f not in blob:
                            continue
                    cards.append(card)
                sliced = cards[off : off + max(1, min(120, lim))]
                self._send_json(
                    {"ok": True, "total": len(cards), "items": sliced},
                    cache_control="no-store",
                    extra_headers=adm_hdrs,
                )
                return

            if path.startswith("/api/who/admin/share/"):
                sid = path.removeprefix("/api/who/admin/share/").strip("/")
                srec = get_share_store().get(sid)
                meta = ADMIN_STORE.get_share_meta_map([sid]).get(sid, {})
                viewers = ADMIN_STORE.get_share_viewers(sid, limit=100)
                if not srec and not viewers and not meta:
                    self._send_json({"ok": False, "error": "share_not_found"}, status=HTTPStatus.NOT_FOUND, extra_headers=adm_hdrs)
                    return
                self._send_json(
                    {
                        "ok": True,
                        "id": sid,
                        "exists": bool(srec),
                        "createdAt": srec["createdAt"] if srec else 0,
                        "report": srec["report"] if srec else None,
                        "meta": meta,
                        "viewers": viewers,
                    },
                    cache_control="no-store",
                    extra_headers=adm_hdrs,
                )
                return

            self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND, extra_headers=adm_hdrs)
            return

        # 0) 隐私脱敏分享数据查询与矢量分享卡片 (/api/who/share/<id>, /r/<id>.svg, /r/<id>)
        if path.startswith("/api/who/share/"):
            sid = path.removeprefix("/api/who/share/").strip("/")
            rec = get_share_store().get(sid)
            if not rec:
                self._send_json({"ok": False, "error": "share_not_found"}, status=HTTPStatus.NOT_FOUND)
                return
            if not self._head_only:
                record_admin_visit_async(
                    ip=self._extract_client_ip(),
                    event="share_view",
                    ua=self.headers.get("User-Agent") or "",
                    share_id=sid,
                    dedup_sec=10.0,
                )
            self._send_json({"ok": True, **rec}, cache_control="public, max-age=300")
            return

        if path.startswith("/r/") and len(path) > 3:
            tail = path.removeprefix("/r/").strip("/")
            if tail.endswith(".svg"):
                sid = tail[:-4]
                rec = get_share_store().get(sid)
                if not rec:
                    self._send_json({"ok": False, "error": "share_not_found"}, status=HTTPStatus.NOT_FOUND)
                    return
                svg_bytes = share_store.render_share_svg(rec["id"], rec["createdAt"], rec["report"])
                self._send_bytes(svg_bytes, "image/svg+xml; charset=utf-8", cache_control="public, max-age=86400")
                return

            sid = tail
            index_file = STATIC_DIR / "index.html"
            if index_file.is_file():
                rec = get_share_store().get(sid)
                if rec and not self._head_only:
                    record_admin_visit_async(
                        ip=self._extract_client_ip(),
                        event="share_view",
                        ua=self.headers.get("User-Agent") or "",
                        share_id=sid,
                        dedup_sec=10.0,
                    )
                raw_html = index_file.read_text(encoding="utf-8")
                body = share_store.inject_html_for_route(
                    raw_html,
                    base_href=base_href,
                    origin_prefix=origin_prefix,
                    share_record=rec,
                    missing_share_id=None if rec else sid,
                )
                self._send_bytes(
                    body,
                    "text/html; charset=utf-8",
                    cache_control="no-cache",
                    status=HTTPStatus.OK if rec else HTTPStatus.NOT_FOUND,
                )
                return

        # 1) 测速、微脉冲抖动测绘、WebSocket 控制帧主动 Ping、QUIC 采集读取与 Worker 探针脚本
        if path == "/sw-probe.js":
            sw_js = (
                b"function snap(){var o={ua:navigator.userAgent||'',plat:navigator.platform||'',"
                b"lang:navigator.language||'',langs:Array.from(navigator.languages||[]),"
                b"hc:navigator.hardwareConcurrency||0,dm:navigator.deviceMemory||0,tz:'',gpu:''};"
                b"try{o.tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}"
                b"try{if(typeof OffscreenCanvas==='function'){var c=new OffscreenCanvas(8,8),"
                b"g=c.getContext('webgl2')||c.getContext('webgl');"
                b"if(g){var d=g.getExtension('WEBGL_debug_renderer_info');"
                b"o.gpu=String(d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):g.getParameter(g.RENDERER)||'');}}}catch(e){}"
                b"return o;}"
                b"self.onconnect=function(e){var p=e.ports[0];p.onmessage=function(){p.postMessage(snap());};p.start();"
                b"p.postMessage(snap());};"
                b"self.addEventListener('install',function(){self.skipWaiting&&self.skipWaiting();});"
                b"self.addEventListener('activate',function(e){e.waitUntil&&self.clients&&e.waitUntil(self.clients.claim());});"
                b"self.addEventListener('message',function(e){var p=e.ports&&e.ports[0];"
                b"if(p&&p.postMessage){p.postMessage(snap());return;}"
                b"var t=e.source;if(t&&t.postMessage)t.postMessage(snap());});"
            )
            self._send_bytes(sw_js, "application/javascript; charset=utf-8", cache_control="no-store")
            return

        if path == "/api/who/quic":
            self._send_json({
                "ok": True,
                "collectorActive": bool(QUIC_COLLECTOR and QUIC_COLLECTOR.active),
                "quic": None,  # 旁路 UDP 监听不会完成 H3，无可验证的 HTTP 请求关联
            })
            return

        if path == "/api/who/tls2":
            _, packet = self._observed_connection()
            self._send_json({"ok": True, "tlsPermutation": packet["tlsPermutation"]})
            return

        if path == "/api/who/ws-ping":
            ws_key = (self.headers.get("Sec-WebSocket-Key") or "").strip()
            if not ws_key or "websocket" not in (self.headers.get("Upgrade") or "").lower():
                self._send_json({"ok": False, "error": "upgrade_required"}, status=HTTPStatus.BAD_REQUEST)
                return
            accept_val = base64.b64encode(
                hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept_val)
            self.end_headers()
            self.connection.settimeout(3.5)
            rtts: list[float] = []
            try:
                for _ in range(2):
                    tok = secrets.token_bytes(8)
                    t_p0 = time.perf_counter()
                    self.wfile.write(b"\x89\x08" + tok)
                    self.wfile.flush()
                    fhdr = self.rfile.read(2)
                    if len(fhdr) < 2:
                        break
                    opcode = fhdr[0] & 0x0F
                    masked = (fhdr[1] & 0x80) != 0
                    plen = fhdr[1] & 0x7F
                    mask_key = self.rfile.read(4) if masked else b""
                    pdata = bytearray(self.rfile.read(plen)) if plen else bytearray()
                    if masked and len(mask_key) == 4:
                        for idx in range(len(pdata)):
                            pdata[idx] ^= mask_key[idx % 4]
                    if opcode == 0x0A and bytes(pdata) == tok:
                        rtts.append(round((time.perf_counter() - t_p0) * 1000.0, 2))
                res_bytes = json.dumps({
                    "ok": True,
                    "wsPingRttMs": min(rtts) if rtts else None,
                    "samples": rtts,
                }).encode("utf-8")
                ln = len(res_bytes)
                hdr_out = bytes([0x81, ln]) if ln < 126 else struct.pack("!BBH", 0x81, 126, ln)
                self.wfile.write(hdr_out + res_bytes + b"\x88\x00")
                self.wfile.flush()
            except Exception:
                pass
            self.close_connection = True
            return

        if path == "/api/who/blank":
            self._send_bytes(
                b"<!doctype html><meta charset='utf-8'><title>.</title>",
                "text/html; charset=utf-8",
                cache_control="private, max-age=300",
            )
            return
        if path in ("/api/who/ping", "/api/ping"):
            qs = urllib.parse.parse_qs(parsed.query)
            seq_raw = (qs.get("seq") or [""])[0]
            self._send_json({
                "ok": True,
                "seq": seq_raw,
                "serverTimeMs": round(time.time() * 1000, 2),
                "serverPerfUs": round(time.perf_counter() * 1_000_000),
                "serverCoords": get_server_coarse_coords(),
            })
            return

        # 1b) 深度出口情报、BGP/ASN 租赁核验、同段脏邻居与 :443 Reality 反向验真接口
        if path == "/api/who/intel":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            req_ip = (qs.get("ip") or [""])[0].strip()
            client_ip = self._extract_client_ip()
            target_ip = req_ip or client_ip
            target_public, _ = egress_intel.normalize_public_ip(target_ip)
            client_public, _ = egress_intel.normalize_public_ip(client_ip)
            is_self_query = not req_ip or (target_public is not None and target_public == client_public)
            # 任意 ?ip（即使等于访客）只查被动情报；主动探测必须为双方显式同意的原始对端。
            wire_key = self._observed_wire_key() if ENABLE_ACTIVE_443 and "ip" not in qs else None
            active = bool(not self._head_only and wire_key and target_public == wire_key[0]
                          and self._single_header(ACTIVE_PROBE_HEADER) == "1")
            intel_payload = egress_intel.inspect_ip_intelligence(
                target_ip, enable_active_443=active, enable_port_scan=active,
            )
            intel_payload["isSelfEgress"] = is_self_query
            if not is_self_query and intel_payload.get("ok"):
                record_admin_visit_async(
                    ip=self._extract_client_ip(),
                    event="ip_query",
                    ua=self.headers.get("User-Agent") or "",
                    target_ip=str(intel_payload.get("targetIp") or target_ip),
                    dedup_sec=5.0,
                )
            self._send_json(intel_payload)
            return

        # 1c) 轻量批量候选 IP 归属与运营商核验接口 (消除原生双栈 IPv6 与 5G CGNAT STUN/分流误报)
        if path == "/api/who/ip-meta":
            qs = urllib.parse.parse_qs(parsed.query)
            raw_ips = ",".join(qs.get("ips") or [])
            seen_ips: list[str] = []
            for tok in raw_ips.split(","):
                norm_ip, _ = egress_intel.normalize_public_ip(tok.strip())
                if norm_ip and norm_ip not in seen_ips:
                    seen_ips.append(norm_ip)
                if len(seen_ips) >= 8:
                    break
            futs = {ip_item: _GEO_POOL.submit(lookup_ip_geo, ip_item) for ip_item in seen_ips}
            if futs:
                concurrent.futures.wait(list(futs.values()), timeout=2.2)
            items: dict[str, dict] = {}
            for ip_item, fut in futs.items():
                if fut.done():
                    try:
                        g = fut.result()
                        if isinstance(g, dict) and g.get("ok"):
                            items[ip_item] = {
                                "cc": g.get("countryCode") or "",
                                "asn": g.get("asn") or "",
                                "org": g.get("org") or g.get("isp") or "",
                                "isp": g.get("isp") or "",
                                "asFull": g.get("asFull") or "",
                                "mobile": bool(g.get("mobile")),
                                "hosting": bool(g.get("hosting") or g.get("hostingInferred")),
                            }
                    except Exception:
                        continue
            self._send_json({"ok": True, "items": items}, cache_control="private, max-age=180")
            return

        # 2) 无状态 HTTP ETag 缓存追踪演示探针 (零服务端存储)
        if path == "/api/who/etag":
            inm = (self.headers.get("If-None-Match") or "").strip().strip('"').replace("W/", "").strip('"')
            if inm and len(inm) <= 48 and all(c in "0123456789abcdef" for c in inm.lower()):
                token = inm.lower()
                seen_before = True
            else:
                token = secrets.token_hex(8)
                seen_before = False
            self._send_json(
                {"ok": True, "etagId": token, "seenBefore": seen_before},
                cache_control="private, no-cache, max-age=0, must-revalidate",
                extra_headers={"ETag": f'"{token}"'},
            )
            return

        # 3) 主服务端观测接口
        if path in ("/api/who/me", "/api/inspect"):
            client_ip = self._extract_client_ip()
            xri_peer = self._trusted_real_ip()
            trusted_cf = bool(xri_peer and is_cloudflare_edge_ip(xri_peer))
            internal_hdrs = {
                "x-real-ip", "x-forwarded-for", "x-forwarded-proto", "connection",
                WHO_RUN_TOKEN_HEADER.lower(), ACTIVE_PROBE_HEADER.lower(),
                *(name.lower() for name in EDGE_WIRE_HEADERS),
                *(name.lower() for name in EDGE_PROTOCOL_HEADERS.values()),
            }
            if trusted_cf:
                internal_hdrs.update({"cf-connecting-ip", "cf-ray", "cf-ipcountry", "cf-visitor", "cdn-loop"})
            header_order = [
                k for k, _ in self.headers.items() if k.lower() not in internal_hdrs
            ]
            visible_headers = visibility.legacy_header_values(self.headers, exclude=internal_hdrs)

            connection, packet = self._observed_connection()
            proxy_hdrs = detect_proxy_headers(self.headers, real_ip=xri_peer, trusted_cf=trusted_cf)

            geo = lookup_ip_geo(client_ip)
            tcp_info = packet.get("tcp") or {}
            record_admin_visit_async(
                ip=client_ip,
                event="scan",
                ua=self.headers.get("User-Agent") or "",
                geo=geo,
                tcp_os=str(tcp_info.get("osGuess") or ""),
                dedup_sec=4.0,
            )
            self._send_json({
                "ok": True,
                "serverTimeMs": round(time.time() * 1000, 2),
                "serverCoords": get_server_coarse_coords(),
                "clientIp": client_ip,
                "ipVersion": 6 if ":" in client_ip else 4,
                "geo": geo,
                "connection": connection,
                "packet": packet,
                "headerOrder": header_order,
                "headers": visible_headers,
                "proxyHeaders": proxy_hdrs,
                # 兼容旧版调用字段
                "ipGeo": geo,
            })
            return

        # 4) 页面入口与静态资源
        if path in ("/", "/zh-cn", "/zh-cn/", "/index.html"):
            index_file = STATIC_DIR / "index.html"
            if index_file.is_file():
                # 请求首页时附加 Accept-CH 让 Chromium 浏览器主动发送高熵 Client Hints
                accept_ch = (
                    "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, "
                    "Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Mobile, "
                    "Sec-CH-UA-Form-Factors, Sec-CH-UA-WoW64"
                )
                body = share_store.inject_html_for_route(
                    index_file.read_text(encoding="utf-8"),
                    base_href=base_href,
                    origin_prefix=origin_prefix,
                )
                body = visibility.inject_receipt(body, VISIBILITY_VIEW.receipt(self, parsed, kind="navigation"))
                self._send_bytes(
                    body,
                    "text/html; charset=utf-8",
                    cache_control="no-store, no-cache, must-revalidate",
                    extra_headers={"Accept-CH": accept_ch, "Pragma": "no-cache"},
                )
                return

        if path.startswith("/assets/"):
            rel = path.removeprefix("/assets/")
            target = (STATIC_DIR / rel).resolve()
            if str(target).startswith(str(STATIC_DIR)) and target.is_file():
                ctype, _ = mimetypes.guess_type(str(target))
                if target.suffix == ".js":
                    ctype = "application/javascript; charset=utf-8"
                elif target.suffix == ".css":
                    ctype = "text/css; charset=utf-8"
                elif target.suffix == ".svg":
                    ctype = "image/svg+xml"
                self._send_bytes(
                    target.read_bytes(),
                    ctype or "application/octet-stream",
                    cache_control="public, max-age=300",
                )
                return

        if path == "/favicon.ico":
            svg_file = STATIC_DIR / "favicon.svg"
            if svg_file.is_file():
                self._send_bytes(svg_file.read_bytes(), "image/svg+xml", cache_control="public, max-age=86400")
                return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(b'{"ok":false,"error":"not_found"}')

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        mounted_under_who = path.startswith("/who/")
        if mounted_under_who:
            path = path[4:]

        if VISIBILITY_VIEW.handle_post(self, path):
            return

        if path.startswith("/api/who/admin/"):
            qs_post = urllib.parse.parse_qs(parsed.query)
            if path == "/api/who/admin/logout":
                if ADMIN_AUTH is None:
                    self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                    return
                is_https = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower() == "https"
                cookie_flags = f"Path=/; HttpOnly; SameSite=Strict{'; Secure' if is_https else ''}"
                self._send_json(
                    {"ok": True},
                    extra_headers={"Set-Cookie": f"{ADMIN_AUTH.COOKIE_NAME}=; Max-Age=0; {cookie_flags}"},
                )
                return

            if path.startswith("/api/who/admin/share/") and path.endswith("/delete"):
                if not self._require_admin(qs_post):
                    return
                assert ADMIN_STORE is not None
                sid = path.removeprefix("/api/who/admin/share/").removesuffix("/delete").strip("/")
                deleted = get_share_store().delete(sid)
                ADMIN_STORE.delete_share_meta(sid)
                self._send_json({"ok": True, "deleted": deleted})
                return

            self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
            return

        if path != "/api/who/share":
            self._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > 32768:
            self._send_json({"ok": False, "error": "payload_too_large_or_empty"}, status=HTTPStatus.BAD_REQUEST)
            return

        # 匿名内存限速（仅存加盐哈希计数，绝不落盘真实客户端 IP）
        client_ip = self._extract_client_ip()
        rate_key = hashlib.sha256(f"{client_ip}:{_SHARE_RATE_SALT}".encode("utf-8")).hexdigest()[:24]
        used = int(SHARE_RATE_CACHE.get(rate_key) or 0)
        if used >= 20:
            self._send_json({"ok": False, "error": "rate_limited"}, status=HTTPStatus.TOO_MANY_REQUESTS)
            return
        SHARE_RATE_CACHE.set(rate_key, used + 1, ttl_sec=60.0)

        raw_bytes = self.rfile.read(length)
        try:
            raw_obj = json.loads(raw_bytes.decode("utf-8", errors="strict"))
            sid, created_at, clean_rep = get_share_store().create(raw_obj)
        except Exception:
            self._send_json({"ok": False, "error": "invalid_share_payload"}, status=HTTPStatus.BAD_REQUEST)
            return

        record_admin_visit_async(
            ip=client_ip,
            event="share_create",
            ua=self.headers.get("User-Agent") or "",
            share_id=sid,
            score=int(clean_rep.get("score") or 0),
            grade=str(clean_rep.get("grade") or ""),
            created_at=created_at,
            dedup_sec=0.0,
        )

        origin_prefix, base_href = self._origin_and_base(mounted_under_who)
        self._send_json({
            "ok": True,
            "id": sid,
            "createdAt": created_at,
            "path": f"{base_href}r/{sid}",
            "badgePath": f"{base_href}r/{sid}.svg",
            "url": f"{origin_prefix}/r/{sid}",
            "badgeUrl": f"{origin_prefix}/r/{sid}.svg",
        })


def run_self_test() -> None:
    # 1) 校验 TCP SYN & TLS ClientHello 解析器纯函数
    sample_opts = bytes.fromhex("020405b4010303060101080a112233440000000004020000")
    opts, mss, ws = parse_tcp_options(sample_opts)
    assert mss == 1460 and ws == 6 and "mss" in opts and "ts" in opts
    assert extract_tcp_tsval(sample_opts) == 0x11223344
    ja4t = build_ja4t(65535, opts, mss, ws)
    assert ja4t.startswith("65535_2-1-3-1-1-8-4-0_1460_6"), f"unexpected ja4t: {ja4t}"
    os_label, os_fam = guess_tcp_os(64, 65535, opts)
    assert "macOS" in os_label and os_fam == "apple"
    assert infer_tunnel_from_mss(1460) == "ethernet"
    assert infer_tunnel_from_mss(1380) == "wireguard"
    assert infer_mobile({"asFull": "AS140486 CHINATELECOM 5GC network", "isp": "China Telecom"}) is True
    assert infer_mobile({"isp": "Comcast Cable"}) is False
    assert is_cloudflare_edge_ip("104.16.1.1") is True
    assert is_cloudflare_edge_ip("2606:4700::1") is True
    assert is_cloudflare_edge_ip("8.8.8.8") is False
    assert egress_intel.normalize_public_ip("8.8.8.8") == ("8.8.8.8", 4)
    assert egress_intel.normalize_public_ip("[240e:471:e30:612f:4c40:aea1:867e:18ed]") == (
        "240e:471:e30:612f:4c40:aea1:867e:18ed",
        6,
    )
    assert egress_intel.normalize_public_ip("fe80::1%en0") == (None, None)
    assert egress_intel.normalize_public_ip("100.64.0.1") == (None, None)
    assert egress_intel.normalize_public_ip("192.0.0.2") == (None, None)
    assert egress_intel.normalize_public_ip("127.0.0.1") == (None, None)

    # 1b) 代理转发头识别：Nginx 追加的真实对端不计入上游跳数，Via 中的 IP 必须脱敏
    ph_clean = detect_proxy_headers({"X-Forwarded-For": "8.8.8.8", "User-Agent": "x"}, real_ip="8.8.8.8")
    assert ph_clean["suspect"] is False and ph_clean["xffHops"] == 0
    ph_dirty = detect_proxy_headers(
        {"X-Forwarded-For": "10.1.2.3, 8.8.8.8", "Via": "1.1 squid (203.0.113.9)", "CF-Ray": "abc"},
        real_ip="8.8.8.8",
    )
    assert ph_dirty["suspect"] is True and ph_dirty["xffHops"] == 1
    assert "via" in ph_dirty["names"] and "cf-ray" in ph_dirty["names"] and "203.0.113.9" not in ph_dirty["via"]
    ph_cf = detect_proxy_headers({"X-Forwarded-For": "1.1.1.1, 104.16.2.3", "CF-Ray": "abc"}, real_ip="104.16.2.3", trusted_cf=True)
    assert ph_cf["suspect"] is False

    # 1c) 端口回扫汇总：SYN-Proxy 全端口“开放”时不得输出代理端口结论；横幅中的 IP 必须脱敏
    fake_open = [{"port": p, "svc": s, "kind": k, "banner": ""} for p, s, k in egress_intel.PROXY_SCAN_PORTS]
    assert egress_intel._summarize_ports(fake_open, len(fake_open), 5.0)["synProxyLikely"] is True
    assert egress_intel._summarize_ports(fake_open, len(fake_open), 5.0)["proxyOpen"] == []
    two_open = [{"port": 22, "svc": "SSH", "kind": "remote", "banner": ""}, {"port": 1080, "svc": "SOCKS", "kind": "proxy", "banner": ""}]
    summ = egress_intel._summarize_ports(two_open, 17, 5.0)
    assert summ["proxyOpen"] == [1080] and summ["remoteOpen"] == [22] and summ["synProxyLikely"] is False
    assert "198.51.100.7" not in egress_intel._clean_banner(b"SSH-2.0-OpenSSH_9.6 198.51.100.7\r\n")

    # 1d) 校验 HTTP/2 Akamai 原始帧解析器（模拟真实 Chrome、Firefox 与 Go H2 握手首包）
    chrome_settings = struct.pack("!HIHIHIHI", 1, 65536, 2, 0, 4, 6291456, 6, 262144)
    f_settings = struct.pack("!I", len(chrome_settings))[1:] + b"\x04\x00\x00\x00\x00\x00" + chrome_settings
    f_wu = b"\x00\x00\x04\x08\x00\x00\x00\x00\x00" + struct.pack("!I", 15663105)
    # HPACK: :method GET (0x82), :authority example.com (0x41 + len=3 'who'), :scheme https (0x87), :path / (0x84), user-agent (0x0f 0x2a ...)
    hpack_chrome = b"\x82\x41\x03who\x87\x84\x40\x02ua\x01x"
    f_hdr_chrome = struct.pack("!I", len(hpack_chrome))[1:] + b"\x01\x25\x00\x00\x00\x01" + struct.pack("!IB", 0x80000000, 255) + hpack_chrome
    h2_chr = parse_h2_client_preface(H2_CLIENT_PREFACE + f_settings + f_wu + f_hdr_chrome)
    assert h2_chr is not None
    assert h2_chr["akamai"] == "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p", h2_chr
    assert h2_chr["clientFamily"] == "chromium"

    ff_settings = struct.pack("!HIHIHI", 1, 65536, 4, 131072, 5, 16384)
    f_ff_set = struct.pack("!I", len(ff_settings))[1:] + b"\x04\x00\x00\x00\x00\x00" + ff_settings
    f_ff_wu = b"\x00\x00\x04\x08\x00\x00\x00\x00\x00" + struct.pack("!I", 12517377)
    hpack_ff = b"\x82\x84\x41\x03who\x87"  # m, p, a, s
    f_ff_hdr = struct.pack("!I", len(hpack_ff))[1:] + b"\x01\x04\x00\x00\x00\x01" + hpack_ff
    h2_ff = parse_h2_client_preface(H2_CLIENT_PREFACE + f_ff_set + f_ff_wu + f_ff_hdr)
    assert h2_ff is not None and h2_ff["pseudoOrder"] == ["m", "p", "a", "s"] and h2_ff["clientFamily"] == "firefox"

    # 1e) 校验 RFC 9001 Appendix A.1 密钥派生与 TLS 扩展洗牌去重判定
    dcid_rfc = bytes.fromhex("8394c8f03e515708")
    isec_rfc = hmac.new(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), dcid_rfc, hashlib.sha256).digest()
    csec_rfc = _hkdf_expand_label(isec_rfc, b"client in", 32)
    assert _hkdf_expand_label(csec_rfc, b"quic key", 16).hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert _hkdf_expand_label(csec_rfc, b"quic hp", 16).hex() == "9f50449e04a0e810283a1e9933adedd2"
    run = secrets.token_hex(16)
    c1 = ("198.51.100.1", 50123, "203.0.113.10", 443)
    c2 = ("198.51.100.1", 50124, "203.0.113.10", 443)
    hello1 = {"helloId": "aa11", "extOrder": [0, 10, 11, 13, 16, 43, 51], "ja3": "h1"}
    hello2 = {"helloId": "bb22", "extOrder": [0, 16, 51, 10, 43, 13, 11], "pskPresent": True, "ja3": "h2"}
    p_s1 = record_tls_hello_sample(hello1, run, c1)
    assert p_s1["samples"] == 1 and p_s1["permuted"] is None
    assert record_tls_hello_sample(hello1, run, c1)["samples"] == 1
    p_s2 = record_tls_hello_sample(hello2, run, c2)
    assert p_s2["samples"] == 2 and p_s2["permuted"] is True and p_s2["pskSeen"] is True

    # 2) 内存中的 HTTP 请求/响应，验证路由与隐私脱敏，不监听、不连网。
    from http.client import HTTPResponse
    from io import BytesIO
    from unittest.mock import patch

    class MemorySocket:
        def __init__(self, data: bytes) -> None:
            self.incoming = BytesIO(data)
            self.outgoing = BytesIO()

        def makefile(self, _mode: str, _buffering: int = -1) -> BytesIO:
            return self.incoming

        def sendall(self, data: bytes) -> None:
            self.outgoing.write(data)

        def getsockname(self) -> tuple[str, int]:
            return "127.0.0.1", port

    port = 8899  # 虚拟端口，未绑定真实 socket

    def offline_open(req: str | urllib.request.Request, **_kwargs) -> HTTPResponse:
        if isinstance(req, str):
            req = urllib.request.Request(req)
        assert req.type == "http" and req.host == f"127.0.0.1:{port}", f"unexpected self-test URL: {req.full_url}"
        method = req.get_method()
        headers = dict(req.header_items())
        headers.setdefault("Host", req.host)
        if req.data is not None:
            headers["Content-Length"] = str(len(req.data))
        message = f"{method} {req.selector} HTTP/1.1\r\n"
        message += "".join(f"{name}: {value}\r\n" for name, value in headers.items()) + "\r\n"
        sock = MemorySocket(message.encode("ascii") + (req.data or b""))
        WhoProbeHandler(sock, ("127.0.0.1", 50123), None)
        response = HTTPResponse(MemorySocket(sock.outgoing.getvalue()), method=method)
        response.begin()
        if response.status >= 400:
            raise urllib.error.HTTPError(req.full_url, response.status, response.reason, response.headers, response)
        return response

    with tempfile.TemporaryDirectory(prefix="whoprobe_test_") as tmp_dir:
        with (
            patch.object(urllib.request, "urlopen", offline_open),
            patch(f"{__name__}.SHARE_STORE", share_store.ShareStore(data_dir=tmp_dir)),
            patch(f"{__name__}.lookup_ip_geo", side_effect=lambda ip: {"ok": False, "ip": ip}),
            patch(f"{__name__}.get_server_coarse_coords", return_value=None),
        ):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as r1:
                html_doc = r1.read().decode("utf-8")
                assert r1.status == 200 and len(html_doc) > 500
                assert '<base href="/">' in html_doc
                assert "Sec-CH-UA-Arch" in (r1.headers.get("Accept-CH") or "")

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/who/", timeout=3) as rw:
                who_html = rw.read().decode("utf-8")
                assert rw.status == 200 and '<base href="/who/">' in who_html

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/who/api/who/ping", timeout=3) as rwp:
                assert rwp.status == 200 and json.loads(rwp.read().decode("utf-8")).get("ok") is True

            req_head = urllib.request.Request(f"http://127.0.0.1:{port}/who/", method="HEAD")
            with urllib.request.urlopen(req_head, timeout=3) as rh:
                assert rh.status == 200 and rh.read() == b""

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/assets/app.js", timeout=3) as r_js:
                assert r_js.status == 200 and len(r_js.read()) > 1000

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/ping", timeout=3) as r2:
                ping = json.loads(r2.read().decode("utf-8"))
                assert r2.status == 200 and ping.get("ok") is True

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/etag", timeout=3) as r3:
                et1 = json.loads(r3.read().decode("utf-8"))
                etag_hdr = r3.headers.get("ETag")
                assert et1["seenBefore"] is False and etag_hdr

            req_et2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/who/etag",
                headers={"If-None-Match": etag_hdr},
            )
            with urllib.request.urlopen(req_et2, timeout=3) as r4:
                et2 = json.loads(r4.read().decode("utf-8"))
                assert et2["seenBefore"] is True and et2["etagId"] == et1["etagId"]

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/me", timeout=6) as r5:
                me = json.loads(r5.read().decode("utf-8"))
                assert r5.status == 200 and me.get("ok") is True and "headerOrder" in me
                assert isinstance(me.get("proxyHeaders"), dict) and me["proxyHeaders"]["suspect"] is False

            req_via = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/who/me",
                headers={"Via": "1.1 corp-gateway", "X-Real-IP": "8.8.8.8", "X-Forwarded-For": "10.0.0.5, 8.8.8.8"},
            )
            with urllib.request.urlopen(req_via, timeout=6) as r_via:
                via_me = json.loads(r_via.read().decode("utf-8"))
                assert via_me["proxyHeaders"]["suspect"] is True and via_me["proxyHeaders"]["xffHops"] == 1

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/intel?ip=127.0.0.1", timeout=3) as r6:
                intel_priv = json.loads(r6.read().decode("utf-8"))
                assert r6.status == 200 and intel_priv.get("ok") is False

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/ip-meta?ips=127.0.0.1,10.0.0.1", timeout=3) as r_meta:
                meta_priv = json.loads(r_meta.read().decode("utf-8"))
                assert r_meta.status == 200 and meta_priv.get("ok") is True and meta_priv.get("items") == {}

            # 校验 CF-Connecting-IP 仅在可信 Cloudflare 边缘源 IP 时生效，杜绝伪造请求头欺骗
            req_cf_spoof = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/who/me",
                headers={"X-Real-IP": "8.8.8.8", "CF-Connecting-IP": "1.1.1.1"},
            )
            with urllib.request.urlopen(req_cf_spoof, timeout=5) as r_sp:
                sp_me = json.loads(r_sp.read().decode("utf-8"))
                assert sp_me["clientIp"] == "8.8.8.8"

            req_cf_ok = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/who/me",
                headers={"X-Real-IP": "104.16.2.3", "CF-Connecting-IP": "1.1.1.1"},
            )
            with urllib.request.urlopen(req_cf_ok, timeout=5) as r_cf:
                cf_me = json.loads(r_cf.read().decode("utf-8"))
                assert cf_me["clientIp"] == "1.1.1.1"

            # 3) 验证隐私脱敏分享创建、IP 强过滤、OpenGraph 注入与 SVG 徽章渲染
            dirty_share = {
                "scene": "disguise",
                "score": 68,
                "grade": "C",
                "badCnt": 2,
                "warnCnt": 1,
                "okCnt": 16,
                "secretIp": "198.51.100.77",
                "summary": "发现 203.0.113.42 分流泄漏与 2001:db8::99 双栈暴露",
                "verdict": {"tone": "bad", "text": "实测 203.0.113.42 节点与 aa:bb:cc:11:22:33 坐标 35.6895, 139.6917"},
                "topo": {"exitRegion": "🇺🇸 美国 · 203.0.113.42", "exitType": "机房 IDC", "purityText": "纯净度 82 / 100"},
                "scenarios": [{"id": "ai", "name": "AI 大模型", "score": 76, "reason": "机房出口 203.0.113.42"}],
                "checks": [{"id": "split", "level": "bad", "diff": {"left": "US", "op": "≠", "right": "203.0.113.42"}, "summary": "泄漏 203.0.113.42"}],
            }
            req_sh = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/who/share",
                data=json.dumps(dirty_share).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req_sh, timeout=3) as r_sh:
                sh_res = json.loads(r_sh.read().decode("utf-8"))
                assert sh_res.get("ok") is True and len(sh_res["id"]) >= 8
                sid = sh_res["id"]

            for check_url in (
                f"http://127.0.0.1:{port}/api/who/share/{sid}",
                f"http://127.0.0.1:{port}/r/{sid}",
                f"http://127.0.0.1:{port}/r/{sid}.svg",
            ):
                with urllib.request.urlopen(check_url, timeout=3) as r_chk:
                    txt = r_chk.read().decode("utf-8")
                    for leaked in ("198.51.100.77", "203.0.113.42", "2001:db8::99", "aa:bb:cc:11:22:33", "35.6895"):
                        assert leaked not in txt, f"PII leak {leaked} found in {check_url}!"

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/r/{sid}", timeout=3) as r_page:
                p_html = r_page.read().decode("utf-8")
                assert "__WHOPROBE_SHARED__" in p_html and f"/r/{sid}.svg" in p_html

            # 4) 验证 5G 蜂窝 CGNAT TSopt 剥离、多核负向微偏置、32 位正常回绕、1MHz 高频时钟与真实 osfuscate 改包判据
            assert evaluate_tcp_continuity(
                syn_ttl=52, hello_ttl=52, syn_had_ts=True, syn_tsval=123456, hello_tsval=None, dt_sec=0.055
            ) == (None, False, "ts_stripped_by_middlebox")
            assert evaluate_tcp_continuity(
                syn_ttl=52, hello_ttl=52, syn_had_ts=True, syn_tsval=500001, hello_tsval=499999, dt_sec=0.045
            ) == (None, False, "cgnat_or_subtick_skew")
            hz_wrap, sp_wrap, _ = evaluate_tcp_continuity(
                syn_ttl=52, hello_ttl=52, syn_had_ts=True, syn_tsval=0xFFFFFFF0, hello_tsval=0x00000020, dt_sec=0.048
            )
            assert sp_wrap is False and hz_wrap == 1000
            hz_1m, sp_1m, _ = evaluate_tcp_continuity(
                syn_ttl=52, hello_ttl=52, syn_had_ts=True, syn_tsval=1_000_000, hello_tsval=1_060_000, dt_sec=0.060
            )
            assert sp_1m is False and hz_1m == 1_000_000
            assert evaluate_tcp_continuity(
                syn_ttl=116, hello_ttl=52, syn_had_ts=False, syn_tsval=None, hello_tsval=None, dt_sec=0.050
            )[1] is True
            assert evaluate_tcp_continuity(
                syn_ttl=52, hello_ttl=52, syn_had_ts=True, syn_tsval=0, hello_tsval=2_850_000_000, dt_sec=0.050
            )[1] is True

            # Exercise the opt-in administrator routes with the same offline HTTP fixture.
            global ADMIN_AUTH, ADMIN_STORE
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/admin", timeout=3)
                raise AssertionError("/admin must return 404 when ADMIN_AUTH is None")
            except urllib.error.HTTPError as he:
                assert he.code == 404

            test_secret = secrets.token_urlsafe(24)
            adm_tmp_obj = tempfile.TemporaryDirectory()
            ADMIN_AUTH = admin_store.AdminAuth(test_secret)
            ADMIN_STORE = admin_store.AdminStore(adm_tmp_obj.name)
            try:
                for unauth_url in (
                    f"http://127.0.0.1:{port}/admin",
                    f"http://127.0.0.1:{port}/admin?k=wrongtoken000000",
                    f"http://127.0.0.1:{port}/api/who/admin/overview",
                ):
                    try:
                        urllib.request.urlopen(unauth_url, timeout=3)
                        raise AssertionError(f"{unauth_url} must return 404")
                    except urllib.error.HTTPError as he:
                        assert he.code == 404

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/admin?k={test_secret}", timeout=3) as r_lg:
                    assert r_lg.status == 200
                    set_ck = r_lg.headers.get("Set-Cookie") or ""
                    assert "wp_adm=" in set_ck and "HttpOnly" in set_ck
                    adm_cookie = set_ck.split(";", 1)[0]

                # 模拟真实访客检测与打开分享页
                GEO_CACHE.set("36.21.224.142", {"ok": True, "countryCode": "CN", "city": "Hangzhou", "asn": "AS140486", "isp": "China Telecom"})
                ADMIN_STORE.record_visit(
                    ip="36.21.224.142",
                    event="scan",
                    ua="Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) Version/18.7 Safari/604.1",
                    geo=GEO_CACHE.get("36.21.224.142"),  # type: ignore[arg-type]
                    tcp_os="macOS / iOS (Darwin)",
                    dedup_sec=0.0,
                )
                req_view = urllib.request.Request(
                    f"http://127.0.0.1:{port}/r/{sid}",
                    headers={"X-Real-IP": "36.21.224.142", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Chrome/136.0.0.0"},
                )
                with urllib.request.urlopen(req_view, timeout=3) as _:
                    pass
                time.sleep(0.15)

                req_ov = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/who/admin/overview?days=30",
                    headers={"Cookie": adm_cookie},
                )
                with urllib.request.urlopen(req_ov, timeout=3) as r_ov:
                    ov = json.loads(r_ov.read().decode("utf-8"))
                    assert ov["ok"] is True and ov["kpis"]["todayUv"] >= 1 and ov["kpis"]["todayShareViews"] >= 1

                req_vs = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/who/admin/visits",
                    headers={"Cookie": adm_cookie},
                )
                with urllib.request.urlopen(req_vs, timeout=3) as r_vs:
                    vs = json.loads(r_vs.read().decode("utf-8"))
                    assert vs["total"] >= 2
                    sv_row = next(x for x in vs["items"] if x["event"] == "share_view")
                    assert sv_row["shareId"] == sid and sv_row["shareSummary"]["exists"] is True

                req_sd = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/who/admin/share/{sid}",
                    headers={"Cookie": adm_cookie},
                )
                with urllib.request.urlopen(req_sd, timeout=3) as r_sd:
                    sd = json.loads(r_sd.read().decode("utf-8"))
                    assert sd["exists"] is True and sd["meta"]["viewCount"] == 1 and len(sd["viewers"]) == 1
            finally:
                ADMIN_AUTH = None
                ADMIN_STORE = None
                adm_tmp_obj.cleanup()

            print(f"SELF-TEST OK (offline) | ja4t={ja4t} | etag={et1['etagId']} | share={sid}")


def _parse_host_port(spec: str, default_port: int) -> tuple[str, int]:
    host, _, p = spec.rpartition(":")
    return (host or "127.0.0.1", int(p)) if p.isdigit() else (spec, default_port)


def main(*, enable_builtin_admin: bool = True) -> None:
    global SNIFFER, TLS_BRIDGE, QUIC_COLLECTOR, ENABLE_ACTIVE_443, TRUSTED_EDGES, VISIBILITY_VIEW
    global ADMIN_AUTH, ADMIN_STORE
    parser = argparse.ArgumentParser(description="WhoProbe v7.9：网站可见性、协议与出口诊断")
    visibility.add_arguments(parser)
    visibility_dns.add_arguments(parser)
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8899, help="监听端口 (默认 8899)")
    parser.add_argument("--trusted-edge", action="append", type=_parse_trusted_edge, metavar="IP_OR_CIDR",
                        help="受信即时代理来源，可重复；显式列表替代默认 127.0.0.0/8、::1")
    parser.add_argument("--sniff-iface", default="", help="可选 Linux 网卡名(如 ens5)，开启旁路 TCP SYN/JA4 抓包")
    parser.add_argument("--sniff-port", type=int, default=443, help="旁路抓包目标端口 (默认 443)")
    parser.add_argument("--quic-port", type=int, default=0, help="可选 UDP QUIC Initial 旁路解析端口，不提供 H3 服务")
    parser.add_argument("--tls-bridge-port", type=int, default=0, help="可选本地回环 TLS+H2 帧嗅探桥端口 (如 18449)")
    parser.add_argument("--tls-cert", default="", help="TLS 桥默认证书路径 (或读取 CREDENTIALS_DIRECTORY/tls_cert)")
    parser.add_argument("--tls-key", default="", help="TLS 桥默认私钥路径 (或读取 CREDENTIALS_DIRECTORY/tls_key)")
    parser.add_argument("--tls-sni", action="append", default=[], help="额外 SNI 证书映射: domain=cert_path,key_path")
    parser.add_argument("--h2c-backend", default="127.0.0.1:10082", help="解密后 HTTP/2 (h2c) 转发目标 (默认 127.0.0.1:10082)")
    parser.add_argument("--h1-backend", default="127.0.0.1:10081", help="解密后 HTTP/1.1 转发目标 (默认 127.0.0.1:10081)")
    parser.add_argument("--data-dir", default="", help="可选分享快照与统计 SQLite 目录 (默认使用 STATE_DIRECTORY 或 ./data)")
    parser.add_argument("--admin-token", default="", help="可选管理后台访问口令 (或通过 WHOPROBE_ADMIN_TOKEN / LoadCredential admin_token 注入)")
    parser.add_argument("--admin-token-file", default="", help="可选管理后台口令文件路径")
    active = parser.add_mutually_exclusive_group()
    active.add_argument("--active-probe", action="store_true",
                        help="允许访客经 X-Who-Active-Probe: 1 同意对自身原始公网对端做回探（默认禁用）")
    active.add_argument("--no-active-probe", dest="active_probe", action="store_false",
                        help="禁用反向 :443 TLS/Reality 验真与代理端口回探（默认）")
    parser.set_defaults(active_probe=False)
    parser.add_argument("--self-test", action="store_true", help="运行离线自检后退出")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    data_dir_arg = args.data_dir or None
    get_share_store(data_dir_arg)

    if enable_builtin_admin:
        cred_dir_env = os.environ.get("CREDENTIALS_DIRECTORY", "")
        adm_token = (args.admin_token or os.environ.get("WHOPROBE_ADMIN_TOKEN") or "").strip()
        if not adm_token:
            cand_file = args.admin_token_file or (str(Path(cred_dir_env) / "admin_token") if cred_dir_env else "")
            if cand_file and Path(cand_file).is_file():
                try:
                    adm_token = Path(cand_file).read_text(encoding="utf-8").strip()
                except OSError:
                    adm_token = ""
        if adm_token:
            try:
                ADMIN_AUTH = admin_store.AdminAuth(adm_token)
                ADMIN_STORE = admin_store.AdminStore(data_dir_arg)
                print("[admin] 已启用管理后台与访问审计 (/admin)")
            except Exception as exc:
                print(f"[admin] 未能启用管理后台: {exc}")

    try:
        settings = visibility.Settings.from_args(args)
        dns = visibility_dns.start_from_args(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    VISIBILITY_VIEW = visibility.View(settings, dns)
    ENABLE_ACTIVE_443 = args.active_probe
    TRUSTED_EDGES = tuple(args.trusted_edge) if args.trusted_edge is not None else DEFAULT_TRUSTED_EDGES
    start_server_geo_prewarmer()
    egress_intel.start_cidr_prewarmer()

    if args.sniff_iface:
        SNIFFER = LinuxPacketSniffer(args.sniff_iface, args.sniff_port)
        SNIFFER.start()
        if SNIFFER.active:
            print(f"[sniffer] 已挂载只读 BPF 探针: iface={args.sniff_iface} tcp dst port {args.sniff_port}")
        else:
            print(f"[sniffer] 未启用旁路抓包 ({SNIFFER.error})；包级观测可能缺测")

    if args.quic_port > 0:
        QUIC_COLLECTOR = QUICInitialCollector(args.quic_port)
        QUIC_COLLECTOR.start()
        if QUIC_COLLECTOR.active:
            print(f"[quic] 已挂载只读 QUIC Initial 解密采集器: udp port {args.quic_port}")
        else:
            print(f"[quic] 未启用 QUIC UDP 采集 ({QUIC_COLLECTOR.error})")

    if args.tls_bridge_port > 0:
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
        cert_file = args.tls_cert or (str(Path(cred_dir) / "tls_cert") if cred_dir else "")
        key_file = args.tls_key or (str(Path(cred_dir) / "tls_key") if cred_dir else "")
        sni_map: dict[str, tuple[str, str]] = {}
        for item in args.tls_sni:
            if "=" in item and "," in item:
                dom, pair = item.split("=", 1)
                cp, kp = pair.split(",", 1)
                cp, kp = cp.strip(), kp.strip()
                if cred_dir and not cp.startswith("/"):
                    cp = str(Path(cred_dir) / cp)
                if cred_dir and not kp.startswith("/"):
                    kp = str(Path(cred_dir) / kp)
                sni_map[dom.strip()] = (cp, kp)
        if cert_file and key_file:
            TLS_BRIDGE = TLSBridgeServer(
                listen_host="127.0.0.1",
                listen_port=args.tls_bridge_port,
                default_cert=cert_file,
                default_key=key_file,
                sni_certs=sni_map,
                h2c_backend=_parse_host_port(args.h2c_backend, 10082),
                h1_backend=_parse_host_port(args.h1_backend, 10081),
            )
            TLS_BRIDGE.start()
            if TLS_BRIDGE.active:
                print(f"[tls-h2-bridge] 已启动 HTTP/2 Akamai 原始帧嗅探桥: 127.0.0.1:{args.tls_bridge_port}")
            else:
                print(f"[tls-h2-bridge] 启动失败 ({TLS_BRIDGE.error})")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), WhoProbeHandler)
    print(f"[who-probe] 监听启动: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[who-probe] 已停止。")
    finally:
        server.server_close()
        if dns is not None:
            dns.close()


if __name__ == "__main__":
    main()
