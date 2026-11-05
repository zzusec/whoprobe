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
import collections
import concurrent.futures
import gzip
import hashlib
import json
import mimetypes
import os
import secrets
import socket
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

import egress_intel  # noqa: E402
import share_store  # noqa: E402

ENABLE_ACTIVE_443 = True
SHARE_STORE: share_store.ShareStore | None = None
_SHARE_STORE_LOCK = threading.Lock()
_SHARE_RATE_SALT = secrets.token_hex(16)

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
        self._data: collections.OrderedDict[str, tuple[float, object]] = collections.OrderedDict()

    def get(self, key: str) -> object | None:
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

    def set(self, key: str, val: object, ttl_sec: float | None = None) -> None:
        exp = time.monotonic() + (self.ttl_sec if ttl_sec is None else ttl_sec)
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = (exp, val)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)


GEO_CACHE = TTLCache(maxsize=2048, ttl_sec=900.0)
PTR_CACHE = TTLCache(maxsize=2048, ttl_sec=900.0)
PACKET_CACHE = TTLCache(maxsize=4096, ttl_sec=180.0)
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


def parse_tls_client_hello(payload: bytes) -> dict | None:
    """解析单包 TLS Record 中的 ClientHello，计算 JA3 与 JA4。"""
    # TLS Record Header: ContentType(1)=0x16, LegacyVersion(2)=0x0301/0x0303, Length(2)
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    rec_len = struct.unpack("!H", payload[3:5])[0]
    hs = payload[5 : 5 + rec_len]
    # HandshakeType(1)=0x01 (ClientHello), Length(3)
    if len(hs) < 38 or hs[0] != 0x01:
        return None
    hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    body = hs[4 : 4 + hs_len]
    if len(body) < 34:
        return None

    client_version = struct.unpack("!H", body[0:2])[0]
    pos = 2 + 32  # skip client_version(2) + random(32)
    if pos >= len(body):
        return None

    # Session ID
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return None

    # Cipher Suites
    cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    if pos + cs_len > len(body):
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

    if pos + 2 <= len(body):
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end_ext = min(len(body), pos + ext_total)
        while pos + 4 <= end_ext:
            etype, elen = struct.unpack("!HH", body[pos : pos + 4])
            pos += 4
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

    ja4 = f"t{ver_code}{sni_code}{c_cnt}{e_cnt}{alpn_code}_{c_hash}_{e_hash}"

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
        "certCompression": [comp_map.get(a, str(a)) for a in cert_comp_algs],
    }


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

    def start(self) -> None:
        if not sys.platform.startswith("linux"):
            self.error = "non-linux-platform"
            return
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.iface, 0))
            self._attach_bpf(sock, self.port)
            self.active = True
            t = threading.Thread(target=self._loop, args=(sock,), daemon=True, name="tls-syn-sniffer")
            t.start()
        except Exception as exc:
            self.error = str(exc)

    @classmethod
    def _attach_bpf(cls, sock: socket.socket, port: int) -> None:
        """
        Classic BPF 字节码 (Ethernet II + IPv4 TCP dst port == port):
        仅放行 TCP SYN 包与非应用层密文(非 0x1703)的握手载荷(完整兼容后量子 ML-KEM 分片 ClientHello)，
        所有纯 ACK 与 TLS Application Data (0x1703) 业务流量均在内核态直接丢弃。
        """
        insns = [
            (0x28, 0, 0, 12),        #  0: ldh [12] (EtherType)
            (0x15, 0, 18, 0x0800),   #  1: if != IPv4 -> 20 (drop)
            (0x30, 0, 0, 23),        #  2: ldb [23] (IPv4 proto)
            (0x15, 0, 16, 6),        #  3: if != TCP -> 20 (drop)
            (0x28, 0, 0, 20),        #  4: ldh [20] (frag offset)
            (0x45, 14, 0, 0x1FFF),   #  5: if fragmented -> 20 (drop)
            (0xB1, 0, 0, 14),        #  6: ldxb 4*([14]&0xf) (X = ihl)
            (0x48, 0, 0, 16),        #  7: ldh [x + 16] (tcp.dst_port)
            (0x15, 0, 11, port),     #  8: if != port -> 20 (drop)
            (0x50, 0, 0, 27),        #  9: ldb [x + 27] (tcp.flags)
            (0x54, 0, 0, 0x3F),      # 10: and #0x3f (兼容携带 ECN ECE/CWR 的 macOS/iOS SYN)
            (0x15, 7, 0, 0x02),      # 11: if SYN (ACK=0) -> 19 (accept)
            (0x50, 0, 0, 26),        # 12: ldb [x + 26] (tcp data offset)
            (0x74, 0, 0, 2),         # 13: rsh #2
            (0x54, 0, 0, 0x3C),      # 14: and #0x3c (A = tcp_hdr_len)
            (0x0C, 0, 0, 0),         # 15: add x (A = ihl + tcp_hdr_len)
            (0x07, 0, 0, 0),         # 16: tax
            (0x48, 0, 0, 14),        # 17: ldh [x + 14] (payload[0:2], 无载荷包越界自动丢弃)
            (0x15, 1, 0, 0x1703),    # 18: if TLS AppData (0x1703) -> 20 (drop)
            (0x06, 0, 0, 4096),      # 19: ret #4096 (accept)
            (0x06, 0, 0, 0),         # 20: ret #0 (drop)
        ]
        bpf_buf = b"".join(struct.pack("HBBI", code, jt, jf, k) for code, jt, jf, k in insns)
        import ctypes

        c_buf = ctypes.create_string_buffer(bpf_buf)
        fprog = struct.pack("@HP", len(insns), ctypes.addressof(c_buf))
        sock.setsockopt(socket.SOL_SOCKET, cls.SO_ATTACH_FILTER, fprog)

    def _loop(self, sock: socket.socket) -> None:
        frag_cache = TTLCache(maxsize=1024, ttl_sec=5.0)
        syn_cache = TTLCache(maxsize=4096, ttl_sec=10.0)
        while True:
            try:
                pkt = sock.recv(4096)
                now_mono = time.monotonic()
                if len(pkt) < 54:
                    continue
                eth_proto = struct.unpack("!H", pkt[12:14])[0]
                if eth_proto != 0x0800:
                    continue
                ip_tot_len = struct.unpack("!H", pkt[16:18])[0]
                ihl = (pkt[14] & 0x0F) * 4
                if ihl < 20 or len(pkt) < 14 + ihl + 20:
                    continue
                frame_end = min(len(pkt), 14 + ip_tot_len)
                ip_tos = pkt[14 + 1]
                ip_id = struct.unpack("!H", pkt[14 + 4 : 14 + 6])[0]
                ip_flags_frag = struct.unpack("!H", pkt[14 + 6 : 14 + 8])[0]
                df_flag = bool(ip_flags_frag & 0x4000)
                ttl = pkt[14 + 8]
                proto = pkt[14 + 9]
                if proto != 6:
                    continue
                src_ip = socket.inet_ntoa(pkt[14 + 12 : 14 + 16])
                if is_private_or_loopback(src_ip):
                    continue

                tcp_start = 14 + ihl
                src_port, dst_port = struct.unpack("!HH", pkt[tcp_start : tcp_start + 4])
                if dst_port != self.port:
                    continue
                data_offset = (pkt[tcp_start + 12] >> 4) * 4
                flags = pkt[tcp_start + 13]
                window = struct.unpack("!H", pkt[tcp_start + 14 : tcp_start + 16])[0]
                if data_offset < 20 or frame_end < tcp_start + data_offset:
                    continue

                conn_key = f"{src_ip}:{src_port}"
                existing = PACKET_CACHE.get(src_ip)
                rec = dict(existing) if isinstance(existing, dict) else {}
                prev_tcp = rec.get("tcp") if isinstance(rec.get("tcp"), dict) else {}

                # 1) 纯 TCP SYN 包 (SYN=1, ACK=0，支持携带 ECN ECE/CWR)
                if (flags & 0x3F) == 0x02:
                    opts_raw = pkt[tcp_start + 20 : tcp_start + data_offset]
                    opts, mss, wscale = parse_tcp_options(opts_raw)
                    syn_tsval = extract_tcp_tsval(opts_raw)
                    syn_cache.set(conn_key, (now_mono, syn_tsval, "ts" in opts), ttl_sec=10.0)
                    init_ttl = infer_initial_ttl(ttl)
                    os_guess, os_family = guess_tcp_os(init_ttl, window, opts)
                    rec["tcp"] = {
                        "observedTtl": ttl,
                        "initialTtl": init_ttl,
                        "hops": max(0, init_ttl - ttl),
                        "window": window,
                        "mss": mss,
                        "mtu": (mss + 40) if mss else None,
                        "tunnelGuess": infer_tunnel_from_mss(mss, ipv6=False),
                        "wscale": wscale,
                        "options": opts,
                        "ja4t": build_ja4t(window, opts, mss, wscale),
                        "osGuess": os_guess,
                        "osFamily": os_family,
                        "df": df_flag,
                        "synIpId": ip_id,
                        "helloIpId": prev_tcp.get("helloIpId"),
                        "tos": ip_tos,
                        "ecn": bool(flags & 0xC0) or ((ip_tos & 0x03) != 0),
                        "synTsval": syn_tsval,
                        "tsHz": prev_tcp.get("tsHz"),
                        "synSpoofSuspect": prev_tcp.get("synSpoofSuspect", False),
                        "handshakeRttMs": prev_tcp.get("handshakeRttMs"),
                        "minHandshakeRttMs": prev_tcp.get("minHandshakeRttMs"),
                        "capturedAt": round(time.time(), 2),
                    }
                    PACKET_CACHE.set(src_ip, rec)
                    continue

                # 2) TLS ClientHello 首包或后量子分片重组
                payload = pkt[tcp_start + data_offset : frame_end]
                if not payload:
                    continue
                if len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
                    # SYN -> ClientHello 首包时间差即服务端到客户端/代理节点的真实 TCP 往返握手 RTT，
                    # 同时利用同五元组 TSval 增量测算发包端内核物理时钟频率并抓捕无状态 SYN 改包器
                    hello_tsval = extract_tcp_tsval(pkt[tcp_start + 20 : tcp_start + data_offset])
                    syn_entry = syn_cache.get(conn_key)
                    if isinstance(syn_entry, tuple) and len(syn_entry) == 3:
                        syn_t, syn_tsval, syn_had_ts = syn_entry
                        syn_cache.set(conn_key, None, ttl_sec=0.0)
                        dt_sec = now_mono - syn_t
                        rtt_ms = round(dt_sec * 1000.0, 1)
                        if 0.2 <= rtt_ms <= 4000.0 and isinstance(rec.get("tcp"), dict):
                            tcp_obj = dict(rec["tcp"])
                            tcp_obj["handshakeRttMs"] = rtt_ms
                            old_min = tcp_obj.get("minHandshakeRttMs")
                            tcp_obj["minHandshakeRttMs"] = (
                                min(old_min, rtt_ms) if isinstance(old_min, (int, float)) else rtt_ms
                            )
                            tcp_obj["helloIpId"] = ip_id
                            if syn_tsval is not None and hello_tsval is not None and dt_sec >= 0.008:
                                ts_delta = (hello_tsval - syn_tsval) & 0xFFFFFFFF
                                ts_hz = round(ts_delta / dt_sec)
                                tcp_obj["tsHz"] = ts_hz
                                tcp_obj["synSpoofSuspect"] = bool(
                                    ts_delta > 5_000_000 or (dt_sec >= 0.02 and ts_hz > 25000)
                                )
                            elif syn_had_ts and hello_tsval is None:
                                tcp_obj["synSpoofSuspect"] = True
                            rec["tcp"] = tcp_obj
                            PACKET_CACHE.set(src_ip, rec)

                    rec_len = struct.unpack("!H", payload[3:5])[0]
                    if len(payload) >= 5 + rec_len:
                        tls_info = parse_tls_client_hello(payload)
                        if tls_info:
                            rec["tlsClientHello"] = tls_info
                            PACKET_CACHE.set(src_ip, rec)
                    elif rec_len <= 8192:
                        frag_cache.set(conn_key, (rec_len, payload), ttl_sec=4.0)
                else:
                    prev = frag_cache.get(conn_key)
                    if isinstance(prev, tuple):
                        rec_len, buf = prev
                        merged = buf + payload
                        if len(merged) >= 5 + rec_len:
                            frag_cache.set(conn_key, None, ttl_sec=0.0)
                            tls_info = parse_tls_client_hello(merged)
                            if tls_info:
                                rec["tlsClientHello"] = tls_info
                                PACKET_CACHE.set(src_ip, rec)
                        elif len(merged) <= 8192:
                            frag_cache.set(conn_key, (rec_len, merged), ttl_sec=4.0)
            except Exception:
                continue


SNIFFER: LinuxPacketSniffer | None = None


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

    def _origin_and_base(self, mounted_under_who: bool) -> tuple[str, str]:
        proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip() or "http"
        host = (self.headers.get("Host") or "localhost").strip()
        base_href = "/who/" if mounted_under_who else "/"
        origin_prefix = f"{proto}://{host}{'/who' if mounted_under_who else ''}"
        return origin_prefix, base_href

    def _extract_client_ip(self) -> str:
        xri = (self.headers.get("X-Real-IP") or "").strip()
        if xri:
            return xri
        xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xff:
            return xff
        return self.client_address[0]

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

        origin_prefix, base_href = self._origin_and_base(mounted_under_who)

        # 0) 隐私脱敏分享数据查询与矢量分享卡片 (/api/who/share/<id>, /r/<id>.svg, /r/<id>)
        if path.startswith("/api/who/share/"):
            sid = path.removeprefix("/api/who/share/").strip("/")
            rec = get_share_store().get(sid)
            if not rec:
                self._send_json({"ok": False, "error": "share_not_found"}, status=HTTPStatus.NOT_FOUND)
                return
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

        # 1) 测速、微脉冲抖动测绘与时钟校准探针
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
            qs = urllib.parse.parse_qs(parsed.query)
            req_ip = (qs.get("ip") or [""])[0].strip()
            target_ip = req_ip or self._extract_client_ip()
            is_self_query = not bool(req_ip) or (target_ip == self._extract_client_ip())
            intel_payload = egress_intel.inspect_ip_intelligence(
                target_ip,
                enable_active_443=ENABLE_ACTIVE_443,
            )
            intel_payload["isSelfEgress"] = is_self_query
            self._send_json(intel_payload)
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
            internal_hdrs = {
                "x-real-ip", "x-forwarded-for", "x-forwarded-proto",
                "x-tls-protocol", "x-tls-cipher", "x-tls-curves",
                "x-tls-alpn", "x-tls-reused", "x-http-version", "connection",
            }
            header_order = [
                k for k, _ in self.headers.items() if k.lower() not in internal_hdrs
            ]
            visible_headers = {
                k.lower(): v
                for k, v in self.headers.items()
                if k.lower() not in internal_hdrs and k.lower() != "cookie"
            }

            nginx_conn = {
                "httpVersion": self.headers.get("X-HTTP-Version") or self.request_version,
                "tlsProtocol": self.headers.get("X-TLS-Protocol") or "",
                "tlsCipher": self.headers.get("X-TLS-Cipher") or "",
                "tlsCurves": self.headers.get("X-TLS-Curves") or "",
                "tlsAlpn": self.headers.get("X-TLS-ALPN") or "",
                "tlsSessionReused": self.headers.get("X-TLS-Reused") or "",
            }

            pkt_data = PACKET_CACHE.get(client_ip)
            low_level = pkt_data if isinstance(pkt_data, dict) else {}

            geo = lookup_ip_geo(client_ip)
            self._send_json({
                "ok": True,
                "serverTimeMs": round(time.time() * 1000, 2),
                "serverCoords": get_server_coarse_coords(),
                "clientIp": client_ip,
                "ipVersion": 6 if ":" in client_ip else 4,
                "geo": geo,
                "connection": nginx_conn,
                "packet": {
                    "snifferActive": bool(SNIFFER and SNIFFER.active),
                    "tcp": low_level.get("tcp"),
                    "tlsClientHello": low_level.get("tlsClientHello"),
                },
                "headerOrder": header_order,
                "headers": visible_headers,
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
            sid, created_at, _ = get_share_store().create(raw_obj)
        except Exception:
            self._send_json({"ok": False, "error": "invalid_share_payload"}, status=HTTPStatus.BAD_REQUEST)
            return

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
    assert egress_intel.normalize_public_ip("8.8.8.8") == ("8.8.8.8", 4)
    assert egress_intel.normalize_public_ip("127.0.0.1") == (None, None)

    # 2) 启动临时 HTTP 服务验证所有路由（含隐私脱敏分享系统）
    with tempfile.TemporaryDirectory(prefix="whoprobe_test_") as tmp_dir:
        global SHARE_STORE
        SHARE_STORE = share_store.ShareStore(data_dir=tmp_dir)
        server = ThreadingHTTPServer(("127.0.0.1", 0), WhoProbeHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
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

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/who/intel?ip=127.0.0.1", timeout=3) as r6:
                intel_priv = json.loads(r6.read().decode("utf-8"))
                assert r6.status == 200 and intel_priv.get("ok") is False

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

            print(f"SELF-TEST OK on 127.0.0.1:{port} | ja4t={ja4t} | etag={et1['etagId']} | share={sid}")
        finally:
            server.shutdown()
            server.server_close()


def main() -> None:
    global SNIFFER, ENABLE_ACTIVE_443
    parser = argparse.ArgumentParser(description="全维度浏览器与网络环境指纹探测服务 (WhoProbe v7.2)")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8899, help="监听端口 (默认 8899)")
    parser.add_argument("--sniff-iface", default="", help="可选 Linux 网卡名(如 ens5)，开启旁路 TCP SYN/JA4 抓包")
    parser.add_argument("--sniff-port", type=int, default=443, help="旁路抓包目标端口 (默认 443)")
    parser.add_argument("--data-dir", default="", help="可选分享快照 SQLite 目录 (默认使用 STATE_DIRECTORY 或 ./data)")
    parser.add_argument("--no-active-probe", action="store_true", help="禁用针对来访公网 IP:443 的反向 TLS/Reality 证书验真")
    parser.add_argument("--self-test", action="store_true", help="运行自动化自检后退出")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if args.data_dir:
        get_share_store(args.data_dir)
    else:
        get_share_store()

    ENABLE_ACTIVE_443 = not args.no_active_probe
    start_server_geo_prewarmer()
    egress_intel.start_cidr_prewarmer()

    if args.sniff_iface:
        SNIFFER = LinuxPacketSniffer(args.sniff_iface, args.sniff_port)
        SNIFFER.start()
        if SNIFFER.active:
            print(f"[sniffer] 已挂载只读 BPF 探针: iface={args.sniff_iface} tcp dst port {args.sniff_port}")
        else:
            print(f"[sniffer] 未启用旁路抓包 ({SNIFFER.error})，自动回退至 Nginx TLS 头模式")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), WhoProbeHandler)
    print(f"[who-probe] 监听启动: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[who-probe] 已停止。")


if __name__ == "__main__":
    main()
