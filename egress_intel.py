#!/usr/bin/env python3
"""
WhoProbe v6.0 — 深度出口情报、BGP/ASN 画像、同段邻居信誉与主动 :443 伪装验真引擎
纯 Python 3 标准库实现（零第三方依赖），融合多源加权几率投票、RDAP 租赁/广播判定、
PeeringDB 自报冲突核验、12 项 DoH DNSBL、14 项 CIDR 威胁/机房/VPN 段与全 ASN 滥用密度计算，
以及针对来访出口 IP:443 的轻量 TLS 证书与 VLESS-Reality 偷证书伪装反向探测。
"""

from __future__ import annotations

import bisect
import concurrent.futures
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "Mozilla/5.0 (compatible; WhoProbe/6.0; +https://github.com/zzusec/whoprobe)"

# ---------------------------------------------------------------------------
# 线程安全有界 TTL 缓存
# ---------------------------------------------------------------------------


class SimpleTTLCache:
    def __init__(self, maxsize: int = 1024, ttl_sec: float = 600.0) -> None:
        self.maxsize = maxsize
        self.ttl_sec = ttl_sec
        self._lock = threading.Lock()
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            exp, val = item
            if now >= exp:
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, val: Any, ttl_sec: float | None = None) -> None:
        ttl = self.ttl_sec if ttl_sec is None else ttl_sec
        exp = time.monotonic() + ttl
        with self._lock:
            if len(self._store) >= self.maxsize and key not in self._store:
                oldest = next(iter(self._store))
                self._store.pop(oldest, None)
            self._store[key] = (exp, val)


INTEL_CACHE = SimpleTTLCache(maxsize=1024, ttl_sec=600.0)
ASN_CACHE = SimpleTTLCache(maxsize=1024, ttl_sec=3600.0)
TLS443_CACHE = SimpleTTLCache(maxsize=2048, ttl_sec=900.0)
CIDR_CACHE = SimpleTTLCache(maxsize=32, ttl_sec=21600.0)  # 6 hours
_CIDR_LOCKS: dict[str, threading.Lock] = {}
_CIDR_GLOBAL_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# 已知自治系统分类表 & 关键字 & IP 租赁经纪商特征
# ---------------------------------------------------------------------------

KNOWN_ASN_LISTS: dict[str, list[int]] = {
    "hosting": [
        16509, 14618, 8987, 396982, 19527, 8075, 8068, 8069, 12076, 31898,
        36351, 45102, 37963, 132203, 45090, 136907, 55990, 135377, 59019,
        14061, 63949, 20473, 16276, 24940, 213230, 51167, 40021, 12876,
        60781, 28753, 30633, 59253, 7203, 395954, 9009, 60068, 212238,
        40676, 8100, 36352, 53667, 25820, 906, 199524, 202422, 36007,
        63473, 35916, 62240, 21859, 54600, 35908, 46844, 54290, 47583,
        8560, 6724, 31034, 202053, 54825, 3258, 35913, 397423, 62904,
        46606, 26496, 32244, 22612, 19318, 32613, 13213, 29802, 33387,
        138997, 141995, 55933, 20278, 397373, 49505, 207990, 44477,
        203020, 210644, 50673, 48282, 58061, 211252, 31173, 39351,
        9370, 2635, 7506, 38001,
    ],
    "cdn": [13335, 209242, 20940, 16625, 54113, 22822, 33438, 15169, 32934, 2906, 16550, 60626],
    "transit": [
        174, 3356, 3549, 1299, 2914, 6453, 6762, 3257, 6939, 4637, 3491,
        1239, 6461, 5511, 9002, 4826, 58453, 4809, 23764, 10099, 9929,
        12956, 1273, 2828, 10026, 20485, 7473, 5400, 4651, 9304, 37100, 64049,
    ],
    "mobile": [
        9605, 21928, 22394, 6167, 20057, 55836, 31133, 16135, 45609,
        24445, 56040, 56041, 56042, 56044, 56046, 56047, 56048,
    ],
    "isp": [
        4134, 4837, 9808, 4812, 17621, 4808, 17816, 7922, 7018, 701, 209,
        20115, 22773, 5650, 11427, 20001, 10796, 11351, 12271, 33363, 6128,
        3209, 5089, 2856, 3215, 12322, 5410, 15557, 3352, 3269, 1136, 2516,
        4713, 17676, 2527, 4766, 9318, 3786, 3462, 4780, 9924, 4760, 9269,
        10091, 9506, 45899, 7552, 18403, 17974, 9829, 24560, 1221, 4804,
        7545, 812, 577, 6327, 852, 8151, 28573, 12389, 8402, 25513, 9121,
        8452, 6849, 5617, 12741, 2119, 3301, 1759, 5432, 6805, 8881, 3303,
        8447, 15502, 2860, 3243, 12430, 6739, 30722, 12874, 4788, 9583,
        23969, 4818, 17552, 131090, 18881, 26599, 27699, 7303, 10318,
        22927, 13999, 4230, 6830, 3320, 7713,
    ],
}
KNOWN_ASN_MAP: dict[int, str] = {
    asn: cls for cls, asns in KNOWN_ASN_LISTS.items() for asn in asns
}
TRANSIT_HOSTING_ASNS = {6939, 58453, 4809, 23764, 10099, 9929, 3491}

ASN_CLASS_LABELS = {
    "isp": "运营商宽带",
    "mobile": "移动蜂窝网",
    "hosting": "机房 / 云厂商",
    "cdn": "CDN / 边缘网络",
    "transit": "国际骨干网",
    "business": "企业专线",
    "education": "教育科研网",
    "government": "政府机构网",
}

ASN_KEYWORDS: list[tuple[str, re.Pattern[str], float]] = [
    ("cdn", re.compile(r"\b(cdn|akamai|cloudflare|fastly|edgecast|limelight|bunnycdn|content delivery)\b", re.I), 1.5),
    ("hosting", re.compile(r"(hosting|\bhost\b|server|datacent(er|re)|data cent(er|re)|\bidc\b|cloud|\bvps\b|colo(cation)?|dedicated|compute|virtual|\bovh|hetzner|leaseweb|contabo|digitalocean|linode|vultr|choopa|amazon|\baws\b|azure|alibaba|aliyun|tencent|oracle|softlayer|rackspace|\bm247|datacamp|cdn77|psychz|quadranet|colocrossing|frantech|buyvm|krypt|sharktech|hostwinds|ionos|scaleway|upcloud|kamatera|g-?core|zenlayer|clouvider|dmit|xtom|racknerd|hostinger|\bvpn\b|proxy)", re.I), 1.4),
    ("transit", re.compile(r"(backbone|transit|\bcarrier\b|cogent|lumen|level ?3|arelion|telia|\bgtt\b|zayo|tata comm|sparkle|pccw global|hurricane electric|ntt (america|global)|global crossing|\bretn\b)", re.I), 1.6),
    ("mobile", re.compile(r"(mobile|wireless|cellular|\blte\b|\b5g\b|\bgsm\b|mobil\b|movil)", re.I), 1.2),
    ("education", re.compile(r"(universit|college|school|academ|education|research|\bedu\b|cernet|institute|\bnren\b)", re.I), 1.6),
    ("government", re.compile(r"(government|ministry|\bgov\b|federal|municipal)", re.I), 1.4),
    ("isp", re.compile(r"(telecom|telekom|telecommunication|broadband|\bcable|communications?|comcast|charter|verizon|at&t|\bisp\b|internet service|\bdsl\b|fib(er|re)|ftth|netcom|unicom|telefonica|vodafone|orange|kddi|\bntt\b|softbank|telstra|optus|rogers|\bbell\b|shaw|telus|hinet|chunghwa|pccw|hkbn|singtel|starhub|chinanet|china telecom|china mobile|cmnet)", re.I), 1.0),
]

PDB_TYPE_MAP: dict[str, tuple[str, float]] = {
    "Cable/DSL/ISP": ("isp", 2.2),
    "NSP": ("transit", 2.2),
    "Content": ("hosting", 1.8),
    "Enterprise": ("business", 1.6),
    "Educational/Research": ("education", 2.2),
    "Non-Profit": ("business", 1.0),
    "Government": ("government", 2.0),
}

BROKER_RE = re.compile(
    r"(ipxo|interlir|heficed|ipbroker|internet utilities|logicweb|ip-?volume|ipv4 ?(mall|market|depot)|abuseradar|cloud innovation|larus|netutils|cogent.*sub|lease)",
    re.I,
)

# 常见 VLESS-Reality / ShadowTLS 偷用的大厂诱饵证书域名及其合法归属 ASN 集合
REALITY_BAIT_BRANDS: list[tuple[re.Pattern[str], set[int], str]] = [
    (re.compile(r"(^|\.)(microsoft\.com|msecnd\.net|live\.com|bing\.com|office\.com|windowsupdate\.com)$", re.I), {8075, 8068, 8069, 3598, 20940, 16625}, "Microsoft / Bing"),
    (re.compile(r"(^|\.)(apple\.com|icloud\.com|cdn-apple\.com|mzstatic\.com|itunes\.com|aaplimg\.com)$", re.I), {714, 6185, 20940, 16625, 54113}, "Apple / iCloud"),
    (re.compile(r"(^|\.)(yahoo\.com|yimg\.com|yahoo\.co\.jp)$", re.I), {10310, 36646, 36647, 26101, 54113, 20940}, "Yahoo"),
    (re.compile(r"(^|\.)(google\.com|dl\.google\.com|googleapis\.com|gstatic\.com|1e100\.net|youtube\.com)$", re.I), {15169, 396982, 19527, 36040}, "Google"),
    (re.compile(r"(^|\.)(lovelive-anime\.jp|bandainamco\.co\.jp|nintendo\.com|playstation\.com|sony\.com)$", re.I), {16509, 14618, 13335, 20940, 54113, 2906}, "日本娱乐官网诱饵"),
    (re.compile(r"(^|\.)(amd\.com|nvidia\.com|intel\.com|samsung\.com|asus\.com)$", re.I), {20940, 16625, 13335, 54113, 16509}, "硬件官网诱饵"),
    (re.compile(r"(^|\.)(awsstatic\.com|amazonaws\.com|cloudfront\.net|amazon\.com)$", re.I), {16509, 14618, 8987}, "Amazon / AWS"),
    (re.compile(r"(^|\.)(cloudflare\.com|cloudflare-dns\.com|one\.one\.one\.one)$", re.I), {13335, 209242}, "Cloudflare"),
    (re.compile(r"(^|\.)(paypal\.com|stripe\.com|visa\.com|mastercard\.com|swift\.com)$", re.I), {17012, 16509, 20940, 54113, 13335}, "金融门户诱饵"),
    (re.compile(r"(^|\.)(steampowered\.com|steamstatic\.com|epicgames\.com|discord\.com)$", re.I), {32590, 20940, 54113, 13335, 16509}, "游戏平台诱饵"),
]

# 源权重表（遵循多源加权投票与直接观测奇数比放大）
SOURCE_WEIGHTS: dict[str, dict[str, Any]] = {
    "ipinfo": {"flags": 1.3, "type": 1.3, "geo": 1.6},
    "ipapiis": {"flags": 0.95, "type": 0.95, "risk": 0.9, "geo": 1.0},
    "iplocate": {"flags": 0.9, "type": 0.85, "geo": 1.0},
    "ipquery": {"flags": 0.85, "type": 0.7, "risk": 0.65, "geo": 1.0},
    "ipapi": {"flags": 0.8, "type": 0.8, "geo": 1.0},
    "blackbox": {"flags": 0.6, "type": 0.6, "geo": 0.0},
    "freeipapi": {"flags": 0.45, "geo": 0.8},
    "ipleak": {"geo": 1.0},
    "ipwhois": {"geo": 0.9},
    "shodan": {"flags": 0.55, "positiveOnly": True, "observed": True},
    "sfs": {"flags": 0.8, "positiveOnly": True, "observed": True},
    "otx": {"flags": 0.6, "positiveOnly": True, "observed": True},
    "onionoo": {"flags": 1.0, "observed": True},
    "ptr": {"flags": 0.5, "type": 0.5},
}

GEO_FAMILY: dict[str, str] = {
    "ipleak": "maxmind",
    "ipwhois": "ipwhois",
    "freeipapi": "dbip",
    "ipapi": "ipapi",
    "ipinfo": "ipinfo",
    "ipapiis": "ipapiis",
    "ipquery": "ipquery",
    "iplocate": "iplocate",
}

AI_BLOCKED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU"}

DNSBLS: list[dict[str, Any]] = [
    {"id": "spamcop", "name": "SpamCop", "zone": "bl.spamcop.net", "kind": "mail"},
    {"id": "barracuda", "name": "Barracuda", "zone": "b.barracudacentral.org", "kind": "mail"},
    {"id": "psbl", "name": "PSBL", "zone": "psbl.surriel.com", "kind": "mail"},
    {"id": "mailspike", "name": "Mailspike", "zone": "bl.mailspike.net", "kind": "mail"},
    {"id": "uceprotect", "name": "UCEPROTECT L1", "zone": "dnsbl-1.uceprotect.net", "kind": "mail"},
    {"id": "spfbl", "name": "SPFBL", "zone": "dnsbl.spfbl.net", "kind": "mail", "ignore": {"127.0.0.4"}},
    {"id": "zerospam", "name": "0spam", "zone": "bl.0spam.org", "kind": "mail"},
    {"id": "interserver", "name": "InterServer", "zone": "rbl.interserver.net", "kind": "abuse"},
    {"id": "blocklistde", "name": "blocklist.de", "zone": "bl.blocklist.de", "kind": "abuse"},
    {"id": "s5h", "name": "S5H", "zone": "all.s5h.net", "kind": "abuse"},
    {"id": "dronebl", "name": "DroneBL", "zone": "dnsbl.dronebl.org", "kind": "abuse", "proxyCodes": {8, 9, 10, 11, 14, 19}},
    {"id": "dantor", "name": "dan.me.uk Tor", "zone": "torexit.dan.me.uk", "kind": "tor"},
]

FIREHOL_BASE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
CIDR_LISTS: list[dict[str, Any]] = [
    {"id": "firehol1", "name": "FireHOL Level 1", "kind": "attack", "pts": 15, "density": False, "url": FIREHOL_BASE + "firehol_level1.netset"},
    {"id": "firehol2", "name": "FireHOL Level 2", "kind": "attack", "pts": 10, "density": False, "url": FIREHOL_BASE + "firehol_level2.netset"},
    {"id": "blocklistde", "name": "blocklist.de", "kind": "attack", "pts": 10, "density": True, "url": FIREHOL_BASE + "blocklist_de.ipset"},
    {"id": "greensnow", "name": "GreenSnow", "kind": "attack", "pts": 8, "density": True, "url": FIREHOL_BASE + "greensnow.ipset"},
    {"id": "cybercrime", "name": "CyberCrime C&C", "kind": "attack", "pts": 15, "density": True, "url": FIREHOL_BASE + "cybercrime.ipset"},
    {"id": "sfs7d", "name": "StopForumSpam 7d", "kind": "spam", "pts": 0, "density": True, "url": FIREHOL_BASE + "stopforumspam_7d.ipset"},
    {"id": "dshield", "name": "DShield 攻击段", "kind": "attack", "pts": 0, "density": False, "url": FIREHOL_BASE + "dshield_7d.netset"},
    {"id": "ipsum3", "name": "IPsum ≥3 黑名单", "kind": "attack", "pts": 8, "density": True, "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"id": "etcompromised", "name": "ET 已入侵主机", "kind": "attack", "pts": 10, "density": True, "url": FIREHOL_BASE + "et_compromised.ipset"},
    {"id": "ciarmy", "name": "CINS Army", "kind": "attack", "pts": 8, "density": True, "url": FIREHOL_BASE + "ciarmy.ipset"},
    {"id": "socksproxy", "name": "公开 SOCKS 代理", "kind": "proxy", "pts": 0, "density": False, "url": FIREHOL_BASE + "socks_proxy_7d.ipset"},
    {"id": "sslproxy", "name": "公开 HTTPS 代理", "kind": "proxy", "pts": 0, "density": False, "url": FIREHOL_BASE + "sslproxies_7d.ipset"},
    {"id": "torexits", "name": "Tor 出口列表", "kind": "tor", "pts": 0, "density": False, "url": FIREHOL_BASE + "tor_exits.ipset"},
    {"id": "x4bdc", "name": "X4BNet 机房段", "kind": "datacenter", "pts": 0, "density": False, "url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"},
    {"id": "x4bvpn", "name": "X4BNet VPN 段", "kind": "vpn", "pts": 0, "density": False, "url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"},
]

ROUTED_IPV4_SPACE = 3_000_000_000.0


# ---------------------------------------------------------------------------
# 基础解析与网络请求辅助函数
# ---------------------------------------------------------------------------


def normalize_public_ip(raw_ip: str) -> tuple[str | None, int | None]:
    try:
        addr = ipaddress.ip_address((raw_ip or "").strip())
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return None, None
        return str(addr), addr.version
    except ValueError:
        return None, None


def _http_json(url: str, timeout: float = 3.8, headers: dict[str, str] | None = None) -> Any:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def _http_text(url: str, timeout: float = 6.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _cc(val: Any) -> str | None:
    if not isinstance(val, str):
        return None
    s = val.strip().upper()
    return s if len(s) == 2 and s.isalpha() else None


def _asn_num(val: Any) -> int | None:
    if isinstance(val, int) and val > 0:
        return val
    if isinstance(val, str):
        m = re.search(r"(\d+)", val)
        if m:
            n = int(m.group(1))
            return n if n > 0 else None
    return None


def _bool_or_none(val: Any) -> bool | None:
    return val if isinstance(val, bool) else None


def _num_or_none(val: Any) -> float | None:
    if isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val):
        return float(val)
    if isinstance(val, str):
        try:
            f = float(val.strip())
            return f if math.isfinite(f) else None
        except ValueError:
            return None
    return None


def classify_ptr_hostname(hostname: str | None) -> dict[str, Any]:
    name = (hostname or "").strip().lower()
    if not name:
        return {"type": None, "hosting": None, "mobile": None}
    if re.search(r"(^|[.-])(vps|server|srv|host|hosting|cloud|dedi(cated)?|colo|static\.\d|compute|ec2|googleusercontent|linode|vultr|contabo|hetzner|ovh|leaseweb|your-server|kimsufi|racknerd|dmit)([.-]|\d|$)", name):
        return {"type": "hosting", "hosting": True, "mobile": None}
    if re.search(r"(^|[.-])(dyn|dynamic|dhcp|pool|ppp|pppoe|adsl|dsl|vdsl|cable|cpe|fttx|ftth|fiber|fibre|home|broadband|res|customer|client|subscriber|bb|flets|ocn|kddi|softbank|hinet|dynamicip)([.-]|\d|$)", name):
        return {"type": "residential", "hosting": False, "mobile": None}
    if re.search(r"(^|[.-])(mobile|wireless|lte|4g|5g|gprs|umts|cellular|mob)([.-]|\d|$)", name):
        return {"type": "mobile", "hosting": False, "mobile": True}
    return {"type": None, "hosting": None, "mobile": None}


# ---------------------------------------------------------------------------
# 多源 IP 情报适配器
# ---------------------------------------------------------------------------


def _src_ipapiis(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}", timeout=4.0)
    if d.get("error") or not d.get("ip"):
        raise ValueError(str(d.get("error") or "invalid"))
    comp = d.get("company") if isinstance(d.get("company"), dict) else {}
    asn_obj = d.get("asn") if isinstance(d.get("asn"), dict) else {}
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    abuser_raw = str(comp.get("abuser_score") or "")
    m_lbl = re.search(r"\(([^)]+)\)", abuser_raw)
    lbl_map = {"very low": 3.0, "low": 10.0, "elevated": 40.0, "high": 70.0, "very high": 90.0}
    risk = lbl_map.get(m_lbl.group(1).strip().lower()) if m_lbl else None
    ctype_map = {
        "isp": "residential",
        "hosting": "hosting",
        "business": "business",
        "education": "education",
        "government": "government",
        "banking": "business",
    }
    comp_type = ctype_map.get(str(comp.get("type") or "").lower())
    usage_type = "hosting" if d.get("is_datacenter") is True else ("mobile" if d.get("is_mobile") is True else comp_type)
    return {
        "id": "ipapiis",
        "name": "ipapi.is",
        "country": _cc(loc.get("country_code") or d.get("country")),
        "region": loc.get("state") or d.get("region"),
        "city": loc.get("city") or d.get("city"),
        "tz": loc.get("timezone") or d.get("timezone"),
        "asn": _asn_num(asn_obj.get("asn") or d.get("asn")),
        "org": comp.get("name") or asn_obj.get("org"),
        "asnType": asn_obj.get("type"),
        "companyType": comp_type,
        "type": usage_type,
        "risk": risk,
        "flags": {
            "vpn": _bool_or_none(d.get("is_vpn")),
            "proxy": _bool_or_none(d.get("is_proxy")),
            "tor": _bool_or_none(d.get("is_tor")),
            "hosting": _bool_or_none(d.get("is_datacenter")),
            "crawler": _bool_or_none(d.get("is_crawler")),
            "abuser": _bool_or_none(d.get("is_abuser")),
            "mobile": _bool_or_none(d.get("is_mobile")),
        },
    }


def _src_ipquery(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://api.ipquery.io/{urllib.parse.quote(ip)}?format=json", timeout=4.0)
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    isp = d.get("isp") if isinstance(d.get("isp"), dict) else {}
    rsk = d.get("risk") if isinstance(d.get("risk"), dict) else {}
    is_dc = _bool_or_none(rsk.get("is_datacenter"))
    is_mob = _bool_or_none(rsk.get("is_mobile"))
    return {
        "id": "ipquery",
        "name": "IPQuery",
        "country": _cc(loc.get("country_code")),
        "region": loc.get("state"),
        "city": loc.get("city"),
        "tz": loc.get("timezone"),
        "asn": _asn_num(isp.get("asn")),
        "org": isp.get("org") or isp.get("isp"),
        "type": "hosting" if is_dc else ("mobile" if is_mob else None),
        "risk": _num_or_none(rsk.get("risk_score")),
        "flags": {
            "vpn": _bool_or_none(rsk.get("is_vpn")),
            "proxy": _bool_or_none(rsk.get("is_proxy")),
            "tor": _bool_or_none(rsk.get("is_tor")),
            "hosting": is_dc,
            "mobile": is_mob,
        },
    }


def _src_iplocate(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://www.iplocate.io/api/lookup/{urllib.parse.quote(ip)}", timeout=4.0)
    if d.get("error"):
        raise ValueError(str(d.get("error")))
    p = d.get("privacy") if isinstance(d.get("privacy"), dict) else {}
    comp = d.get("company") if isinstance(d.get("company"), dict) else {}
    asn_obj = d.get("asn") if isinstance(d.get("asn"), dict) else {}
    ctype_map = {
        "isp": "residential",
        "hosting": "hosting",
        "business": "business",
        "education": "education",
        "government": "government",
    }
    comp_type = ctype_map.get(str(comp.get("type") or "").lower())
    is_host = _bool_or_none(p.get("is_hosting"))
    return {
        "id": "iplocate",
        "name": "IPLocate",
        "country": _cc(d.get("country_code")),
        "region": d.get("subdivision"),
        "city": d.get("city"),
        "tz": d.get("time_zone"),
        "asn": _asn_num(asn_obj.get("asn")),
        "org": comp.get("name") or asn_obj.get("name"),
        "asnType": asn_obj.get("type"),
        "companyType": comp_type,
        "type": "hosting" if is_host else comp_type,
        "anycast": d.get("is_anycast") is True,
        "flags": {
            "vpn": _bool_or_none(p.get("is_vpn")),
            "proxy": _bool_or_none(p.get("is_proxy")),
            "tor": _bool_or_none(p.get("is_tor")),
            "relay": _bool_or_none(p.get("is_icloud_relay")),
            "hosting": is_host,
            "abuser": _bool_or_none(p.get("is_abuser")),
        },
    }


def _src_blackbox(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://blackbox.ipinfo.app/api/v3beta/{urllib.parse.quote(ip)}", timeout=4.0)
    sigs = d.get("signals") if isinstance(d.get("signals"), dict) else {}
    if d.get("error") or not sigs:
        raise ValueError("blackbox unavailable")
    cls = str(d.get("classification") or "").strip().lower()
    valid_cls = cls in {"residential", "mobile", "business", "hosting", "vpn", "tor", "privacy_relay", "bogon"}
    cflag = lambda v: True if v is True else (_bool_or_none(v) if valid_cls else None)
    host_sig = True if (sigs.get("hosting") is True or sigs.get("cloud") is True) else (False if (sigs.get("hosting") is False and sigs.get("cloud") is False and valid_cls) else None)
    asn_obj = d.get("asn") if isinstance(d.get("asn"), dict) else {}
    prefix = f"{asn_obj['network']}/{asn_obj['cidr']}" if asn_obj.get("network") and isinstance(asn_obj.get("cidr"), int) else None
    return {
        "id": "blackbox",
        "name": "Blackbox v3",
        "asn": _asn_num(asn_obj.get("number")),
        "org": asn_obj.get("name"),
        "prefix": prefix,
        "hostname": (d.get("rdns") or {}).get("hostname") if isinstance(d.get("rdns"), dict) else None,
        "type": cls if cls in {"residential", "mobile", "business", "hosting"} else None,
        "geoVote": False,
        "flags": {
            "proxy": cflag(sigs.get("proxy")),
            "tor": cflag(sigs.get("tor")),
            "vpn": True if cls == "vpn" else cflag(sigs.get("vpnasn")),
            "relay": cflag(sigs.get("goodvpn")),
            "hosting": host_sig,
            "mobile": True if cls == "mobile" else cflag(sigs.get("mobileasn")),
        },
    }


def _src_ipapi(ip: str) -> dict[str, Any]:
    fields = "status,countryCode,regionName,city,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
    d = _http_json(f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields={fields}", timeout=3.8)
    if d.get("status") != "success":
        raise ValueError("ip-api failed")
    is_host = _bool_or_none(d.get("hosting"))
    is_mob = _bool_or_none(d.get("mobile"))
    return {
        "id": "ipapi",
        "name": "ip-api.com",
        "country": _cc(d.get("countryCode")),
        "region": d.get("regionName"),
        "city": d.get("city"),
        "tz": d.get("timezone"),
        "asn": _asn_num(d.get("as")),
        "org": d.get("org") or d.get("isp"),
        "hostname": d.get("reverse") or None,
        "type": "hosting" if is_host else ("mobile" if is_mob else None),
        "flags": {
            "proxy": _bool_or_none(d.get("proxy")),
            "hosting": is_host,
            "mobile": is_mob,
        },
    }


def _src_ipinfo(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://ipinfo.io/{urllib.parse.quote(ip)}/json", timeout=3.8)
    if not d.get("ip"):
        raise ValueError("ipinfo failed")
    org_raw = str(d.get("org") or "")
    org_clean = re.sub(r"^AS\d+\s+", "", org_raw, flags=re.I).strip() or None
    return {
        "id": "ipinfo",
        "name": "IPinfo",
        "country": _cc(d.get("country")),
        "region": d.get("region"),
        "city": d.get("city"),
        "tz": d.get("timezone"),
        "asn": _asn_num(org_raw),
        "org": org_clean,
        "hostname": d.get("hostname"),
        "anycast": d.get("anycast") is True,
        "flags": {},
    }


def _src_ipleak(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://ipleak.net/json/{urllib.parse.quote(ip)}", timeout=4.0)
    return {
        "id": "ipleak",
        "name": "MaxMind (ipleak)",
        "country": _cc(d.get("country_code")),
        "region": d.get("region_name"),
        "city": d.get("city_name"),
        "tz": d.get("time_zone"),
        "asn": _asn_num(d.get("as_number")),
        "org": d.get("isp_name"),
        "regCountry": _cc(d.get("registered_country_code")),
        "prefix": d.get("as_network"),
        "hostname": d.get("reverse") or None,
        "flags": {},
    }


def _src_freeipapi(ip: str) -> dict[str, Any]:
    d = _http_json(f"https://free.freeipapi.com/api/v1/json/{urllib.parse.quote(ip)}", timeout=3.8)
    tzs = d.get("timeZones") if isinstance(d.get("timeZones"), list) else []
    return {
        "id": "freeipapi",
        "name": "FreeIPAPI (DB-IP)",
        "country": _cc(d.get("countryCode")),
        "region": d.get("regionName"),
        "city": d.get("cityName"),
        "tz": tzs[0] if tzs else None,
        "asn": _asn_num(d.get("asn")),
        "org": d.get("asnOrganization"),
        "flags": {"proxy": _bool_or_none(d.get("isProxy"))},
    }


# ---------------------------------------------------------------------------
# 注册信息 (RDAP / RIPEstat / PeeringDB) & 威胁扫描源 (Shodan / SFS / OTX / Tor)
# ---------------------------------------------------------------------------


def _fetch_rdap_ip(ip: str) -> dict[str, Any] | None:
    try:
        d = _http_json(
            f"https://rdap.org/ip/{urllib.parse.quote(ip)}",
            timeout=4.5,
            headers={"Accept": "application/rdap+json"},
        )
        events = {e.get("eventAction"): e.get("eventDate") for e in (d.get("events") or []) if isinstance(e, dict)}
        flat: list[dict[str, Any]] = []

        def _walk(ents: Any) -> None:
            for ent in ents or []:
                if isinstance(ent, dict):
                    flat.append(ent)
                    _walk(ent.get("entities"))

        _walk(d.get("entities"))

        def _vcard(ent: dict[str, Any] | None) -> dict[str, Any]:
            if not ent:
                return {}
            vc = ent.get("vcardArray")
            if not isinstance(vc, list) or len(vc) < 2 or not isinstance(vc[1], list):
                return {}
            out: dict[str, Any] = {}
            for item in vc[1]:
                if isinstance(item, list) and len(item) >= 4:
                    k = item[0]
                    out[k] = (item[1].get("label") if isinstance(item[1], dict) and item[1].get("label") else item[3]) if k == "adr" else item[3]
            return out

        reg_ent = next((e for e in flat if "registrant" in (e.get("roles") or [])), None)
        abuse_ent = next((e for e in flat if "abuse" in (e.get("roles") or [])), None)
        reg_vc = _vcard(reg_ent)
        abuse_vc = _vcard(abuse_ent)
        cidrs = d.get("cidr0_cidrs") or []
        cidr_str = None
        if cidrs and isinstance(cidrs[0], dict):
            p = cidrs[0].get("v4prefix") or cidrs[0].get("v6prefix")
            ln = cidrs[0].get("length")
            if p and ln is not None:
                cidr_str = f"{p}/{ln}"
        port43 = str(d.get("port43") or "")
        rir = re.sub(r"^whois\.|\.(net|org)$", "", port43, flags=re.I).upper() or None
        status_val = d.get("type") or ", ".join(d.get("status") or [])
        return {
            "regCountry": _cc(d.get("country")),
            "netname": d.get("name"),
            "handle": d.get("handle"),
            "status": status_val,
            "cidr": cidr_str,
            "regDate": events.get("registration"),
            "changedDate": events.get("last changed"),
            "orgName": reg_vc.get("fn"),
            "abuseName": abuse_vc.get("fn"),
            "abuseEmail": abuse_vc.get("email"),
            "rir": rir,
        }
    except Exception:
        return None


def _fetch_shodan(ip: str) -> dict[str, Any] | None:
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3.8) as resp:
            d = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ports": [], "tags": [], "vulns": [], "hostnames": [], "unseen": True}
        return None
    except Exception:
        return None
    tags = [str(t) for t in (d.get("tags") or [])]
    ports = [int(p) for p in (d.get("ports") or []) if isinstance(p, int)]
    vulns = [str(v) for v in (d.get("vulns") or [])][:12]
    hosts = [str(h) for h in (d.get("hostnames") or [])][:5]
    return {"ports": ports, "tags": tags, "vulns": vulns, "hostnames": hosts, "unseen": False}


def _fetch_sfs(ip: str) -> dict[str, Any] | None:
    try:
        d = _http_json(f"https://api.stopforumspam.org/api?ip={urllib.parse.quote(ip)}&json", timeout=3.8)
        rec = d.get("ip") if isinstance(d.get("ip"), dict) else {}
        return {
            "appears": int(rec.get("appears") or 0),
            "frequency": int(rec.get("frequency") or 0),
            "confidence": _num_or_none(rec.get("confidence")),
            "lastseen": rec.get("lastseen"),
            "torexit": bool(rec.get("torexit")),
        }
    except Exception:
        return None


def _fetch_otx(ip: str, ip_ver: int) -> dict[str, Any] | None:
    kind = "IPv6" if ip_ver == 6 else "IPv4"
    try:
        d = _http_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{urllib.parse.quote(ip)}/general", timeout=4.0)
        pinfo = d.get("pulse_info") if isinstance(d.get("pulse_info"), dict) else {}
        pulses = pinfo.get("pulses") if isinstance(pinfo.get("pulses"), list) else []
        vals = [str(v.get("source") or v.get("name") or "") for v in (d.get("validation") or []) if isinstance(v, dict)]
        benign = bool(d.get("false_positive")) or any(re.search(r"whitelist|alexa|majestic|akamai|false", v, re.I) for v in vals)
        return {
            "pulses": int(pinfo.get("count") or 0),
            "pulseNames": [str(p.get("name")) for p in pulses if isinstance(p, dict) and p.get("name")][:4],
            "benign": benign,
        }
    except Exception:
        return None


def _fetch_onionoo(ip: str, ip_ver: int) -> dict[str, Any] | None:
    query = (".".join(ip.split(".")[:3]) + ".") if ip_ver == 4 else ip
    try:
        d = _http_json(
            f"https://onionoo.torproject.org/details?search={urllib.parse.quote(query)}&fields=nickname,or_addresses,exit_addresses,flags,running",
            timeout=4.0,
        )
        relays = d.get("relays") or []

        def _addrs(r: dict[str, Any]) -> list[str]:
            out = list(r.get("exit_addresses") or [])
            for oa in r.get("or_addresses") or []:
                s = re.sub(r"^\[|\]?:\d+$", "", str(oa)).rstrip("]")
                out.append(s)
            return out

        exact = [r for r in relays if ip in _addrs(r)]
        neigh = [r for r in relays if r not in exact and any(a.startswith(query) for a in _addrs(r))] if ip_ver == 4 else []
        is_exit = any("Exit" in (r.get("flags") or []) or ip in (r.get("exit_addresses") or []) for r in exact)
        return {
            "torRelay": len(exact) > 0,
            "torExit": is_exit,
            "nicknames": [str(r.get("nickname") or "") for r in exact[:3]],
            "neighbourRelays": len(neigh),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 主动反向探测来访出口 IP:443 — 专杀 VLESS-Reality / ShadowTLS / Trojan 偷证书伪装
# ---------------------------------------------------------------------------


def _decode_der_cert(der_bytes: bytes) -> dict[str, Any]:
    """解析 X.509 DER 二进制证书中的 Subject CN / Org、Issuer 与 SAN 域名列表。"""
    subject_cn = ""
    subject_org = ""
    issuer_cn = ""
    issuer_org = ""
    sans: list[str] = []

    if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
        tmp_path = ""
        try:
            pem = ssl.DER_cert_to_PEM_cert(der_bytes)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tf:
                tf.write(pem)
                tmp_path = tf.name
            decoded = ssl._ssl._test_decode_cert(tmp_path) or {}
            for rdn in decoded.get("subject") or ():
                for k, v in rdn:
                    if k == "commonName" and not subject_cn:
                        subject_cn = str(v)
                    elif k == "organizationName" and not subject_org:
                        subject_org = str(v)
            for rdn in decoded.get("issuer") or ():
                for k, v in rdn:
                    if k == "commonName" and not issuer_cn:
                        issuer_cn = str(v)
                    elif k == "organizationName" and not issuer_org:
                        issuer_org = str(v)
            for kind, val in decoded.get("subjectAltName") or ():
                if kind == "DNS" and val:
                    sans.append(str(val))
            return {
                "subjectCN": subject_cn,
                "subjectOrg": subject_org,
                "issuerCN": issuer_cn,
                "issuerOrg": issuer_org,
                "sans": sans[:20],
            }
        except Exception:
            pass
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    # 纯 Python 字节扫描兜底（提取常见 ASCII 域名型 dNSName tag 0x82）
    idx = 0
    n = len(der_bytes)
    while idx + 4 < n:
        if der_bytes[idx] == 0x82:
            ln = der_bytes[idx + 1]
            if 3 <= ln <= 120 and idx + 2 + ln <= n:
                raw_s = der_bytes[idx + 2 : idx + 2 + ln]
                if all(33 <= b <= 122 for b in raw_s) and b"." in raw_s:
                    dom = raw_s.decode("ascii", errors="ignore")
                    if re.match(r"^(\*\.)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$", dom) and dom not in sans:
                        sans.append(dom)
                        idx += 2 + ln
                        continue
        idx += 1
    return {
        "subjectCN": sans[0] if sans else "",
        "subjectOrg": "",
        "issuerCN": "",
        "issuerOrg": "",
        "sans": sans[:20],
    }


def inspect_exit_tls_443(ip: str, asn: int | None = None) -> dict[str, Any]:
    """
    对来访客户端公网 IP 的 443 端口进行一次轻量只读 TLS 证书探查（缓存 15 分钟）：
    1. 家庭宽带通常处于 NAT/防火墙后，443 关闭或超时；若开放说明该出口运行公网服务或为服务器节点。
    2. 若该 IP 不属于微软/苹果/雅虎/Google 等大厂 ASN，但其 443 端口却返回了这些大厂的有效证书，
       或能通过大厂 SNI 的完整加密签名校验，即可实锤 VLESS-Reality / ShadowTLS / SNI 透明转发伪装！
    """
    cache_key = f"{ip}:{asn or 0}"
    cached = TLS443_CACHE.get(cache_key)
    if isinstance(cached, dict):
        return cached

    t0 = time.monotonic()
    result: dict[str, Any] = {
        "probed": True,
        "port443Open": False,
        "tlsActive": False,
        "tlsVersion": None,
        "cipher": None,
        "subjectCN": None,
        "issuerOrg": None,
        "sans": [],
        "selfSignedOrIpCert": False,
        "realitySuspect": False,
        "realityBrand": None,
        "realityDomain": None,
        "verdict": "closed",
        "rttMs": None,
    }

    # Step 1: 尝试 TCP 连接 443（超时 1.4 秒，绝不拖慢接口）
    try:
        raw_sock = socket.create_connection((ip, 443), timeout=1.4)
    except Exception:
        TLS443_CACHE.set(cache_key, result)
        return result

    result["port443Open"] = True
    result["rttMs"] = round((time.monotonic() - t0) * 1000.0, 1)

    # Step 2: 无 SNI / 宽松模式提取默认证书
    cert_info: dict[str, Any] = {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw_sock.settimeout(1.5)
        with ctx.wrap_socket(raw_sock) as ssock:
            result["tlsActive"] = True
            result["tlsVersion"] = ssock.version()
            ciph = ssock.cipher()
            result["cipher"] = ciph[0] if ciph else None
            der = ssock.getpeercert(binary_form=True)
            if der:
                cert_info = _decode_der_cert(der)
    except Exception:
        try:
            raw_sock.close()
        except Exception:
            pass

    if cert_info:
        cn = cert_info.get("subjectCN") or ""
        issuer_org = cert_info.get("issuerOrg") or cert_info.get("issuerCN") or ""
        sans = cert_info.get("sans") or []
        result["subjectCN"] = cn or None
        result["issuerOrg"] = issuer_org or None
        result["sans"] = sans[:8]
        if cn and cn == (cert_info.get("issuerCN") or "") and not issuer_org:
            result["selfSignedOrIpCert"] = True

        all_domains = [d for d in ([cn] + sans) if d]
        for dom in all_domains:
            clean_dom = dom.lstrip("*.")
            for pat, legit_asns, brand in REALITY_BAIT_BRANDS:
                if pat.search(clean_dom) and (asn is None or asn not in legit_asns):
                    result["realitySuspect"] = True
                    result["realityBrand"] = brand
                    result["realityDomain"] = dom
                    result["verdict"] = "reality_bait_cert"
                    break
            if result["realitySuspect"]:
                break

    # Step 3: 若 443 端口开放但无默认证书返回（典型配置了严格 serverNames 的 Reality 转发器），
    # 用系统根证书池做一次高频诱饵域名 (www.microsoft.com) 密码学真实验签探测！
    if result["port443Open"] and not result["realitySuspect"] and not result["sans"]:
        if asn not in {8075, 8068, 8069, 20940, 16625}:
            try:
                strict_ctx = ssl.create_default_context()
                with socket.create_connection((ip, 443), timeout=1.1) as s2:
                    s2.settimeout(1.2)
                    with strict_ctx.wrap_socket(s2, server_hostname="www.microsoft.com") as ss2:
                        result["tlsActive"] = True
                        result["tlsVersion"] = ss2.version()
                        result["realitySuspect"] = True
                        result["realityBrand"] = "Microsoft (透明转发验签命中)"
                        result["realityDomain"] = "www.microsoft.com"
                        result["verdict"] = "reality_strict_relay"
            except Exception:
                pass

    if not result["realitySuspect"]:
        if result["tlsActive"]:
            result["verdict"] = "open_tls_service"
        elif result["port443Open"]:
            result["verdict"] = "open_tcp_non_tls"

    TLS443_CACHE.set(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# DNSBL (DoH) 与 CIDR 列表 + /24 脏邻居 + 全 ASN 滥用密度
# ---------------------------------------------------------------------------


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_single_dnsbl(entry: dict[str, Any], ip: str, ip_ver: int) -> dict[str, Any]:
    if ip_ver == 6:
        return {"id": entry["id"], "name": entry["name"], "kind": entry["kind"], "status": "skip", "listed": False}
    qname = f"{_reverse_ipv4(ip)}.{entry['zone']}"
    doh_urls = [
        f"https://dns.google/resolve?name={qname}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={qname}&type=A",
    ]
    for url in doh_urls:
        try:
            d = _http_json(url, timeout=3.2, headers={"Accept": "application/dns-json"})
            st = d.get("Status")
            if st == 3:
                return {"id": entry["id"], "name": entry["name"], "kind": entry["kind"], "status": "ok", "listed": False, "codes": [], "proxy": False}
            if st != 0:
                continue
            ans = [str(a.get("data")) for a in (d.get("Answer") or []) if isinstance(a, dict) and a.get("type") == 1]
            ignore = entry.get("ignore") or set()
            codes = [
                a for a in ans
                if a.startswith("127.") and not a.startswith("127.255.") and a != "127.0.0.1" and a not in ignore
            ]
            proxy_codes = entry.get("proxyCodes") or set()
            is_proxy = any(int(c.split(".")[3]) in proxy_codes for c in codes if len(c.split(".")) == 4 and c.split(".")[3].isdigit())
            return {
                "id": entry["id"],
                "name": entry["name"],
                "kind": entry["kind"],
                "status": "ok",
                "listed": len(codes) > 0,
                "codes": codes,
                "proxy": is_proxy,
            }
        except Exception:
            continue
    return {"id": entry["id"], "name": entry["name"], "kind": entry["kind"], "status": "error", "listed": False}


def _ipv4_to_u32(ip: str) -> int:
    p = ip.split(".")
    return (int(p[0]) << 24) | (int(p[1]) << 16) | (int(p[2]) << 8) | int(p[3])


def _u32_to_ipv4(val: int) -> str:
    return f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}.{(val >> 8) & 0xFF}.{val & 0xFF}"


def _parse_cidr_ranges(body: str) -> tuple[list[int], list[tuple[int, int]], int]:
    raw: list[tuple[int, int]] = []
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        # IPsum 格式为 "1.2.3.4\t5"
        token = s.split()[0]
        if "/" in token:
            addr_s, plen_s = token.split("/", 1)
            if not plen_s.isdigit():
                continue
            plen = int(plen_s)
        else:
            addr_s, plen = token, 32
        parts = addr_s.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) or not (0 <= plen <= 32):
            continue
        u = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen > 0 else 0
        start = u & mask
        end = start + (1 << (32 - plen)) - 1
        raw.append((start, end))
    raw.sort()
    merged: list[tuple[int, int]] = []
    for st, en in raw:
        if merged and st <= merged[-1][1] + 1:
            if en > merged[-1][1]:
                merged[-1] = (merged[-1][0], en)
        else:
            merged.append((st, en))
    starts = [r[0] for r in merged]
    total_ips = sum(en - st + 1 for st, en in merged)
    return starts, merged, total_ips


def _get_cidr_lock(list_id: str) -> threading.Lock:
    with _CIDR_GLOBAL_LOCK:
        if list_id not in _CIDR_LOCKS:
            _CIDR_LOCKS[list_id] = threading.Lock()
        return _CIDR_LOCKS[list_id]


def load_cidr_list(entry: dict[str, Any], timeout: float = 5.5) -> tuple[list[int], list[tuple[int, int]], int] | None:
    lid = entry["id"]
    cached = CIDR_CACHE.get(lid)
    if cached is not None:
        return cached
    lock = _get_cidr_lock(lid)
    with lock:
        cached = CIDR_CACHE.get(lid)
        if cached is not None:
            return cached
        try:
            body = _http_text(entry["url"], timeout=timeout)
            parsed = _parse_cidr_ranges(body)
            CIDR_CACHE.set(lid, parsed)
            return parsed
        except Exception:
            return None


def start_cidr_prewarmer() -> None:
    """后台异步预热威胁/机房/VPN 网段列表，使首个用户请求亦能毫秒级命中内存区间树。"""
    def _worker() -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda item: load_cidr_list(item, timeout=12.0), CIDR_LISTS))

    t = threading.Thread(target=_worker, daemon=True, name="cidr-prewarmer")
    t.start()


def _intersect_merged(starts: list[int], merged: list[tuple[int, int]], a: int, b: int) -> list[tuple[int, int]]:
    if not merged:
        return []
    idx = bisect.bisect_right(starts, b) - 1
    out: list[tuple[int, int]] = []
    while idx >= 0 and merged[idx][1] >= a:
        out.append(merged[idx])
        idx -= 1
    return out


def _overlap_count(merged_a: list[tuple[int, int]], merged_b: list[tuple[int, int]]) -> int:
    total = 0
    j = 0
    len_b = len(merged_b)
    for st, en in merged_a:
        while j < len_b and merged_b[j][1] < st:
            j += 1
        k = j
        while k < len_b and merged_b[k][0] <= en:
            total += min(en, merged_b[k][1]) - max(st, merged_b[k][0]) + 1
            k += 1
    return total


def _merge_route_cidrs(routes: list[str]) -> tuple[list[tuple[int, int]], int]:
    raw: list[tuple[int, int]] = []
    for cidr in routes:
        if ":" in cidr or "/" not in cidr:
            continue
        addr_s, plen_s = cidr.split("/", 1)
        parts = addr_s.split(".")
        if len(parts) != 4 or not plen_s.isdigit() or not all(p.isdigit() for p in parts):
            continue
        plen = int(plen_s)
        if not (0 <= plen <= 32):
            continue
        u = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen > 0 else 0
        st = u & mask
        raw.append((st, st + (1 << (32 - plen)) - 1))
    raw.sort()
    merged: list[tuple[int, int]] = []
    for st, en in raw:
        if merged and st <= merged[-1][1] + 1:
            if en > merged[-1][1]:
                merged[-1] = (merged[-1][0], en)
        else:
            merged.append((st, en))
    size = sum(en - st + 1 for st, en in merged)
    return merged, size


# ---------------------------------------------------------------------------
# ASN 档案获取、自报冲突核验 (inferASN) 与租赁段判定 (detectLease)
# ---------------------------------------------------------------------------


def fetch_asn_profile(asn: int, prefix: str | None = None) -> dict[str, Any]:
    cache_key = f"AS{asn}:{prefix or ''}"
    cached = ASN_CACHE.get(cache_key)
    if isinstance(cached, dict):
        return cached

    profile: dict[str, Any] = {"asn": asn}

    def _ripe(call: str, params: dict[str, str]) -> Any:
        q = urllib.parse.urlencode({**params, "sourceapp": "whoprobe"})
        return _http_json(f"https://stat.ripe.net/data/{call}/data.json?{q}", timeout=4.2)

    tasks: dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        tasks["overview"] = pool.submit(_ripe, "as-overview", {"resource": f"AS{asn}"})
        tasks["pdb"] = pool.submit(_http_json, f"https://www.peeringdb.com/api/net?asn={asn}", 4.2)
        tasks["rdap"] = pool.submit(
            _http_json,
            f"https://rdap.org/autnum/{asn}",
            4.2,
            {"Accept": "application/rdap+json"},
        )
        tasks["guide"] = pool.submit(_http_json, f"https://ip.guide/AS{asn}", 4.5)
        if prefix:
            tasks["rpki"] = pool.submit(_ripe, "rpki-validation", {"resource": f"AS{asn}", "prefix": prefix})

    try:
        ov = tasks["overview"].result().get("data") or {}
        profile["holder"] = ov.get("holder")
    except Exception:
        pass

    try:
        pdb_data = (tasks["pdb"].result().get("data") or [])
        if pdb_data and isinstance(pdb_data[0], dict):
            n0 = pdb_data[0]
            profile["pdb"] = {
                "name": n0.get("name"),
                "type": n0.get("info_type"),
                "types": n0.get("info_types") if isinstance(n0.get("info_types"), list) else None,
                "ratio": n0.get("info_ratio"),
                "traffic": n0.get("info_traffic"),
                "scope": n0.get("info_scope"),
            }
    except Exception:
        pass

    try:
        rdap_as = tasks["rdap"].result()
        evs = {e.get("eventAction"): e.get("eventDate") for e in (rdap_as.get("events") or []) if isinstance(e, dict)}
        profile["regDate"] = evs.get("registration")
        profile["asCountry"] = _cc(rdap_as.get("country"))
        profile["rdapName"] = rdap_as.get("name")
        port43 = str(rdap_as.get("port43") or "")
        profile["asRir"] = re.sub(r"^whois\.|\.(net|org)$", "", port43, flags=re.I).upper() or None
    except Exception:
        pass

    routes: list[str] = []
    try:
        gd = tasks["guide"].result()
        v4_routes = (gd.get("routes") or {}).get("v4")
        if isinstance(v4_routes, list):
            routes = [str(r) for r in v4_routes if isinstance(r, str)]
        if not profile.get("asCountry"):
            profile["asCountry"] = _cc(gd.get("country"))
        if not profile.get("asRir"):
            profile["asRir"] = str(gd.get("rir") or "").upper() or None
    except Exception:
        pass

    if not routes:
        try:
            ann = _ripe("announced-prefixes", {"resource": f"AS{asn}"}).get("data") or {}
            routes = [
                str(item.get("prefix"))
                for item in (ann.get("prefixes") or [])
                if isinstance(item, dict) and isinstance(item.get("prefix"), str) and ":" not in item["prefix"]
            ]
        except Exception:
            pass

    if routes:
        merged_routes, v4_count = _merge_route_cidrs(routes)
        profile["v4Prefixes"] = len(routes)
        profile["v4Ips"] = v4_count
        profile["_mergedRoutes"] = merged_routes

    if "rpki" in tasks:
        try:
            rp = tasks["rpki"].result().get("data") or {}
            profile["rpki"] = rp.get("status")
        except Exception:
            pass

    ASN_CACHE.set(cache_key, profile)
    return profile


def infer_asn_class(
    asn: int | None,
    names: list[str],
    pdb: dict[str, Any] | None,
    v4_ips: int | None,
    ipapiis_type: str | None,
    iplocate_type: str | None,
    company_types: list[tuple[str, str]],
    reg_date: str | None,
) -> dict[str, Any]:
    if not asn:
        return {"cls": None, "label": "未知", "hostingShare": 0.0, "confidence": 0.0, "reasons": [], "conflict": None}

    votes: dict[str, float] = {}
    own_votes: dict[str, float] = {}
    own_reasons: list[str] = []
    seen_votes: dict[str, float] = {}
    reasons: list[str] = []
    independent = False

    def _vote(cls: str, w: float, reason: str | None = None, is_self: bool = False) -> None:
        nonlocal independent
        votes[cls] = votes.get(cls, 0.0) + w
        if reason:
            reasons.append(reason)
        if is_self:
            own_votes[cls] = own_votes.get(cls, 0.0) + w
            if reason:
                own_reasons.append(reason)
        else:
            independent = True
            seen_votes[cls] = seen_votes.get(cls, 0.0) + w

    known = KNOWN_ASN_MAP.get(asn)
    if known:
        _vote(known, 3.0, f"AS{asn} 属于已知{ASN_CLASS_LABELS[known]}名单")
    if asn in TRANSIT_HOSTING_ASNS:
        _vote("hosting", 1.2, "该骨干网同时经营大量机房/跨境专线业务")

    if pdb:
        ptypes = pdb.get("types") or ([pdb["type"]] if pdb.get("type") else [])
        for pt in ptypes:
            if pt in PDB_TYPE_MAP:
                mc, mw = PDB_TYPE_MAP[pt]
                _vote(mc, mw, f"PeeringDB 自报：{pt}", is_self=True)
        ratio = str(pdb.get("ratio") or "")
        if ratio in ("Heavy Outbound", "Mostly Outbound"):
            _vote("hosting", 0.8, f"PeeringDB 流量以出向为主 ({ratio})，具服务器特征", is_self=True)
        elif ratio in ("Heavy Inbound", "Mostly Inbound"):
            _vote("isp", 0.8, f"PeeringDB 流量以入向为主 ({ratio})，具宽带接入特征", is_self=True)

    joined_names = " | ".join(n for n in names if n)
    for cls, pat, w in ASN_KEYWORDS:
        m = pat.search(joined_names)
        if m:
            _vote(cls, w, f"机构名称含{ASN_CLASS_LABELS[cls]}特征词 ({m.group(0)})", is_self=True)
            break

    comp_map = {"residential": "isp", "mobile": "mobile", "hosting": "hosting", "business": "business", "education": "education", "government": "government"}
    for by_name, cval in company_types:
        if cval in comp_map:
            _vote(comp_map[cval], 1.0, f"{by_name} 公司类型：{cval}")

    for src_label, raw_t in (("ipapi.is", ipapiis_type), ("IPLocate", iplocate_type)):
        if raw_t:
            rt = str(raw_t).lower()
            mapped = {"isp": "isp", "hosting": "hosting", "business": "business", "education": "education", "government": "government"}.get(rt)
            if mapped:
                _vote(mapped, 1.5, f"{src_label} ASN 类型：{rt}")

    if isinstance(v4_ips, int) and v4_ips > 0:
        if v4_ips >= 1_000_000:
            _vote("isp", 0.5, f"宣告 {v4_ips:,} 个 IPv4 地址（大型运营商规模）")
        elif v4_ips <= 4096:
            _vote("hosting", 0.4, f"仅宣告 {v4_ips:,} 个 IPv4 地址（微型宣告段）")

    if reg_date and not known:
        try:
            yr = int(reg_date[:4])
            if time.gmtime().tm_year - yr < 5:
                _vote("hosting", 0.4, f"ASN 注册于 {reg_date[:10]}（新近注册 ASN）")
        except ValueError:
            pass

    if not votes:
        return {"cls": None, "label": "未知", "hostingShare": 0.0, "confidence": 0.0, "reasons": [], "conflict": None}

    ranked = sorted(votes.items(), key=lambda x: x[1], reverse=True)
    total_w = sum(v for _, v in ranked)
    top_cls, top_w = ranked[0]
    hosting_share = (votes.get("hosting", 0.0) + votes.get("cdn", 0.0) + 0.3 * votes.get("transit", 0.0)) / total_w
    conf = min(1.0, top_w / 4.0) * (top_w / total_w)
    if not independent:
        conf *= 0.65
        reasons.append("仅含 ASN 自报资料（PeeringDB/名称），缺乏独立第三方佐证")

    # 自报与独立证据冲突核验（抓伪家宽 ISP 包装）
    conflict = None
    if own_votes and seen_votes:
        own_top = max(own_votes.items(), key=lambda x: x[1])[0]
        seen_total = sum(seen_votes.values())
        seen_top = max(seen_votes.items(), key=lambda x: x[1])[0]
        if seen_total >= 1.5:
            seen_dc = (seen_votes.get("hosting", 0.0) + seen_votes.get("cdn", 0.0)) / seen_total
            if own_top not in {"hosting", "cdn", "transit"} and seen_top in {"hosting", "cdn"} and seen_dc >= 0.5:
                conflict = f"自报为「{ASN_CLASS_LABELS[own_top]}」，但独立证据指向「{ASN_CLASS_LABELS[seen_top]}」（机房倾向 {round(seen_dc * 100)}%）"

    return {
        "cls": top_cls,
        "label": ASN_CLASS_LABELS.get(top_cls, top_cls),
        "hostingShare": round(hosting_share, 2),
        "confidence": round(conf, 2),
        "reasons": reasons[:6],
        "conflict": conflict,
    }


def detect_ip_lease(
    rdap_ip: dict[str, Any] | None,
    holder: str | None,
    orgs: list[str],
    as_rir: str | None,
    as_country: str | None,
    geo_country: str | None,
) -> dict[str, Any] | None:
    if not rdap_ip:
        return None
    stop_words = {"inc", "ltd", "llc", "limited", "the", "and", "corp", "corporation", "company", "network", "networks", "global", "international", "internet", "services", "asn", "telecom", "communications"}

    def _tokens(s: str | None) -> set[str]:
        words = re.sub(r"[^a-z0-9 ]", " ", str(s or "").lower()).split()
        return {w for w in words if len(w) > 2 and w not in stop_words}

    weights: list[float] = []
    reasons: list[str] = []
    org_name = rdap_ip.get("orgName") or rdap_ip.get("netname")
    holder_toks = _tokens(holder)
    overlap = any(w in holder_toks for w in _tokens(org_name))
    status_str = str(rdap_ip.get("status") or "")
    sub_alloc = bool(re.search(r"SUB-ALLOCATED|ASSIGNED PA|REASSIGNED|REALLOCATED|ALLOCATED-BY-LIR", status_str, re.I))

    if org_name and holder and not overlap and sub_alloc:
        weights.append(0.4)
        reasons.append(f"地址段登记给 {org_name}，与 BGP 宣告方 {holder} 不同")

    reg_date = str(rdap_ip.get("regDate") or "")
    if len(reg_date) >= 4 and reg_date[:4].isdigit() and sub_alloc:
        if time.gmtime().tm_year - int(reg_date[:4]) <= 3:
            weights.append(0.25)
            reasons.append(f"{reg_date[:10]} 新近子分配地址段")

    broker_haystack = " ".join(str(x) for x in [rdap_ip.get("abuseName"), rdap_ip.get("abuseEmail"), rdap_ip.get("netname"), rdap_ip.get("orgName"), *orgs] if x)
    m_brk = BROKER_RE.search(broker_haystack)
    if m_brk:
        weights.append(0.6)
        reasons.append(f"管理/滥用联系人命中 IP 租赁平台 ({m_brk.group(0)})")

    ip_rir = rdap_ip.get("rir")
    if ip_rir and as_rir and ip_rir.upper() != as_rir.upper():
        weights.append(0.35)
        reasons.append(f"地址段归属 {ip_rir}，而宣告 ASN 归属 {as_rir}")
    elif rdap_ip.get("regCountry") and as_country and geo_country:
        rc = rdap_ip["regCountry"]
        if rc != as_country and rc != geo_country:
            weights.append(0.25)
            reasons.append(f"注册国 ({rc})、ASN 国 ({as_country}) 与定位国 ({geo_country}) 三方分离")

    prod = 1.0
    for w in weights:
        prod *= (1.0 - w)
    conf = round(1.0 - prod, 2)
    return {
        "leased": conf >= 0.5,
        "possible": 0.3 <= conf < 0.5,
        "confidence": conf,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# 多源加权几率投票 (E = H / (H + N)) 与综合纯净度评分
# ---------------------------------------------------------------------------


def _tally_votes(votes: list[dict[str, Any]]) -> dict[str, Any]:
    known = [v for v in votes if isinstance(v.get("value"), bool)]
    pos = [v for v in known if v["value"] is True]
    neg = [v for v in known if v["value"] is False]
    hard = any(v.get("hard") for v in pos)
    H = 0.0
    for v in pos:
        w = min(0.95, float(v.get("w", 0.5)))
        H += (w / (1.0 - w)) if v.get("obs") else w
    N = sum(float(v.get("w", 0.5)) for v in neg)
    E = 1.0 if hard else (H / (H + N) if (H + N) > 0 and H > 0 else 0.0)
    return {
        "E": round(E, 3),
        "yes": len(pos),
        "of": len(known),
        "hard": hard,
        "by": [v["by"] for v in pos],
        "clear": [v["by"] for v in neg],
    }


def inspect_ip_intelligence(target_ip: str, enable_active_443: bool = True) -> dict[str, Any]:
    norm_ip, ip_ver = normalize_public_ip(target_ip)
    if not norm_ip or not ip_ver:
        return {"ok": False, "error": "invalid-or-private-ip", "targetIp": target_ip}

    cache_key = f"{norm_ip}:{1 if enable_active_443 else 0}"
    cached = INTEL_CACHE.get(cache_key)
    if isinstance(cached, dict):
        out = dict(cached)
        out["cacheHit"] = True
        return out

    t_start = time.monotonic()

    # Stage 1: 并发拉取 8 大情报源 + RDAP + Shodan + StopForumSpam + OTX + Tor Onionoo + 12 项 DNSBL + 15 项 CIDR
    source_fns = [
        _src_ipapiis, _src_ipquery, _src_iplocate, _src_blackbox,
        _src_ipapi, _src_ipinfo, _src_ipleak, _src_freeipapi,
    ]
    sources: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        f_srcs = [pool.submit(fn, norm_ip) for fn in source_fns]
        f_rdap = pool.submit(_fetch_rdap_ip, norm_ip)
        f_shodan = pool.submit(_fetch_shodan, norm_ip)
        f_sfs = pool.submit(_fetch_sfs, norm_ip)
        f_otx = pool.submit(_fetch_otx, norm_ip, ip_ver)
        f_tor = pool.submit(_fetch_onionoo, norm_ip, ip_ver)
        f_dnsbls = [pool.submit(_check_single_dnsbl, entry, norm_ip, ip_ver) for entry in DNSBLS]
        f_cidrs = [pool.submit(load_cidr_list, entry, 4.8) for entry in CIDR_LISTS] if ip_ver == 4 else []

        for fut in f_srcs:
            try:
                res = fut.result()
                if isinstance(res, dict):
                    sources.append(res)
            except Exception:
                pass

        rdap_ip = f_rdap.result()
        shodan = f_shodan.result()
        sfs = f_sfs.result()
        otx = f_otx.result()
        onionoo = f_tor.result()
        dnsbl_results = [f.result() for f in f_dnsbls]
        loaded_cidrs = [f.result() for f in f_cidrs]

    # 提取去重定位共识（按底层数据源家族去重）
    family_best: dict[str, dict[str, Any]] = {}
    for s in sources:
        if not s.get("country") or s.get("geoVote") is False:
            continue
        fam = GEO_FAMILY.get(s["id"], s["id"])
        w = float(SOURCE_WEIGHTS.get(s["id"], {}).get("geo", 1.0))
        if fam not in family_best or w > family_best[fam]["w"]:
            family_best[fam] = {"country": s["country"], "city": s.get("city"), "tz": s.get("tz"), "w": w, "by": s["name"]}

    country_weights: dict[str, float] = {}
    country_by: dict[str, list[str]] = {}
    for item in family_best.values():
        cc = item["country"]
        country_weights[cc] = country_weights.get(cc, 0.0) + item["w"]
        country_by.setdefault(cc, []).append(item["by"])

    total_geo_w = sum(country_weights.values()) or 1.0
    ranked_countries = sorted(country_weights.items(), key=lambda x: x[1], reverse=True)
    consensus_country = ranked_countries[0][0] if ranked_countries else None
    country_support = round(ranked_countries[0][1] / total_geo_w, 2) if ranked_countries else 1.0

    # 主 ASN / 前缀 / PTR 汇总
    asn_candidates = [s["asn"] for s in sources if isinstance(s.get("asn"), int)]
    primary_asn = max(set(asn_candidates), key=asn_candidates.count) if asn_candidates else None
    primary_prefix = next((s.get("prefix") for s in sources if s.get("prefix")), None) or (rdap_ip.get("cidr") if rdap_ip else None)
    hostname = next((s.get("hostname") for s in sources if s.get("hostname")), None) or ((shodan.get("hostnames") or [None])[0] if shodan else None)
    ptr_hint = classify_ptr_hostname(hostname)

    # Stage 2: 并行拉取 BGP ASN 档案 + 主动 :443 TLS/Reality 反向证书验真
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool2:
        f_asn = pool2.submit(fetch_asn_profile, primary_asn, primary_prefix) if primary_asn else None
        f_tls443 = pool2.submit(inspect_exit_tls_443, norm_ip, primary_asn) if enable_active_443 else None
        asn_prof = f_asn.result() if f_asn else {}
        tls443 = f_tls443.result() if f_tls443 else {"probed": False, "verdict": "skipped"}

    # Stage 3: CIDR 命中、同 /24 脏邻居与全 ASN 滥用密度计算
    cidr_hits: list[dict[str, Any]] = []
    neighbour_ips: set[int] = set()
    neighbour_lists: list[str] = []
    whole_block_lists: list[str] = []
    x4b_dc_hit: bool | None = None
    x4b_vpn_hit: bool | None = None
    open_proxy_hit = False
    cidr_tor_hit = False

    if ip_ver == 4:
        ip_u32 = _ipv4_to_u32(norm_ip)
        block_start = ip_u32 & 0xFFFFFF00
        block_end = block_start + 255
        for entry, parsed in zip(CIDR_LISTS, loaded_cidrs):
            if not parsed:
                continue
            starts, merged, _ = parsed
            direct = _intersect_merged(starts, merged, ip_u32, ip_u32)
            is_hit = len(direct) > 0
            kind = entry["kind"]
            if entry["id"] == "x4bdc":
                x4b_dc_hit = is_hit
            elif entry["id"] == "x4bvpn":
                x4b_vpn_hit = is_hit
            elif kind == "proxy" and is_hit:
                open_proxy_hit = True
            elif kind == "tor" and is_hit:
                cidr_tor_hit = True

            if is_hit:
                cidr_hits.append({"id": entry["id"], "name": entry["name"], "kind": kind, "pts": entry["pts"]})

            if kind in {"attack", "spam"}:
                ov = _intersect_merged(starts, merged, block_start, block_end)
                had_nb = False
                for st, en in ov:
                    if st <= block_start and en >= block_end:
                        whole_block_lists.append(entry["name"])
                        continue
                    for addr_u in range(max(st, block_start), min(en, block_end) + 1):
                        if addr_u != ip_u32:
                            neighbour_ips.add(addr_u)
                            had_nb = True
                if had_nb:
                    neighbour_lists.append(entry["name"])

    asn_rep: dict[str, Any] | None = None
    merged_routes = asn_prof.get("_mergedRoutes")
    asn_v4_size = asn_prof.get("v4Ips") or 0
    if ip_ver == 4 and merged_routes and asn_v4_size > 0:
        listed_in_asn = 0
        global_listed = 0
        for entry, parsed in zip(CIDR_LISTS, loaded_cidrs):
            if not entry.get("density") or not parsed:
                continue
            _, merged, total_ips = parsed
            listed_in_asn += _overlap_count(merged, merged_routes)
            global_listed += total_ips
        if global_listed > 0:
            per_10k = (listed_in_asn / asn_v4_size) * 10000.0
            baseline = (global_listed / ROUTED_IPV4_SPACE) * 10000.0
            asn_rep = {
                "asnIps": asn_v4_size,
                "listedIps": listed_in_asn,
                "per10k": round(per_10k, 2),
                "ratio": round(per_10k / baseline, 1) if baseline > 0 else 0.0,
            }

    # Stage 4: ASN 类型推断 & 租赁段判定 & 原生/广播判定
    orgs = [str(s["org"]) for s in sources if s.get("org")]
    if asn_prof.get("holder"):
        orgs.append(str(asn_prof["holder"]))
    comp_types = [(s["name"], str(s["companyType"])) for s in sources if s.get("companyType")]
    ipapiis_src = next((s for s in sources if s["id"] == "ipapiis"), {})
    iplocate_src = next((s for s in sources if s["id"] == "iplocate"), {})

    inferred_asn = infer_asn_class(
        primary_asn,
        orgs,
        asn_prof.get("pdb"),
        asn_prof.get("v4Ips"),
        ipapiis_src.get("asnType"),
        iplocate_src.get("asnType"),
        comp_types,
        asn_prof.get("regDate"),
    )
    lease_info = detect_ip_lease(
        rdap_ip,
        asn_prof.get("holder"),
        orgs,
        asn_prof.get("asRir"),
        asn_prof.get("asCountry"),
        consensus_country,
    )

    reg_countries = [c for c in [
        next((s.get("regCountry") for s in sources if s.get("regCountry")), None),
        rdap_ip.get("regCountry") if rdap_ip else None,
        asn_prof.get("asCountry"),
    ] if c]
    reg_country = reg_countries[0] if reg_countries else None
    is_native = (reg_country == consensus_country) if (reg_country and consensus_country) else None

    # Stage 5: 多源加权几率投票 (VPN / Proxy / Tor / Hosting / Abuser)
    def _collect_flag(flag: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for s in sources:
            val = (s.get("flags") or {}).get(flag)
            if not isinstance(val, bool):
                continue
            sw = SOURCE_WEIGHTS.get(s["id"], {"flags": 0.5})
            if sw.get("positiveOnly") and val is False:
                continue
            out.append({"by": s["name"], "value": val, "w": sw.get("flags", 0.5), "obs": bool(sw.get("observed")) and val})
        return out

    vpn_votes = _collect_flag("vpn")
    proxy_votes = _collect_flag("proxy")
    tor_votes = _collect_flag("tor")
    hosting_votes = _collect_flag("hosting")
    abuser_votes = _collect_flag("abuser")

    if x4b_vpn_hit is not None:
        vpn_votes.append({"by": "X4BNet VPN 段", "value": x4b_vpn_hit, "w": 0.7 if x4b_vpn_hit else 0.2})
    if x4b_dc_hit is not None:
        hosting_votes.append({"by": "X4BNet 机房段", "value": x4b_dc_hit, "w": 0.7 if x4b_dc_hit else 0.22})
    if isinstance(ptr_hint.get("hosting"), bool):
        hosting_votes.append({"by": "PTR 主机名命名", "value": ptr_hint["hosting"], "w": 0.45})
    if open_proxy_hit:
        proxy_votes.append({"by": "FireHOL 公开代理列表", "value": True, "w": 0.85, "obs": True})
    if any(d.get("proxy") for d in dnsbl_results):
        proxy_votes.append({"by": "DroneBL 代理特征码", "value": True, "w": 0.9, "obs": True})
    if shodan and "proxy" in (shodan.get("tags") or []):
        proxy_votes.append({"by": "Shodan 代理标签", "value": True, "w": 0.55, "obs": True})
    if shodan and "vpn" in (shodan.get("tags") or []):
        vpn_votes.append({"by": "Shodan VPN 标签", "value": True, "w": 0.55, "obs": True})
    if tls443.get("realitySuspect"):
        proxy_votes.append({"by": f":443 伪装证书 ({tls443.get('realityBrand')})", "value": True, "w": 0.92, "obs": True})
    if cidr_tor_hit or any(d["id"] == "dantor" and d.get("listed") for d in dnsbl_results) or (onionoo and onionoo.get("torExit")):
        tor_votes.append({"by": "Tor 官方共识/出口表", "value": True, "w": 0.95, "hard": True, "obs": True})
    if sfs and sfs.get("appears", 0) > 0:
        abuser_votes.append({"by": "StopForumSpam", "value": True, "w": 0.8, "obs": True})

    t_vpn = _tally_votes(vpn_votes)
    t_proxy = _tally_votes(proxy_votes)
    t_tor = _tally_votes(tor_votes)
    t_hosting = _tally_votes(hosting_votes)
    t_abuser = _tally_votes(abuser_votes)

    # 聚合风险分
    risk_vals = [float(s["risk"]) for s in sources if isinstance(s.get("risk"), (int, float))]
    agg_risk = round(0.6 * (sum(risk_vals) / len(risk_vals)) + 0.4 * max(risk_vals), 1) if risk_vals else 0.0

    # Stage 6: 透明扣分与加分引擎（满分 100，基准 92 + 安全加分 ≤ 10 − 分类封顶扣分）
    deductions: list[dict[str, Any]] = []
    bonuses: list[dict[str, Any]] = []
    cat_sums = {"anon": 0.0, "abuse": 0.0, "neighbours": 0.0, "network": 0.0, "geo": 0.0}
    cat_caps = {"anon": 50.0, "abuse": 40.0, "neighbours": 25.0, "network": 20.0, "geo": 8.0}

    def _deduct(cat: str, label: str, pts: float, detail: str) -> None:
        if pts >= 0.3:
            cat_sums[cat] += pts
            deductions.append({"cat": cat, "label": label, "pts": round(pts, 1), "detail": detail})

    # 1) 匿名化
    if t_tor["E"] > 0:
        _deduct("anon", "Tor 匿名出口", 40.0 * t_tor["E"], f"{t_tor['yes']}/{t_tor['of']} 命中：{', '.join(t_tor['by'][:3])}")
    vpn_pts = 24.0 * t_vpn["E"]
    prx_pts = 26.0 * t_proxy["E"]
    if vpn_pts > 0 and prx_pts > 0:
        if prx_pts >= vpn_pts:
            _deduct("anon", "代理 / 伪装转发", prx_pts, f"命中：{', '.join(t_proxy['by'][:4])} (E={round(t_proxy['E']*100)}%)")
            _deduct("anon", "VPN 特征 (重叠折半)", vpn_pts * 0.5, f"命中：{', '.join(t_vpn['by'][:3])}")
        else:
            _deduct("anon", "VPN 隧道出口", vpn_pts, f"命中：{', '.join(t_vpn['by'][:4])} (E={round(t_vpn['E']*100)}%)")
            _deduct("anon", "代理特征 (重叠折半)", prx_pts * 0.5, f"命中：{', '.join(t_proxy['by'][:3])}")
    elif prx_pts > 0:
        _deduct("anon", "代理 / 伪装节点", prx_pts, f"命中：{', '.join(t_proxy['by'][:4])} (E={round(t_proxy['E']*100)}%)")
    elif vpn_pts > 0:
        _deduct("anon", "VPN 隧道出口", vpn_pts, f"命中：{', '.join(t_vpn['by'][:4])} (E={round(t_vpn['E']*100)}%)")

    # 2) 滥用与黑名单
    if agg_risk >= 5:
        _deduct("abuse", "欺诈/滥用风险分", agg_risk * 0.3, f"多库综合风险分 {agg_risk}/100")
    if t_abuser["E"] > 0:
        _deduct("abuse", "滥用源标记", 10.0 * t_abuser["E"], f"命中：{', '.join(t_abuser['by'][:3])}")

    listed_dnsbls = [d for d in dnsbl_results if d.get("listed")]
    if listed_dnsbls:
        dnsbl_pts = min(20.0, sum(6.0 if d["kind"] == "abuse" else 4.0 for d in listed_dnsbls))
        _deduct("abuse", "DNS 实时黑名单上榜", dnsbl_pts, f"命中 {len(listed_dnsbls)} 家：{', '.join(d['name'] for d in listed_dnsbls[:4])}")

    threat_cidrs = [c for c in cidr_hits if c["pts"] > 0]
    if threat_cidrs:
        threat_cidrs.sort(key=lambda x: x["pts"], reverse=True)
        c_pts = threat_cidrs[0]["pts"] + 2.0 * (len(threat_cidrs) - 1)
        _deduct("abuse", "公开威胁网段命中", c_pts, f"命中：{', '.join(c['name'] for c in threat_cidrs[:4])}")

    if otx and not otx.get("benign") and otx.get("pulses", 0) > 0:
        pc = otx["pulses"]
        _deduct("abuse", "AlienVault OTX 威胁情报", 10.0 if pc >= 10 else (6.0 if pc >= 3 else 3.0), f"关联 {pc} 份安全脉冲报告")

    if sfs and sfs.get("appears", 0) > 0:
        conf_sfs = (sfs.get("confidence") or 50.0) / 100.0
        _deduct("abuse", "StopForumSpam 垃圾注册记录", min(12.0, 3.0 + 9.0 * conf_sfs), f"历史举报 {sfs.get('frequency', 1)} 次")

    if shodan and shodan.get("vulns"):
        _deduct("abuse", "Shodan 暴露端口含历史 CVE", 6.0, f"涉及 {', '.join(shodan['vulns'][:3])}")

    # 3) 同段邻居与 ASN 信誉
    nb_count = len(neighbour_ips)
    if whole_block_lists:
        _deduct("neighbours", "整个 /24 网段被封禁", 15.0, f"整段列入 {', '.join(whole_block_lists[:3])}")
    if nb_count > 0:
        nb_pts = 14.0 if nb_count >= 30 else (10.0 if nb_count >= 10 else (6.0 if nb_count >= 3 else 3.0))
        _deduct("neighbours", "同 /24 C 段脏邻居连坐", nb_pts, f"同网段另有 {nb_count} 个 IP 近期上榜 ({', '.join(neighbour_lists[:3])})")
    if onionoo and onionoo.get("neighbourRelays", 0) > 0:
        _deduct("neighbours", "同 /24 网段存在 Tor 中继", 3.0, f"同段发现 {onionoo['neighbourRelays']} 个 Tor 节点")
    if asn_rep and asn_rep["ratio"] >= 2.0:
        r = asn_rep["ratio"]
        ar_pts = 12.0 if r >= 50 else (9.0 if r >= 15 else (6.0 if r >= 5 else 3.0))
        _deduct("neighbours", "所属 ASN 全网滥用密度偏高", ar_pts, f"每万地址 {asn_rep['per10k']} 个上榜，为全网均值 {r} 倍")
    if asn_prof.get("rpki") == "invalid":
        _deduct("neighbours", "BGP RPKI 路由签名无效", 3.0, "路由宣告未通过 ROA 校验")

    # 4) 网络类型、自报冲突与租赁画像
    if t_hosting["E"] > 0:
        _deduct("network", "数据中心 / 机房线路", 15.0 * t_hosting["E"], f"{t_hosting['yes']}/{t_hosting['of']} 来源标记机房 ({', '.join(t_hosting['by'][:3])})")
    elif inferred_asn.get("cls") in {"hosting", "cdn"}:
        _deduct("network", "机房 ASN 推断", 10.0 * max(0.5, inferred_asn.get("hostingShare", 0.7)), inferred_asn["reasons"][0] if inferred_asn["reasons"] else "ASN 属于云服务商")

    if inferred_asn.get("conflict"):
        _deduct("network", "伪家宽 / ASN 自报冲突", 5.0 * max(0.6, inferred_asn.get("hostingShare", 0.6)), str(inferred_asn["conflict"]))

    if lease_info and (lease_info["leased"] or lease_info["possible"]):
        _deduct("network", "租赁 / 转售子分配地址段", 3.0 * min(1.0, lease_info["confidence"] / 0.7), "；".join(lease_info["reasons"][:2]))

    # 5) 原生与定位分歧
    if is_native is False and reg_country and consensus_country:
        _deduct("geo", "广播 IP（非原生注册国）", 3.0, f"RIR 注册于 {reg_country}，当前广播定位在 {consensus_country}")
    if len(ranked_countries) > 1 and country_support < 0.85:
        _deduct("geo", "多库地理位置分歧", min(5.0, 6.0 * (0.85 - country_support) / 0.35), " · ".join(f"{c} ({len(country_by[c])}源)" for c, _ in ranked_countries[:3]))

    # 正面干净加分（最高 +10）
    anon_max = max(t_vpn["E"], t_proxy["E"], t_tor["E"])
    if len(sources) >= 4 and anon_max == 0 and agg_risk <= 10:
        bonuses.append({"label": "多库一致无匿名标记", "pts": 2.0})
    if ip_ver == 4 and nb_count == 0 and not whole_block_lists and not (onionoo and onionoo.get("neighbourRelays")):
        bonuses.append({"label": "同 /24 邻居零污点", "pts": 2.0})
    if asn_rep and asn_v4_size >= 4096 and asn_rep["ratio"] < 0.5:
        b_asn = round(2.0 + 2.0 * min(1.0, max(0.0, (0.5 - asn_rep["ratio"]) / 0.4)), 1)
        bonuses.append({"label": f"ASN 滥用密度优异 ({asn_rep['ratio']}x)", "pts": b_asn})
    if t_hosting["E"] < 0.15 and anon_max < 0.15 and inferred_asn.get("cls") in {"isp", "mobile"} and not listed_dnsbls:
        bonuses.append({"label": "纯净原生宽带/移动接入网", "pts": 2.5})
    if is_native is True:
        bonuses.append({"label": "注册地与定位一致 (原生 IP)", "pts": 0.5})
    if asn_prof.get("rpki") == "valid":
        bonuses.append({"label": "RPKI 路由 ROA 有效", "pts": 0.5})

    bonus_total = min(10.0, sum(b["pts"] for b in bonuses))
    deduct_total = sum(min(cat_caps[k], cat_sums[k]) for k in cat_sums)
    purity_score = max(0, min(100, round(92.0 + bonus_total - deduct_total)))
    if t_tor["hard"] or t_tor["E"] >= 0.7:
        purity_score = min(purity_score, 25)

    grade = (
        "S" if purity_score >= 95 else
        "A" if purity_score >= 85 else
        "B" if purity_score >= 70 else
        "C" if purity_score >= 55 else
        "D" if purity_score >= 40 else "F"
    )

    # 剥离内部大体积路由数组后缓存返回
    asn_clean = {k: v for k, v in asn_prof.items() if not k.startswith("_")}
    payload: dict[str, Any] = {
        "ok": True,
        "targetIp": norm_ip,
        "ipVersion": ip_ver,
        "elapsedMs": round((time.monotonic() - t_start) * 1000.0, 1),
        "cacheHit": False,
        "purity": {
            "score": purity_score,
            "grade": grade,
            "base": 92,
            "bonusTotal": round(bonus_total, 1),
            "deductTotal": round(deduct_total, 1),
            "bonuses": bonuses,
            "deductions": sorted(deductions, key=lambda x: x["pts"], reverse=True),
        },
        "consensus": {
            "country": consensus_country,
            "countrySupport": country_support,
            "countries": [{"cc": c, "by": country_by[c]} for c, _ in ranked_countries],
            "regCountry": reg_country,
            "isNative": is_native,
            "aiBlockedRegion": consensus_country in AI_BLOCKED_COUNTRIES if consensus_country else False,
            "asn": primary_asn,
            "prefix": primary_prefix,
            "hostname": hostname,
            "ptrType": ptr_hint.get("type"),
            "riskScore": agg_risk,
            "sourceCount": len(sources),
        },
        "votes": {
            "vpn": t_vpn,
            "proxy": t_proxy,
            "tor": t_tor,
            "hosting": t_hosting,
            "abuser": t_abuser,
        },
        "sources": [
            {
                "id": s["id"],
                "name": s["name"],
                "country": s.get("country"),
                "org": s.get("org"),
                "type": s.get("type"),
                "risk": s.get("risk"),
                "flags": s.get("flags"),
            }
            for s in sources
        ],
        "asnProfile": {
            **asn_clean,
            "inferred": inferred_asn,
            "lease": lease_info,
            "abuseDensity": asn_rep,
        },
        "rdap": rdap_ip,
        "tls443": tls443,
        "shodan": shodan,
        "threat": {
            "sfs": sfs,
            "otx": otx,
            "onionoo": onionoo,
        },
        "dnsbl": {
            "total": len([d for d in dnsbl_results if d["status"] == "ok"]),
            "listedCount": len(listed_dnsbls),
            "listed": [d["name"] for d in listed_dnsbls],
            "droneProxy": any(d.get("proxy") for d in dnsbl_results),
        },
        "cidr": {
            "hits": cidr_hits,
            "x4bDatacenter": x4b_dc_hit,
            "x4bVpn": x4b_vpn_hit,
            "openProxy": open_proxy_hit,
            "neighbours": {
                "prefix": f"{'.'.join(norm_ip.split('.')[:3])}.0/24" if ip_ver == 4 else None,
                "dirtyCount": nb_count,
                "lists": neighbour_lists,
                "wholeBlockListed": whole_block_lists,
            },
        },
    }
    INTEL_CACHE.set(cache_key, payload)
    return payload
