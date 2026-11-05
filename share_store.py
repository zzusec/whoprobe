#!/usr/bin/env python3
"""
Privacy-Safe Diagnostic Share Store & Dynamic SVG Result Card Renderer for WhoProbe.

Design guarantees:
  1. Zero-IP Persistence: Neither the creator's socket IP nor any IPv4/IPv6, CIDR, MAC,
     PTR hostname, or GPS coordinate inside the submitted report is ever stored.
  2. Strict Schema Whitelist: Unknown keys are dropped; every text field is length-capped
     and scrubbed via regexes; every HTML/SVG interpolation is escaped.
  3. Bounded Storage: SQLite WAL store with automatic 90-day TTL and 50,000-row cap.
"""

from __future__ import annotations

import datetime
import html
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import string
import tempfile
import threading
import time
from pathlib import Path

SHARE_ALPHABET = string.ascii_letters + string.digits
SHARE_ID_RE = re.compile(r"^[A-Za-z0-9]{6,16}$")

# Defense-in-depth server-side PII / IP scrubbers
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b"
)
_IPV6_CAND_RE = re.compile(
    r"(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?(?![:\w])"
)
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_PTR_IP_RE = re.compile(
    r"\b[a-zA-Z0-9-]*\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b"
)
_COORD_RE = re.compile(r"(?<!\d)-?\d{1,2}\.\d{3,8}\s*,\s*-?\d{1,3}\.\d{3,8}(?!\d)")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

VALID_GRADES = {"A+", "A", "B", "C", "D", "F"}
VALID_TONES = {"ok", "warn", "bad", "info", "neutral", "pending"}
VALID_ICONS = {"clock", "shield", "layers", "chip", "scan", "fp"}


def _replace_ipv6_match(m: re.Match[str]) -> str:
    cand = m.group(0)
    try:
        net = ipaddress.ip_network(cand, strict=False)
        if net.version == 6:
            return "[IPv6已隐藏]"
    except ValueError:
        pass
    return cand


def scrub_sensitive_text(val: object, max_len: int = 200) -> str:
    """Strip control chars and redact any IPv4, IPv6, MAC, PTR, or GPS coordinates."""
    if val is None:
        return ""
    s = _CTRL_RE.sub("", str(val)).strip()
    if not s:
        return ""
    s = _MAC_RE.sub("[MAC已隐藏]", s)
    s = _PTR_IP_RE.sub("[主机已隐藏]", s)
    s = _COORD_RE.sub("[坐标已隐藏]", s)
    s = _IPV4_RE.sub("[IP已隐藏]", s)
    s = _IPV6_CAND_RE.sub(_replace_ipv6_match, s)
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _clamp_int(val: object, lo: int, hi: int, default: int = 0) -> int:
    try:
        n = int(round(float(val)))  # type: ignore[arg-type]
    except Exception:
        return default
    return max(lo, min(hi, n))


def _clean_tone(val: object, default: str = "info") -> str:
    s = str(val or "").strip().lower()
    return s if s in VALID_TONES else default


def _clean_diff(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    left = scrub_sensitive_text(raw.get("left"), 48)
    right = scrub_sensitive_text(raw.get("right"), 48)
    op = scrub_sensitive_text(raw.get("op"), 6)
    single = scrub_sensitive_text(raw.get("single"), 56)
    if left and right:
        return {"left": left, "op": op or "≠", "right": right}
    if single:
        return {"single": single}
    return {}


def sanitize_share_payload(raw: object) -> dict:
    """Validate and strictly sanitize a share snapshot payload before persistence."""
    if not isinstance(raw, dict):
        raise ValueError("invalid_payload")

    scene = "privacy" if raw.get("scene") == "privacy" else "disguise"
    score = _clamp_int(raw.get("score"), 5, 100, 50)
    grade_raw = str(raw.get("grade") or "").strip().upper()
    grade = grade_raw if grade_raw in VALID_GRADES else (
        "A+" if score >= 92 else "A" if score >= 85 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 42 else "F"
    )
    bad_cnt = _clamp_int(raw.get("badCnt"), 0, 24, 0)
    warn_cnt = _clamp_int(raw.get("warnCnt"), 0, 24, 0)
    ok_cnt = _clamp_int(raw.get("okCnt"), 0, 24, 0)
    unv_cnt = _clamp_int(raw.get("unverifiedCnt"), 0, 24, 0)
    total_issues = _clamp_int(raw.get("totalIssues"), 0, 24, bad_cnt + warn_cnt)

    verdict_in = raw.get("verdict") if isinstance(raw.get("verdict"), dict) else {}
    verdict = {
        "tone": _clean_tone(verdict_in.get("tone"), "ok"),
        "text": scrub_sensitive_text(verdict_in.get("text"), 120) or "全栈风控与指纹体检快照",
    }

    topo_in = raw.get("topo") if isinstance(raw.get("topo"), dict) else {}
    topo = {
        "originLabel": scrub_sensitive_text(topo_in.get("originLabel"), 40) or "端侧环境",
        "clientTag": scrub_sensitive_text(topo_in.get("clientTag"), 20) or "终端",
        "clientTone": _clean_tone(topo_in.get("clientTone"), "neutral"),
        "deviceSub": scrub_sensitive_text(topo_in.get("deviceSub"), 56) or "系统环境",
        "link1Badge": scrub_sensitive_text(topo_in.get("link1Badge"), 24) or "路由核验",
        "link1Sub": scrub_sensitive_text(topo_in.get("link1Sub"), 28) or "",
        "link1Tone": _clean_tone(topo_in.get("link1Tone"), "neutral"),
        "exitType": scrub_sensitive_text(topo_in.get("exitType"), 24) or "网络出口",
        "exitTone": _clean_tone(topo_in.get("exitTone"), "neutral"),
        "purityText": scrub_sensitive_text(topo_in.get("purityText"), 28) or "信誉 --",
        "purityTone": _clean_tone(topo_in.get("purityTone"), "neutral"),
        "exitRegion": scrub_sensitive_text(topo_in.get("exitRegion"), 64) or "出口地区已脱敏",
        "link2Badge": scrub_sensitive_text(topo_in.get("link2Badge"), 28) or "TLS 1.3",
        "link2Rtt": scrub_sensitive_text(topo_in.get("link2Rtt"), 36) or "",
        "link2Tone": _clean_tone(topo_in.get("link2Tone"), "neutral"),
        "trackState": scrub_sensitive_text(topo_in.get("trackState"), 40) or "追踪码已脱敏隐藏",
    }

    tiles_out = []
    for item in (raw.get("tiles") if isinstance(raw.get("tiles"), list) else [])[:6]:
        if not isinstance(item, dict):
            continue
        icon_k = str(item.get("icon") or "").strip()
        tiles_out.append({
            "icon": icon_k if icon_k in VALID_ICONS else "shield",
            "label": scrub_sensitive_text(item.get("label"), 24),
            "status": scrub_sensitive_text(item.get("status"), 18),
            "tone": _clean_tone(item.get("tone"), "info"),
            "val": scrub_sensitive_text(item.get("val"), 44),
            "sub": scrub_sensitive_text(item.get("sub"), 64),
        })

    tags_out = []
    for t in (raw.get("tags") if isinstance(raw.get("tags"), list) else [])[:10]:
        if isinstance(t, (list, tuple)) and len(t) >= 2:
            lbl = scrub_sensitive_text(t[0], 24)
            if lbl:
                tags_out.append([lbl, _clean_tone(t[1], "neutral")])

    prio_out = []
    for p in (raw.get("priority") if isinstance(raw.get("priority"), list) else [])[:4]:
        if not isinstance(p, dict):
            continue
        cid = re.sub(r"[^a-z0-9_]", "", str(p.get("id") or "").lower())[:24]
        prio_out.append({
            "id": cid,
            "title": scrub_sensitive_text(p.get("title"), 36),
            "lv": "bad" if p.get("lv") == "bad" else "warn",
            "diff": _clean_diff(p.get("diff")),
        })

    scen_out = []
    for sc in (raw.get("scenarios") if isinstance(raw.get("scenarios"), list) else [])[:6]:
        if not isinstance(sc, dict):
            continue
        sid = re.sub(r"[^a-z0-9_]", "", str(sc.get("id") or "").lower())[:20]
        scen_out.append({
            "id": sid,
            "name": scrub_sensitive_text(sc.get("name"), 24),
            "score": _clamp_int(sc.get("score"), 5, 100, 50),
            "reason": scrub_sensitive_text(sc.get("reason"), 80),
        })

    checks_out = []
    for ck in (raw.get("checks") if isinstance(raw.get("checks"), list) else [])[:24]:
        if not isinstance(ck, dict):
            continue
        cid = re.sub(r"[^a-z0-9_]", "", str(ck.get("id") or "").lower())[:24]
        if not cid:
            continue
        checks_out.append({
            "id": cid,
            "level": _clean_tone(ck.get("level"), "info"),
            "counted": bool(ck.get("counted", True)),
            "diff": _clean_diff(ck.get("diff")),
            "summary": scrub_sensitive_text(ck.get("summary"), 180),
        })

    return {
        "v": 1,
        "scene": scene,
        "score": score,
        "grade": grade,
        "totalIssues": total_issues,
        "badCnt": bad_cnt,
        "warnCnt": warn_cnt,
        "okCnt": ok_cnt,
        "unverifiedCnt": unv_cnt,
        "summary": scrub_sensitive_text(raw.get("summary"), 120),
        "verdict": verdict,
        "topo": topo,
        "tiles": tiles_out,
        "tags": tags_out,
        "priority": prio_out,
        "scenarios": scen_out,
        "checks": checks_out,
    }


class ShareStore:
    """Bounded thread-safe SQLite store for anonymized diagnostic share snapshots."""

    TTL_SEC = 90 * 86400
    MAX_ROWS = 50_000

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._ops = 0
        self.db_path = self._resolve_db_path(data_dir)
        self._init_db()

    @staticmethod
    def _resolve_db_path(data_dir: str | Path | None) -> Path:
        candidates: list[Path] = []
        if data_dir:
            candidates.append(Path(data_dir))
        env_state = os.environ.get("STATE_DIRECTORY") or os.environ.get("WHOPROBE_DATA_DIR")
        if env_state:
            candidates.append(Path(env_state.split(":")[0]))
        candidates.append(Path(__file__).resolve().parent / "data")
        candidates.append(Path(tempfile.gettempdir()) / "whoprobe-data")

        for folder in candidates:
            try:
                folder.mkdir(parents=True, exist_ok=True)
                probe_file = folder / ".write_check"
                probe_file.write_text("ok", encoding="utf-8")
                probe_file.unlink(missing_ok=True)
                return folder / "shares.db"
            except Exception:
                continue
        return Path(":memory:")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            self._conn = self._connect()
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shares (
                    id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_shares_created ON shares(created_at)"
            )
            self._conn.commit()

    def create(self, raw_payload: object) -> tuple[str, int, dict]:
        clean = sanitize_share_payload(raw_payload)
        encoded = json.dumps(clean, ensure_ascii=False, separators=(",", ":"))
        now = int(time.time())

        with self._lock:
            share_id = ""
            for _ in range(8):
                cand = "".join(secrets.choice(SHARE_ALPHABET) for _ in range(9))
                cur = self._conn.execute("SELECT 1 FROM shares WHERE id = ?", (cand,))
                if cur.fetchone() is None:
                    share_id = cand
                    break
            if not share_id:
                share_id = secrets.token_urlsafe(8).replace("-", "A").replace("_", "B")[:10]

            self._conn.execute(
                "INSERT INTO shares (id, created_at, payload) VALUES (?, ?, ?)",
                (share_id, now, encoded),
            )
            self._ops += 1
            if self._ops % 64 == 0:
                cutoff = now - self.TTL_SEC
                self._conn.execute("DELETE FROM shares WHERE created_at < ?", (cutoff,))
                self._conn.execute(
                    """
                    DELETE FROM shares WHERE id IN (
                        SELECT id FROM shares ORDER BY created_at DESC LIMIT -1 OFFSET ?
                    )
                    """,
                    (self.MAX_ROWS,),
                )
            self._conn.commit()
        return share_id, now, clean

    def get(self, share_id: str) -> dict | None:
        sid = (share_id or "").strip()
        if not SHARE_ID_RE.match(sid):
            return None
        cutoff = int(time.time()) - self.TTL_SEC
        with self._lock:
            cur = self._conn.execute(
                "SELECT created_at, payload FROM shares WHERE id = ? AND created_at >= ?",
                (sid, cutoff),
            )
            row = cur.fetchone()
        if not row:
            return None
        created_at, payload_str = row
        try:
            report = json.loads(payload_str)
        except Exception:
            return None
        return {"id": sid, "createdAt": int(created_at), "report": report}


def _svg_esc(val: object) -> str:
    return html.escape(str(val or ""), quote=True)


def render_share_svg(share_id: str, created_at: int, report: dict) -> bytes:
    """Render a Speedtest-style 760x380 Retina-sharp SVG badge card (zero external deps)."""
    score = _clamp_int(report.get("score"), 5, 100, 50)
    grade = str(report.get("grade") or "-").upper()
    bad_cnt = _clamp_int(report.get("badCnt"), 0, 24, 0)
    warn_cnt = _clamp_int(report.get("warnCnt"), 0, 24, 0)
    ok_cnt = _clamp_int(report.get("okCnt"), 0, 24, 0)

    if grade.startswith("A"):
        ring_color, pill_bg, pill_fg = "#10B981", "#064E3B", "#6EE7B7"
    elif grade in ("B", "C"):
        ring_color, pill_bg, pill_fg = "#F59E0B", "#78350F", "#FCD34D"
    else:
        ring_color, pill_bg, pill_fg = "#F43F5E", "#881337", "#FDA4AF"

    r = 46
    circ = 2 * math.pi * r
    dash_off = circ * (1.0 - max(4, score) / 100.0)

    verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
    v_tone = verdict.get("tone", "ok")
    v_text = str(verdict.get("text") or report.get("summary") or "抗风控与全栈指纹体检报告")
    if len(v_text) > 34:
        v_text = v_text[:33] + "…"
    v_dot = "#F43F5E" if v_tone == "bad" else "#F59E0B" if v_tone == "warn" else "#10B981"

    topo = report.get("topo") if isinstance(report.get("topo"), dict) else {}
    exit_region = str(topo.get("exitRegion") or "地区已隐藏")[:22]
    exit_type = str(topo.get("exitType") or "网络出口")[:14]
    purity_txt = str(topo.get("purityText") or "信誉 --")[:16]
    rtt_txt = str(topo.get("link2Rtt") or "延迟已采样")[:22]
    dev_sub = str(topo.get("deviceSub") or "系统终端")[:26]
    proto_badge = str(topo.get("link2Badge") or "TLS 1.3")[:18]

    tz_cn = datetime.timezone(datetime.timedelta(hours=8))
    dt_str = datetime.datetime.fromtimestamp(created_at, tz=tz_cn).strftime("%Y-%m-%d %H:%M UTC+8")

    # 6 scenario bars in a 2-col x 3-row layout inside bottom-right panel
    default_scens = [
        ("AI 大模型", 50),
        ("流媒体解锁", 50),
        ("社媒注册", 50),
        ("无感免盾", 50),
        ("金融支付", 50),
        ("SMTP 邮件信誉", 50),
    ]
    scen_list = report.get("scenarios") if isinstance(report.get("scenarios"), list) else []
    scen_svg_parts: list[str] = []
    for idx in range(6):
        if idx < len(scen_list) and isinstance(scen_list[idx], dict):
            nm = str(scen_list[idx].get("name") or default_scens[idx][0])[:12]
            sc_val = _clamp_int(scen_list[idx].get("score"), 5, 100, 50)
        else:
            nm, sc_val = default_scens[idx]
        col = idx % 2
        row = idx // 2
        bx = 282 + col * 224
        by = 248 + row * 36
        bar_w = 204
        fill_w = max(8, round(bar_w * sc_val / 100))
        bar_c = "#10B981" if sc_val >= 80 else "#F59E0B" if sc_val >= 55 else "#F43F5E"
        scen_svg_parts.append(
            f'<g transform="translate({bx},{by})">'
            f'<text x="0" y="0" fill="#CBD5E1" font-size="11.5" font-weight="600">{_svg_esc(nm)}</text>'
            f'<text x="{bar_w}" y="0" fill="{bar_c}" font-size="11.5" font-weight="700" text-anchor="end" font-family="ui-monospace,SFMono-Regular,Menlo,monospace">{sc_val}%</text>'
            f'<rect x="0" y="7" width="{bar_w}" height="6" rx="3" fill="#1E2532"/>'
            f'<rect x="0" y="7" width="{fill_w}" height="6" rx="3" fill="{bar_c}"/>'
            f"</g>"
        )

    font_sans = "-apple-system,BlinkMacSystemFont,'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif"
    font_mono = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="760" height="380" viewBox="0 0 760 380" fill="none">
  <rect width="760" height="380" rx="20" fill="#0B0E14"/>
  <rect x="0.5" y="0.5" width="759" height="379" rx="19.5" stroke="#1E2634"/>

  <!-- Header -->
  <g transform="translate(26, 22)">
    <rect width="28" height="28" rx="8" fill="#F8FAFC"/>
    <path d="M14 11.5a2.2 2.2 0 0 0-2.2 2.2c0 1.2-.15 2.8-.35 4.5M16.2 14.5c0 2.6 0 6.2-1.1 8.5M8.5 14a5.5 5.5 0 0 1 11 0v2.2M5.5 13.5a8.5 8.5 0 0 1 15-4.8" stroke="#0B0E14" stroke-width="1.9" stroke-linecap="round"/>
    <text x="38" y="19" fill="#F8FAFC" font-size="15.5" font-weight="700" font-family="{font_sans}">WhoProbe</text>
    <text x="122" y="19" fill="#64748B" font-size="12" font-weight="500" font-family="{font_sans}">全栈指纹与出口风控体检快照</text>

    <rect x="436" y="3" width="108" height="22" rx="11" fill="#064E3B"/>
    <circle cx="449" cy="14" r="3" fill="#34D399"/>
    <text x="458" y="18" fill="#A7F3D0" font-size="10.5" font-weight="600" font-family="{font_sans}">真实 IP 已抹除</text>
    <text x="708" y="18" fill="#64748B" font-size="11" text-anchor="end" font-family="{font_mono}">{_svg_esc(dt_str)}</text>
  </g>

  <!-- Left Gauge Card -->
  <rect x="26" y="64" width="222" height="290" rx="16" fill="#121722" stroke="#1E2634"/>
  <text x="46" y="92" fill="#94A3B8" font-size="12" font-weight="600" font-family="{font_sans}">抗风控健康度</text>
  <text x="228" y="92" fill="#64748B" font-size="10.5" text-anchor="end" font-family="{font_mono}">#{_svg_esc(share_id)}</text>

  <g transform="translate(137, 168)">
    <circle cx="0" cy="0" r="{r}" stroke="#1E2634" stroke-width="9" fill="none"/>
    <circle cx="0" cy="0" r="{r}" stroke="{ring_color}" stroke-width="9" stroke-linecap="round"
            stroke-dasharray="{circ:.2f}" stroke-dashoffset="{dash_off:.2f}" transform="rotate(-90)" fill="none"/>
    <text x="0" y="3" fill="#F8FAFC" font-size="34" font-weight="800" text-anchor="middle" font-family="{font_mono}">{score}</text>
    <rect x="-24" y="14" width="48" height="19" rx="9.5" fill="{pill_bg}"/>
    <text x="0" y="27" fill="{pill_fg}" font-size="10.5" font-weight="700" text-anchor="middle" font-family="{font_sans}">{_svg_esc(grade)} 级</text>
  </g>

  <!-- 3 Status Counters -->
  <g transform="translate(42, 246)" font-family="{font_sans}">
    <rect x="0" y="0" width="58" height="46" rx="9" fill="#2A121B"/>
    <text x="29" y="22" fill="#FDA4AF" font-size="15" font-weight="700" text-anchor="middle" font-family="{font_mono}">{bad_cnt}</text>
    <text x="29" y="38" fill="#FB7185" font-size="10" font-weight="600" text-anchor="middle">高危</text>

    <rect x="66" y="0" width="58" height="46" rx="9" fill="#291D0E"/>
    <text x="95" y="22" fill="#FCD34D" font-size="15" font-weight="700" text-anchor="middle" font-family="{font_mono}">{warn_cnt}</text>
    <text x="95" y="38" fill="#FBBF24" font-size="10" font-weight="600" text-anchor="middle">可疑</text>

    <rect x="132" y="0" width="58" height="46" rx="9" fill="#0B2922"/>
    <text x="161" y="22" fill="#6EE7B7" font-size="15" font-weight="700" text-anchor="middle" font-family="{font_mono}">{ok_cnt}</text>
    <text x="161" y="38" fill="#34D399" font-size="10" font-weight="600" text-anchor="middle">通过</text>
  </g>
  <text x="137" y="330" fill="#64748B" font-size="10.5" text-anchor="middle" font-family="{font_sans}">148 项无感探针全量核验</text>

  <!-- Top-Right Verdict & Telemetry Card -->
  <rect x="262" y="64" width="472" height="128" rx="16" fill="#121722" stroke="#1E2634"/>
  <circle cx="285" cy="90" r="4.5" fill="{v_dot}"/>
  <text x="297" y="94" fill="#F1F5F9" font-size="13" font-weight="700" font-family="{font_sans}">{_svg_esc(v_text)}</text>
  <line x1="280" y1="109" x2="716" y2="109" stroke="#1E2634"/>

  <g transform="translate(282, 130)" font-family="{font_sans}">
    <text x="0" y="0" fill="#64748B" font-size="10.5" font-weight="600">出口地区与属性</text>
    <text x="0" y="20" fill="#F8FAFC" font-size="12.5" font-weight="700">{_svg_esc(exit_region)}</text>
    <text x="0" y="38" fill="#94A3B8" font-size="11" font-family="{font_mono}">{_svg_esc(exit_type)} · *.*.*.*</text>

    <text x="156" y="0" fill="#64748B" font-size="10.5" font-weight="600">多源信誉与测距</text>
    <text x="156" y="20" fill="#F8FAFC" font-size="12.5" font-weight="700" font-family="{font_mono}">{_svg_esc(purity_txt)}</text>
    <text x="156" y="38" fill="#94A3B8" font-size="11" font-family="{font_mono}">{_svg_esc(rtt_txt)}</text>

    <text x="312" y="0" fill="#64748B" font-size="10.5" font-weight="600">端侧与握手协议栈</text>
    <text x="312" y="20" fill="#F8FAFC" font-size="12.5" font-weight="700" font-family="{font_mono}">{_svg_esc(proto_badge)}</text>
    <text x="312" y="38" fill="#94A3B8" font-size="11">{_svg_esc(dev_sub)}</text>
  </g>

  <!-- Bottom-Right 6 Business Scenarios Card -->
  <rect x="262" y="204" width="472" height="150" rx="16" fill="#121722" stroke="#1E2634"/>
  <text x="282" y="229" fill="#94A3B8" font-size="11.5" font-weight="600" font-family="{font_sans}">六大业务场景准入模拟（融合 8 源欺诈库 + 浏览器指纹）</text>
  {"".join(scen_svg_parts)}
</svg>"""
    return svg.encode("utf-8")


def inject_html_for_route(
    raw_html: str,
    base_href: str = "/",
    origin_prefix: str = "",
    share_record: dict | None = None,
    missing_share_id: str | None = None,
) -> bytes:
    """Inject <base href>, OpenGraph / Twitter Card tags, and hydrated share JSON into index.html."""
    tags: list[str] = [f'  <base href="{html.escape(base_href, quote=True)}">']

    if share_record and isinstance(share_record.get("report"), dict):
        sid = share_record["id"]
        rep = share_record["report"]
        score = rep.get("score", "--")
        grade = rep.get("grade", "-")
        topo = rep.get("topo") if isinstance(rep.get("topo"), dict) else {}
        region = topo.get("exitRegion") or "脱敏出口"
        verdict = (rep.get("verdict") or {}).get("text") or rep.get("summary") or "148 项全栈风控与指纹体检"
        og_title = f"WhoProbe 体检评分 {score}/100 ({grade} 级) · {region}"
        og_desc = f"{verdict}（真实 IP 已隐私抹除，点击查看完整脱敏报告或自测）"
        page_url = f"{origin_prefix}/r/{sid}" if origin_prefix else f"/r/{sid}"
        img_url = f"{origin_prefix}/r/{sid}.svg" if origin_prefix else f"/r/{sid}.svg"

        tags.extend([
            '  <meta property="og:type" content="website">',
            f'  <meta property="og:title" content="{html.escape(og_title, quote=True)}">',
            f'  <meta property="og:description" content="{html.escape(og_desc, quote=True)}">',
            f'  <meta property="og:url" content="{html.escape(page_url, quote=True)}">',
            f'  <meta property="og:image" content="{html.escape(img_url, quote=True)}">',
            '  <meta name="twitter:card" content="summary_large_image">',
            f'  <meta name="twitter:title" content="{html.escape(og_title, quote=True)}">',
            f'  <meta name="twitter:description" content="{html.escape(og_desc, quote=True)}">',
            f'  <meta name="twitter:image" content="{html.escape(img_url, quote=True)}">',
        ])
        safe_json = (
            json.dumps({"ok": True, **share_record}, ensure_ascii=False, separators=(",", ":"))
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        tags.append(f"  <script>window.__WHOPROBE_SHARED__={safe_json};</script>")
    elif missing_share_id:
        safe_json = json.dumps(
            {"ok": False, "notFound": True, "id": scrub_sensitive_text(missing_share_id, 20)},
            ensure_ascii=False,
        ).replace("<", "\\u003c")
        tags.append(f"  <script>window.__WHOPROBE_SHARED__={safe_json};</script>")

    injected_block = "\n".join(tags) + "\n"
    if "<head>" in raw_html:
        out_html = raw_html.replace("<head>", "<head>\n" + injected_block, 1)
    else:
        out_html = injected_block + raw_html
    return out_html.encode("utf-8")
