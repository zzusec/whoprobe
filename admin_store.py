#!/usr/bin/env python3
"""
Opt-in Self-Hosted Admin Analytics & Share Audit Store for WhoProbe.

Security & Privacy Design:
  1. Disabled by Default: Unless an admin token is explicitly configured via
     --admin-token / --admin-token-file / WHOPROBE_ADMIN_TOKEN / systemd LoadCredential,
     admin routes return 404 and zero visitor IP logs are written to disk.
  2. Constant-Time Auth & Signed HttpOnly Cookie: Password login uses hmac.compare_digest,
     per-IP brute-force rate limiting, and HMAC-SHA256 stateless session tokens.
  3. Bounded SQLite WAL Storage: Automatic 90-day retention and 200,000-row cap;
     public share snapshots in ShareStore remain 100% zero-IP for public viewers.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

TZ_CN = datetime.timezone(datetime.timedelta(hours=8))
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHARE_ID_RE = re.compile(r"^[A-Za-z0-9]{6,16}$")


def cn_day_str(ts: int | float | None = None) -> str:
    t = time.time() if ts is None else float(ts)
    return datetime.datetime.fromtimestamp(t, tz=TZ_CN).strftime("%Y-%m-%d")


def parse_ua_brief(ua_raw: str) -> tuple[str, str]:
    """Extract concise (os_label, browser_label) from a User-Agent header."""
    ua = (ua_raw or "").strip()
    if not ua:
        return "未知系统", "未知客户端"

    low = ua.lower()
    for bot_kw, bot_name in (
        ("telegrambot", "Telegram 预览爬虫"),
        ("twitterbot", "X/Twitter 预览爬虫"),
        ("slackbot", "Slack 预览爬虫"),
        ("discordbot", "Discord 预览爬虫"),
        ("whatsapp", "WhatsApp 预览"),
        ("facebookexternalhit", "Meta 预览爬虫"),
        ("micromessenger", "微信内置浏览器"),
        ("curl/", "curl 命令行"),
        ("python-urllib", "Python urllib"),
        ("python-requests", "Python requests"),
        ("go-http-client", "Go HTTP 客户端"),
        ("uptimerobot", "UptimeRobot 监控"),
    ):
        if bot_kw in low and bot_kw != "micromessenger":
            return "Bot / CLI", bot_name

    # OS detection
    os_lbl = "未知系统"
    m_ios = re.search(r"(?:iPhone|iPad|iPod).*?OS (\d+[._]\d+)", ua)
    m_and = re.search(r"Android (\d+(?:\.\d+)?)", ua)
    m_mac = re.search(r"Mac OS X (\d+[._]\d+)", ua)
    if m_ios:
        dev = "iPadOS" if "iPad" in ua else "iOS"
        os_lbl = f"{dev} {m_ios.group(1).replace('_', '.')}"
    elif "HarmonyOS" in ua:
        os_lbl = "HarmonyOS"
    elif m_and:
        os_lbl = f"Android {m_and.group(1)}"
    elif "Windows NT 10.0" in ua:
        os_lbl = "Windows 10/11"
    elif "Windows NT" in ua:
        os_lbl = "Windows"
    elif m_mac:
        os_lbl = f"macOS {m_mac.group(1).replace('_', '.')}"
    elif "CrOS" in ua:
        os_lbl = "ChromeOS"
    elif "Linux" in ua:
        os_lbl = "Linux"

    # Browser detection
    br_lbl = "浏览器"
    if "MicroMessenger/" in ua:
        m = re.search(r"MicroMessenger/(\d+\.\d+)", ua)
        br_lbl = f"微信 {m.group(1)}" if m else "微信内置"
    elif "Edg/" in ua or "EdgiOS/" in ua or "EdgA/" in ua:
        m = re.search(r"Edg(?:iOS|A)?/(\d+)", ua)
        br_lbl = f"Edge {m.group(1)}" if m else "Edge"
    elif "OPR/" in ua or "OPiOS/" in ua:
        m = re.search(r"(?:OPR|OPiOS)/(\d+)", ua)
        br_lbl = f"Opera {m.group(1)}" if m else "Opera"
    elif "CriOS/" in ua:
        m = re.search(r"CriOS/(\d+)", ua)
        br_lbl = f"Chrome iOS {m.group(1)}" if m else "Chrome iOS"
    elif "FxiOS/" in ua:
        m = re.search(r"FxiOS/(\d+)", ua)
        br_lbl = f"Firefox iOS {m.group(1)}" if m else "Firefox iOS"
    elif "Firefox/" in ua:
        m = re.search(r"Firefox/(\d+)", ua)
        br_lbl = f"Firefox {m.group(1)}" if m else "Firefox"
    elif "HeadlessChrome/" in ua:
        m = re.search(r"HeadlessChrome/(\d+)", ua)
        br_lbl = f"HeadlessChrome {m.group(1)}" if m else "HeadlessChrome"
    elif "Chrome/" in ua:
        m = re.search(r"Chrome/(\d+)", ua)
        br_lbl = f"Chrome {m.group(1)}" if m else "Chrome"
    elif "Version/" in ua and "Safari/" in ua:
        m = re.search(r"Version/(\d+(?:\.\d+)?)", ua)
        br_lbl = f"Safari {m.group(1)}" if m else "Safari"
    elif "Safari/" in ua:
        br_lbl = "Safari / WebKit"

    return os_lbl[:32], br_lbl[:32]


def _clean_str(val: object, max_len: int = 120) -> str:
    if val is None:
        return ""
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(val)).strip()
    return s[:max_len]


class AdminAuth:
    """Stateless HMAC session & brute-force limiter for the WhoProbe admin console."""

    COOKIE_NAME = "wp_adm"
    SESSION_TTL_SEC = 14 * 86400
    MAX_FAILS_PER_10M = 8

    def __init__(self, admin_token: str) -> None:
        token = (admin_token or "").strip()
        if len(token) < 8:
            raise ValueError("admin_token must be at least 8 characters")
        self._token = token
        # Derive a separate signing key so the raw password is never used directly as HMAC key
        self._sign_key = hashlib.sha256(f"whoprobe-admin-v1:{token}".encode("utf-8")).digest()
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    def check_rate_limit(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 600.0
        with self._lock:
            arr = [t for t in self._fails.get(client_ip, []) if t >= cutoff]
            if arr:
                self._fails[client_ip] = arr
            else:
                self._fails.pop(client_ip, None)
            return len(arr) < self.MAX_FAILS_PER_10M

    def record_failure(self, client_ip: str) -> None:
        now = time.monotonic()
        cutoff = now - 600.0
        with self._lock:
            arr = [t for t in self._fails.get(client_ip, []) if t >= cutoff]
            arr.append(now)
            self._fails[client_ip] = arr[-20:]
            if len(self._fails) > 2048:
                oldest_ip = next(iter(self._fails))
                self._fails.pop(oldest_ip, None)

    def clear_failures(self, client_ip: str) -> None:
        with self._lock:
            self._fails.pop(client_ip, None)

    def verify_password(self, candidate: str) -> bool:
        cand = (candidate or "").strip()
        if not cand:
            return False
        return hmac.compare_digest(cand.encode("utf-8"), self._token.encode("utf-8"))

    def issue_session_cookie(self, now_ts: int | None = None) -> str:
        exp = int(now_ts if now_ts is not None else time.time()) + self.SESSION_TTL_SEC
        nonce = secrets.token_hex(8)
        msg = f"{exp}.{nonce}".encode("ascii")
        sig = hmac.new(self._sign_key, msg, hashlib.sha256).hexdigest()
        return f"{exp}.{nonce}.{sig}"

    def verify_session_cookie(self, cookie_val: str) -> bool:
        parts = (cookie_val or "").strip().split(".")
        if len(parts) != 3:
            return False
        exp_s, nonce, sig = parts
        if not exp_s.isdigit() or not (8 <= len(nonce) <= 32) or len(sig) != 64:
            return False
        if int(exp_s) < int(time.time()):
            return False
        expected = hmac.new(self._sign_key, f"{exp_s}.{nonce}".encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)

    def verify_request_headers(self, cookie_header: str, auth_header: str) -> bool:
        auth = (auth_header or "").strip()
        if auth.lower().startswith("bearer "):
            if self.verify_password(auth[7:].strip()):
                return True
        for chunk in (cookie_header or "").split(";"):
            k, sep, v = chunk.strip().partition("=")
            if sep and k.strip() == self.COOKIE_NAME:
                if self.verify_session_cookie(v.strip()):
                    return True
        return False


class AdminStore:
    """Bounded thread-safe SQLite store for visitor telemetry and share-link audit logs."""

    TTL_SEC = 90 * 86400
    MAX_ROWS = 200_000

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._dedup: dict[str, float] = {}
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
                probe_file = folder / ".write_check_adm"
                probe_file.write_text("ok", encoding="utf-8")
                probe_file.unlink(missing_ok=True)
                return folder / "admin.db"
            except Exception:
                continue
        return Path(":memory:")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            self._conn = self._connect()
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS visits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    day TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    event TEXT NOT NULL,
                    share_id TEXT NOT NULL DEFAULT '',
                    target_ip TEXT NOT NULL DEFAULT '',
                    cc TEXT NOT NULL DEFAULT '',
                    city TEXT NOT NULL DEFAULT '',
                    asn TEXT NOT NULL DEFAULT '',
                    org TEXT NOT NULL DEFAULT '',
                    os TEXT NOT NULL DEFAULT '',
                    browser TEXT NOT NULL DEFAULT '',
                    tcp_os TEXT NOT NULL DEFAULT '',
                    ua TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_visits_day ON visits(day, ip);
                CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_visits_share ON visits(share_id, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_visits_event ON visits(event, ts DESC);

                CREATE TABLE IF NOT EXISTS share_meta (
                    share_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    creator_ip TEXT NOT NULL DEFAULT '',
                    creator_cc TEXT NOT NULL DEFAULT '',
                    creator_city TEXT NOT NULL DEFAULT '',
                    creator_org TEXT NOT NULL DEFAULT '',
                    creator_ua TEXT NOT NULL DEFAULT '',
                    score INTEGER NOT NULL DEFAULT 0,
                    grade TEXT NOT NULL DEFAULT '',
                    view_count INTEGER NOT NULL DEFAULT 0,
                    last_viewed_at INTEGER NOT NULL DEFAULT 0,
                    last_viewer_ip TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_smeta_viewed ON share_meta(last_viewed_at DESC);
                """
            )
            self._conn.commit()

    def _should_skip_dup(self, key: str, window_sec: float) -> bool:
        if window_sec <= 0:
            return False
        now_m = time.monotonic()
        with self._lock:
            prev = self._dedup.get(key)
            if prev is not None and (now_m - prev) < window_sec:
                return True
            self._dedup[key] = now_m
            if len(self._dedup) > 4096:
                cutoff = now_m - 30.0
                self._dedup = {k: v for k, v in self._dedup.items() if v >= cutoff}
            return False

    def _prune_if_needed_locked(self, now: int) -> None:
        self._ops += 1
        if self._ops % 128 != 0:
            return
        cutoff = now - self.TTL_SEC
        self._conn.execute("DELETE FROM visits WHERE ts < ?", (cutoff,))
        self._conn.execute(
            """
            DELETE FROM visits WHERE id IN (
                SELECT id FROM visits ORDER BY id DESC LIMIT -1 OFFSET ?
            )
            """,
            (self.MAX_ROWS,),
        )
        self._conn.execute("DELETE FROM share_meta WHERE created_at < ?", (cutoff,))

    @staticmethod
    def _extract_geo_fields(geo: dict | None) -> tuple[str, str, str, str]:
        g = geo if isinstance(geo, dict) else {}
        cc = _clean_str(g.get("countryCode") or g.get("cc"), 8).upper()
        city = _clean_str(g.get("city") or g.get("region"), 48)
        raw_asn = _clean_str(g.get("asn"), 20)
        asn = (f"AS{raw_asn}" if raw_asn and not raw_asn.upper().startswith("AS") else raw_asn.upper())
        org = _clean_str(g.get("isp") or g.get("org") or g.get("asName"), 80)
        return cc, city, asn, org

    def record_visit(
        self,
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
    ) -> bool:
        clean_ip = _clean_str(ip, 64)
        if not clean_ip:
            return False
        ev = _clean_str(event, 24)
        sid = _clean_str(share_id, 20)
        tgt = _clean_str(target_ip, 64)
        dedup_key = f"{clean_ip}|{ev}|{sid}|{tgt}"
        if self._should_skip_dup(dedup_key, dedup_sec):
            return False

        now = int(created_at if created_at is not None else time.time())
        day = cn_day_str(now)
        cc, city, asn, org = self._extract_geo_fields(geo)
        clean_ua = _clean_str(ua, 280)
        os_lbl, br_lbl = parse_ua_brief(clean_ua)
        clean_tcp_os = _clean_str(tcp_os, 36)

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO visits (ts, day, ip, event, share_id, target_ip, cc, city, asn, org, os, browser, tcp_os, ua)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, day, clean_ip, ev, sid, tgt, cc, city, asn, org, os_lbl, br_lbl, clean_tcp_os, clean_ua),
            )
            if ev == "share_create" and sid:
                self._conn.execute(
                    """
                    INSERT INTO share_meta (
                        share_id, created_at, creator_ip, creator_cc, creator_city, creator_org, creator_ua, score, grade
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(share_id) DO UPDATE SET
                        creator_ip=excluded.creator_ip,
                        creator_cc=excluded.creator_cc,
                        creator_city=excluded.creator_city,
                        creator_org=excluded.creator_org,
                        creator_ua=excluded.creator_ua,
                        score=excluded.score,
                        grade=excluded.grade
                    """,
                    (sid, now, clean_ip, cc, city, org, clean_ua, int(score or 0), _clean_str(grade, 8)),
                )
            elif ev == "share_view" and sid:
                # Avoid counting preview bots toward human view_count if obvious bot, or count all views cleanly
                self._conn.execute(
                    """
                    INSERT INTO share_meta (share_id, created_at, view_count, last_viewed_at, last_viewer_ip)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(share_id) DO UPDATE SET
                        view_count = share_meta.view_count + 1,
                        last_viewed_at = excluded.last_viewed_at,
                        last_viewer_ip = excluded.last_viewer_ip
                    """,
                    (sid, now, now, clean_ip),
                )
            self._prune_if_needed_locked(now)
            self._conn.commit()
        return True

    def get_overview(self, days: int = 30, total_shares_in_store: int = 0) -> dict:
        days = max(7, min(90, int(days)))
        now_dt = datetime.datetime.now(tz=TZ_CN)
        today_str = now_dt.strftime("%Y-%m-%d")
        yesterday_str = (now_dt - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        day_list = [(now_dt - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
        start_day = day_list[0]
        day7_start = (now_dt - datetime.timedelta(days=6)).strftime("%Y-%m-%d")

        with self._lock:
            daily_rows = self._conn.execute(
                """
                SELECT
                    day,
                    COUNT(DISTINCT ip) AS uv,
                    COUNT(*) AS pv,
                    SUM(CASE WHEN event = 'scan' THEN 1 ELSE 0 END) AS scans,
                    SUM(CASE WHEN event = 'share_view' THEN 1 ELSE 0 END) AS share_views,
                    SUM(CASE WHEN event = 'share_create' THEN 1 ELSE 0 END) AS share_creates,
                    SUM(CASE WHEN event = 'ip_query' THEN 1 ELSE 0 END) AS ip_queries
                FROM visits
                WHERE day >= ?
                GROUP BY day
                """,
                (start_day,),
            ).fetchall()

            w7 = self._conn.execute(
                "SELECT COUNT(DISTINCT ip) AS uv, COUNT(*) AS pv FROM visits WHERE day >= ?",
                (day7_start,),
            ).fetchone()
            w30 = self._conn.execute(
                "SELECT COUNT(DISTINCT ip) AS uv, COUNT(*) AS pv FROM visits WHERE day >= ?",
                (start_day,),
            ).fetchone()
            tot_views_row = self._conn.execute(
                "SELECT COALESCE(SUM(view_count), 0) AS tv FROM share_meta"
            ).fetchone()

            top_cc_rows = self._conn.execute(
                """
                SELECT cc, COUNT(DISTINCT ip) AS uv, COUNT(*) AS pv
                FROM visits
                WHERE day >= ? AND cc != ''
                GROUP BY cc
                ORDER BY uv DESC, pv DESC
                LIMIT 10
                """,
                (start_day,),
            ).fetchall()

            top_ip_rows = self._conn.execute(
                """
                SELECT
                    ip,
                    MAX(cc) AS cc,
                    MAX(city) AS city,
                    MAX(asn) AS asn,
                    MAX(org) AS org,
                    MAX(os) AS os,
                    MAX(browser) AS browser,
                    COUNT(*) AS pv,
                    SUM(CASE WHEN event = 'scan' THEN 1 ELSE 0 END) AS scans,
                    SUM(CASE WHEN event = 'share_view' THEN 1 ELSE 0 END) AS share_views,
                    SUM(CASE WHEN event = 'share_create' THEN 1 ELSE 0 END) AS share_creates,
                    MIN(ts) AS first_seen,
                    MAX(ts) AS last_seen,
                    GROUP_CONCAT(DISTINCT CASE WHEN share_id != '' THEN share_id END) AS share_ids
                FROM visits
                WHERE day >= ?
                GROUP BY ip
                ORDER BY last_seen DESC
                LIMIT 50
                """,
                (start_day,),
            ).fetchall()

        by_day = {r["day"]: dict(r) for r in daily_rows}
        daily_series = []
        for d in day_list:
            row = by_day.get(d)
            daily_series.append({
                "day": d,
                "uv": int(row["uv"]) if row else 0,
                "pv": int(row["pv"]) if row else 0,
                "scans": int(row["scans"] or 0) if row else 0,
                "shareViews": int(row["share_views"] or 0) if row else 0,
                "shareCreates": int(row["share_creates"] or 0) if row else 0,
                "ipQueries": int(row["ip_queries"] or 0) if row else 0,
            })

        td = by_day.get(today_str, {})
        yd = by_day.get(yesterday_str, {})

        top_ips = []
        for r in top_ip_rows:
            sids = [x for x in (r["share_ids"] or "").split(",") if x][:8]
            top_ips.append({
                "ip": r["ip"],
                "cc": r["cc"] or "",
                "city": r["city"] or "",
                "asn": r["asn"] or "",
                "org": r["org"] or "",
                "os": r["os"] or "",
                "browser": r["browser"] or "",
                "pv": int(r["pv"] or 0),
                "scans": int(r["scans"] or 0),
                "shareViews": int(r["share_views"] or 0),
                "shareCreates": int(r["share_creates"] or 0),
                "firstSeen": int(r["first_seen"] or 0),
                "lastSeen": int(r["last_seen"] or 0),
                "shareIds": sids,
            })

        return {
            "today": today_str,
            "kpis": {
                "todayUv": int(td.get("uv") or 0),
                "todayPv": int(td.get("pv") or 0),
                "todayScans": int(td.get("scans") or 0),
                "todayShareViews": int(td.get("share_views") or 0),
                "todayShareCreates": int(td.get("share_creates") or 0),
                "yesterdayUv": int(yd.get("uv") or 0),
                "yesterdayPv": int(yd.get("pv") or 0),
                "days7Uv": int(w7["uv"] if w7 else 0),
                "days7Pv": int(w7["pv"] if w7 else 0),
                "days30Uv": int(w30["uv"] if w30 else 0),
                "days30Pv": int(w30["pv"] if w30 else 0),
                "totalShares": int(total_shares_in_store),
                "totalShareViews": int(tot_views_row["tv"] if tot_views_row else 0),
            },
            "daily": daily_series,
            "topCountries": [
                {"cc": r["cc"], "uv": int(r["uv"]), "pv": int(r["pv"])} for r in top_cc_rows
            ],
            "topIps": top_ips,
        }

    def query_visits(
        self,
        *,
        day: str = "",
        event: str = "",
        q: str = "",
        limit: int = 80,
        offset: int = 0,
    ) -> tuple[int, list[dict]]:
        lim = max(1, min(200, int(limit)))
        off = max(0, int(offset))
        clauses: list[str] = []
        params: list[object] = []

        if day and DAY_RE.match(day):
            clauses.append("day = ?")
            params.append(day)
        if event in ("scan", "share_view", "share_create", "ip_query"):
            clauses.append("event = ?")
            params.append(event)
        q_clean = _clean_str(q, 64).lstrip("#")
        if q_clean:
            like = f"%{q_clean}%"
            clauses.append(
                "(ip LIKE ? OR share_id LIKE ? OR target_ip LIKE ? OR cc LIKE ? OR city LIKE ? OR asn LIKE ? OR org LIKE ? OR os LIKE ? OR browser LIKE ?)"
            )
            params.extend([like] * 9)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            tot_row = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM visits {where_sql}", params
            ).fetchone()
            rows = self._conn.execute(
                f"""
                SELECT id, ts, day, ip, event, share_id, target_ip, cc, city, asn, org, os, browser, tcp_os, ua
                FROM visits
                {where_sql}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                [*params, lim, off],
            ).fetchall()

        items = [
            {
                "id": int(r["id"]),
                "ts": int(r["ts"]),
                "day": r["day"],
                "ip": r["ip"],
                "event": r["event"],
                "shareId": r["share_id"],
                "targetIp": r["target_ip"],
                "cc": r["cc"],
                "city": r["city"],
                "asn": r["asn"],
                "org": r["org"],
                "os": r["os"],
                "browser": r["browser"],
                "tcpOs": r["tcp_os"],
                "ua": r["ua"],
            }
            for r in rows
        ]
        return int(tot_row["c"] if tot_row else 0), items

    def get_share_meta_map(self, share_ids: list[str]) -> dict[str, dict]:
        ids = [s for s in share_ids if SHARE_ID_RE.match(s)]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM share_meta WHERE share_id IN ({placeholders})",
                ids,
            ).fetchall()
        out: dict[str, dict] = {}
        for r in rows:
            out[r["share_id"]] = {
                "creatorIp": r["creator_ip"],
                "creatorCc": r["creator_cc"],
                "creatorCity": r["creator_city"],
                "creatorOrg": r["creator_org"],
                "creatorUa": r["creator_ua"],
                "viewCount": int(r["view_count"] or 0),
                "lastViewedAt": int(r["last_viewed_at"] or 0),
                "lastViewerIp": r["last_viewer_ip"],
            }
        return out

    def get_share_viewers(self, share_id: str, limit: int = 100) -> list[dict]:
        sid = (share_id or "").strip()
        if not SHARE_ID_RE.match(sid):
            return []
        lim = max(1, min(200, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, ts, day, ip, event, cc, city, asn, org, os, browser, ua
                FROM visits
                WHERE share_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (sid, lim),
            ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "ts": int(r["ts"]),
                "day": r["day"],
                "ip": r["ip"],
                "event": r["event"],
                "cc": r["cc"],
                "city": r["city"],
                "asn": r["asn"],
                "org": r["org"],
                "os": r["os"],
                "browser": r["browser"],
                "ua": r["ua"],
            }
            for r in rows
        ]

    def delete_share_meta(self, share_id: str) -> None:
        sid = (share_id or "").strip()
        if not SHARE_ID_RE.match(sid):
            return
        with self._lock:
            self._conn.execute("DELETE FROM share_meta WHERE share_id = ?", (sid,))
            self._conn.commit()
