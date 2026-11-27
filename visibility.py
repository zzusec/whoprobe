"""Data minimization and opt-in endpoint config for the website's-eye view."""
from __future__ import annotations

import html
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from urllib.parse import parse_qsl, urlsplit

import egress_intel
import visibility_dns


# Other header names can be listed, but never echo their values. In particular,
# headers unknown to this application may be used for credentials by upstreams.
DISPLAY_HEADERS = frozenset({
    "host", "user-agent", "accept", "accept-language", "accept-encoding",
    "origin", "referer", "content-type", "content-length", "content-encoding",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-mobile",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-wow64",
    "sec-ch-ua-form-factors", "sec-ch-prefers-color-scheme",
    "dnt", "sec-gpc", "upgrade-insecure-requests", "priority",
    "cache-control", "pragma", "te", "save-data", "viewport-width", "dpr",
})
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9a-zA-Z-]{1,96}\Z")
CHALLENGE = re.compile(r"[0-9a-f]{16,64}\Z")


def clean_text(value: object, limit: int = 512) -> str:
    return " ".join(str(value).split())[:limit] if value is not None else ""


def url_origin(value: str, *, configured: bool = False) -> str | None:
    if not isinstance(value, str) or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        return None
    try:
        url = urlsplit(value)
        name, port = url.hostname, url.port
    except ValueError:
        return None
    if not name or url.username is not None or url.password is not None:
        return None
    try:
        addr = ipaddress.ip_address(name)
        host = f"[{addr}]" if addr.version == 6 else str(addr)
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", name):
            return None
        host = name
    if url.scheme not in ("https", "http"):
        return None
    if configured and url.scheme == "http" and host not in ("localhost", "127.0.0.1", "[::1]"):
        return None
    if port is not None and port != (443 if url.scheme == "https" else 80):
        host = f"{host}:{port}"
    return f"{url.scheme}://{host}"


def display_headers(headers, *, exclude=()) -> list[dict]:
    """HTTP backend header order/case, not H2/H3 wire order."""
    rows = []
    for name, raw in headers.items():
        key = name.lower()
        if key in exclude or not HEADER_NAME.fullmatch(name):
            continue
        value = None
        if key in ("origin", "referer"):
            raw = clean_text(raw)
            value = "null" if key == "origin" and raw == "null" else url_origin(raw)
        elif key == "host":
            origin = url_origin(f"https://{clean_text(raw)}")
            value = origin.removeprefix("https://") if origin else None
        elif key in DISPLAY_HEADERS:
            value = clean_text(raw)
        rows.append({"name": name, "value": value})
        if len(rows) == 100:
            break
    return rows


def legacy_header_values(headers, *, exclude=()) -> dict[str, str]:
    """Public subset, keeping the lower-case names used by existing probes."""
    return {row["name"].lower(): row["value"] for row in display_headers(headers, exclude=exclude)
            if row["value"] is not None}


def address(ip: object, port=None) -> dict:
    try:
        addr = ipaddress.ip_address(str(ip))
        addr = addr.ipv4_mapped or addr if isinstance(addr, ipaddress.IPv6Address) else addr
    except ValueError:
        return {"ip": None, "family": None, "port": None}
    try:
        port_number = int(port)
        if not 0 < port_number < 65536:
            port_number = None
    except (TypeError, ValueError):
        port_number = None
    return {"ip": str(addr), "family": addr.version, "port": port_number}


def connection_record(meta: dict, *, source: str, backend_protocol: str) -> dict:
    known = ("httpVersion", "tlsProtocol", "tlsCipher", "tlsCurves", "tlsAlpn", "tlsSessionReused")
    result = {key: clean_text(meta.get(key), 160) or None for key in known}
    result["source"] = source
    result["backendProtocol"] = backend_protocol
    return result


def wire_record(packet: dict) -> dict:
    def select(group, keys):
        item = packet.get(group)
        return {k: item[k] for k in keys if k in item} if isinstance(item, dict) else None

    return {
        "snifferActive": bool(packet.get("snifferActive")),
        "tlsBridgeActive": bool(packet.get("tlsBridgeActive")),
        "quicCollectorActive": bool(packet.get("quicCollectorActive")),
        "correlation": packet.get("correlation"),
        "tcp": select("tcp", ("ipVersion", "observedTtl", "hopLimit", "window", "mss", "wscale", "ecn", "df", "synIpId",
                                "helloIpId", "tos", "trafficClass", "options", "ja4t", "tsHz", "handshakeRttMs")),
        "tlsClientHello": select("tlsClientHello", ("ja3", "ja4", "helloLength", "cipherCount", "extCount",
                                                    "alpn", "sni", "tls13Supported", "pqGroup", "keyShareGroups",
                                                    "echExtension", "alpsExtension", "pskPresent", "extOrder",
                                                    "certCompression", "hasGrease")),
        "http2": select("http2", ("fingerprint", "akamai", "settings", "windowUpdate", "priority", "pseudoOrder")),
        "quic": select("quic", ("quicVersion", "ja4q", "alpn", "transportParams", "paramOrder", "hasGreaseParam")),
    }


def request_record(headers, *, method: str, path: str, query: str, scheme: str, exclude=()) -> dict:
    header_rows = display_headers(headers, exclude=exclude)
    # The server receives the whole URL query. Show just the count by design;
    # some sites put authentication codes in either query names or values.
    try:
        query_fields = len(parse_qsl(query, keep_blank_values=True, max_num_fields=128))
    except ValueError:
        query_fields = None
    return {
        "method": method,
        "scheme": scheme,
        "path": path,
        "queryFieldCount": query_fields,
        "hasQuery": bool(query),
        "authHeadersPresent": any(name in headers for name in ("Authorization", "Proxy-Authorization")),
        "cookiePresent": "Cookie" in headers,
        "headers": header_rows,
    }


def inject_receipt(document: bytes, payload: dict) -> bytes:
    # The application/json element is still HTML raw text, not a trusted sink.
    data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    script = f'<script type="application/json" id="whoNavigationReceipt">{data}</script>\n'
    return document.replace(b"</body>", script.encode("ascii") + b"</body>", 1)


def add_arguments(parser) -> None:
    parser.add_argument("--visibility-origin", action="append", default=[], metavar="ORIGIN",
                        help="Allowed main site origins for cross-origin visibility samples (repeatable)")
    for key in ("ipv4", "ipv6", "h2", "h3"):
        parser.add_argument(f"--visibility-{key}-url", metavar="URL", help=f"Operator-owned {key} visibility sample URL")
    parser.add_argument("--visibility-storage-frame", metavar="URL", help="Operator-owned storage test frame URL")
    parser.add_argument("--visibility-storage-site", metavar="URL", help="Independent top-level site for the storage test")
    parser.add_argument("--visibility-turn-url", action="append", default=[], metavar="TURN_URL",
                        help="Your TURN URL(s); users enter short-lived credentials in the browser")


def _endpoint(value: str, suffix: str = "") -> str:
    origin = url_origin(value, configured=True)
    if not origin:
        raise ValueError("visibility endpoint requires HTTPS (HTTP allowed on loopback only)")
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment or (suffix and not parsed.path.endswith(suffix)):
        raise ValueError(f"visibility endpoint must have path ending in {suffix or 'a page'}, without query or fragment")
    return f"{origin}{parsed.path or '/'}"


@dataclass(frozen=True)
class Settings:
    origins: frozenset[str] = frozenset()
    routes: dict[str, str] = field(default_factory=dict)
    storage: dict[str, str] = field(default_factory=dict)
    turn_urls: tuple[str, ...] = ()

    @classmethod
    def from_args(cls, args) -> Settings:
        origins = set()
        for value in args.visibility_origin:
            clean = _endpoint(value)
            origin = url_origin(clean, configured=True)
            if clean != f"{origin}/":
                raise ValueError("--visibility-origin must be an origin, without a path")
            origins.add(origin)
        routes = {}
        for key in ("ipv4", "ipv6", "h2", "h3"):
            value = getattr(args, f"visibility_{key}_url")
            if value:
                routes[key] = _endpoint(value, "/api/who/visibility/sample")
        storage = {}
        if args.visibility_storage_frame or args.visibility_storage_site:
            if not (args.visibility_storage_frame and args.visibility_storage_site):
                raise ValueError("provide both visibility storage URLs")
            storage = {"frameURL": _endpoint(args.visibility_storage_frame),
                       "peerURL": _endpoint(args.visibility_storage_site)}
        turn_urls = tuple(args.visibility_turn_url)
        if len(turn_urls) > 4 or any(not re.fullmatch(r"turns?:(?:[a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?(?:\?transport=(?:udp|tcp))?", url) for url in turn_urls):
            raise ValueError("invalid --visibility-turn-url (do not include usernames or passwords)")
        return cls(frozenset(origins), routes, storage, turn_urls)

    def cors(self, origin: str) -> dict[str, str]:
        return {"Access-Control-Allow-Origin": origin, "Timing-Allow-Origin": origin,
                "Referrer-Policy": "no-referrer"} if origin in self.origins else {}

    def public(self, dns_enabled: bool) -> dict:
        return {"routes": self.routes, "dns": dns_enabled, "storage": self.storage, "turnUrls": self.turn_urls}


_EDGE_REQUEST_HEADERS = frozenset({
    "x-edge-peer-ip", "x-edge-peer-port", "x-edge-local-ip", "x-edge-local-port",
    "x-real-ip", "x-forwarded-for", "x-forwarded-proto", "x-http-version",
    "x-tls-protocol", "x-tls-cipher", "x-tls-curves", "x-tls-alpn", "x-tls-reused",
})
_PRIVATE_REQUEST_HEADERS = frozenset({"x-who-run-token", "x-who-active-probe"})
_ROOT = "/api/who/visibility/"


class View:
    def __init__(self, settings: Settings | None = None, dns=None) -> None:
        self.settings = settings or Settings()
        self.dns = dns
        self._history_slots = threading.BoundedSemaphore(4)

    def receipt(self, handler, parsed, *, kind: str) -> dict:
        trusted = handler._is_trusted_edge()
        wire_key = handler._observed_wire_key()
        meta, packet = handler._observed_connection()
        source = meta.get("source", "unknown")
        backend_peer = address(*handler.client_address[:2])
        edge_peer = address(*wire_key[:2]) if trusted and wire_key else None
        client_ip = handler._extract_client_ip()
        peer_source = "edge-reported" if trusted and client_ip != backend_peer["ip"] else source
        peer = address(client_ip, wire_key[1] if wire_key and wire_key[0] == client_ip else None)
        origin_peer_only = source == "origin-leg" and client_ip == (wire_key[0] if wire_key else handler._trusted_real_ip())
        if origin_peer_only or (source == "unknown" and peer_source != "edge-reported"):
            peer = address(None)
            peer_source = "unknown"
        peer["source"] = peer_source
        forwarded_scheme = handler._single_header("X-Forwarded-Proto") if trusted else None
        scheme = forwarded_scheme if forwarded_scheme in ("http", "https") else (
            "https" if meta.get("tlsProtocol") else "http" if source == "direct" else None
        )
        return {
            "ok": True, "kind": kind, "observedAtMs": round(time.time() * 1000),
            "request": request_record(handler.headers, method=handler.command, path=parsed.path,
                                      query=parsed.query, scheme=scheme,
                                      exclude=_PRIVATE_REQUEST_HEADERS | (_EDGE_REQUEST_HEADERS if trusted else frozenset())),
            "peer": peer, "edgePeer": edge_peer, "backendPeer": backend_peer,
            "connection": connection_record(meta, source=source, backend_protocol=handler.request_version),
            "wire": wire_record(packet),
            **({"settings": self.settings.public(self.dns is not None)} if kind == "navigation" else {}),
        }

    def handle_get(self, handler, path: str, parsed) -> bool:
        if not path.startswith(_ROOT):
            return False
        operation = path.removeprefix(_ROOT)
        if operation == "request":
            handler._send_json(self.receipt(handler, parsed, kind="probe"))
        elif operation == "sample":
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            challenge = query.get("challenge", "")
            if not CHALLENGE.fullmatch(challenge):
                handler._send_json({"ok": False, "error": "invalid_challenge"}, status=HTTPStatus.BAD_REQUEST)
                return True
            receipt = self.receipt(handler, parsed, kind="probe")
            meta = receipt["connection"]
            handler._send_json({"ok": True, "challenge": challenge, "peer": receipt["peer"],
                                "connection": {"source": meta["source"], "httpVersion": meta["httpVersion"],
                                               "alpn": meta["tlsAlpn"]}},
                               extra_headers=self.settings.cors(handler.headers.get("Origin", "")))
        elif operation == "bgp" and not handler._head_only:
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not self._history_slots.acquire(blocking=False):
                handler._send_json({"ok": False, "error": "history_busy"}, status=HTTPStatus.SERVICE_UNAVAILABLE)
                return True
            try:
                handler._send_json(egress_intel.fetch_route_history(query.get("prefix", "")))
            finally:
                self._history_slots.release()
        else:
            handler._send_json({"ok": False, "error": "not_found"}, status=HTTPStatus.NOT_FOUND)
        return True

    def handle_post(self, handler, path: str) -> bool:
        if not path.startswith(_ROOT):
            return False
        operation = path.removeprefix(_ROOT)
        if operation not in ("dns/start", "dns/result") or self.dns is None:
            handler.close_connection = True
            handler._send_json({"ok": False, "error": "dns_not_configured"}, status=HTTPStatus.NOT_FOUND)
            return True
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        site = handler.headers.get("Sec-Fetch-Site")
        if (not 0 < length <= 512 or site not in (None, "same-origin", "none") or
                handler.headers.get_content_type() != "application/json"):
            handler.close_connection = True
            handler._send_json({"ok": False, "error": "same_origin_json_required"}, status=HTTPStatus.BAD_REQUEST)
            return True
        before = handler.connection.gettimeout()
        try:
            handler.connection.settimeout(3)
            body = json.loads(handler.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("invalid JSON object")
        except (ValueError, OSError):
            handler.close_connection = True
            handler._send_json({"ok": False, "error": "invalid_body"}, status=HTTPStatus.BAD_REQUEST)
            return True
        finally:
            handler.connection.settimeout(before)
        if operation == "dns/start":
            try:
                handler._send_json({"ok": True, **self.dns.issue()})
            except visibility_dns.CapacityError:
                handler._send_json({"ok": False, "error": "dns_busy"}, status=HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            token = body.get("token")
            result = self.dns.lookup(token) if isinstance(token, str) else None
            if result is None:
                handler._send_json({"ok": False, "error": "dns_session_not_found"}, status=HTTPStatus.NOT_FOUND)
            else:
                handler._send_json({"ok": True, **result})
        return True
