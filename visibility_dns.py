"""Opt-in, non-recursive authority for a dedicated visibility measurement zone.

The DNS name is public; only the independently generated handle can read a
trial. Observations are in memory, local to this process, and never echoed in
DNS. The parent must delegate the zone to an independently resolvable NS
pointing to this listener (UDP and TCP port 53).
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import secrets
import selectors
import socket
import struct
import threading
import time
from collections import OrderedDict
from contextlib import ExitStack
from dataclasses import dataclass, field

_HEADER = struct.Struct("!6H")
_PAIR = struct.Struct("!2H")
_RR = struct.Struct("!2HIH")
_U16 = struct.Struct("!H")
_SOA_FIELDS = struct.pack("!5I", 1, 3600, 600, 86400, 0)
_LABEL = re.compile(rb"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_HANDLE = re.compile(r"[a-zA-Z0-9_-]{43}")
_PUBLIC_LABEL_BYTES = 16

_QR, _OPCODE, _AA, _TC, _RD, _Z, _CD, _RCODE = 0x8000, 0x7800, 0x0400, 0x0200, 0x0100, 0x0040, 0x0010, 0x000f
_FORMERR, _NXDOMAIN, _NOTIMP, _REFUSED, _BADVERS = 1, 3, 4, 5, 16
_IN, _A, _NS, _CNAME, _SOA, _AAAA, _OPT = 1, 1, 2, 5, 6, 28, 41
_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 257: "CAA",
}
_MAX_QUERY = 1232
_MAX_UDP_REPLY = 512
_MAX_UDP_AMPLIFICATION = 4
_MAX_TRIALS = 1024
_MAX_OBSERVATIONS = 16
_MAX_TCP_CLIENTS = 32
_MAX_TCP_REQUESTS = 32
_TCP_TIMEOUT = 3.0
_POLL = 0.2
_APEX_TTL = 60


class CapacityError(RuntimeError):
    """No new trial can be issued until an existing one expires."""


@dataclass(slots=True)
class _Question:
    name: str
    wire: bytes
    qtype: int
    qclass: int
    edns_version: int | None = None
    dnssec_ok: bool = False
    ecs_network: str | None = None


@dataclass(slots=True)
class _Trial:
    host: str
    expires_at: float
    observations: list[tuple[str, int, str | None]] = field(default_factory=list)


@dataclass(slots=True)
class _TCPPeer:
    sock: socket.socket
    ip: str
    deadline: float
    wanted: int = 2
    reading_length: bool = True
    request: bytearray = field(default_factory=bytearray)
    reply: bytes = b""
    completed: int = 0


def _ecs_network(payload: bytes) -> str | None:
    if len(payload) < 4:
        raise ValueError("short ECS option")
    family, source, scope = struct.unpack_from("!HBB", payload)
    if scope:
        raise ValueError("nonzero ECS query scope")
    if family == 1:
        size, privacy_prefix, network = 4, 24, ipaddress.IPv4Network
    elif family == 2:
        size, privacy_prefix, network = 16, 56, ipaddress.IPv6Network
    else:
        return None
    used = (source + 7) // 8
    if source > 8 * size or len(payload) != 4 + used:
        raise ValueError("invalid ECS prefix length")
    if source % 8 and payload[-1] & (0xff >> (source % 8)):
        raise ValueError("nonzero ECS padding bits")
    address = payload[4:].ljust(size, b"\x00")
    # Never retain a full client address or IPv6 interface identifier from ECS.
    return str(network((address, min(source, privacy_prefix)), strict=False))


def _valid_label(label: bytes, *, service: bool = False) -> bool:
    return len(label) <= 63 and _LABEL.fullmatch(label.removeprefix(b"_") if service else label) is not None


def _read_question(packet: bytes, additional: int) -> _Question:
    pos = _HEADER.size
    labels = []
    while True:
        if pos >= len(packet) or pos - _HEADER.size >= 255:
            raise ValueError("invalid QNAME length")
        length = packet[pos]
        pos += 1
        if not length:
            break
        # There is no earlier name to which the first, sole QNAME could point.
        label = packet[pos : pos + length]
        if len(label) != length or not _valid_label(label, service=True):
            raise ValueError("invalid QNAME label")
        labels.append(label.lower())
        pos += length
    if pos + _PAIR.size > len(packet):
        raise ValueError("short question")
    qtype, qclass = _PAIR.unpack_from(packet, pos)
    if not qtype or not qclass:
        raise ValueError("reserved question type or class")
    pos += _PAIR.size
    question = _Question(b".".join(labels).decode("ascii"), packet[_HEADER.size : pos], qtype, qclass)
    if not additional:
        if pos != len(packet):
            raise ValueError("trailing data")
        return question

    if len(packet) - pos < 1 + _RR.size or packet[pos] != 0:
        raise ValueError("invalid OPT owner or length")
    rrtype, _, ttl, size = _RR.unpack_from(packet, pos + 1)
    pos += 1 + _RR.size
    if rrtype != _OPT or ttl >> 24 or len(packet) - pos != size:
        raise ValueError("invalid OPT record")
    question.edns_version = (ttl >> 16) & 0xff
    question.dnssec_ok = bool(ttl & 0x8000)
    if question.edns_version:
        return question

    seen_ecs = False
    while pos < len(packet):
        if len(packet) - pos < _PAIR.size:
            raise ValueError("short EDNS option header")
        code, size = _PAIR.unpack_from(packet, pos)
        pos += _PAIR.size
        if len(packet) - pos < size:
            raise ValueError("short EDNS option data")
        if code == 8:
            if seen_ecs:
                raise ValueError("duplicate ECS option")
            seen_ecs = True
            question.ecs_network = _ecs_network(packet[pos : pos + size])
        pos += size
    return question


def _wire_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def _pointer(offset: int) -> bytes:
    return _U16.pack(0xc000 | offset)


def _record(owner: bytes, rrtype: int, ttl: int, data: bytes) -> bytes:
    return owner + _RR.pack(rrtype, _IN, ttl, len(data)) + data


def _message(txid: int, query_flags: int, question: _Question | None = None, *,
             rcode: int = 0, aa: bool = False, answer: bytes = b"", authority: bytes = b"",
             tcp: bool = False) -> bytes:
    flags = _QR | (query_flags & (_OPCODE | _RD | _CD)) | (rcode & _RCODE)
    if aa:
        flags |= _AA
    wire = question.wire if question else b""
    opt = b""
    if question and question.edns_version is not None:
        ttl = ((rcode >> 4) << 24) | (0x8000 if question.dnssec_ok else 0)
        opt = b"\x00" + _RR.pack(_OPT, _MAX_QUERY, ttl, 0)
    base_size = _HEADER.size + len(wire)
    udp_cap = min(_MAX_UDP_REPLY, _MAX_UDP_AMPLIFICATION * base_size)
    if not tcp and base_size + len(answer) + len(authority) + len(opt) > udp_cap:
        flags |= _TC
        answer = authority = b""
    return (_HEADER.pack(txid, flags, int(bool(wire)), int(bool(answer)), int(bool(authority)), int(bool(opt)))
            + wire + answer + authority + opt)


class VisibilityDNS:
    """A bounded in-memory trial cache and one UDP/TCP authority listener."""

    def __init__(self, bind: str, port: int, zone: str, ns: str, addresses: dict[int, bytes], window: int,
                 acme_cname: str | None = None):
        self._zone = zone
        self._suffix = "." + zone
        self._ns_wire = _wire_name(ns)
        self._acme_name = "_acme-challenge" + self._suffix
        self._acme_wire = _wire_name(acme_cname) if acme_cname else None
        self._addresses = addresses
        self._window = window
        self._trials: OrderedDict[str, _Trial] = OrderedDict()
        self._by_host: dict[str, _Trial] = {}
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._peers: dict[socket.socket, _TCPPeer] = {}

        family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        with ExitStack() as setup:
            self._selector = setup.enter_context(selectors.DefaultSelector())
            self._tcp = setup.enter_context(socket.socket(family, socket.SOCK_STREAM))
            self._udp = setup.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            for sock in (self._tcp, self._udp):
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.setblocking(False)
            self._tcp.bind((bind, port))
            self.address = self._tcp.getsockname()[:2]
            self._udp.bind(self.address)
            self._tcp.listen(_MAX_TCP_CLIENTS)
            self._selector.register(self._udp, selectors.EVENT_READ)
            self._selector.register(self._tcp, selectors.EVENT_READ)
            self._thread = threading.Thread(target=self._serve, name="visibility-dns", daemon=True)
            self._thread.start()
            setup.pop_all()

    def _expire(self, now: float) -> None:
        # All trials share one window and are inserted in expiration order.
        while self._trials:
            first = self._trials[next(iter(self._trials))]
            if first.expires_at > now:
                break
            self._trials.popitem(last=False)
            del self._by_host[first.host]

    def issue(self) -> dict:
        """Issue a fresh public host and unrelated private report handle."""
        with self._lock:
            if self._stopped.is_set():
                raise RuntimeError("visibility DNS listener is closed")
            now = time.monotonic()
            self._expire(now)
            if len(self._trials) >= _MAX_TRIALS:
                raise CapacityError("visibility DNS trial capacity exhausted")
            token = secrets.token_urlsafe(32)
            while token in self._trials:
                token = secrets.token_urlsafe(32)
            host = f"{secrets.token_hex(_PUBLIC_LABEL_BYTES)}{self._suffix}"
            while host in self._by_host:
                host = f"{secrets.token_hex(_PUBLIC_LABEL_BYTES)}{self._suffix}"
            trial = _Trial(host, now + self._window)
            self._trials[token] = self._by_host[host] = trial
            return {"token": token, "host": host, "expiresIn": self._window}

    def lookup(self, token: str) -> dict | None:
        """Snapshot observations for a live, valid private handle only."""
        if not isinstance(token, str) or not _HANDLE.fullmatch(token):
            return None
        with self._lock:
            if self._stopped.is_set():
                return None
            self._expire(time.monotonic())
            trial = self._trials.get(token)
            if trial is None:
                return None
            return {"observations": [
                {"resolverIp": ip, "qtype": _QTYPE_NAMES.get(qtype, f"TYPE{qtype}"), "ecsNetwork": ecs}
                for ip, qtype, ecs in trial.observations
            ]}

    def close(self) -> None:
        """Stop both transports, close active connections, and discard trials."""
        self._stopped.set()
        self._thread.join()

    def _soa(self, owner: bytes, ttl: int) -> bytes:
        return _record(owner, _SOA, ttl, self._ns_wire + b"\x0ahostmaster" + owner + _SOA_FIELDS)

    def _answer(self, packet: bytes, ip: str, *, tcp: bool = False) -> bytes | None:
        if not _HEADER.size <= len(packet) <= _MAX_QUERY:
            return None
        txid, flags, qd, an, ns, ar = _HEADER.unpack_from(packet)
        if flags & _QR:
            return None
        if flags & _OPCODE:
            return _message(txid, flags, rcode=_NOTIMP)
        if qd != 1 or an or ns or ar > 1 or flags & (_TC | _Z | _RCODE):
            return _message(txid, flags, rcode=_FORMERR)
        try:
            question = _read_question(packet, ar)
        except ValueError:
            return _message(txid, flags, rcode=_FORMERR)
        if question.edns_version not in (None, 0):
            return _message(txid, flags, question, rcode=_BADVERS)
        qtype, name = question.qtype, question.name
        # No transfers, ANY, or meta-queries, and no answers outside this zone.
        if (question.qclass != _IN or qtype in (_OPT, 65535) or 249 <= qtype <= 255
                or (name != self._zone and not name.endswith(self._suffix))):
            return _message(txid, flags, question, rcode=_REFUSED)

        # Each dotted prefix character corresponds to one wire byte (a dot to a label length).
        owner = _pointer(_HEADER.size + len(name) - len(self._zone))
        answer = authority = b""
        rcode = 0
        if name == self._zone:
            if qtype == _NS:
                answer = _record(owner, _NS, _APEX_TTL, self._ns_wire)
            elif qtype == _SOA:
                answer = self._soa(owner, _APEX_TTL)
        elif self._acme_wire and name == self._acme_name:
            answer = _record(_pointer(_HEADER.size), _CNAME, _APEX_TTL, self._acme_wire)
        else:
            with self._lock:
                self._expire(time.monotonic())
                trial = self._by_host.get(name)
                if trial is not None and len(trial.observations) < _MAX_OBSERVATIONS:
                    observation = (ip, qtype, question.ecs_network)
                    if observation not in trial.observations:
                        trial.observations.append(observation)
            if trial is None:
                rcode = _NXDOMAIN
            elif qtype in self._addresses:
                answer = _record(_pointer(_HEADER.size), qtype, 0, self._addresses[qtype])
        if not answer:
            authority = self._soa(owner, 0)
        return _message(txid, flags, question, rcode=rcode, aa=True, answer=answer, authority=authority, tcp=tcp)

    def _serve_udp(self) -> None:
        try:
            packet, address = self._udp.recvfrom(_MAX_QUERY + 1)
        except BlockingIOError:
            return
        answer = self._answer(packet, address[0])
        if answer is not None:
            try:
                self._udp.sendto(answer, address)
            except OSError:
                # Datagram send can fail due to a peer route or a full network buffer.
                pass

    def _accept(self) -> None:
        try:
            sock, address = self._tcp.accept()
        except (BlockingIOError, ConnectionAbortedError):
            return
        if len(self._peers) >= _MAX_TCP_CLIENTS:
            sock.close()
            return
        sock.setblocking(False)
        peer = _TCPPeer(sock, address[0], time.monotonic() + _TCP_TIMEOUT)
        self._peers[sock] = peer
        self._selector.register(sock, selectors.EVENT_READ, peer)

    def _drop(self, peer: _TCPPeer) -> None:
        self._selector.unregister(peer.sock)
        del self._peers[peer.sock]
        peer.sock.close()

    def _serve_tcp(self, peer: _TCPPeer, mask: int) -> None:
        if peer.deadline <= time.monotonic():
            self._drop(peer)
            return
        try:
            if mask == selectors.EVENT_WRITE:
                sent = peer.sock.send(peer.reply)
                if not sent:
                    self._drop(peer)
                    return
                peer.reply = peer.reply[sent:]
                if peer.reply:
                    return
                peer.completed += 1
                if peer.completed >= _MAX_TCP_REQUESTS:
                    self._drop(peer)
                    return
                peer.wanted = 2
                peer.reading_length = True
                peer.deadline = time.monotonic() + _TCP_TIMEOUT
                self._selector.modify(peer.sock, selectors.EVENT_READ, peer)
                return

            data = peer.sock.recv(peer.wanted - len(peer.request))
            if not data:
                self._drop(peer)
                return
            peer.request.extend(data)
            if len(peer.request) != peer.wanted:
                return
            if peer.reading_length:
                peer.wanted = _U16.unpack(peer.request)[0]
                if not _HEADER.size <= peer.wanted <= _MAX_QUERY:
                    self._drop(peer)
                    return
                peer.reading_length = False
                peer.request.clear()
                return
            answer = self._answer(bytes(peer.request), peer.ip, tcp=True)
            peer.request.clear()
            if answer is None:
                self._drop(peer)
                return
            peer.reply = _U16.pack(len(answer)) + answer
            self._selector.modify(peer.sock, selectors.EVENT_WRITE, peer)
        except BlockingIOError:
            return
        except OSError:
            self._drop(peer)

    def _serve(self) -> None:
        try:
            while not self._stopped.is_set():
                for key, mask in self._selector.select(_POLL):
                    if key.fileobj is self._udp:
                        self._serve_udp()
                    elif key.fileobj is self._tcp:
                        self._accept()
                    else:
                        self._serve_tcp(key.data, mask)
                now = time.monotonic()
                for peer in tuple(self._peers.values()):
                    if peer.deadline <= now:
                        self._drop(peer)
                with self._lock:
                    self._expire(now)
        finally:
            self._stopped.set()
            for peer in self._peers.values():
                peer.sock.close()
            self._peers.clear()
            self._selector.close()
            self._udp.close()
            self._tcp.close()
            with self._lock:
                self._trials.clear()
                self._by_host.clear()


def add_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("可选可见性权威 DNS")
    group.add_argument("--visibility-dns-zone", metavar="DOMAIN", help="启用监听，指定单独真实委派的测量子域")
    group.add_argument("--visibility-dns-bind", metavar="IP", help="权威 DNS 监听 IP（默认 127.0.0.1）")
    group.add_argument("--visibility-dns-port", type=int, metavar="PORT", help="UDP 和 TCP 监听端口（默认 53）")
    group.add_argument("--visibility-dns-ns", metavar="NAME", help="须配合 --visibility-dns-zone 指定区外 NS 主机名")
    group.add_argument("--visibility-dns-a", metavar="IPV4", help="测量 HTTPS 入口 IPv4（A 和 AAAA 至少配一项）")
    group.add_argument("--visibility-dns-aaaa", metavar="IPV6", help="测量 HTTPS 入口 IPv6")
    group.add_argument("--visibility-dns-window", type=int, metavar="SECONDS", help="测量有效期 1–300 秒（默认 60）")
    group.add_argument("--visibility-dns-acme-cname", metavar="NAME", help="可选，将 _acme-challenge 指向区外 DNS-01 验证名")


def _domain_arg(value: str | None, option: str, *, service: bool = False) -> str:
    try:
        name = (value or "").removesuffix(".").encode("ascii")
    except UnicodeError:
        raise ValueError(f"{option} requires an ASCII DNS hostname") from None
    if len(name) > 253 or not all(_valid_label(label, service=service) for label in name.split(b".")):
        raise ValueError(f"{option} requires a valid DNS hostname")
    return name.decode("ascii").lower()


def _ip_arg(value: str, option: str, version: int | None = None) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"{option} requires a literal IP address") from None
    if (version and address.version != version) or (address.version == 6 and address.scope_id is not None):
        raise ValueError(f"{option} requires an unscoped literal IPv{version or 6} address")
    return address


def start_from_args(args: argparse.Namespace) -> VisibilityDNS | None:
    """Create both listeners, or no listener if the DNS options are absent."""
    zone, bind, port, ns, a, aaaa, window, acme_cname = (
        getattr(args, f"visibility_dns_{key}")
        for key in ("zone", "bind", "port", "ns", "a", "aaaa", "window", "acme_cname")
    )
    if zone is None:
        if any(value is not None for value in (bind, port, ns, a, aaaa, window, acme_cname)):
            raise ValueError("--visibility-dns-zone is required with other --visibility-dns-* options")
        return None
    zone = _domain_arg(zone, "--visibility-dns-zone")
    if "." not in zone or len(zone) + 2 * _PUBLIC_LABEL_BYTES + 1 > 253:
        raise ValueError("--visibility-dns-zone requires a subdomain with room for the measurement label")
    ns = _domain_arg(ns, "--visibility-dns-ns")
    if ns == zone or ns.endswith("." + zone):
        raise ValueError("--visibility-dns-ns must resolve independently outside the measurement zone")
    if acme_cname is not None:
        acme_cname = _domain_arg(acme_cname, "--visibility-dns-acme-cname", service=True)
        if acme_cname == zone or acme_cname.endswith("." + zone):
            raise ValueError("--visibility-dns-acme-cname must be outside the measurement zone")
    bind = str(_ip_arg("127.0.0.1" if bind is None else bind, "--visibility-dns-bind"))
    port = 53 if port is None else port
    if not 0 <= port <= 65535:
        raise ValueError("--visibility-dns-port must be between 0 and 65535")
    window = 60 if window is None else window
    if not 1 <= window <= 300:
        raise ValueError("--visibility-dns-window must be between 1 and 300 seconds")
    addresses = {}
    if a is not None:
        addresses[_A] = _ip_arg(a, "--visibility-dns-a", 4).packed
    if aaaa is not None:
        addresses[_AAAA] = _ip_arg(aaaa, "--visibility-dns-aaaa", 6).packed
    if not addresses:
        raise ValueError("configure at least one of --visibility-dns-a and --visibility-dns-aaaa")
    return VisibilityDNS(bind, port, zone, ns, addresses, window, acme_cname)
