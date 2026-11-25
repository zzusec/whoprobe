"""Offline Ethernet/TCP/TLS and proxy fixtures; no packet socket or network access."""
from __future__ import annotations

from email.message import Message
import ipaddress
import socket
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import probe


V4 = ("198.51.100.1", 50100, "203.0.113.10", 443)
V6 = ("2001:db8::1", 50100, "2001:db8::10", 443)
RUN = "0123456789abcdef" * 2


def client_hello(tag: int, ext_order: tuple[int, ...] = (21, 49, 50, 18, 23)) -> bytes:
    extensions = b"".join(struct.pack("!HH", ext_type, 0) for ext_type in ext_order)
    body = b"\x03\x03" + bytes([tag]) * 32 + b"\0\x00\x02\x13\x01\x01\0"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def frame(
    key=V4, *, seq=50, syn=True, mss=None, limit=57, traffic=0xA3, ip_id=42,
    tcp_options=None, ip_options=b"", v4_frag=0x4000, v6_ext=b"", next_header=6, payload=b"",
):
    source, sport, destination, dport = key
    peer, local = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if tcp_options is None:
        mss = mss or (1460 if peer.version == 4 else 1440)
        tcp_options = struct.pack("!BBH", 2, 4, mss) + b"\x01\x03\x03\x07" if syn else b""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, (5 + len(tcp_options) // 4) << 4,
                      0xC2 if syn else 0x18, 65535, 0, 0) + tcp_options + payload
    if peer.version == 4:
        ip = struct.pack("!BBHHHBBH", 0x45 + len(ip_options) // 4, traffic, 20 + len(ip_options) + len(tcp),
                         ip_id, v4_frag, limit, next_header, 0) + peer.packed + local.packed + ip_options
        return b"\0" * 12 + b"\x08\x00" + ip + tcp
    ip = struct.pack("!IHBB", (6 << 28) | (traffic << 20), len(v6_ext) + len(tcp), next_header, limit)
    return b"\0" * 12 + b"\x86\xdd" + ip + peer.packed + local.packed + v6_ext + tcp


def edge_headers(key):
    return list(zip(probe.EDGE_WIRE_HEADERS, map(str, key)))


def handler(headers=(), *, peer=("127.0.0.1", 50234), local=("127.0.0.1", 8899)):
    h = probe.WhoProbeHandler.__new__(probe.WhoProbeHandler)
    h.headers = Message()
    for name, value in headers:
        h.headers[name] = value
    h.client_address = peer
    h.connection = SimpleNamespace(getsockname=lambda: local)
    h.server = SimpleNamespace()
    h.request_version = "HTTP/1.1"
    h._send_json = Mock()
    return h


def route(h, path):
    h.path = path
    h.do_GET()
    return h._send_json.call_args.args[0]


def bpf_snaplen(raw: bytes) -> int:
    """Execute only the classic BPF opcodes used by this filter, without AF_PACKET."""
    code = probe.LinuxPacketSniffer._bpf_instructions(443)
    a = x = pc = 0
    mem = [0] * 16
    for _ in code:  # all jumps are forward
        op, jt, jf, k = code[pc]
        pc += 1
        if op in (0x28, 0x30, 0x48, 0x50, 0xB1):
            width = 2 if op in (0x28, 0x48) else 1
            start = x + k if op in (0x48, 0x50) else k
            if start + width > len(raw):
                return 0
            value = int.from_bytes(raw[start:start + width], "big")
            if op == 0xB1:
                x = (value & 15) * 4
            else:
                a = value
        elif op == 0x15:
            pc += jt if a == k else jf
        elif op == 0x45:
            pc += jt if a & k else jf
        elif op == 0x05:
            pc += k
        elif op == 0x06:
            return k
        elif op == 0x01:
            x = k
        elif op == 0x00:
            a = k
        elif op == 0x02:
            mem[k] = a
        elif op == 0x60:
            a = mem[k]
        elif op == 0x04:
            a += k
        elif op == 0x0C:
            a += x
        elif op == 0x07:
            x = a
        elif op == 0x54:
            a &= k
        elif op == 0x64:
            a <<= k
        elif op == 0x74:
            a >>= k
        else:
            raise AssertionError(f"Unexpected cBPF opcode: {op:#x}")
    raise AssertionError("BPF filter did not terminate")


class MemoryProxySocket:
    def __init__(self, data, first_peek=None):
        self.data = data
        self.timeout = 8.0
        self.first_peek = first_peek

    def recv(self, count, flags=0):
        if flags == socket.MSG_PEEK:
            if self.first_peek is not None:
                count = min(count, self.first_peek)
                self.first_peek = None
            return self.data[:count]
        result, self.data = self.data[:count], self.data[count:]
        return result

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        pass

    def getsockname(self):
        return "127.0.0.1", 18449


class WireFixtures(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(probe, "PACKET_CACHE", probe.TTLCache(maxsize=64, ttl_sec=180)).start()
        patch.object(probe, "TLS_PERM_CACHE", probe.TTLCache(maxsize=64, ttl_sec=180)).start()
        patch.object(probe, "TRUSTED_EDGES", probe.DEFAULT_TRUSTED_EDGES).start()
        patch.object(probe, "ENABLE_ACTIVE_443", False).start()
        self.sniffer = probe.LinuxPacketSniffer("unused-fixture-interface")
        self.now = time.monotonic()

    def ingest(self, raw, ms=0):
        self.sniffer.ingest_frame(raw, self.now + ms / 1000)

    def capture(self, key, tag=1, ext_order=(21, 49, 50, 18, 23)):
        self.ingest(frame(key, seq=50))
        self.ingest(frame(key, seq=51, syn=False, payload=client_hello(tag, ext_order)), 35)

    def test_ipv4_and_ipv6_fingerprints(self):
        self.ingest(frame(V4, limit=116, ip_options=b"\x01\x01\x01\x01"))
        self.ingest(frame(V4, seq=51, syn=False, payload=client_hello(1), ip_id=43, limit=116), 23)
        hb_to_dest_to_tcp = b"\x3c\0" + b"\0" * 6 + b"\x06\0" + b"\0" * 6
        self.ingest(frame(V6, next_header=0, v6_ext=hb_to_dest_to_tcp))
        self.ingest(frame(V6, seq=51, syn=False, next_header=0, v6_ext=hb_to_dest_to_tcp,
                          payload=client_hello(2)), 37)
        _, ipv4 = handler(edge_headers(V4))._observed_connection()
        _, ipv6 = handler(edge_headers(("2001:0DB8:0000::1", 50100, "2001:0DB8::10", 443)))._observed_connection()
        v4 = ipv4["tcp"]
        self.assertEqual((v4["ipVersion"], v4["observedTtl"], v4["tos"], v4["mtu"]), (4, 116, 0xA3, 1500))
        self.assertEqual((v4["df"], v4["synIpId"], v4["helloIpId"]), (True, 42, 43))
        self.assertEqual(v4["handshakeRttMs"], 23.0)
        v6 = ipv6["tcp"]
        self.assertEqual((v6["ipVersion"], v6["hopLimit"], v6["trafficClass"], v6["mtu"]), (6, 57, 0xA3, 1500))
        self.assertEqual((v6["initialHopLimit"], v6["mss"], v6["tunnelGuess"]), (64, 1440, "ethernet"))
        self.assertEqual(v6["ja4t"], "65535_2-1-3_1440_7")
        self.assertNotIn("df", v6)
        self.assertNotIn("synIpId", v6)
        self.assertNotIn("helloIpId", v6)
        self.assertNotIn("tos", v6)
        self.assertEqual(ipv6["tlsClientHello"]["helloId"], "02" * 12)

    def test_bpf_accepts_existing_capture_budget_and_filters(self):
        ext = b"\x2c\0" + b"\0" * 6 + b"\x33\0" + b"\0" * 6 + b"\x06\x01" + b"\0" * 10
        for raw in (frame(), frame(V6), frame(V6, next_header=0, v6_ext=ext),
                    frame(V6, next_header=0, v6_ext=ext, payload=client_hello(1), syn=False)):
            with self.subTest(raw=raw[:32]):
                self.assertEqual(bpf_snaplen(raw), 4096)
                self.assertIsNotNone(probe._parse_tcp_frame(raw, 443))
        for raw in (frame(v4_frag=0x2000), frame(v4_frag=1), frame(V6, next_header=44, v6_ext=b"\x06\0\0\x01" + b"\0" * 4),
                    frame(V6, next_header=44, v6_ext=b"\x06\0\0\x08" + b"\0" * 4), frame(V6, next_header=50),
                    frame((*V6[:3], 8443)), frame(V6, syn=False), frame(V6, syn=False, payload=b"\x17\x03\x03\0\x01\0")):
            self.assertEqual(bpf_snaplen(raw), 0)
        chain = (b"\x3c\0" + b"\0" * 6) * 4 + b"\x06\0" + b"\0" * 6
        excessive = frame(V6, next_header=60, v6_ext=chain)
        self.assertEqual(bpf_snaplen(excessive), 0)
        self.assertIsNone(probe._parse_tcp_frame(excessive, 443))
        # The final encoded jump offsets also have to fit the kernel's unsigned fields.
        for insn in probe.LinuxPacketSniffer._bpf_instructions(443):
            struct.pack("HBBI", *insn)

    def test_bounds_use_declared_ip_and_tcp_lengths(self):
        for raw in (frame(), frame(V6), frame(V6, next_header=60, v6_ext=b"\x06\0" + b"\0" * 6)):
            for end in range(len(raw)):
                self.assertIsNone(probe._parse_tcp_frame(raw[:end], 443), end)
        ipv4 = bytearray(frame())
        struct.pack_into("!H", ipv4, 16, 25)  # capture contains TCP bytes outside declared IP length
        self.assertIsNone(probe._parse_tcp_frame(ipv4, 443))
        ipv6 = bytearray(frame(V6))
        struct.pack_into("!H", ipv6, 18, 0)  # not a supported jumbogram
        self.assertIsNone(probe._parse_tcp_frame(ipv6, 443))
        ip6_bad_len = frame(V6, next_header=60, v6_ext=b"\x06\xff" + b"\0" * 6)
        self.assertIsNone(probe._parse_tcp_frame(ip6_bad_len, 443))
        for raw in (frame(v4_frag=0x2000), frame(V6, next_header=44, v6_ext=b"\x06\0\0\x01" + b"\0" * 4)):
            self.assertIsNone(probe._parse_tcp_frame(raw, 443))
        complete_tls = client_hello(5)
        self.assertIsNone(probe.parse_tls_client_hello(complete_tls[:-1]))
        bad_extension_length = bytearray(complete_tls)
        struct.pack_into("!H", bad_extension_length, len(bad_extension_length) - 2, 200)
        self.assertIsNone(probe.parse_tls_client_hello(bytes(bad_extension_length)))

    def test_no_same_ip_or_source_port_crossover_with_tls_segments(self):
        port_two = (V4[0], V4[1] + 1, *V4[2:])
        dest_two = (*V4[:2], "203.0.113.11", 443)
        miss = (*V4[:3], 444)
        hello_a, hello_b = client_hello(1), client_hello(2)
        self.ingest(frame(V4, seq=0xFFFFFFFF, limit=59))
        self.ingest(frame(dest_two, seq=0xFFFFFFFF, limit=111))
        self.ingest(frame(port_two, seq=0xFFFFFFFF, limit=121))
        split = 13
        self.ingest(frame(V4, seq=0, syn=False, payload=hello_a[:split]), 20)
        self.ingest(frame(dest_two, seq=0, syn=False, payload=hello_b[:split]), 21)
        self.ingest(frame(V4, seq=split + 5, syn=False, payload=hello_b[split:]), 22)
        self.assertIsNone(handler(edge_headers(V4))._observed_connection()[1]["tlsClientHello"])
        self.ingest(frame(V4, seq=split, syn=False, payload=hello_a[split:]), 24)
        self.ingest(frame(dest_two, seq=split, syn=False, payload=hello_b[split:]), 25)
        a, b, c, missing = [handler(edge_headers(k))._observed_connection()[1] for k in (V4, dest_two, port_two, miss)]
        self.assertEqual((a["tlsClientHello"]["helloId"], b["tlsClientHello"]["helloId"]), ("01" * 12, "02" * 12))
        self.assertEqual((a["tcp"]["observedTtl"], b["tcp"]["observedTtl"], c["tcp"]["observedTtl"]), (59, 111, 121))
        self.assertIsNone(c["tlsClientHello"])
        self.assertIsNone(missing["tcp"])
        self.assertEqual((a["tcp"]["handshakeRttMs"], b["tcp"]["handshakeRttMs"]), (20, 21))

    def test_snap_truncation_cannot_be_glued_to_later_segment(self):
        hello = client_hello(1)
        self.ingest(frame(V6))
        part = frame(V6, seq=51, syn=False, payload=hello[:20])
        self.ingest(part[:-8], 10)
        self.ingest(frame(V6, seq=63, syn=False, payload=hello[12:]), 20)
        self.assertIsNone(handler(edge_headers(V6))._observed_connection()[1]["tlsClientHello"])
        self.ingest(frame(V6, seq=51, syn=False, payload=hello), 30)
        self.assertEqual(handler(edge_headers(V6))._observed_connection()[1]["tlsClientHello"]["helloId"], "01" * 12)

    def test_syn_retransmission_keeps_first_fingerprint_without_rtt(self):
        hello = client_hello(3)
        self.ingest(frame(V4, seq=51, syn=False, payload=hello))
        self.assertIsNone(handler(edge_headers(V4))._observed_connection()[1]["tlsClientHello"])
        self.ingest(frame(V4, limit=58), 10)
        self.ingest(frame(V4, limit=63), 20)
        self.ingest(frame(V4, seq=51, syn=False, payload=hello), 30)
        _, packet = handler(edge_headers(V4))._observed_connection()
        self.assertEqual(packet["tcp"]["observedTtl"], 58)
        self.assertIsNone(packet["tcp"]["handshakeRttMs"])
        self.assertEqual(packet["tlsClientHello"]["helloId"], "03" * 12)

    def test_direct_ignores_forwarded_protocol_ip_and_tuple(self):
        self.capture(V4)
        fake = edge_headers(V4) + [("X-Real-IP", "104.16.2.3"), ("CF-Connecting-IP", "1.1.1.1"),
                                   ("X-Forwarded-Proto", "https"), ("X-HTTP-Version", "HTTP/3.0"),
                                   ("X-TLS-Protocol", "TLSv1.3"), ("X-TLS-ALPN", "h3")]
        own_peer = (V4[0], V4[1] + 1)
        h = handler(fake, peer=own_peer, local=V4[2:])
        self.assertFalse(h._is_trusted_edge())
        self.assertEqual(h._observed_wire_key(), (*own_peer, *V4[2:]))
        self.assertEqual(h._extract_client_ip(), V4[0])
        self.assertTrue(h._origin_and_base(False)[0].startswith("http://"))
        metadata, packet = h._observed_connection()
        self.assertEqual((metadata["source"], metadata["httpVersion"], metadata["tlsProtocol"]), ("direct", "HTTP/1.1", ""))
        self.assertIsNone(packet["tcp"])
        self.assertIsNone(packet["tlsClientHello"])
        self.ingest(frame((*own_peer, *V4[2:]), limit=125))
        self.assertEqual(h._observed_connection()[1]["tcp"]["observedTtl"], 125)

    def test_trusted_peer_requires_a_single_valid_complete_tuple(self):
        self.capture(V4)
        hdrs = [("X-Real-IP", V4[0]), ("X-HTTP-Version", "HTTP/2.0"), ("X-TLS-Protocol", "TLSv1.3")]
        complete = handler(hdrs + edge_headers(V4), peer=("::ffff:127.0.0.5", 50111, 0, 0))
        self.assertEqual(complete._observed_wire_key(), V4)
        conn, pkt = complete._observed_connection()
        self.assertEqual((conn["source"], conn["httpVersion"], conn["tlsProtocol"]), ("trusted-edge", "HTTP/2.0", "TLSv1.3"))
        self.assertIsNotNone(pkt["tlsClientHello"])
        for wire in ([], edge_headers(V4)[:-1], edge_headers(V4) + [("X-Edge-Peer-Port", "50101")],
                     edge_headers((V4[0], "+50100", *V4[2:])), edge_headers((*V4[:3], 0)),
                     edge_headers((*V4[:2], V6[2], 443)), edge_headers((*V4[:2], "0.0.0.0", 443))):
            h = handler(hdrs + wire)
            self.assertTrue(h._is_trusted_edge())
            self.assertIsNone(h._observed_wire_key())
            meta, packet = h._observed_connection()
            self.assertEqual((meta["source"], meta["httpVersion"], meta["tlsProtocol"]), ("unknown", "", ""))
            self.assertIsNone(packet["tlsClientHello"])
        self.assertFalse(handler(edge_headers(V4), peer=("10.0.0.1", 40123))._is_trusted_edge())
        with patch.object(probe, "TRUSTED_EDGES", (probe._parse_trusted_edge("192.0.2.0/24"),
                                                   probe._parse_trusted_edge("2001:db8::123"))):
            self.assertFalse(handler(edge_headers(V4))._is_trusted_edge())
            self.assertTrue(handler(edge_headers(V4), peer=("192.0.2.10", 50321))._is_trusted_edge())
            self.assertTrue(handler(edge_headers(V4), peer=("2001:0DB8::123", 50321, 0, 0))._is_trusted_edge())

    def test_tls_run_samples_only_from_current_matched_connections(self):
        other = (V4[0], V4[1] + 1, *V4[2:])
        self.capture(V4, 1)
        self.capture(other, 2, (23, 18, 50, 49, 21, 41))
        token = (probe.WHO_RUN_TOKEN_HEADER, RUN)
        a = handler(edge_headers(V4) + [token])
        b = handler(edge_headers(other) + [token])
        single = route(a, "/api/who/tls2")["tlsPermutation"]
        self.assertEqual((single["samples"], single["permuted"]), (1, None))
        self.assertEqual(route(a, "/api/who/tls2")["tlsPermutation"], single)
        multiple = route(b, "/api/who/tls2")["tlsPermutation"]
        self.assertEqual((multiple["samples"], multiple["permuted"], multiple["pskSeen"]), (2, True, True))
        for hdrs in (edge_headers(other), edge_headers(other) + [token, token],
                     edge_headers(other) + [(probe.WHO_RUN_TOKEN_HEADER, "a" * 32)]):
            isolated = route(handler(hdrs), f"/api/who/tls2?run={RUN}")["tlsPermutation"]
            self.assertEqual((isolated["samples"], isolated["permuted"]), (1, None))
        self.assertIsNone(route(handler([token, ("X-Real-IP", V4[0])]), "/api/who/tls2")["tlsPermutation"])
        self.assertIsNone(route(handler(edge_headers(V4) + [token], peer=(V4[0], V4[1] + 2), local=V4[2:]),
                                "/api/who/tls2")["tlsPermutation"])
        with patch.object(probe, "lookup_ip_geo", return_value={}), patch.object(probe, "get_server_coarse_coords", return_value=None):
            me = route(a, "/api/who/me")
        self.assertEqual(me["packet"]["tlsPermutation"], multiple)
        internal = {name.lower() for name in (*probe.EDGE_WIRE_HEADERS, probe.WHO_RUN_TOKEN_HEADER)}
        self.assertFalse(internal.intersection(name.lower() for name in me["headerOrder"]))
        self.assertFalse(internal.intersection(me["headers"]))

    def test_new_syn_clears_old_bridge_and_tls_evidence(self):
        self.capture(V4)
        owner = object()
        probe.TLSBridgeServer._publish_handshake(V4, owner, {"tlsAlpn": "h2", "tlsProtocol": "TLSv1.3"}, None)
        probe.TLSBridgeServer._publish_h2(V4, owner, {"h2Used": True, "akamai": "fixture"})
        _, packet = handler(edge_headers(V4))._observed_connection()
        self.assertEqual(packet["http2"]["akamai"], "fixture")
        self.assertIsNotNone(packet["tlsClientHello"])
        # Even a reused initial sequence number must not resurrect the old completed handshake.
        self.ingest(frame(V4, seq=50, limit=62), 60)
        probe.TLSBridgeServer._publish_h2(V4, owner, {"h2Used": True, "akamai": "stale"})
        meta, fresh = handler(edge_headers(V4))._observed_connection()
        self.assertEqual(fresh["tcp"]["observedTtl"], 62)
        self.assertIsNone(fresh["http2"])
        self.assertIsNone(fresh["tlsClientHello"])
        self.assertEqual(meta["tlsProtocol"], "")

    def test_proxy_v1_validates_both_endpoints_without_consuming_tls(self):
        hello = client_hello(6)
        for key in (V4, V6):
            endpoint_line = probe._proxy_v1_line(key)
            sock = MemoryProxySocket(endpoint_line + hello, first_peek=1)
            self.assertEqual(probe._read_proxy_protocol_v1(sock, trusted_peer=True), key)
            self.assertEqual(sock.data, hello)
            self.assertEqual(sock.timeout, 8.0)
            with self.assertRaises(ValueError):
                probe._read_proxy_protocol_v1(MemoryProxySocket(endpoint_line + hello), trusted_peer=False)
        for preface in (hello, b"PROXY UNKNOWN\r\n" + hello):
            sock = MemoryProxySocket(preface)
            self.assertIsNone(probe._read_proxy_protocol_v1(sock, trusted_peer=True))
            self.assertEqual(sock.data, hello)
        for invalid in (b"PROXY TCP4 198.51.100.1 203.0.113.10 50100 0\r\n",
                        b"PROXY TCP6 198.51.100.1 203.0.113.10 50100 443\r\n", b"PROXY TCP4 198.51.100.1\r\n",
                        b"PROXY " + b"x" * 110):
            with self.assertRaises(ValueError):
                probe._read_proxy_protocol_v1(MemoryProxySocket(invalid), trusted_peer=True)

    def test_bridge_routes_h2_using_original_destination_and_port(self):
        bridge = probe.TLSBridgeServer.__new__(probe.TLSBridgeServer)
        bridge.upstream_proxy_protocol = True
        bridge.h2c_backend = ("127.0.0.1", 10082)
        bridge.h1_backend = ("127.0.0.1", 10081)
        settings = b"\0\0\6\x04\0\0\0\0\0" + struct.pack("!HI", 1, 65536)
        h2 = probe.H2_CLIENT_PREFACE + settings
        for key, alpn in ((V6, "h2"), ((V6[0], V6[1] + 1, *V6[2:]), "http/1.1"), (None, "h2")):
            tls = Mock(session_reused=False)
            tls.selected_alpn_protocol.return_value = alpn
            tls.version.return_value = "TLSv1.3"
            tls.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
            tls.recv.side_effect = [h2, b""]
            bridge._ctx = Mock()
            bridge._ctx.wrap_socket.return_value = tls
            upstream = Mock()
            upstream.recv.return_value = b""
            snapshots = []

            def sent(payload):
                if payload == h2:
                    h = handler(edge_headers(key) if key else [("X-Real-IP", V6[0])])
                    snapshots.append(h._observed_connection())

            upstream.sendall.side_effect = sent
            conn = MemoryProxySocket(probe._proxy_v1_line(key) + client_hello(1))
            with patch.object(probe.socket, "create_connection", return_value=upstream) as connect:
                bridge._handle_conn(conn, ("127.0.0.1", 40123))
            connect.assert_called_once_with(bridge.h2c_backend if alpn == "h2" else bridge.h1_backend, timeout=5.0)
            self.assertEqual(upstream.sendall.call_args_list[0].args, (probe._proxy_v1_line(key),))
            self.assertEqual(len(snapshots), 1)
            metadata, packet = snapshots[0]
            if key:
                self.assertEqual(metadata["tlsProtocol"], "TLSv1.3")
                self.assertEqual(packet["tlsClientHello"]["helloId"], "01" * 12)
                self.assertEqual(packet["http2"]["h2Used"], alpn == "h2")
                self.assertIsNone(handler(edge_headers(key))._observed_connection()[1]["http2"])
            else:
                self.assertEqual(metadata["source"], "unknown")
                self.assertIsNone(packet["tlsClientHello"])
                self.assertIsNone(packet["http2"])
        self.assertIsNone(probe.PACKET_CACHE.get(("127.0.0.1", 40123, "127.0.0.1", 18449)))

    def test_udp_initial_does_not_turn_into_http_evidence(self):
        q = probe.QUICInitialCollector()
        q.active = True
        with patch.object(probe, "decrypt_quic_initial_packet", return_value=(b"cid", 1, [(0, client_hello(1)[5:])])), \
                patch.object(probe, "QUIC_COLLECTOR", q):
            self.assertIsNotNone(q.ingest_datagram(b"fixture", V4[:2]))
            h = handler(edge_headers(V4))
            self.assertIsNone(h._observed_connection()[1]["quic"])
            out = route(h, "/api/who/quic")
            self.assertTrue(out["ok"])
            self.assertTrue(out["collectorActive"])
            self.assertIsNone(out["quic"])

    def test_active_probe_needs_opt_in_and_can_only_target_observed_peer(self):
        own = ("8.8.8.8", 50121)
        consent = (probe.ACTIVE_PROBE_HEADER, "1")
        with patch.object(probe.egress_intel, "inspect_ip_intelligence", return_value={"ok": True}) as inspect:
            route(handler([consent], peer=own, local=V4[2:]), "/api/who/intel")
            inspect.assert_called_with(own[0], enable_active_443=False, enable_port_scan=False)
            with patch.object(probe, "ENABLE_ACTIVE_443", True):
                for query in ("?ip=1.1.1.1", "?ip=8.8.8.8", "?ip"):
                    route(handler([consent], peer=own, local=V4[2:]), "/api/who/intel" + query)
                    self.assertEqual(inspect.call_args.kwargs, {"enable_active_443": False, "enable_port_scan": False})
                route(handler(peer=own, local=V4[2:]), "/api/who/intel")
                inspect.assert_called_with(own[0], enable_active_443=False, enable_port_scan=False)
                route(handler([consent, ("X-Real-IP", own[0])]), "/api/who/intel")
                inspect.assert_called_with(own[0], enable_active_443=False, enable_port_scan=False)
                route(handler([consent, ("X-Real-IP", "1.1.1.1")], peer=own, local=V4[2:]), "/api/who/intel")
                inspect.assert_called_with(own[0], enable_active_443=True, enable_port_scan=True)


if __name__ == "__main__":
    unittest.main()
