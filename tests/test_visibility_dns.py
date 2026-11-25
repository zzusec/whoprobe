import argparse
import errno
import ipaddress
import socket
import struct
import unittest
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch

import visibility_dns


ZONE = "visibility.example.test"
NS = "ns.example.test"
IPV4 = "192.0.2.80"
IPV6 = "2001:db8::80"
RD, RA, QR, AA, TC = 0x0100, 0x0080, 0x8000, 0x0400, 0x0200


def name_wire(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label) + b"\0"


def query(name, qtype=1, *, qclass=1, txid=42, flags=RD, options=None, version=0, do=False):
    question = (name_wire(name) if isinstance(name, str) else name) + struct.pack("!HH", qtype, qclass)
    header = struct.pack("!6H", txid, flags, 1, 0, 0, int(options is not None))
    if options is None:
        return header + question
    opt = b"\0" + struct.pack("!HHIH", 41, 4096, (version << 16) | (0x8000 if do else 0), len(options))
    return header + question + opt + options


def option(code, payload):
    return struct.pack("!HH", code, len(payload)) + payload


def ecs(family, source, address, scope=0):
    return option(8, struct.pack("!HBB", family, source, scope) + address)


def name_read(packet, offset):
    labels = []
    end = None
    while True:
        length = packet[offset]
        if length == 0:
            return ".".join(labels), end if end is not None else offset + 1
        if length & 0xc0 == 0xc0:
            target = ((length & 0x3f) << 8) | packet[offset + 1]
            if target >= offset:
                raise AssertionError("invalid compression pointer in reply")
            if end is None:
                end = offset + 2
            offset = target
        else:
            if length > 63:
                raise AssertionError("invalid label length in reply")
            labels.append(packet[offset + 1 : offset + 1 + length].decode("ascii"))
            offset += length + 1


@dataclass
class Record:
    owner: str
    qtype: int
    qclass: int
    ttl: int
    offset: int
    data: bytes


def read_reply(packet):
    txid, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = name_read(packet, offset)
        questions.append((name, *struct.unpack_from("!HH", packet, offset)))
        offset += 4
    sections = []
    for count in (an, ns, ar):
        section = []
        for _ in range(count):
            name, offset = name_read(packet, offset)
            qtype, qclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            section.append(Record(name, qtype, qclass, ttl, offset, packet[offset : offset + size]))
            offset += size
        sections.append(section)
    if offset != len(packet):
        raise AssertionError("response length does not match its sections")
    return SimpleNamespace(txid=txid, flags=flags, rcode=flags & 15, questions=questions,
                           answers=sections[0], authority=sections[1], additional=sections[2])


def tcp_read(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise AssertionError("TCP reply ended before its frame length")
        result.extend(data)
    return bytes(result)


def frame(packet):
    return struct.pack("!H", len(packet)) + packet


def tcp_reply(sock):
    return tcp_read(sock, struct.unpack("!H", tcp_read(sock, 2))[0])


class VisibilityDNSTests(unittest.TestCase):
    def args(self, *options):
        parser = argparse.ArgumentParser()
        visibility_dns.add_arguments(parser)
        return parser.parse_args(options)

    def start(self, *overrides):
        args = self.args("--visibility-dns-zone", ZONE, "--visibility-dns-ns", NS,
                         "--visibility-dns-port", "0", "--visibility-dns-a", IPV4,
                         "--visibility-dns-aaaa", IPV6, *overrides)
        server = visibility_dns.start_from_args(args)
        self.addCleanup(server.close)
        return server

    def udp(self, server, packet):
        family = socket.AF_INET6 if ":" in server.address[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(server.address)
            sock.send(packet)
            return sock.recv(2048)

    def assert_status(self, reply, rcode=0, *, authority=True):
        self.assertEqual(reply.rcode, rcode)
        self.assertTrue(reply.flags & QR)
        self.assertFalse(reply.flags & RA)
        self.assertEqual(bool(reply.flags & AA), authority)

    def test_opt_in_and_config_validation(self):
        with patch.object(visibility_dns.socket, "socket") as create_socket:
            self.assertIsNone(visibility_dns.start_from_args(self.args()))
            valid = ("--visibility-dns-zone", ZONE, "--visibility-dns-ns", NS, "--visibility-dns-a", IPV4)
            invalid_options = [
                ("--visibility-dns-port", "53"),
                valid[:2],
                valid[:4],
                (*valid, "--visibility-dns-zone", "example..test"),
                (*valid, "--visibility-dns-zone", "*.example.test"),
                (*valid, "--visibility-dns-ns", "ns." + ZONE),
                (*valid, "--visibility-dns-a", IPV6),
                (*valid, "--visibility-dns-aaaa", IPV4),
                (*valid, "--visibility-dns-bind", "localhost"),
                (*valid, "--visibility-dns-port", "65536"),
                (*valid, "--visibility-dns-window", "0"),
                (*valid, "--visibility-dns-acme-cname", "_acme-challenge." + ZONE),
            ]
            for options in invalid_options:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    visibility_dns.start_from_args(self.args(*options))
            create_socket.assert_not_called()

    def test_udp_tcp_reuse_and_private_report(self):
        server = self.start("--visibility-dns-zone", ZONE.upper() + ".")
        trial = server.issue()
        other = server.issue()
        host = trial["host"]
        token = trial["token"]
        self.assertRegex(host, r"^[0-9a-f]{32}\.visibility\.example\.test$")
        self.assertRegex(token, r"^[a-zA-Z0-9_-]{43}$")
        self.assertEqual(trial["expiresIn"], 60)
        self.assertNotEqual(host, other["host"])
        for invalid in (host, host.split(".")[0], other["token"] + "x", "X" * 43, None):
            self.assertIsNone(server.lookup(invalid))
        self.assertEqual(server.lookup(token), {"observations": []})

        first = read_reply(self.udp(server, query(host.upper(), txid=500)))
        self.assert_status(first)
        self.assertEqual(first.txid, 500)
        self.assertTrue(first.flags & RD)
        self.assertEqual(first.questions, [(host.upper(), 1, 1)])
        self.assertEqual(len(first.answers), 1)
        a = first.answers[0]
        self.assertEqual((a.owner, a.qtype, a.qclass, a.ttl, a.data),
                         (host.upper(), 1, 1, 0, ipaddress.ip_address(IPV4).packed))
        self.udp(server, query(host))  # A retry should not add a duplicate.

        with socket.create_connection(server.address, timeout=2) as sock:
            aaaa_frame = frame(query(host, 28, flags=0, txid=501))
            sock.sendall(aaaa_frame[:1])
            sock.sendall(aaaa_frame[1:] + frame(query(host, 65, txid=502)))
            second = read_reply(tcp_reply(sock))
            third = read_reply(tcp_reply(sock))
        self.assert_status(second)
        self.assertFalse(second.flags & RD)
        self.assertEqual(second.txid, 501)
        self.assertEqual(len(second.answers), 1)
        aaaa = second.answers[0]
        self.assertEqual((aaaa.qtype, aaaa.ttl, aaaa.data), (28, 0, ipaddress.ip_address(IPV6).packed))
        self.assert_status(third)
        self.assertEqual(third.txid, 502)
        self.assertEqual(third.answers, [])
        self.assertEqual([(rr.owner, rr.qtype, rr.ttl) for rr in third.authority], [(ZONE, 6, 0)])

        expected = [{"resolverIp": "127.0.0.1", "qtype": qtype, "ecsNetwork": None}
                    for qtype in ("A", "AAAA", "HTTPS")]
        report = server.lookup(token)
        self.assertEqual(report, {"observations": expected})
        report["observations"][0]["resolverIp"] = "spoof"
        self.assertEqual(server.lookup(token), {"observations": expected})
        self.assertEqual(server.lookup(other["token"]), {"observations": []})

    def test_apex_delegation_and_outside_refusal(self):
        server = self.start()
        trial = server.issue()
        host = trial["host"]
        for qtype in (2, 6):
            raw = self.udp(server, query(ZONE.upper(), qtype))
            reply = read_reply(raw)
            self.assert_status(reply)
            self.assertEqual(len(reply.answers), 1)
            rr = reply.answers[0]
            self.assertEqual((rr.owner, rr.qtype, rr.qclass), (ZONE.upper(), qtype, 1))
            name, end = name_read(raw, rr.offset)
            self.assertEqual(name, NS)
            if qtype == 2:
                self.assertEqual(end, rr.offset + len(rr.data))
            else:
                rname, end = name_read(raw, end)
                self.assertEqual(rname.lower(), f"hostmaster.{ZONE}")
                self.assertEqual(end + 20, rr.offset + len(rr.data))
                self.assertEqual(struct.unpack_from("!5I", raw, end)[-1], 0)

        for unrelated in ("", NS, host + ".outside.test", "p.not-" + ZONE):
            with self.subTest(name=unrelated):
                reply = read_reply(self.udp(server, query(unrelated)))
                self.assert_status(reply, 5, authority=False)
                self.assertEqual(reply.answers + reply.authority, [])
        for unissued in ("never-issued." + ZONE, "nested." + host, "_acme-challenge." + ZONE):
            with self.subTest(name=unissued):
                reply = read_reply(self.udp(server, query(unissued)))
                self.assert_status(reply, 3)
                self.assertEqual(reply.answers, [])
                self.assertEqual([(rr.owner, rr.qtype, rr.ttl) for rr in reply.authority], [(ZONE, 6, 0)])
        for extra in (query(host, 252), query(host, 251), query(host, 255), query(host, qclass=3)):
            reply = read_reply(self.udp(server, extra))
            self.assert_status(reply, 5, authority=False)
            self.assertFalse(reply.answers)
        update = read_reply(self.udp(server, query(host, flags=5 << 11)))
        self.assert_status(update, 4, authority=False)
        self.assertEqual(update.flags & 0x7800, 5 << 11)
        self.assertEqual(server.lookup(trial["token"]), {"observations": []})

    def test_fixed_acme_cname_without_recursive_answers(self):
        target = "_acme-challenge.certificates.example.test"
        server = self.start("--visibility-dns-acme-cname", target.upper() + ".")
        trial = server.issue()
        owner = "_acme-challenge." + ZONE
        for qtype in (5, 16):
            raw = self.udp(server, query(owner, qtype))
            reply = read_reply(raw)
            self.assert_status(reply)
            self.assertEqual(len(reply.answers), 1)
            rr = reply.answers[0]
            self.assertEqual((rr.owner, rr.qtype), (owner, 5))
            self.assertEqual(name_read(raw, rr.offset), (target, rr.offset + len(rr.data)))
        self.assert_status(read_reply(self.udp(server, query(target, 16))), 5, authority=False)
        self.assert_status(read_reply(self.udp(server, query("nested." + owner, 16))), 3)
        self.assertEqual(server.lookup(trial["token"]), {"observations": []})

    def test_ecs_networks_are_normalized_private_and_not_echoed(self):
        server = self.start()
        trial = server.issue()
        inputs = [
            (ecs(1, 20, bytes([198, 51, 96])), "198.51.96.0/20"),
            (ecs(1, 32, bytes([198, 51, 100, 229])), "198.51.100.0/24"),
            (ecs(2, 128, ipaddress.ip_address("2001:db8:abcd:12ff:feed::2").packed), "2001:db8:abcd:1200::/56"),
            (ecs(2, 0, b""), "::/0"),
            (ecs(99, 0, b""), None),
        ]
        for options, expected in inputs:
            with self.subTest(ecs=expected):
                request = query(trial["host"], options=option(10, bytes(8)) + options, do=True)
                reply = read_reply(self.udp(server, request))
                self.assert_status(reply)
                self.assertEqual(len(reply.answers), 1)
                self.assertEqual(len(reply.additional), 1)
                opt = reply.additional[0]
                self.assertEqual((opt.owner, opt.qtype, opt.ttl, opt.data), ("", 41, 0x8000, b""))
        self.assertEqual(server.lookup(trial["token"]), {"observations": [
            {"resolverIp": "127.0.0.1", "qtype": "A", "ecsNetwork": expected} for _, expected in inputs
        ]})

    def test_malformed_requests_and_ecs_are_not_recorded(self):
        server = self.start()
        trial = server.issue()
        host = trial["host"]
        broken_names = [b"\xc0\x0c", b"\xc0\x00", b"\xc0\x14", b"\x40" + b"x" * 64 + b"\0",
                        b"\x04ab\xffc\0", b"\x03a\0b\0", b"\x0az",
                        bytes([len(host)]) + host.encode("ascii") + b"\0", (b"\x3f" + b"x" * 63) * 4 + b"\0"]
        base = query(host)
        encoded_ecs = ecs(1, 24, bytes([192, 0, 2]))
        malformed = [query(wire) for wire in broken_names] + [
            base[:-1], base + b"x", base[:4] + b"\0\x02" + base[6:] + base[12:],
            query(host, qtype=0), query(host, flags=RD | TC),
            query(host, options=option(8, b"\x00")),
            query(host, options=ecs(1, 24, bytes([192, 0, 2]), scope=24)),
            query(host, options=ecs(1, 24, bytes([192, 0, 2, 1]))),
            query(host, options=ecs(1, 25, bytes([192, 0, 2, 1]))),
            query(host, options=ecs(1, 33, bytes(5))),
            query(host, options=encoded_ecs * 2),
            query(host, options=encoded_ecs[:-1]),
            query(host, options=encoded_ecs)[:-1],
        ]
        for case, packet in enumerate(malformed):
            with self.subTest(case=case):
                response = self.udp(server, packet)
                reply = read_reply(response)
                self.assert_status(reply, 1, authority=False)
                self.assertEqual(len(response), 12)
        bad_version = read_reply(self.udp(server, query(host, options=encoded_ecs, version=1)))
        self.assert_status(bad_version, authority=False)
        self.assertFalse(bad_version.answers)
        self.assertEqual(bad_version.additional[0].ttl, 1 << 24)
        self.assertEqual(server.lookup(trial["token"]), {"observations": []})

    def test_responses_and_oversize_datagrams_are_dropped(self):
        server = self.start()
        host = server.issue()["host"]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.1)
            sock.connect(server.address)
            for packet in (b"\0" * 11, query(host, flags=QR), query(host, options=option(12, bytes(1300)))):
                sock.send(packet)
                with self.assertRaises(TimeoutError):
                    sock.recv(2048)

    def test_capacity_and_expiry_release_private_and_dns_names(self):
        clock = SimpleNamespace(now=1000.0)
        with (patch.object(visibility_dns, "_MAX_TRIALS", 2),
              patch.object(visibility_dns, "_MAX_OBSERVATIONS", 2),
              patch.object(visibility_dns, "time", SimpleNamespace(monotonic=lambda: clock.now))):
            server = self.start("--visibility-dns-window", "1")
            self.addCleanup(server.close)
            trial = server.issue()
            clock.now += 0.5
            other = server.issue()
            self.assertEqual(trial["expiresIn"], 1)
            with self.assertRaises(visibility_dns.CapacityError):
                server.issue()
            for qtype in (1, 28, 65):
                self.assert_status(read_reply(self.udp(server, query(trial["host"], qtype))))
            self.assertEqual([o["qtype"] for o in server.lookup(trial["token"])["observations"]], ["A", "AAAA"])
            clock.now += 0.5
            self.assertIsNone(server.lookup(trial["token"]))
            self.assert_status(read_reply(self.udp(server, query(trial["host"]))), 3)
            self.assertEqual(server.lookup(other["token"]), {"observations": []})
            replacement = server.issue()
            self.assertNotEqual(replacement["host"], trial["host"])
            self.assertNotEqual(replacement["token"], trial["token"])
            server.close()

    def test_bounded_udp_replies_have_tcp_fallback(self):
        long_zone = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 28])
        long_ns = ".".join(["n" * 63, "s" * 63, "r" * 63, "t" * 61])
        for zone in ("v.test", long_zone):
            with self.subTest(zone=zone):
                server = self.start("--visibility-dns-zone", zone, "--visibility-dns-ns", long_ns)
                request = query(zone, 6)
                raw = self.udp(server, request)
                self.assertLessEqual(len(raw), min(512, 4 * len(request)))
                udp = read_reply(raw)
                self.assert_status(udp)
                self.assertTrue(udp.flags & TC)
                self.assertFalse(udp.answers)
                with socket.create_connection(server.address, timeout=2) as sock:
                    sock.sendall(frame(request))
                    full = tcp_reply(sock)
                tcp = read_reply(full)
                self.assert_status(tcp)
                self.assertFalse(tcp.flags & TC)
                self.assertEqual(tcp.answers[0].qtype, 6)
                self.assertEqual(name_read(full, tcp.answers[0].offset)[0], long_ns)
                self.assertGreater(len(full), min(512, 4 * len(request)))

    def test_stalled_tcp_peer_times_out_without_blocking_udp(self):
        with patch.object(visibility_dns, "_TCP_TIMEOUT", 0.4):
            server = self.start()
            host = server.issue()["host"]
            with socket.create_connection(server.address, timeout=2) as sock:
                sock.sendall(frame(query(host))[:3])
                self.assert_status(read_reply(self.udp(server, query(host))))
                self.assertEqual(sock.recv(1), b"")
            server.close()

    def test_close_cleans_up_and_udp_conflict_does_not_leak_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            port = str(occupied.getsockname()[1])
            with self.assertRaises(OSError):
                self.start("--visibility-dns-port", port)
        server = self.start("--visibility-dns-port", port)
        trial = server.issue()
        with socket.create_connection(server.address, timeout=2) as sock:
            sock.sendall(b"\x00")
            server.close()
            try:
                self.assertEqual(sock.recv(1), b"")
            except ConnectionResetError:
                pass  # A queued connection can be reset rather than sent FIN.
        self.assertIsNone(server.lookup(trial["token"]))
        with self.assertRaises(RuntimeError):
            server.issue()
        replacement = self.start("--visibility-dns-port", port)
        self.assert_status(read_reply(self.udp(replacement, query(ZONE, 2))))

    @unittest.skipUnless(socket.has_ipv6, "IPv6 unavailable")
    def test_ipv6_loopback_and_aaaa_only(self):
        try:
            server = visibility_dns.start_from_args(self.args(
                "--visibility-dns-zone", ZONE, "--visibility-dns-ns", NS,
                "--visibility-dns-bind", "::1", "--visibility-dns-port", "0", "--visibility-dns-aaaa", IPV6,
            ))
        except OSError as error:
            if error.errno in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
                self.skipTest("IPv6 loopback unavailable")
            raise
        self.addCleanup(server.close)
        trial = server.issue()
        nodata = read_reply(self.udp(server, query(trial["host"])))
        self.assert_status(nodata)
        self.assertFalse(nodata.answers)
        self.assertEqual(nodata.authority[0].qtype, 6)
        with socket.create_connection(server.address, timeout=2) as sock:
            sock.sendall(frame(query(trial["host"], 28)))
            reply = read_reply(tcp_reply(sock))
        self.assert_status(reply)
        self.assertEqual(reply.answers[0].data, ipaddress.ip_address(IPV6).packed)
        self.assertEqual([o["resolverIp"] for o in server.lookup(trial["token"])["observations"]], ["::1", "::1"])


if __name__ == "__main__":
    unittest.main()
