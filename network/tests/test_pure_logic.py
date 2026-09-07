import socket
import struct

from django.test import SimpleTestCase

from network.arp_mitm import build_arp_reply
from network.dns_capture import _parse_dns_query_frame
from network.dns_wire import TYPE_A, TYPE_PTR, TYPE_TXT, build_query, parse_message, parse_question
from network.ip_utils import cidr_to_mask, ip_to_long, is_in_same_subnet, long_to_ip, mask_to_cidr
from network.isp_brands import brand_name_for_isp
from network.os_fingerprint import _fuse_signals, _normalize_family, _parse_best_os_match, _to_signal_details


class IpUtilsTests(SimpleTestCase):
    def test_ip_to_long_and_back(self):
        self.assertEqual(ip_to_long("192.168.1.1"), 3232235777)
        self.assertEqual(long_to_ip(3232235777), "192.168.1.1")

    def test_is_in_same_subnet(self):
        self.assertTrue(is_in_same_subnet("192.168.1.50", "192.168.1.1", "255.255.255.0"))
        self.assertFalse(is_in_same_subnet("192.168.2.50", "192.168.1.1", "255.255.255.0"))

    def test_mask_cidr_round_trip(self):
        self.assertEqual(mask_to_cidr("255.255.255.0"), 24)
        self.assertEqual(cidr_to_mask(24), "255.255.255.0")
        self.assertEqual(cidr_to_mask(0), "0.0.0.0")


class DnsWireTests(SimpleTestCase):
    def test_build_and_parse_round_trip_for_a_record(self):
        query = build_query([("device.local", TYPE_A)], transaction_id=42)
        self.assertEqual(query[0:2], (42).to_bytes(2, "big"))

    def test_parse_message_decodes_a_record(self):
        # Hand-built response: 1 answer, A record for host.local -> 1.2.3.4.
        import struct
        name = b"\x04host\x05local\x00"
        header = struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        rr = name + struct.pack(">HHIH", TYPE_A, 1, 120, 4) + bytes([1, 2, 3, 4])
        message = parse_message(header + rr)
        self.assertEqual(message["answers"], [{"name": "host.local", "type": TYPE_A, "data": "1.2.3.4"}])

    def test_parse_message_decodes_txt_record(self):
        import struct
        name = b"\x04host\x05local\x00"
        header = struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        txt_data = bytes([5]) + b"model" + bytes([11]) + b"model=iPad9"
        rr = name + struct.pack(">HHIH", TYPE_TXT, 1, 120, len(txt_data)) + txt_data
        message = parse_message(header + rr)
        self.assertEqual(message["answers"][0]["data"], ["model", "model=iPad9"])

    def test_parse_message_follows_compression_pointer(self):
        import struct
        # Question at offset 12 names "a.local"; answer's name is a pointer back to offset 12.
        question_name = b"\x01a\x05local\x00"
        header = struct.pack(">HHHHHH", 1, 0x8400, 1, 1, 0, 0)
        question = question_name + struct.pack(">HH", TYPE_PTR, 1)
        pointer_name = bytes([0xC0, 12])
        rr = pointer_name + struct.pack(">HHIH", TYPE_PTR, 1, 120, len(question_name)) + question_name
        message = parse_message(header + question + rr)
        self.assertEqual(message["answers"][0]["name"], "a.local")

    def test_parse_question_extracts_name_and_type(self):
        header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", TYPE_A, 1)
        self.assertEqual(parse_question(header + question), ("example.com", TYPE_A))

    def test_parse_question_returns_none_for_truncated_buffer(self):
        self.assertIsNone(parse_question(b"\x00" * 5))


class DnsCaptureTests(SimpleTestCase):
    SRC_MAC = bytes.fromhex("aabbccddeeff")
    DST_MAC = bytes.fromhex("112233445566")

    def _build_frame(self, *, dst_port=53, protocol=17, dns_payload=b""):
        eth = self.DST_MAC + self.SRC_MAC + struct.pack(">H", 0x0800)
        ip_header = (
            bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0])
            + socket.inet_aton("10.0.0.5") + socket.inet_aton("8.8.8.8")
        )
        udp_header = struct.pack(">HHHH", 12345, dst_port, 8 + len(dns_payload), 0)
        return eth + ip_header + udp_header + dns_payload

    def _dns_query_payload(self, domain="example.com", qtype=TYPE_A):
        header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        labels = b"".join(bytes([len(part)]) + part.encode() for part in domain.split("."))
        return header + labels + b"\x00" + struct.pack(">HH", qtype, 1)

    def test_full_frame_parses_mac_and_domain(self):
        frame = self._build_frame(dns_payload=self._dns_query_payload("example.com"))
        self.assertEqual(_parse_dns_query_frame(frame), ("aa:bb:cc:dd:ee:ff", "example.com"))

    def test_non_dns_port_is_ignored(self):
        frame = self._build_frame(dst_port=80, dns_payload=self._dns_query_payload())
        self.assertIsNone(_parse_dns_query_frame(frame))

    def test_non_udp_protocol_is_ignored(self):
        frame = self._build_frame(protocol=6, dns_payload=self._dns_query_payload())  # TCP
        self.assertIsNone(_parse_dns_query_frame(frame))

    def test_truncated_frames_do_not_raise(self):
        for length in (0, 5, 14, 20, 34, 41):
            with self.subTest(length=length):
                self.assertIsNone(_parse_dns_query_frame(b"\x00" * length))


class ArpMitmTests(SimpleTestCase):
    THIS_MAC = bytes.fromhex("aabbccddeeff")
    VICTIM_MAC = bytes.fromhex("112233445566")

    def test_build_arp_reply_byte_layout(self):
        frame = build_arp_reply(
            src_mac=self.THIS_MAC, dst_mac=self.VICTIM_MAC,
            sender_ip="192.168.1.1", sender_mac=self.THIS_MAC,
            target_ip="192.168.1.50", target_mac=self.VICTIM_MAC,
        )
        # Ethernet: dst(6) + src(6) + ethertype(2)
        self.assertEqual(frame[0:6], self.VICTIM_MAC)
        self.assertEqual(frame[6:12], self.THIS_MAC)
        self.assertEqual(frame[12:14], struct.pack(">H", 0x0806))
        # ARP: htype, ptype, hlen, plen, opcode
        self.assertEqual(struct.unpack(">HHBBH", frame[14:22]), (1, 0x0800, 6, 4, 2))
        # sender mac/ip, target mac/ip
        self.assertEqual(frame[22:28], self.THIS_MAC)
        self.assertEqual(frame[28:32], socket.inet_aton("192.168.1.1"))
        self.assertEqual(frame[32:38], self.VICTIM_MAC)
        self.assertEqual(frame[38:42], socket.inet_aton("192.168.1.50"))

    def test_build_arp_reply_is_42_bytes(self):
        frame = build_arp_reply(
            src_mac=self.THIS_MAC, dst_mac=self.VICTIM_MAC,
            sender_ip="192.168.1.1", sender_mac=self.THIS_MAC,
            target_ip="192.168.1.50", target_mac=self.VICTIM_MAC,
        )
        self.assertEqual(len(frame), 42)


class IspBrandsTests(SimpleTestCase):
    def test_known_asn_overrides_registry_name(self):
        self.assertEqual(brand_name_for_isp(15399, "Wananchi Cable Tanzania"), "Zuku")

    def test_unknown_asn_falls_back_to_registry_name(self):
        self.assertEqual(brand_name_for_isp(64512, "Some Registry Name"), "Some Registry Name")


class OsFingerprintPureLogicTests(SimpleTestCase):
    def test_normalize_family(self):
        self.assertEqual(_normalize_family("Microsoft Windows 10"), "Windows")
        self.assertEqual(_normalize_family("Linux 5.0 - 6.2"), "Linux")
        self.assertIsNone(_normalize_family("router"))

    def test_fuse_signals_requires_minimum_weight(self):
        self.assertIsNone(_fuse_signals([{"family": "Windows", "weight": 0.5}]))

    def test_fuse_signals_requires_clear_margin(self):
        signals = [{"family": "Windows", "weight": 3}, {"family": "Linux", "weight": 2.5}]
        self.assertIsNone(_fuse_signals(signals))

    def test_fuse_signals_picks_clear_winner(self):
        signals = [{"family": "Linux", "weight": 4}, {"family": "Windows", "weight": 1}]
        fused = _fuse_signals(signals)
        self.assertEqual(fused["family"], "Linux")
        self.assertEqual(fused["confidence"], 80)

    def test_to_signal_details_sorts_strongest_first_and_filters_family(self):
        signals = [
            {"source": "a", "family": "Windows", "detail": "weak", "weight": 1},
            {"source": "b", "family": "Windows", "detail": "strong", "weight": 5},
            {"source": "c", "family": "Linux", "detail": "other", "weight": 9},
        ]
        details = _to_signal_details(signals, only_family="Windows")
        self.assertEqual(details, [{"source": "b", "detail": "strong"}, {"source": "a", "detail": "weak"}])

    def test_parse_best_os_match_picks_highest_accuracy(self):
        xml = """
        <osmatch name="Linux 5.0" accuracy="90"><osclass type="general purpose" osfamily="Linux" osgen="5.X"/></osmatch>
        <osmatch name="Windows 10" accuracy="95"><osclass type="general purpose" osfamily="Windows" osgen="10"/></osmatch>
        """
        best = _parse_best_os_match(xml)
        self.assertEqual(best["name"], "Windows 10")
        self.assertEqual(best["osFamily"], "Windows")
        self.assertEqual(best["accuracy"], 95.0)
