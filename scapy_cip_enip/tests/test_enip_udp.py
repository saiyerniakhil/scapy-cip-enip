import unittest
from scapy import all as scapy_all

from scapy_cip_enip.enip_udp import ENIP_UDP_Item, ENIP_UDP_SequencedAddress, ENIP_UDP

ENIP_UDP_KEEPALIVE = (
    b'\x01\x00\xff\xff\xff\xff' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00')

class TestEnipUDP(unittest.TestCase):
    def setUp(self):
        self.pkt = scapy_all.Ether(src='00:1d:9c:c8:13:37', dst='01:00:5e:40:12:34')
        self.pkt /= scapy_all.IP(src='192.168.1.42', dst='239.192.18.52')
        self.pkt /= scapy_all.UDP(sport=2222, dport=2222)
        self.pkt /= ENIP_UDP(items=[
            ENIP_UDP_Item() / ENIP_UDP_SequencedAddress(connection_id=1337, sequence=42),
            ENIP_UDP_Item(type_id=0x00b1) / scapy_all.Raw(load=ENIP_UDP_KEEPALIVE),
        ])

    def test_enip_udp(self):
        self.assertEqual(self.pkt[ENIP_UDP].count, 2)  # Fixed
        self.assertEqual(self.pkt[ENIP_UDP].items[0].type_id, 0x8002)
        # self.assertEqual(self.pkt[ENIP_UDP].items[0].length, 8)  # FIXME: Not working
        self.assertEqual(self.pkt[ENIP_UDP].items[0].payload, self.pkt[ENIP_UDP_SequencedAddress])
        self.assertEqual(self.pkt[ENIP_UDP_SequencedAddress].connection_id, 1337)
        self.assertEqual(self.pkt[ENIP_UDP_SequencedAddress].sequence, 42)
        self.assertEqual(self.pkt[ENIP_UDP].items[1].type_id, 0x00b1)
        # self.assertEqual(self.pkt[ENIP_UDP].items[1].length, 38)  # FIXME: not working
        self.assertEqual(self.pkt[ENIP_UDP].items[1].payload.load, ENIP_UDP_KEEPALIVE)