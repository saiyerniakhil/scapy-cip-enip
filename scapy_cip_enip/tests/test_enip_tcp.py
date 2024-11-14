import unittest
from scapy import all as scapy_all

from scapy_cip_enip.enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, ENIP_ConnectionAddress, \
    ENIP_ConnectionPacket


class TestEnipTcp(unittest.TestCase):



    def setUp(self):
        # Test building/dissecting packets
        # Build a raw packet over ENIP
        self.pkt = scapy_all.Ether(src='01:23:45:67:89:ab', dst='ba:98:76:54:32:10')
        self.pkt /= scapy_all.IP(src='192.168.1.1', dst='192.168.1.42')
        self.pkt /= scapy_all.TCP(sport=10000, dport=44818)
        self.pkt /= ENIP_TCP(length=None)
        self.pkt /= ENIP_SendUnitData(items=[
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=1337),
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=4242) / scapy_all.Raw(load='test'),
        ])

    def test_enip_tcp(self):
        # self.assertEqual(self.pkt[ENIP_TCP].command_id, "0x70") #FIXME:
        self.assertEqual(self.pkt[ENIP_TCP].session, 0)
        self.assertEqual(self.pkt[ENIP_TCP].status, 0)
        # self.assertEqual(self.pkt[ENIP_TCP].length, 26) #FIXME:
        # self.assertEqual(self.pkt[ENIP_SendUnitData].count, 2) #FIXME:
        self.assertEqual(self.pkt[ENIP_SendUnitData].items[0].type_id, 0x00a1)
        # self.assertEqual(self.pkt[ENIP_SendUnitData].items[0].length, 4) #FIXME:
        self.assertEqual(self.pkt[ENIP_SendUnitData].items[0].payload, self.pkt[ENIP_ConnectionAddress])
        self.assertEqual(self.pkt[ENIP_ConnectionAddress].connection_id, 1337)
        self.assertEqual(self.pkt[ENIP_SendUnitData].items[1].type_id, 0x00b1)
        # self.assertEqual(self.pkt[ENIP_SendUnitData].items[1].length, 6) #FIXME:
        self.assertEqual(self.pkt[ENIP_SendUnitData].items[1].payload, self.pkt[ENIP_ConnectionPacket])
        self.assertEqual(self.pkt[ENIP_ConnectionPacket].sequence, 4242)
        self.assertEqual(self.pkt[ENIP_ConnectionPacket].payload.load, b'test')