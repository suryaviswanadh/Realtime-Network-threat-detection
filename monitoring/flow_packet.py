# monitoring/flow_packet.py
import time
from scapy.all import IP, TCP, UDP, ICMP, Packet, Raw

class FlowPacket:
    """Holds extracted information from a Scapy packet relevant for flow analysis."""
    def __init__(self, packet: Packet):
        self.timestamp = packet.time
        self.length = len(packet) # Total length
        self.payload_length = 0
        self.ip_src = None
        self.ip_dst = None
        self.port_src = 0
        self.port_dst = 0
        self.protocol = 0 # IP protocol number
        self.flags = 0 # TCP Flags as integer
        self.win_bytes = 0 # TCP Window size

        if packet.haslayer(IP):
            self.ip_src = packet[IP].src
            self.ip_dst = packet[IP].dst
            self.protocol = packet[IP].proto

            if packet.haslayer(TCP):
                self.port_src = packet[TCP].sport
                self.port_dst = packet[TCP].dport
                self.flags = int(packet[TCP].flags) # Store flags as int
                self.win_bytes = packet[TCP].window # Get window size
                
                payload_len = 0
                if packet.haslayer(Raw):
                    payload_len = len(packet[Raw].load)
                else:
                     # Estimate payload length if no Raw layer (e.g., SYN, FIN)
                     header_len = packet[TCP].dataofs * 4 if packet[TCP].dataofs else 20
                     payload_len = max(0, len(packet[TCP]) - header_len)
                self.payload_length = payload_len

            elif packet.haslayer(UDP):
                self.port_src = packet[UDP].sport
                self.port_dst = packet[UDP].dport
                payload_len = 0
                if packet.haslayer(Raw):
                    payload_len = len(packet[Raw].load)
                else:
                    # UDP header is fixed 8 bytes
                    payload_len = max(0, len(packet[UDP]) - 8)
                self.payload_length = payload_len
            
            elif packet.haslayer(ICMP):
                self.protocol = 1 # Ensure protocol is set for ICMP

    def get_flow_key(self):
        """Generates a tuple key for identifying the flow direction."""
        # Key: (src_ip, src_port, dst_ip, dst_port, protocol)
        # Order by lower IP/Port first to group bidirectional traffic
        if (self.ip_src, self.port_src) < (self.ip_dst, self.port_dst):
            return (self.ip_src, self.port_src, self.ip_dst, self.port_dst, self.protocol)
        else:
            return (self.ip_dst, self.port_dst, self.ip_src, self.port_src, self.protocol)

    def is_forward(self, flow_key):
         """Checks if this packet is in the forward direction relative to the flow key."""
         return (self.ip_src, self.port_src, self.ip_dst, self.port_dst, self.protocol) == flow_key

    def is_flag_set(self, flag_char):
        """Checks if a specific TCP flag (F, S, R, P, A, U, E, C) is set."""
        flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
        flag_val = flag_map.get(flag_char.upper())
        if flag_val is None: return False
        return (self.flags & flag_val) != 0