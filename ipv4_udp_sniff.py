import os
import sys
import socket
import struct
from ctypes import *

#This is the IP Class inherited from Structure.
class IP(Structure):

    #A fields attribute is required to be able to parse the buffer into 1, 2 or
    #4 byte sections as below
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    #class is then instantiated with further attributes
    def __init__(self, socket_buffer=None):
        #create a mapping between IP protocol numbers and names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        #assign the protocol attribute
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        # Human readable protocol
        self.ip_src = socket.inet_ntoa(struct.pack("<L", self.src))
        self.ip_dst = socket.inet_ntoa(struct.pack("<L", self.dst))

socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

try:
    sniffer.bind(("0.0.0.0", 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except:
    sys.exit(1)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]

        ip_header = IP(raw_buffer[0:20])

        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.ip_src, ip_header.ip_dst))

except KeyboardInterrupt:
    sys.exit(0)
