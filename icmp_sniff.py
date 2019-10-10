import os
import sys
import socket
import struct
from ctypes import *

#This is the IP Class inherited from Structure.
class IP(Structure):
	# Internet  protocol structure in bits
	_fields_ = [
        	("ihl", c_ubyte, 4),		# 4-bits
       		("version", c_ubyte, 4),	# 4-bits
	        ("tos", c_ubyte),		# 8-bits
	        ("len", c_ushort),		# 16-bits
        	("id", c_ushort),		# 16-bits
	        ("offset", c_ushort),		# 16-bits
	        ("ttl", c_ubyte),		# 8-bits
	        ("protocol_num", c_ubyte),	# 8-bits
	        ("sum", c_ushort),		# 16-bits
	        ("src", c_uint32),		# 32-bits
	        ("dst", c_uint32)		# 32-bits
	    ]

 	def __new__(self, socket_buffer=None):
        	return self.from_buffer_copy(socket_buffer)

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

class ICMP(Structure):
	_fields_=[
		("type",	c_ubyte),
		("code",	c_ubyte),
		("checksum", 	c_ushort),
		("unused",	c_ushort),
		("next_hop_mtu",c_ushort),
	]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)
		
	def __init__(self, socket_buffer):
		pass

socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

try: 
	 sniffer.bind(("0.0.0.0", 0))	# Bind the socket
	 sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) 
except:
 	 sys.exit(1)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]

        ip_header = IP(raw_buffer[0:20])

        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.ip_src, ip_header.ip_dst))
	
	if ip_header.protocol == "ICMP":
		# calculate where ICMP packet starts
		offset = ip_header.ihl * 4

		buf = raw_buffer[offset:offset + sizeof(ICMP)]

		# create ICMP structure
		icmp_header = ICMP(buf)

		print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

except KeyboardInterrupt:
    sys.exit(0)
