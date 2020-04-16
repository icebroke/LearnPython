import sys
import socket
import struct

icmpv6_type = map(str, range(133, 138))

def mac_format(mac):
    return  ':'.join('%02x' % ord(b) for b in mac)

def main():
    try:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while True:
            pkt = s.recvfrom(65536)
            ether_header = struct.unpack("!6s6sH", pkt[0][:14])
            dest_mac = mac_format(ether_header[0])
            src_mac = mac_format(ether_header[1])
            ether_type = ether_header[2]

            if ether_type == 0x86DD: # If the packet is IPv6
                ipv6_header = struct.unpack("!4sHBB16s16s", pkt[0][14:54])
                src_addr = socket.inet_ntop(socket.AF_INET6, ipv6_header[4])
                dest_addr = socket.inet_ntop(socket.AF_INET6, ipv6_header[5])

                print "\nSource MAC               : ", src_mac
                print "Destination MAC          : ", dest_mac
                print "Source ipv6 address      : ", src_addr
                print "Destination ipv6 address : ", dest_addr

    except KeyboardInterrupt, e:
        sys.exit()

main()
