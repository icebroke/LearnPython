import netaddr
import sys
from scapy.all import *


target_addr = "10.0.2.0/24"

addresses = netaddr.IPNetwork(target_addr)

counter = 0

try:
	for host in addresses:
		if(host==addresses.network or host==addresses.broadcast):
			continue

		response = sr1(IP(dst=str(host)) / ICMP(), timeout=2, verbose=0)

		if(str(type(response)) == "<type 'NoneType'>"):	
			print(str(host) + " is down or not responding.")
		elif(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP),code) in [1,2,3,9,10,13]):
			print(str(host) + " is blocking ICMP.")
		else:
			print(str(host) + " is up!")
			counter += 1

	print("Out of " + str(addresses.size) + " hosts, " + str(counter) + " are online.")

except KeyboardInterrupt:
	print("Process Interrupted!")
