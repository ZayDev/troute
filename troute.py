#!/usr/bin/env python

#ping every ip
#plot ping with matplotlib add as argument
#ping using tcp

import socket as s
import sys
import argparse
from pprint import pprint
import logging
logging.getLogger("scapy").setLevel(1)
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("--maxHops", help="maximum amount of hops", type=int)
args = parser.parse_args()
dst = args.host
if args.maxHops == None:
	maxTTL = 30
else:
	maxTTL = args.maxHops
sport = 888
hosts = []

print("traceroute to {} ({}), {} hops max").format(dst, s.gethostbyname(dst), maxTTL)

for i in range(1,int(maxTTL)):
	p0=IP(dst=dst, ttl=i)/ICMP()
	p1=sr1(p0, verbose=0)
	try:
		hostname, a, b = s.gethostbyaddr(p1.src)
	except s.herror:
		hostname = p1.src
	print(" {} {} ( {} ) ping here").format(i, hostname, p1.src)
	if p1.src == s.gethostbyname(dst):
		hops = i
		break
