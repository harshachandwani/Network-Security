#!/usr/bin/env python

import os
import sys, getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
from collections import deque
import datetime

PRESENT = 1
ABSENT = 0

packet_queue = deque(maxlen = 10)

def dns_detection(packet):
	if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNSRR) and packet.haslayer(DNS) :
        	if len(packet_queue) > 0:
            		for p in packet_queue:
                		if p[IP].dst == packet[IP].dst and\
				p[IP].dport == packet[IP].dport and p[IP].sport == packet[IP].sport and\
                		p[DNS].id == packet[DNS].id and p[DNS].qd.qname == packet[DNS].qd.qname and\
                		p[DNSRR].rdata != packet[DNSRR].rdata and p[IP].payload != packet[IP].payload:
                    			print_responses(p, packet)
       		packet_queue.append(packet)

def print_responses(p, packet):
	s_queue=""
	s_packet=""
	for i in range(p[DNS].ancount):
		if p[DNS].an[i].type==1:
			s_queue+=p[DNS].an[i].rdata+","
	for i in range(packet[DNS].ancount):
		if packet[DNS].an[i].type==1:
			s_packet+=packet[DNS].an[i].rdata+","
	s_queue=s_queue.rstrip(',')
	s_packet=s_packet.rstrip(',')
	if s_packet and s_queue:
		print "DNS poisoning detected, URL requested %s, TXID %s," %(p[DNS].qd.qname.rstrip('.'),p[DNS].id)
		print "Answer1: [%s]" %s_queue
		print "Answer2: [%s]" %s_packet
		print(datetime.datetime.fromtimestamp(int(packet.time)).strftime('%H:%M:%S %d-%m-%Y '))

def main(argv):
	bpf_filter = ''
	pcap_file = ''
	interface = ''

	interface_is = ABSENT
	file_is = ABSENT
	
	try:
		opts, args = getopt.getopt(argv, 'i:r::')
	except getopt.GetoptError as err:
		print str(err)
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ('-r'):
			file_is = PRESENT
			pcap_file = arg
		if opt in ('-i'):
			interface_is = PRESENT
			interface = arg
	if len(args) == 1:
		bpf_filter = ars[0]
	
	if len(args) > 1:
		print "More than one expression not supported"
		sys.exit(2)

  	if interface_is == PRESENT:
		if file_is == PRESENT:
			print "-r and -i are not supported together"
			sys.exit(2)
		else:
			print"Sniffing on the interface",interface
			sniff(prn = dns_detection, iface = interface, filter = bpf_filter, store = 0)
	
	elif file_is == PRESENT:
		print "Sniffing from the pcap file:", pcap_file
		sniff(prn = dns_detection, offline = pcap_file, filter = bpf_filter, store = 0)
	else:
		print "No -i option provided, sniffing on all interfaces"
		sniff(prn = dns_detection, filter = bpf_filter, store = 0)


if __name__ == '__main__' :
	main(sys.argv[1:])		
		
	
	


