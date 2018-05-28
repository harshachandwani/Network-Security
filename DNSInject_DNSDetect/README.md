                                # Network-Security-DNSInject-DNSDetect

                                       Name: Harsha Chandwani
                                          SBU ID: 111481387

								                              DNS Inject
					            ----------------------------------------------------------

a) Test Environment 
	Ubuntu 16.04.3 LTS
	Linux 4.10.0-37-generic x86_64

b) Compiler and its version

	gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) 

c)Language
	Python 2.7.12  

d)Command Line commands and options	

	sudo python dnsinject.py [-i interface] [-h hostnames] expression

	1. sudo python dnsinject.py 
		On doing an nslookup, this is what we get 
		
		harsha@harsha-ThinkPad-E470:~/111481387_hw4$ sudo python dnsinject.py 
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 


	2. sudo python dnsinject.py -i wlp2s0 
		On doing an nslookup www.facebook.com

		harsha@harsha-ThinkPad-E470:~/111481387_hw4$ sudo python dnsinject.py -i wlp5s0
			wlp5s0
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 
			Using attacker IP for response
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "172.24.224.1" 


	3. sudo python dnsinject.py -i wlp2s0 -h hostname 
		on doing an nslookup  for facebook.com
		harsha@harsha-ThinkPad-E470:~/111481387_hw4$ sudo python dnsinject.py -i wlp5s0 -h hostnawlp5s0
			hostname
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
			.
			Sent 1 packets.
			Packet sent: IP / UDP / DNS Ans "2.2.2.2" 


		
	4. sudo python dnsinject.py -i wlp2s0 -h hostname ip 
		ON doing an nsloopkup facebook.com
		
		harsha@harsha-ThinkPad-E470:~/111481387_hw4sudo python dnsinject.py -i wlp5s0 -h hostname ip
		wlp5s0
		hostname
		ip
		.
		Sent 1 packets.
		Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
		.
		Sent 1 packets.
		Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
		.
		Sent 1 packets.
		Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
		.
		Sent 1 packets.
		Packet sent: IP / UDP / DNS Ans "2.2.2.2" 
		.
		Sent 1 packets.
		Packet sent: IP / UDP / DNS Ans "2.2.2.2" 


Design and Implementation
	1. If hostname file is specified, dnsinject will spoof the hostnames with the IPs mentioned in the file
	2. If interface is specified, dnsinject will spoof the DNS reply packet on the interface with the IP mentioned in the hostname file or 	if the hostname file is not specified, the attackers IP is used for the response.

	
							                                      	DNS Detect
					                        ----------------------------------------------------------

a) Test Environment 
	Ubuntu 16.04.3 LTS
	Linux 4.10.0-37-generic x86_64

b) Compiler and its version

	gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) 

c)Language
	Python 2.7.12  

d)Command Line commands and options	

	sudo python dnsdetect [-i interface] [-r tracefile] expression

	1. sudo python dnsdetect.py 
		nslookup www.twitter.com

		DNS poisoning detected, URL requested piazza.com, TXID 54355,
		Answer1: [54.172.146.126]
		Answer2: [172.24.224.1]
		18:01:53 11-12-2017 
		DNS poisoning detected, URL requested piazza.com, TXID 54355,
		Answer1: [54.172.146.126]
		Answer2: [172.24.224.1]
		18:01:53 11-12-2017 
		DNS poisoning detected, URL requested piazza.com, TXID 54355,
		Answer1: [54.172.146.126]
		Answer2: [172.24.224.1]
		18:01:53 11-12-2017 
		DNS poisoning detected, URL requested piazza.com, TXID 54355,
		Answer1: [54.172.146.126]
		Answer2: [172.24.224.1]
		18:01:53 11-12-2017 

	2. sudo python dnsdetect.py -r trace.pcap 

		DNS poisoning detected, URL requested cdn.syndication.twimg.com, TXID 18563,
		Answer1: [cs139.wac.edgecastcdn.net.]
		Answer2: [172.25.82.240]
		00:22:39 10-12-2017 
		DNS poisoning detected, URL requested cdn.syndication.twimg.com, TXID 26912,
		Answer1: [cs139.wac.edgecastcdn.net.]
		Answer2: [172.25.82.240]
		00:22:39 10-12-2017 
		DNS poisoning detected, URL requested cdn.syndication.twimg.com, TXID 26912,
		Answer1: [cs139.wac.edgecastcdn.net.]
		Answer2: [172.25.82.240]
		00:22:39 10-12-2017 
		DNS poisoning detected, URL requested cdn.syndication.twimg.com, TXID 61205,
		Answer1: [cs139.wac.edgecastcdn.net.]
		Answer2: [172.25.82.240]
		00:22:39 10-12-2017 
		DNS poisoning detected, URL requested cdn.syndication.twimg.com, TXID 61205,
		Answer1: [cs139.wac.edgecastcdn.net.]
		Answer2: [172.25.82.240]
		00:22:39 10-12-2017 



