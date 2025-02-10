from scapy.all import Ether, UDP, IP, TCP, ICMP, send, sniff

send(IP(dst="127.0.0.1", src="127.0.0.1") / TCP(sport=8081, dport=8080, flags="S"))
