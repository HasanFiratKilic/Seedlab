from scapy.all import *
import argparse

def user_inputs():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i","--iface",dest="iface",help="to interface")
	return parser.parse_args()

def spoof_icmp_reply_packet(pkt):
    if pkt[ICMP].type == 8:
        
        spoof_ip_pkt = IP(src=pkt[IP].dst,dst=pkt[IP].src)
        spoof_icmp_pkt = ICMP(id=pkt[ICMP].id,seq=pkt[ICMP].seq,type=0)
        raw_data = pkt[Raw].load
        spoof_pkt = spoof_ip_pkt/spoof_icmp_pkt/raw_data

        send(spoof_pkt,verbose=0)
        
        print("-----------------------------")
        print("Original Packet")
        print(f"Source Ip: {pkt[IP].src}")
        print(f"Destination Ip: {pkt[IP].dst}")
        print(f"Spoofed Packet")
        print(f"Source Ip: {spoof_ip_pkt[IP].src}")
        print(f"Destination Ip: {spoof_ip_pkt[IP].dst}")
        
        
user_options = user_inputs()
user_iface = user_options.iface

print("Program running...")
pkt = sniff(filter="icmp",iface=user_iface,prn=spoof_icmp_reply_packet)