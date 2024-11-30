from scapy.all import *
import argparse
import time



def send_fake_icmp_packets(target_ip,source_ip, count):
	for _ in range(count):
		packet = IP(src=source_ip, dst=target_ip) / ICMP()
		send(packet)
		print(f"Sent packet from {source_ip} to {target_ip}")
		time.sleep(1)  

def get_user_input():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t","--target",dest="target",help="to set the destination ip")
	parser.add_argument("-s","--source",dest="source",help="to set the source ip")
	parser.add_argument("-c","--count",dest="count",type=int, default=10,help="to set the number of packets to send")
	return parser.parse_args()
	
user_options = get_user_input()
user_target = user_options.target
user_source = user_options.source
user_count = user_options.count		

send_fake_icmp_packets(user_target,user_source, user_count)




