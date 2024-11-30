from scapy.all import *
import argparse

def argparse_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="for Target IP address")
    return parser.parse_args()

def traceroute(ip):
    print("Starting traceroute...")
    target_ip = IP(dst=ip)
    ttl = 1

    while True:
        target_ip.ttl = ttl
        icmp_packet = ICMP()
        packet = target_ip / icmp_packet
        reply_packet = sr1(packet, timeout=2, verbose=0)

        if reply_packet is None:
            print(f"{ttl} hops: No reply")
        elif reply_packet[ICMP].type == 0:  
            print(f"{ttl} hops: {reply_packet[IP].src} (Destination reached)")
            break
        else:
            print(f"{ttl} hops: {reply_packet[IP].src}")

        ttl += 1

user_input = argparse_input()
traceroute(user_input.target)