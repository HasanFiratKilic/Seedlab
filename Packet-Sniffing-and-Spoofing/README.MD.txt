Tasks and instructions : [https://seedsecuritylabs.org/Labs_20.04/Files/Sniffing_Spoofing/Sniffing_Spoofing.pdf]

# Task 1

## Task 1.1: Sniffing Packets
Running sudo captured the package and printed the information inside. For example when pinging:
https://seedsecuritylabs.org/

    ###[ Ethernet ]###    dst       = 02:42:5b:c3:a6:9b   src       = 02:42:0a:09:00:06   type      = IPv4
    ###[ IP ]### 
         version   = 4
         ihl       = 5
         tos       = 0x0
         len       = 84
         id        = 10321
         flags     = DF
         frag      = 0
         ttl       = 64
         proto     = icmp
         chksum    = 0xe0e8
         src       = 10.9.0.6
         dst       = 185.199.109.153
         \options   \
    ###[ ICMP ]### 
            type      = echo-request
            code      = 0
            chksum    = 0x82
            id        = 0x29
            seq       = 0x1
    ###[ Raw ]### 
               load      = '\xd6)Cg\x00\x00\x00\x00\x12\xf0\x0c\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
Scapy requires administrative (root) permissions to listen to packets on the network interface using raw sockets. If you run this code as a normal user, you will encounter this error.

    Traceback (most recent call last):
      File "snf.py", line 10, in <module>
        pkt = sniff(iface=iface[1], filter="icmp", prn=print_pkt)
      File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 1036, in sniff
        sniffer._run(*args, **kwargs)
      File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 906, in _run
        sniff_sockets[L2socket(type=ETH_P_ALL, iface=iface,
      File "/usr/local/lib/python3.8/dist-packages/scapy/arch/linux.py", line 398, in __init__
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))  # noqa: E501
      File "/usr/lib/python3.8/socket.py", line 231, in __init__
        _socket.socket.__init__(self, family, type, proto, fileno)
    PermissionError: [Errno 1] Operation not permitted

## Task 1.1B.

Ref to the  [documentation](https://scapy.readthedocs.io/en/latest/usage.html#generating-sets-of-packets)  of module  `scapy`  and  [BPF syntax](https://biot.com/capstats/bpf.html), I can pass the following strings as argument  `filter`  in  `sniff`:

-   `proto icmp`  /  `icmp`
-   `tcp dst port 23 and src host x.x.x.x`
-   `net 128.230.0.0/16`
## Task 1.2: Spoofing ICMP Packets

    from scapy.all import *
    import argparse
    import random
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
-   Kullanıcıdan üç argüman alır:
    -   `-t` or `--target`: Destination IP address.
    -   `-s` or `--source`: Fake source IP address.
    -   `-c` or `--count`: The number of packets to send (10 by default).

To run this program, you can use a command like the following in the terminal:
`python3 Spoofing_ICMP.py -t 10.9.0.6 -s 192.168.5.6`
Output on wireshark:
seed.jpg


