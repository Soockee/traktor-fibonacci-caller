#!/usr/bin/env python3
import os
import socket
from netfilterqueue import NetfilterQueue

from scapy.all import *

print("Starting SCAPY-Script")


# Source: https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
# modified by simon stockhause
# Checked: 27.01.2020

iptablesr = "iptables -A OUTPUT -j NFQUEUE --queue-num 0"
print("Adding uptable rules: ")
print(iptablesr)
os.system(iptablesr)

print("Set ipv4 forward settings: ")
os.system("sysctl net.ipv4.ip_forward=1")

def callback(packet):
    data = packet.get_payload()
    pkt_obj = IP(data)
    print("Got a packet from: " + str(pkt_obj.src) + " to :" + str(pkt_obj.dst))

    packet.set_payload(str(pkt_obj))
    packet.accept()
    #if you want to modify the packet, copy and modify it with scapy then do:
    # payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))

def main():
    # this is the intercept
    q = NetfilterQueue()
    q.bind(0,callback)
    s = socket.fromfd(q.get_fd(),socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        q.run_socket(s) # blocking
    except KeyboardInterrupt:
        q.unbind()
        print("flushing iptables")
      #  os.system('iptables -F')
      #  os.system('iptables -X')
if __name__ == "__main__":
    main()
# sniff(iface='eth0',filter= ,prn=Packet.summary,store=0)

