#!/usr/bin/env python3
import os
import socket
from netfilterqueue import NetfilterQueue

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP

from scapy.all import *

print("Starting SCAPY-Script")


# Source: https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
# modified by simon stockhause
# Checked: 27.01.2020

iptablesr = "iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0"
print("Adding uptable rules: ")
print(iptablesr)
os.system(iptablesr)

print("Set ipv4 forward settings: ")
os.system("sysctl net.ipv4.ip_forward=1")

def callback(packet):
    pkt_obj = IP(packet.get_payload())
   # if(pkt_obj.haslayer(Raw) and pkt_obj.haslayer(TCP)):
    if(pkt_obj.haslayer(WebSocket) and pkt_obj.haslayer(TCP)):
        #pkt_obj = WebSocket(packet)
        ip_src = pkt_obj[IP].src
        ip_dst = pkt_obj[IP].dst
        print(ip_src + " -> " + ip_dst)
        if(pkt_obj[TCP].dport == 8090):
            #ws = pkt_obj[WebSocket]
            print("Got a Websocket Packet:: ")
            pkt_obj[WebSocket].show()            
            #packet.set_payload(str(pkt_obj))
            packet.accept()
            #if you want to modify the packet, copy and modify it with scapy then do:
            # payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))
    else:
        packet.accept()

def main():
    # this is the intercept

    #bind Websocket on top of TCP layer and tells to bind to port 8090
    load_layer("WebSocket")
    bind_layers(TCP, WebSocket,dport=8090)
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

