#!/usr/bin/env python3
from scapy.all import *
import sys

print("Starting SCAPY")

print(get_if_list())

sniff(iface='eth0',prn=Packet.summary,store=0)