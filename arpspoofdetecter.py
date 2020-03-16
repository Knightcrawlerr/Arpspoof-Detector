#!/usr/bin/python3.8

from scapy.all import *
from scapy.layers.l2 import *
from termcolor import cprint


def get_mac(ip):
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), verbose=False)[0]
    return ans[0][1].hwsrc


def sniffer(interface):
    sniff(iface=interface, store=False, prn=process_sniff)


def process_sniff(packets):
    if packets.haslayer(ARP) and packets[ARP].op == 2:
        try:
            real_mac = get_mac(packets[ARP].psrc)
            response_mac = packets[ARP].hwsrc

            if real_mac != response_mac:
                cprint("[-] Arpspoofing Detected", "red")
        except IndexError:
            pass


sniffer('eth0')
