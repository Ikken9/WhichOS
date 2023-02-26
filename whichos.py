#!/usr/bin/python3

from scapy.all import *
import ipaddress
import sys

from scapy.layers.inet import IP, ICMP  # For some reason Windows is not capable of recognize these modules with the
# scapy.all import


def check_input():
    try:
        ip = sys.argv[1]
        return ipaddress.ip_address(ip).exploded
    except:
        print("[!] Syntax error, enter a valid IP address")
        print("[*] Usage: whichos <ip-address>")
        sys.exit()


def guess_os(ip):
    pkt_size = 64
    ttl_array = [32, 64, 128]

    for ttl in ttl_array:
        pkt = IP(dst=ip, ttl=ttl) / ICMP() / Raw(load=b"X" * pkt_size)
        response = sr1(pkt, timeout=1, verbose=0)
        if response:
            print("[*] TTL: " + str(response.ttl))
            if response.ttl <= 64:
                print("[*] Linux/Unix Operating System")
            elif 64 < response.ttl <= 128:
                print("[*] Windows Operating System")
            else:
                print("[*] Unknown Operating System")
            break


if __name__ == '__main__':
    guess_os(check_input())
