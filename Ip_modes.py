from scapy.all import *
import hashlib
import ipaddress
import configparser
import hmac
ip_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read('/etc/sniffer/config.ini')
hashipv4=config.get('General','HashIpv4',fallback='Secreto')


def hash(packet):
    if IP in packet:
        ip_org = packet[IP].src
        ip_dst = packet[IP].dst
        hashed_ip_src = hmac.new(hashipv4.encode(), ip_org.encode(), hashlib.sha256).hexdigest()
        hashed_ip_dst = hmac.new(hashipv4.encode(), ip_dst.encode(), hashlib.sha256).hexdigest()
        packet[IP].src = ipaddress.IPv4Address(int(hashed_ip_src[:8],16))
        packet[IP].dst = ipaddress.IPv4Address(int(hashed_ip_dst[:8],16))
    return packet  

def map(packet):
    global counter
    if IP in packet:
        ip_org = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_org not in ip_mapping:
            ip_mapping[ip_org] = counter
            counter += 1
        packet[IP].src = ip_mapping[ip_org]
        if ip_dst not in ip_mapping:
            ip_mapping[ip_dst] = counter
            counter += 1
        packet[IP].dst = ip_mapping[ip_dst]
    return packet  

def zero(packet):
    if IP in packet:
        packet[IP].src = 0
        packet[IP].dst = 0
    return packet  

anon = {
    "map": map,
    "hash": hash,
    "zero": zero,
}