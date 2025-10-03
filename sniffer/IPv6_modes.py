from scapy.all import *
import hashlib
import ipaddress
import configparser
import hmac
import config_search
import re
ipv6_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read(config_search.search_config())
hashIpv6=config.get('General','HashIpv6',fallback='Secreto')
regex=config.get('General','RegexIpv6',fallback=None)
repl=config.get('General','ReplIpv6',fallback=None)
mask_bits=config.getint('General','MaskBitsIpv6',fallback=64)

def regexf(packet):
    if IPv6 in packet:
        if regex and repl:
            packet[IPv6].src = re.sub(regex, repl, packet[IPv6].src)
            packet[IPv6].dst = re.sub(regex, repl, packet[IPv6].dst)
    return packet

def randomipv6(packet):
    if IPv6 in packet:
        packet[IPv6].src = ipaddress.IPv6Address(random.randint(0, 2**128 - 1))
        packet[IPv6].dst = ipaddress.IPv6Address(random.randint(0, 2**128 - 1))
    return packet

def mask(packet):
    if IPv6 in packet:
        def mask_ipv6(ip, mask_bits=64):
            ip_int = int(ipaddress.IPv6Address(ip))
            mask = ((1 << 128) - 1) ^ ((1 << (128 - mask_bits)) - 1)
            return ipaddress.IPv6Address(ip_int & mask)
        packet[IPv6].src = mask_ipv6(packet[IPv6].src, mask_bits)
        packet[IPv6].dst = mask_ipv6(packet[IPv6].dst, mask_bits)
    return packet
def hash(packet):
    if IPv6 in packet:
        ip_org = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        
        hashed_ip_src = hmac.new(hashIpv6.encode(), ip_org.encode(), hashlib.sha256).hexdigest()
        hashed_ip_dst = hmac.new(hashIpv6.encode(), ip_dst.encode(), hashlib.sha256).hexdigest()

        packet[IPv6].src = ipaddress.IPv6Address(int(hashed_ip_src[:32], 16))
        packet[IPv6].dst = ipaddress.IPv6Address(int(hashed_ip_dst[:32], 16))

    return packet

def map(packet):
    global counter
    if IPv6 in packet:
        ip_org = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        if ip_org not in ipv6_mapping:
            ipv6_mapping[ip_org] = ipaddress.IPv6Address(counter)
            counter += 1
        packet[IPv6].src = ipv6_mapping[ip_org]
        if ip_dst not in ipv6_mapping:
            ipv6_mapping[ip_dst] = ipaddress.IPv6Address(counter)
            counter += 1
        packet[IPv6].dst = ipv6_mapping[ip_dst]
    return packet  

def zero(packet):
    if IPv6 in packet:
        packet[IPv6].src = ipaddress.IPv6Address(0)
        packet[IPv6].dst = ipaddress.IPv6Address(0)
    return packet  

modes6 = {
    "first-seen": map,
    "hash": hash,
    "zero": zero,
    "mask": mask,
    "random": randomipv6,
    "regex": regexf,
}

