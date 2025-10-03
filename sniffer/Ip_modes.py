from scapy.all import *
import hashlib
import ipaddress
import configparser
import hmac
import config_search
import re
ip_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read(config_search.search_config())
hashipv4=config.get('General','HashIpv4',fallback='Secreto')
regex=config.get('General','RegexIpv4',fallback=None)
repl=config.get('General','ReplIpv4',fallback=None)

def regexf(packet):
    if IP in packet:
        if regex and repl:
            packet[IP].src = re.sub(regex, repl, packet[IP].src)
            packet[IP].dst = re.sub(regex, repl, packet[IP].dst)
    return packet

def randomip(packet):
    if IP in packet:
        packet[IP].src = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        packet[IP].dst = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
    return packet

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

def mask(packet):
    if IP in packet:
        def mask_ip(ip):
            ip_int = int(ipaddress.IPv4Address(ip))
            first_octet = (ip_int >> 24) & 0xFF
            # Clase A: 1.0.0.0 - 126.255.255.255
            if 1 <= first_octet <= 126:
                mask = 0xFF000000  # Solo primer octeto
            # Clase B: 128.0.0.0 - 191.255.255.255
            elif 128 <= first_octet <= 191:
                mask = 0xFFFF0000  # Primeros dos octetos
            # Clase C: 192.0.0.0 - 223.255.255.255
            elif 192 <= first_octet <= 223:
                mask = 0xFFFFFF00  # Primeros tres octetos
            # Clase D (Multicast): 224.0.0.0 - 239.255.255.255
            elif 224 <= first_octet <= 239:
                mask = 0xF0000000  # Solo primer nibble (no tiene host, pero se enmascara todo menos el tipo)
            else:
                mask = 0x00000000  # Otras clases, todo a 0
            return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(ip)) & mask))
        packet[IP].src = mask_ip(packet[IP].src)
        packet[IP].dst = mask_ip(packet[IP].dst)
    return packet

anon = {
    "first-seen": map,
    "hash": hash,
    "zero": zero,
    "random": randomip,
    "regex": regexf,
    "mask": mask,
}
