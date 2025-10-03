import hmac
import hashlib
from scapy.all import *
import re
import configparser
import config_search
mac_mapping = {}
counter = 1
config=configparser.ConfigParser()
config.read(config_search.search_config())
hashIpv6=config.get('General','HashMac',fallback='Secreto')
import random
regex_mac = config.get('General','RegexMac',fallback=None)
repl_mac = config.get('General','ReplMac',fallback=None)

def regexf(packet):
    if Ether in packet:
        if regex_mac and repl_mac:
            packet[Ether].src = re.sub(regex_mac, repl_mac, packet[Ether].src)
            packet[Ether].dst = re.sub(regex_mac, repl_mac, packet[Ether].dst)
    return packet

def randomf(packet):
    if Ether in packet:
        def rand_mac():
            return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
        packet[Ether].src = rand_mac()
        packet[Ether].dst = rand_mac()
    return packet

def mask(packet):
    if Ether in packet:
        def mask_mac(mac):
            # Mantener solo los 3 primeros octetos, resto a 00
            parts = mac.split(':')
            if len(parts) == 6:
                return parts[0] + ':' + parts[1] + ':' + parts[2] + ':00:00:00'
            return mac
        packet[Ether].src = mask_mac(packet[Ether].src)
        packet[Ether].dst = mask_mac(packet[Ether].dst)
    return packet

def hash(packet):
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        
        hashed_mac_src = hmac.new(hashIpv6.encode(), mac_src.encode(), hashlib.sha256).hexdigest()
        hashed_mac_dst = hmac.new(hashIpv6.encode(), mac_dst.encode(), hashlib.sha256).hexdigest()
        
        packet[Ether].src = ':'.join(hashed_mac_src[i:i+2] for i in range(0, 12, 2))
        packet[Ether].dst = ':'.join(hashed_mac_dst[i:i+2] for i in range(0, 12, 2))
    return packet

def int_to_mac(macint):
    return  ":".join(re.findall("..", "%012x"%macint))

def map(packet):
    global counter
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        
        if mac_src not in mac_mapping:
            mac_mapping[mac_src] = int_to_mac(counter)
            counter += 1
        packet[Ether].src = mac_mapping[mac_src]
        
        if mac_dst not in mac_mapping:
            mac_mapping[mac_dst] = int_to_mac(counter)
            counter += 1
        packet[Ether].dst = mac_mapping[mac_dst]
    return packet

def zero(packet):
    if Ether in packet:
        packet[Ether].src = '00:00:00:00:00:00'
        packet[Ether].dst = '00:00:00:00:00:00'
    return packet

modesMac = {
    "first-seen": map,
    "hash": hash,
    "zero": zero,
    "regex": regexf,
    "random": randomf,
    "mask": mask,
}
