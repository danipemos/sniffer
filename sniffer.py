from scapy.all import *
import argparse
import time
import os
import sys
import threading
import configparser
import pcapy
from ctypes import *
import IPv6_modes
import Mac_modes
import Ip_modes
import cipher
import send
import argparse
import requests
import json

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts_sec", ctypes.c_long),
                ("ts_usec", ctypes.c_long),
                ("caplen", ctypes.c_uint),
                ("len", ctypes.c_uint)]

class Packet(ctypes.Structure):
    _fields_ = [("header", pcap_pkthdr),
                ("data", ctypes.POINTER(ctypes.c_ubyte))]

ip_mapping = {}
counter = 1
start_time = time.time()
packet_counter=defaultdict(int)
total_bytes=0
last_pcap_time=time.time()
session_dict={}
event = threading.Event()
packetQueue=queue.Queue()
cipher_event= threading.Event()
list_protocols=["IP","IPv6","MAC"]

list_send=["WEB","DISK","FTP","S3","WEBDAV","SFTP","SCP"]

headers = {
    "ip": [IP],
    "ipv6": [IPv6],
    "network": [IP,IPv6],
    "tcp": [TCP],
    "udp": [UDP],
    "icmp": [ICMP],
    "transport": [TCP, UDP, ICMP],
    "dns": [DNS],
    "none": [],
}

protocol_list=[IP,IPv6,UDP,TCP,ICMP,DNS]


def get_pcap_name():
    pcap_filename=f"capture_{time.strftime('%Y%m%d_%H%M%S', time.localtime())}.pcap"
    PcapWriter(pcap_filename,sync=True)
    return pcap_filename

pcap_filename=get_pcap_name()


def process_pcap():
    global pcap_filename
    last_pcap_name=pcap_filename
    pcap_filename=get_pcap_name()
    filename=cipher.ciphers_modes.get(cipher)(last_pcap_name)
    for loc in location:
        send.send_modes.get(loc)(filename)
    if not disk:
        os.remove(filename)

def rotation():
    global last_pcap_time,pcap_filename
    while not cipher_event.is_set():
        if (size) and (os.path.exists(pcap_filename) and (os.path.getsize(pcap_filename)) > size):
            if rotate:
                last_pcap_time=time.time()
            process_pcap()
        if rotate and ((time.time()-last_pcap_time)>rotate):
            last_pcap_time=time.time()
            process_pcap()
        if packages_pcap and (os.path.exists(pcap_filename) and (count_packets_pcap()>= packages_pcap)):
            if rotate:
                last_pcap_time=time.time()
            process_pcap()
        time.sleep(0.01)
    process_pcap()
    cipher_event.set()

def procces_packet(packet):
    global pcap_filename
    global total_bytes
    total_bytes+=len(packet)
    global packet_counter,last_pcap_time
    packet_counter["Total Packets"]+=1
    src_ip = None
    dst_ip = None
    if "MAC" in protocols:
        packet=Mac_modes.modesMac.get(macmode)(packet)
    if IP in packet:
        if "IP" in protocols:
            packet = Ip_modes.anon.get(mode)(packet)
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
    if IPv6 in packet:
        if "IPv6" in protocols:
            packet = IPv6_modes.modes6.get(ipv6mode)(packet)
        src_ip = packet["IPv6"].src
        dst_ip = packet["IPv6"].dst
    if src_ip and dst_ip:
        for protocol in headers["transport"]:
            if protocol in packet:
                protocol_name=protocol.__name__
                src_port = ":"+str(packet.sport) if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
                dst_port = ":"+str(packet.dport) if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
                key = protocol_name,src_ip,src_port,dst_ip,dst_port
                inverse_key=protocol_name,dst_ip,dst_port,src_ip,src_port
                if key not in session_dict and inverse_key not in session_dict:
                    session_dict[key] = {"packet count": 0, "total_size": 0}
                if key in session_dict:
                    session_dict[key]["packet count"] += 1
                    session_dict[key]["total_size"] += len(packet)
                else:
                    session_dict[inverse_key]["packet count"] += 1
                    session_dict[inverse_key]["total_size"] += len(packet)        
        header_del_list = headers.get(header_ptr)
        for protocol in protocol_list:
            if protocol in packet:
                packet_counter[f"Total Packets {protocol.__name__}"] += 1  
                if protocol in header_del_list :
                    packet[protocol].remove_payload()
    wrpcap(pcap_filename,packet,append=True,sync=True)
    
def format_time(seconds):
    hrs, rem = divmod(seconds, 3600)
    mins, secs = divmod(rem, 60)
    return f"{int(hrs):02}:{int(mins):02}:{int(secs):02}"

def stadistics():
    global last_pcap_time,pcap_filename
    if config.has_section('WEB'):
        host=config.get('WEB','Server')
        port=config.getint('WEB','Port',fallback=80)
        URL="http://"+host+":"+str(port)+"/monitorize/api/stats/"
        hostname=os.uname().nodename

    while cipher_event:
        elapsed_time = time.time() - start_time
        stats_data = {
            "elapsed_time": format_time(elapsed_time),
            "total_packets": dict(packet_counter),
            "total_megabytes": total_bytes / 1048576,
            "bandwidth_mbps": (total_bytes * 8) / elapsed_time / 1048576 if elapsed_time > 0 else 0,
            "sessions": []
        }

        for session_key, session_data in list(session_dict.items()):
            session_info = {
                "protocol": session_key[0],
                "src_ip": session_key[1],
                "src_port": session_key[2],
                "dst_ip": session_key[3],
                "dst_port": session_key[4],
                "packet_count": session_data["packet count"],
                "total_size_kb": session_data["total_size"] / 1024
            }
            stats_data["sessions"].append(session_info)
        if event.is_set():
            stats_data["processing_packets"] = "Processing last packets"
        if config.has_section('WEB'):
            requests.post(f"{URL}{hostname}/",json.dumps(stats_data), headers={"Content-Type": "application/json"})
        else:
            print(stats_data)
        time.sleep(0.1)


def count_packets_pcap():
    global pcap_filename
    count=0
    cap = pcapy.open_offline(pcap_filename)
    while True:
        try:
            (hdr, pkt) = cap.next()
            if not hdr:
                break
            count+=1
        except pcapy.PcapError:
            break
    return count

def packet_thread():
    while not event.is_set() or not sni.empty():
        packet_ptr=sni.dequeue()
        if packet_ptr:
            packet = packet_ptr.contents
            header=packet.header
            data_len = header.len
            data_ptr=packet.data
            data=bytes(data_ptr[:data_len])
            scapy_packet=Ether(data)
            scapy_packet.time= (header.ts_sec + header.ts_usec / 1000000.0)
            procces_packet(scapy_packet)
            sni.free_packet(packet_ptr)

def valid_option(config,section,option,fallback,valid_values):
    value=config.get(section,option,fallback=fallback)
    if value not in valid_values:
        raise ValueError(f"'{option}' must be one of {valid_values}, providied '{value}'")
    return value

def finish(signum,frame):
    event.set()
    while not cipher_event.is_set():
        time.sleep(0.1)
        continue

def match_regular_expression_size(size):
    if size is None:
        return 0
    regex = r'^(\d+(\.\d+)?)([KMG])$'
    match=re.match(regex, size)
    if match:
        str_size, _, unit = match.groups()
        size=float(str_size)
        units = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
        bytes=int(size*units[unit])
        return bytes
    else:
        raise argparse.ArgumentTypeError(f"Invalid size: {size}. Examples (5K, 8.9M, 100.25G).")
    
def match_regular_expression_time(time):
    if time is None:
        return 0
    regex = r"(\d+)([DHMS])"
    matches = re.findall(regex, time)
    total_time = 0
    for match in matches:
        str_time, unit = match
        int_time = int(str_time)
        units = {'D': 86400, 'H': 3600, 'M': 60, 'S': 1}
        total_time += int_time * units[unit]
    if total_time == 0:
        raise argparse.ArgumentTypeError(f"Invalid time: {time}. Examples (5D, 2H, 30M, 100S, 4D20M).")
    return total_time

def sniffing():
    iface=interface.encode("utf-8")
    bpf_filter=filter_bpf.encode("utf-8")
    sni.start_capture(iface,bpf_filter,timeout,total_packages,total_lenght)

def configure_c():
    sni.empty.restype=ctypes.c_int
    sni.dequeue.restype = ctypes.POINTER(Packet)
    sni.free_packet.argtypes=[ctypes.POINTER(Packet)]
    sni.start_capture.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_int,ctypes.c_int]

def validate_protocols(protocols):
    lista = protocols.split(",") if protocols else []
    if set(lista).issubset(list_protocols):
        return lista
    else:
        argparse.ArgumentTypeError(f"Protocols must be a combination of {', '.join(list_protocols)}")

def validate_send(send):
    lista=send.split(",") if send else []
    if set(lista).issubset(list_send):
        return lista
    else:
        argparse.ArgumentTypeError(f"Send must be a combination of {', '.join(list_send)}")

def print_help_file():
    help_file = "help.txt" 
    if os.path.exists(help_file):
        with open(help_file, "r") as file:
            print(file.read())
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.format_help = print_help_file
    args = parser.parse_args()
    config=configparser.ConfigParser()
    sni=ctypes.CDLL("/home/kali/Desktop/TFG-main/liba.so")
    configure_c()
    try:
        config.read('config.ini')
        mode=valid_option(config,'General','Mode','map',list(Ip_modes.anon.keys()))
        header_ptr=valid_option(config,'General','Header','none',list(headers.keys()))
        interface=valid_option(config,'General','Interface','eth0',get_if_list())
        macmode=valid_option(config,'General','MacMode','map',list(Mac_modes.modesMac.keys()))
        ipv6mode=valid_option(config,'General','IPv6Mode','map',list(IPv6_modes.modes6.keys()))
        timeout=match_regular_expression_time(config.get('General','Timeout',fallback=None))
        total_packages=config.getint('General','TotalPackages',fallback=0)
        total_lenght=match_regular_expression_size(config.get('General','TotalLenght',fallback=None))
        packages_pcap=config.getint('General','PackagesPcap',fallback=0)
        rotate=match_regular_expression_time(config.get('General','RotateTime',fallback=None))
        filter_bpf=config.get('General','BPF',fallback="")
        size=match_regular_expression_size(config.get('General','Size',fallback=None))
        protocols=validate_protocols(config.get('General','Protocols',fallback=None))
        cipher=valid_option(config,'General','Cipher',"none",list(cipher.ciphers_modes.keys()))
        disk=config.getboolean('General','Disk',fallback=True)
        location=validate_send(config.get('General','Send',fallback=None))
        stats_thread = threading.Thread(target=stadistics, daemon=True)
        stats_thread.start() 
        worker = threading.Thread(target=packet_thread, daemon=True)
        worker.start()
        rotate_thread= threading.Thread(target=rotation, daemon=True)
        rotate_thread.start()
        sniffing()
        finish(None,None)
        sni.free_queue()
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sni.free_queue()
        sys.exit(1)
