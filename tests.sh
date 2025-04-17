#!/bin/bash
/bin/python sniffer.py &
sleep 5
hping3 -c 50000 -i u1 127.0.0.1 -q &
timeout 10 tcpdump -w "a.pcap" -i lo
sleep 20