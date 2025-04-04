import scapy.all as scapy
import constants

def get_arp_table(ip_range):
    """Scans the network and retrieves the ARP table."""
    arp_request = scapy.ARP(pdst=ip_range)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    answered, _ = scapy.srp(packet, timeout=2, verbose=0)

    arp_table = {}
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        arp_table[ip] = mac
    return arp_table

target_ip = constants.target_ip
print(get_arp_table(target_ip))