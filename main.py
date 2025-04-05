import scapy.all as scapy
import constants
import time
import sys

def get_arp_table(ip_range):
    """Scans the network and retrieves the ARP table."""
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        answered, _ = scapy.srp(packet, timeout=2, verbose=0)
    except Exception as e:
        print(f"Error sending ARP request : {e}")
        sys.exit(1)

    arp_table = {}
    for _, received in answered:
        try:
            ip = received.psrc
            mac = received.hwsrc
            arp_table[ip] = mac
        except AttributeError:
            print("Malformed ARP response received. Skipping...")
            continue

    return arp_table

def detect_arp_spoofing(arp_table):
    """Detects ARP spoofing and identifies attacker/victim."""
    mac_to_ip = {}
    ip_to_mac = {}

    for ip, mac in arp_table.items():
        ip_to_mac[ip] = mac
        mac_to_ip.setdefault(mac, []).append(ip)

    spoofed_macs = {mac: ips for mac, ips in mac_to_ip.items() if len(ips) > 1}

    if spoofed_macs:
        print("Potential ARP Spoofing Detected!\n")
        for mac, ips in spoofed_macs.items():
            victim_ip = ips[0]
            attacker_ips = ips[1:]

            print(f"Spoofed MAC: {mac}")
            print(f"Victim: IP {victim_ip}, MAC {mac}")
            for attacker_ip in attacker_ips:
                print(f"Attacker: IP {attacker_ip}, MAC {mac}")
            print("-" * 50)
    else:
        print("No ARP Spoofing Detected.")

if __name__ == "__main__":
    network_range = constants.network_range
    first_table = get_arp_table(network_range)
    print(first_table)

    try:
        while True: 
            detect_arp_spoofing(get_arp_table(network_range))
            time.sleep(0.03)
    except KeyboardInterrupt:
        print("\nScript stopped by user. Exiting...")
        sys.exit(0)