import scapy.all as scapy             # For sending and receiving low-level network packets
import network_info                   # Custom module to get the local network range
import time                           # For adding delay in the loop
import sys                            # For exiting the program in case of error or interruption
import keyboard                       # To detect if the user presses 'q' to quit the loop

def get_arp_table(ip_range):
    """
    Scans the network and retrieves the ARP table (IP to MAC mapping).
    Sends an ARP request to the given IP range and collects responses.
    """
    try:
        # Create an ARP request packet for the given IP range
        arp_request = scapy.ARP(pdst=ip_range)

        # Create an Ethernet frame with broadcast MAC address
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine Ethernet frame and ARP request into a complete packet
        packet = ether_frame / arp_request

        # Send the packet and wait for responses (srp = send and receive at Layer 2)
        answered, _ = scapy.srp(packet, timeout=2, verbose=0)
    except Exception as e:
        # Handle any exceptions while sending packets
        print(f"Error sending ARP request : {e}")
        sys.exit(1)

    # Initialize an empty dictionary to store IP-MAC mappings
    arp_table = {}

    # Loop through the responses received from devices on the network
    for _, received in answered:
        try:
            # Extract source IP and MAC address from the response
            ip = received.psrc
            mac = received.hwsrc
            arp_table[ip] = mac
        except AttributeError:
            # In case of malformed response, skip the entry
            print("Malformed ARP response received. Skipping...")
            continue

    return arp_table


def detect_arp_spoofing(arp_table):
    """
    Detects ARP spoofing by analyzing the ARP table.
    Looks for a MAC address that is associated with multiple IPs.
    """
    mac_to_ip = {}  # Dictionary mapping MAC → list of IPs
    ip_to_mac = {}  # Dictionary mapping IP → MAC (for reference)

    # Build both IP→MAC and MAC→IPs mappings
    for ip, mac in arp_table.items():
        ip_to_mac[ip] = mac
        mac_to_ip.setdefault(mac, []).append(ip)

    # Find MAC addresses that are associated with more than one IP
    spoofed_macs = {mac: ips for mac, ips in mac_to_ip.items() if len(ips) > 1}

    if spoofed_macs:
        print("Potential ARP Spoofing Detected!\n")
        for mac, ips in spoofed_macs.items():
            # First IP is assumed to be the real device (victim)
            victim_ip = ips[0]
            attacker_ips = ips[1:]  # Other IPs are likely spoofed

            print(f"Spoofed MAC: {mac}")
            print(f"Victim: IP {victim_ip}, MAC {mac}")

            # Display each spoofing attacker using same MAC
            for attacker_ip in attacker_ips:
                print(f"Attacker: IP {attacker_ip}, MAC {mac}")
            
            print("-" * 50)
    else:
        print("No ARP Spoofing Detected.")

if __name__ == "__main__":
    network_range = network_info.get_network_range()

    # Get the initial ARP table (optional first check / can be removed)
    first_table = get_arp_table(network_range)
    print(first_table)

    try:
        while True: 
            # Scan the network and check for spoofing
            detect_arp_spoofing(get_arp_table(network_range))

            # Wait for a short interval before the next scan
            time.sleep(0.03)

            if keyboard.is_pressed('q'):
                break

    except KeyboardInterrupt:
        # Handle user interrupt (Ctrl+C)
        print("\nScript stopped by user. Exiting...")
        sys.exit(0)
