from scapy.all import ARP, Ether, srp
import constants

def scan_network(ip_range):
    """Scans the network and returns detected devices."""
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    answered, _ = srp(packet, timeout=3, verbose=0)

    devices = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def main():
    # Step 1: Define the test network range
    test_network = constants.network_range  # Adjust based on your network

    # Step 2: Execute the scanner
    print("🔍 Scanning network...")
    detected_devices = scan_network(test_network)

    # Step 3: Display the results
    if detected_devices:
        print("\n✅ Devices Found:")
        for device in detected_devices:
            print(f"IP: {device['ip']} \t MAC: {device['mac']}")
    else:
        print("\nNo devices detected. Check your network settings.")

    print("\n🎯 Test complete!")