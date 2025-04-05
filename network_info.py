import netifaces # pip install netifaces
import ipaddress

def get_network_range() -> str:
    # Get the default interface used for internet
    default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][1]
    interface_info = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]

    ip = interface_info['addr']
    netmask = interface_info['netmask']

    # Calculate network range
    network = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    return network