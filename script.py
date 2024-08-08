import socket
from urllib.request import urlopen
import re
import netifaces
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def get_public_ip():
    """Obtain host's Public IP"""
    # Urllib.request is a Python module for fetching URLs
    raw_ip = str(urlopen('http://checkip.dyndns.com/').read())
    # Create the IP address's pattern and then seek for it in the fetched string
    pattern = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.\d{1,3}"
    return re.findall(pattern, raw_ip)[0]


def get_private_ip():
    """Obtain host's private IP"""
    # Initialize net_value to None, so if no interfaces, and thus addresses are present, the method returns this string.
    net_value = "None"
    # List of interface identifiers for your machine.
    net_int = netifaces.interfaces()
    # Removing the loopback interface from the list.
    # net_int.remove("lo") --> REMOVED: Just select net_int[1] that is always the interfaces with IPv4 private address.
    # If at least one interface exist, and so the list net_int is not empty, the method enters this statement
    if net_int:
        # Check the address of a particular interface.
        net_value = netifaces.ifaddresses(net_int[1])
        # 2 is AF_INET (normal Internet addresses), 0 is the position of the last dictionary in the list, addr is the
        # key of the last dictionary, that contains the IP Address
    return net_value[2][0]["addr"], net_value[2][0]["netmask"]


def convert_mask_dec_to_bin(mask):
    # Split and convert every octet in an int value. Then, add every octet (4 in total) in a list.
    split_mask = list(map(int, mask.split(".", 4)))
    # Initialize a list than is going to be fill with four binary octet
    mask_bit = []
    # If the mask exist and is not empty
    while split_mask:
        value = split_mask.pop(0)
        if value != 0:
            # The bin() method converts a specified integer number to its binary representation and returns it.
            # It is needed to remove the prefix that indicates that what bin return is a string and not an int!
            fragment = bin(value).removeprefix("0b")
            if len(fragment) < 8:
                # Every octet must have eight element. For smaller number than 128, a varying quantity of zero has to be
                # added.
                fragment = (8 - len(fragment)) * "0" + fragment
                mask_bit.append(fragment)
            else:
                # If the number is higher than 127, just add the number to the list.
                mask_bit.append(fragment)
        else:
            # str.zfill(width) @ Return the numeric string left filled with zeros in a string of length width. A sign
            # prefix is handled correctly. The original string is returned if width is less than or equal to len(s)
            mask_bit.append("".zfill(8))
    # Define a delimiter
    delimiter = ""
    # The .join() method can concatenate list elements into a single string based on a delimiter
    # THus, count is used to enumerate the number of zeros that the mask has got.
    no_zeros = delimiter.join(mask_bit).count("0")
    no_hosts = abs(2 ** no_zeros - 2)
    mask_dec = str(32 - no_zeros)
    return no_hosts, mask_dec


def calculate_network(address, net_mask):
    """Calculate the network address to which the host belongs"""
    # Initialize the list that is going to contain the four octet
    net_addr = []
    network_addr = ""
    split_mask = list(map(int, net_mask.split(".", 4)))
    split_addr = list(map(int, address.split(".", 4)))
    while split_addr:
        # The result of the bitwise AND operation of IP address and the subnet mask is the network prefix
        value = split_mask.pop(0) & split_addr.pop(0)
        net_addr.append(str(value))
        delimiter = "."
        network_addr = delimiter.join(net_addr)
    return network_addr


def hostname(addr):
    """Get the hostname through the use of getnameinfo function in built-in socket module"""
    # Need to provide a host+port tuple, but you can provide 0 for the port, and you'll get the hostname back.
    name = socket.getnameinfo((addr, 0), 0)
    # If no parenthesis, it gives back the whole tuple, port included.
    return name[0]


def scan(ip, mask):
    arp_request = ARP(pdst=ip+"/"+mask)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    ask_list = srp(packet, timeout=1, verbose=False)[0]

    packet_list = []
    for i in ask_list:
        packet_dict = {"IP Address": i[1].psrc, "MAC Address": i[1].hwsrc}
        packet_list.append(packet_dict)
    for element in packet_list:
        ip_host = element["IP Address"]
        name = hostname(ip_host)
        element["Hostname"] = name
    return packet_list
