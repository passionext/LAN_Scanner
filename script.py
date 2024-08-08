from urllib.request import urlopen
import re
import netifaces
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def get_public_ip():
    """Obtain host's Public IP"""
    raw_ip = str(urlopen('http://checkip.dyndns.com/').read())
    pattern = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.\d{1,3}"
    return re.findall(pattern, raw_ip)


def get_private_ip():
    """Obtain host's private IP"""
    # Initialize net_value to None, so if no interfaces, and thus addresses are present, the method returns this string.
    net_value = "None"
    # List of interface identifiers for your machine.
    net_int = netifaces.interfaces()
    # Removing the loopback interface from the list.
    net_int.remove("lo")
    # If at least one interface exist, and so the list net_int is not empty, the method enters this statement
    if net_int:
        for element in net_int:
            # Check the address of a particular interface.
            net_value = netifaces.ifaddresses(element)
        # 2 is AF_INET (normal Internet addresses), 0 is the position of the last dictionary in the list, addr is the
        # key of the last dictionary, that contains the IP Address
        return net_value[2][0]["addr"], net_value[2][0]["netmask"]


print(get_public_ip())
addr, mask = get_private_ip()


def convert_mask_dec_to_bin():
    a = list(map(int, mask.split(".", 4)))
    mask_bit = []
    print(a)
    while a:
        cifra = a.pop(0)
        if cifra != 0:
            mask_bit.append(bin(cifra).removeprefix("0b"))
        else:
            # str.zfill(width) @ Return the numeric string left filled with zeros in a string of length width. A sign
            # prefix is handled correctly. The original string is returned if width is less than or equal to len(s).
            mask_bit.append("".zfill(8))
        return mask_bit


def calculate_network(addr, mask):
    networkl = []
    a = list(map(int, mask.split(".", 4)))
    addrlist = list(map(int, addr.split(".", 4)))
    print(addrlist)
    while addrlist:
        no = addrlist.pop(0) & a.pop(0)
        networkl.append(no)
    print(networkl)


##aggiungere il numero di host possibili in base alla maschera

def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    ask_list = srp(packet, timeout=1, verbose=False)[0]

    packet_list = []
    for i in ask_list:
        packet_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        packet_list.append(packet_dict)
    return (packet_list)

print(scan("192.168.178.0/24"))
#Scan all the addresses (except the lowest, which is your network address and the highest, which is your broadcast address).
#Use your DNS's reverse lookup to determine the hostname for IP addresses which respond to your scan.
#sistemare codice
calculate_network(addr, mask)

# https://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python
