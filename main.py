import script

if __name__ == "__main__":
    public_ip = script.get_public_ip()
    private_ip, mask = script.get_private_ip()
    net_address = script.calculate_network(private_ip, mask)
    no_hosts, mask_dec = script.convert_mask_dec_to_bin(mask)
    hostname = script.hostname(private_ip)
    net_host = script.scan(net_address, mask_dec)
    print(f"The hostname is: {hostname}.\nPrivate Address: {private_ip}/{mask}.\nNetwork Address: {net_address}.\n"
          f"Public Address: {public_ip}.\nPossible host number in the subnet: {no_hosts}.\n"
          f"The devices on on the network are the following: ")

    print(*net_host, sep='\n')
