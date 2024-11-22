# This script will process data downloaded from https://github.com/sapics/ip-location-db/tree/main/dbip-country
# It then creates object groups for the countries listed in block_countries list
import csv
from ipaddress import IPv4Address, summarize_address_range

input_file = '/Users/vibobrov/Downloads/dbip-country-ipv4-num.csv'
output_file = 'output.txt'

block_countries=["RU","IR","KP"]
block_networks={f"{country}":[] for country in block_countries}

with open(input_file, 'r') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        start_ip_int = int(row[0])
        end_ip_int = int(row[1])
        country_code = row[2]
        if country_code in block_countries:

            # Convert start and end integers to IPv4Address
            start_ip = IPv4Address(start_ip_int)
            end_ip = IPv4Address(end_ip_int)

            # Calculate the range size
            range_size = end_ip_int - start_ip_int + 1

            # Calculate the prefix length
            prefix_length = 32 - (range_size - 1).bit_length()

            # Calculate the subnet mask
            subnet_mask_int = (1 << 32) - (1 << (32 - prefix_length))
            netmask = str(IPv4Address(subnet_mask_int))

            networks = summarize_address_range(start_ip, end_ip)
            for network in networks:
                block_networks[country_code].append(f"{network.network_address} {network.netmask}")

with open(output_file, 'w') as outfile:
    for country,networks in block_networks.items():
        outfile.write(f"object-group network IP-Addresses-{country}\n")
        for network in networks:
            outfile.write(f" network-object {network}\n")
        outfile.write("object-group network Block-Countries\n")
        outfile.write(f" group-object IP-Addresses-{country}\n")