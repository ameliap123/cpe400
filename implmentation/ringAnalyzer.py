from scapy.all import rdpcap, IP
from prettytable import PrettyTable

def analyze_pcap(filepath, source_ip):
    try:
        # Read the pcap file
        packets = rdpcap(filepath)

        # Filter packets based on the provided source IP address
        filtered_packets = [pkt for pkt in packets if IP in pkt and pkt[IP].src == source_ip]

        # Analyze destination addresses, ports, and protocols
        dest_addresses = {}
        dest_ports = {}
        protocols = {}

        for pkt in filtered_packets:
            dest_ip = pkt[IP].dst

            # Check if the packet has a destination port
            if hasattr(pkt, "dport"):
                dest_port = pkt.dport
                # Count destination ports
                dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1

            protocol = pkt[IP].proto

            # Count destination addresses
            dest_addresses[dest_ip] = dest_addresses.get(dest_ip, 0) + 1

            # Count protocols
            protocols[protocol] = protocols.get(protocol, 0) + 1

        # Display tables
        display_table("Destination Addresses", dest_addresses)
        display_table("Destination Ports", dest_ports)
        display_table_with_protocol("Protocols", protocols)

    except Exception as e:
        print(f"Error: {e}")

def display_table(title, data):
    table = PrettyTable()
    table.field_names = [title, "Packet Count"]

    for item, count in data.items():
        table.add_row([item, count])

    print(table)

def display_table_with_protocol(title, data):
    table = PrettyTable()
    table.field_names = ["Protocol", "Packet Count"]

    for protocol, count in data.items():
        table.add_row([protocol, count])

    print(table)

if __name__ == "__main__":
    # Use "ring.pcapng" in the same folder
    pcap_filepath = "ring.pcapng"

    # Enter the source IP address to filter by
    source_ip = input("Enter the source IP address to filter by: ")

    # Analyze the pcap file and display tables
    analyze_pcap(pcap_filepath, source_ip)
