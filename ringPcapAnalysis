import pyshark

def analyze_pcap_file(file_path):
    """
    Analyzes a pcap file of ring doorbell traffic. Will print a dictionary containing the number of packets, 
    source and destination IP addresses, and protocol distribution. There is some error handling if pcap file doesnt exist.
    """

    #opening the pcap
    try:
        capture = pyshark.FileCapture(file_path)
    except FileNotFoundError:
        raise FileNotFoundError("The specified pcap file does not exist.")

    #initializing variables
    packet_count = 0
    source_ips = set()
    destination_ips = set()
    protocol_distribution = {}

    #analyzing packets in the pcap with for loop
    for packet in capture:
        #getting total packet count
        packet_count += 1

        #getting source and destination IP addresses
        source_ip = packet.ip.src
        destination_ip = packet.ip.dst

        #adding source and destination IP addresses to sets
        source_ips.add(source_ip)
        destination_ips.add(destination_ip)

        #counting each different protocol
        protocol = packet.layers[1].layer_name
        if protocol in protocol_distribution:
            protocol_distribution[protocol] += 1
        else:
            protocol_distribution[protocol] = 1

    #closing the pcap file
    capture.close()

    #creating dictionary
    analysis_results = {
        "packet_count": packet_count,
        "source_ips": list(source_ips),
        "destination_ips": list(destination_ips),
        "protocol_distribution": protocol_distribution
    }

    return analysis_results

#example usage of the analyze_pcap_file function:

file_path = "path/to/your/pcap/file.pcap"
results = analyze_pcap_file(file_path)

#print results
print("Analysis Results:")
print(f"Number of Packets: {results['packet_count']}")
print(f"Source IP Addresses: {results['source_ips']}")
print(f"Destination IP Addresses: {results['destination_ips']}")
print("Protocol Distribution:")
for protocol, count in results['protocol_distribution'].items():
    print(f"- {protocol}: {count} packets")

#will add explaination of results later like ohhh it do be sending data to this random ip or not 
