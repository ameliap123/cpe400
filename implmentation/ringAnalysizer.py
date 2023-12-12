import pyshark
import matplotlib.pyplot as plt

def analyze_packet_capture(file_path, ip_address):
    # Initialize counters for destination ports and protocols
    destination_ports = {}
    protocols = {}

    # Parse the packet capture file
    cap = pyshark.FileCapture(file_path)

    # Iterate through each packet in the capture
    for packet in cap:
        try:
            # Extract source and destination IP addresses
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Check if the given IP address is either the source or destination
            if src_ip == ip_address or dst_ip == ip_address:
                # Count hits per destination port
                dst_port = packet.transport_layer.dstport
                destination_ports[dst_port] = destination_ports.get(dst_port, 0) + 1

                # Count hits per protocol
                protocol = packet.transport_layer.layer_name
                protocols[protocol] = protocols.get(protocol, 0) + 1
        except AttributeError:
            # Some packets may not have the expected structure, ignore and continue
            pass

    # Create a bar graph for hits per destination port
    plt.bar(destination_ports.keys(), destination_ports.values())
    plt.xlabel('Destination Port')
    plt.ylabel('Number of Hits')
    plt.title('Hits per Destination Port')
    plt.show()

    # Create a bar graph for hits per protocol
    plt.bar(protocols.keys(), protocols.values())
    plt.xlabel('Protocol')
    plt.ylabel('Number of Hits')
    plt.title('Hits per Protocol')
    plt.show()

if __name__ == "__main__":
    # Get file path and IP address from the user
    file_path = input("Enter the filepath to the .pngcap file: ")
    ip_address = input("Enter the IP address to look for: ")

    # Analyze the packet capture file
    analyze_packet_capture(file_path, ip_address)
