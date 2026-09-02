"""
CodeAlpha Cyber Security Internship
Task 1: Basic Network Sniffer

Description:
    A basic network packet sniffer using Scapy.
    Captures packets and displays:
    - Source IP address
    - Destination IP address
    - Protocol
    - Source/Destination ports
    - Packet length
    - Payload information

Author: CodeAlpha Intern
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf
from datetime import datetime
import argparse
import sys


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

DEFAULT_PACKET_COUNT = 20


# ---------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------

def get_protocol(packet):
    """
    Identify the protocol used by the packet.
    """

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        if packet.haslayer(DNS):
            return "DNS/UDP"
        return "UDP"

    if packet.haslayer(DNS):
        return "DNS"

    return "Other"


def get_payload(packet):
    """
    Extract a readable payload from the packet.
    """

    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)

        # Convert payload to readable text where possible
        try:
            text = raw_data.decode("utf-8", errors="replace")
            text = text.replace("\r", " ").replace("\n", " ")

            # Limit displayed payload size
            if len(text) > 80:
                text = text[:80] + "..."

            return text

        except Exception:
            return raw_data.hex()[:80]

    return "No payload"


def process_packet(packet):
    """
    Process and display information about each captured packet.
    """

    timestamp = datetime.now().strftime("%H:%M:%S")

    # We are mainly interested in IP packets
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = get_protocol(packet)
        packet_length = len(packet)

        source_port = "-"
        destination_port = "-"

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        payload = get_payload(packet)

        print("\n" + "=" * 90)
        print(f"Time          : {timestamp}")
        print(f"Source IP     : {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol      : {protocol}")
        print(f"Source Port   : {source_port}")
        print(f"Destination Port: {destination_port}")
        print(f"Packet Length : {packet_length} bytes")
        print(f"Payload       : {payload}")
        print("=" * 90)

    else:
        print(
            f"\n[{timestamp}] "
            f"Non-IP packet captured | Length: {len(packet)} bytes"
        )


# ---------------------------------------------------------
# Packet Sniffer
# ---------------------------------------------------------

def start_sniffer(packet_count, interface=None):
    """
    Start packet capture.
    """

    print("\n" + "=" * 90)
    print("           CODEALPHA - BASIC NETWORK SNIFFER")
    print("=" * 90)

    print(f"Packets to capture : {packet_count}")

    if interface:
        print(f"Interface          : {interface}")
    else:
        print("Interface           : Default")

    print("\nStarting packet capture...")
    print("Press CTRL+C to stop the sniffer.\n")

    try:

        sniff(
            iface=interface,
            prn=process_packet,
            count=packet_count,
            store=False
        )

    except PermissionError:

        print("\n[ERROR] Permission denied.")
        print("Please run the terminal as Administrator/root.")

        sys.exit(1)

    except KeyboardInterrupt:

        print("\n\n[INFO] Packet capture stopped by user.")

    except Exception as error:

        print(f"\n[ERROR] Unable to start packet capture.")
        print(f"Details: {error}")

        sys.exit(1)

    print("\n" + "=" * 90)
    print("Packet capture completed.")
    print("=" * 90)


# ---------------------------------------------------------
# Command Line Arguments
# ---------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer"
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=DEFAULT_PACKET_COUNT,
        help="Number of packets to capture (default: 20)"
    )

    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on"
    )

    args = parser.parse_args()

    if args.count <= 0:
        print("[ERROR] Packet count must be greater than 0.")
        sys.exit(1)

    start_sniffer(
        packet_count=args.count,
        interface=args.interface
    )


# ---------------------------------------------------------
# Program Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":
    main()