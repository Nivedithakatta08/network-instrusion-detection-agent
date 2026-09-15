import socket

from scapy.all import sniff, IP, TCP, UDP


def get_local_ip():
    """Get the local machine IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    except Exception:
        return "127.0.0.1"


def analyze_live_traffic(duration=5):

    local_ip = get_local_ip()

    print(f"Monitoring local network: {local_ip}")
    print(f"Capturing for {duration} seconds...")

    # Capture packets
    packets = sniff(timeout=duration)

    # Basic statistics
    total_packets = len(packets)

    total_bytes = 0

    tcp_packets = 0
    udp_packets = 0

    incoming_packets = 0
    outgoing_packets = 0

    # Connection direction
    forward_packets = 0
    backward_packets = 0

    forward_bytes = 0
    backward_bytes = 0

    source_ips = []
    destination_ips = []

    # --------------------------------------------------
    # PROCESS PACKETS
    # --------------------------------------------------

    for packet in packets:

        # Ignore non-IP packets
        if IP not in packet:
            continue

        ip_layer = packet[IP]

        packet_size = len(packet)

        total_bytes += packet_size

        # ----------------------------------------------
        # TRAFFIC DIRECTION
        # ----------------------------------------------

        if ip_layer.src == local_ip:

            outgoing_packets += 1

            forward_packets += 1
            forward_bytes += packet_size

        elif ip_layer.dst == local_ip:

            incoming_packets += 1

            backward_packets += 1
            backward_bytes += packet_size

        # ----------------------------------------------
        # SOURCE / DESTINATION
        # ----------------------------------------------

        source_ips.append(ip_layer.src)

        destination_ips.append(ip_layer.dst)

        # ----------------------------------------------
        # PROTOCOL
        # ----------------------------------------------

        if TCP in packet:

            tcp_packets += 1

        elif UDP in packet:

            udp_packets += 1

    # --------------------------------------------------
    # CALCULATE FEATURES
    # --------------------------------------------------

    packets_per_second = (
        total_packets / duration
        if duration > 0
        else 0
    )

    bytes_per_second = (
        total_bytes / duration
        if duration > 0
        else 0
    )

    unique_sources = len(
        set(source_ips)
    )

    unique_destinations = len(
        set(destination_ips)
    )

    # --------------------------------------------------
    # CREATE FEATURE DICTIONARY
    # --------------------------------------------------

    features = {

        "duration": duration,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "packets_per_second": packets_per_second,

        "bytes_per_second": bytes_per_second,

        "tcp_packets": tcp_packets,

        "udp_packets": udp_packets,

        "incoming_packets": incoming_packets,

        "outgoing_packets": outgoing_packets,

        "forward_packets": forward_packets,

        "backward_packets": backward_packets,

        "forward_bytes": forward_bytes,

        "backward_bytes": backward_bytes,

        "unique_sources": unique_sources,

        "unique_destinations": unique_destinations,
    }

    return features