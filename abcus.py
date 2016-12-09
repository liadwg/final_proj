import math
import pyshark



TEST_HOST = '216.58.210.66'


def create_psize_histograms(host):
    tcp_bins = [0 for i in range(12)]
    udp_bins = [0 for i in range(12)]
    host_packets = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap",
                                                only_summaries=True,
                                                display_filter="ip.src==" + host + " or ip.dst==" + host)
    for p in host_packets:
        p_size = int(p.length)
        idx = int(math.floor(math.log(p_size, 2))) if int(math.floor(math.log(p_size, 2))) < 11 else 11
        if p.protocol == "TCP":
            tcp_bins[idx] += 1
        elif p.protocol == "UDP":
            udp_bins[idx] += 1
    return tcp_bins, udp_bins


