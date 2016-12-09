import math
import pyshark


TCP_BINS = [0 for i in range(12)]
UDP_BINS = [0 for i in range(12)]

TEST_HOSTS = ['216.58.210.66']

def add_packet_size_to_hist(p_size,protocol):
    idx = int(math.floor(math.log(p_size, 2))) if int(math.floor(math.log(p_size, 2))) < 11 else 11
    if protocol == "TCP":
        TCP_BINS[idx] += 1
    elif protocol == "UDP":
        UDP_BINS[idx] += 1


def create_psize_histograms(hosts):
    for host in hosts:
        host_packets = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap",
                                                    only_summaries=True,
                                                    display_filter="ip.src==" + host + " or ip.dst==" + host)
        for p in host_packets:
            add_packet_size_to_hist(int(p.length), p.protocol)


create_psize_histograms(TEST_HOSTS)
print(UDP_BINS)
print(TCP_BINS)