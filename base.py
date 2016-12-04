import pyshark

capture_file = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap")
capture_summaries = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap", only_summaries=True)


def get_host_list(cap_file):
    host_ips = set()
    for packet in cap_file:
        if cap_file.only_summaries:
            if packet.info == 'Client Hello':
                host_ips.add(packet.destination)
            elif packet.info == 'Server Hello':
                host_ips.add(packet.source)
        else:
            if hasattr(packet, "ssl") and hasattr(packet.ssl, "handshake"):
                if packet.ssl.handshake == 'Handshake Protocol: Client Hello':
                    host_ips.add(packet.ip.dst)
                elif packet.ssl.handshake == 'Handshake Protocol: Server Hello':
                    host_ips.add(packet.ip.src)

    return list(host_ips)

# feature name map:
# n - number of nodes
# o - number of one degree nodes
# myu - average degree
# alpha - max degree
# betha - back degree of alpha
# TODO - host graphlet dict should look like this:
# {
#     host_ip: {
#         protocol1: {..},
#         protocol2: {
#             dst_ip1: {...},
#             dst_ip2: {
#                 src_port1: {...},
#                 src_port2: [
#                     dst_port1, dst_port2, ...
#                 ]
#             }
#         }
#     }
# }
def get_host_graphlet_dict(cap_file):
    graphlet_dict = {}
    for packet in cap_file:
        if packet.ip.src not in graphlet_dict.keys():
            graphlet_dict[packet.ip.src] = {}
        if packet.transport_layer not in graphlet_dict[packet.ip.src].keys():
            graphlet_dict[packet.ip.src][packet.transport_layer] = {}
        if packet.ip.dst not in graphlet_dict[packet.ip.src][packet.transport_layer].keys():
            graphlet_dict[packet.ip.src][packet.transport_layer][packet.ip.dst] = {}
        if packet[packet.transport_layer].srcport not in graphlet_dict[packet.ip.src][packet.transport_layer][packet.ip.dst].keys():
            graphlet_dict[packet.ip.src][packet.transport_layer][packet.ip.dst][packet[packet.transport_layer].srcport] = set()
        graphlet_dict[packet.ip.src][packet.transport_layer][packet.ip.dst][packet[packet.transport_layer].srcport].add(packet[packet.transport_layer].dstport)

    return graphlet_dict
