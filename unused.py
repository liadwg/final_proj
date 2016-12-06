
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


def get_host_list(cap_file):
    host_ips = set()
    for packet in cap_file:
        if cap_file.only_summaries:
            if "Seq=0 Ack=1" in packet.info:
                # client initiates session, so answer to a SYN packet comes from host
                host_ips.add(packet.source)
        # else:
        #     if hasattr(packet, "ssl") and hasattr(packet.ssl, "handshake"):
        #         if packet.ssl.handshake == 'Handshake Protocol: Client Hello':
        #             host_ips.add(packet.ip.dst)
        #         elif packet.ssl.handshake == 'Handshake Protocol: Server Hello':
        #             host_ips.add(packet.ip.src)

    return list(host_ips)