
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

# host graphlet dict should look like this:
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
# srcIP - protocol - srcPort - dstPort - dstIP
def get_host_graphlet_dict_summ(cap_file):
    graphlet_dict = {}
    for packet in cap_file:
        if packet.source not in graphlet_dict.keys():
            graphlet_dict[packet.source] = {}
        if packet.protocol not in graphlet_dict[packet.source].keys():
            graphlet_dict[packet.source][packet.protocol] = {}
        if packet.destination not in graphlet_dict[packet.source][packet.protocol].keys():
            graphlet_dict[packet.source][packet.protocol][packet.destination] = {}
        src_port, dst_port = get_ports_from_info(packet)
        if src_port not in graphlet_dict[packet.source][packet.protocol][packet.destination].keys():
            graphlet_dict[packet.source][packet.protocol][packet.destination][src_port] = []
        if dst_port not in graphlet_dict[packet.source][packet.protocol][packet.destination][src_port]:
            graphlet_dict[packet.source][packet.protocol][packet.destination][src_port].append(dst_port)

    return graphlet_dict

def get_graphlet_features(graphlet):
    sub_g_a = [graphlet]
    sub_g_b = []
    result = {}
    lvl = 1
    while lvl < 5:
        if lvl < 4:
            result["n%d" % lvl] = len(sub_g_a)
            result["o%d_%d" % (lvl, lvl+1)] = 0
            result["alpha%d_%d" % (lvl, lvl+1)] = 0
            tot = 0
            alpha = None
            for node in sub_g_a:
                tot += len(node.keys())
                if len(node.keys()) == 1:
                    result["o%d_%d" % (lvl, lvl+1)] += 1
                if len(node.keys()) > result["alpha%d_%d" % (lvl, lvl+1)]:
                    result["alpha%d_%d" % (lvl, lvl+1)] = len(node.keys())
                    alpha = node
            result["myu%d_%d" % (lvl, lvl+1)] = tot/len(sub_g_a)

        if lvl > 1:
            result["o%d_%d" % (lvl, lvl-1)] = 0
            result["alpha%d_%d" % (lvl, lvl-1)] = 0
            tot = 0
            for node in sub_g_a:
                cnt = 0
                for bnode in sub_g_b:
                    if node in bnode.keys():
                        cnt += 1
                tot += cnt
                if cnt == 1:
                    result["o%d_%d" % (lvl, lvl-1)] += 1
                if cnt > result["alpha%d_%d" % (lvl, lvl-1)]:
                    result["alpha%d_%d" % (lvl, lvl-1)] = cnt
                    if lvl < 4:
                        result["beta%d_%d" % (lvl, lvl-1)] = len(node.keys())
                if lvl < 4 and node == alpha:
                    result["beta%d_%d" % (lvl, lvl+1)] = cnt

            result["myu%d_%d" % (lvl, lvl-1)] = tot/len(sub_g_a)

        if lvl < 4:
            temp = sub_g_a
            sub_g_a = []
            for item in [key.values() for key in temp]:
                sub_g_a.extend(item)
            sub_g_b = temp
        lvl += 1

    return result