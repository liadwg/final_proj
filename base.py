import pyshark


def get_ports_from_info(p_summ):
    return p_summ.info.split(" ")[0].split("\\xe2\\x86\\x92")

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


# feature name map:
# n - number of nodes
# o - number of one degree nodes
# myu - average degree
# alpha - max degree
# beta - back degree of alpha
def get_graphlet_features(graphlet):
    sub_g_a = graphlet
    sub_g_b = graphlet
    result = {}
    lvl = 1
    result["n%d" % lvl] = len(sub_g_a.keys())
    result["o%d_%d" % (lvl, lvl+1)] = 0
    result["alpha%d_%d" % (lvl, lvl+1)] = 0
    tot = 0
    alpha = None
    for node in sub_g_a.keys():
        tot += len(sub_g_a[node].keys())
        if len(sub_g_a[node].keys()) == 1:
            result["o%d_%d" % (lvl, lvl+1)] += 1
        if len(sub_g_a[node].keys()) > result["alpha%d_%d" % (lvl, lvl+1)]:
            result["alpha%d_%d" % (lvl, lvl+1)] = len(sub_g_a[node].keys())
            alpha = node
    result["myu%d_%d" % (lvl, lvl+1)] = tot/len(sub_g_a.keys())

    if lvl > 1:
        result["o%d_%d" % (lvl, lvl-1)] = 0
        result["alpha%d_%d" % (lvl, lvl-1)] = 0
        tot = 0
        for node in sub_g_a.keys():
            cnt = 0
            for bnode in sub_g_b.keys():
                if node in sub_g_b[bnode]:
                    cnt += 1
            tot += cnt
            if cnt == 1:
                result["o%d_%d" % (lvl, lvl-1)] += 1
            if cnt > result["alpha%d_%d" % (lvl, lvl-1)]:
                result["alpha%d_%d" % (lvl, lvl-1)] = cnt
                if lvl < 5:
                    pass
            if node == alpha:
                result["beta%d_%d" % (lvl, lvl+1)] = cnt

        result["myu%d_%d" % (lvl, lvl-1)] = tot/len(sub_g_a.keys())



capture_summaries = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap", only_summaries=True, display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 1")
g_dict = get_host_graphlet_dict_summ(capture_summaries)
