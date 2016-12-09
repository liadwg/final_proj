import pyshark


class Node:
    def __init__(self, name):
        self.name = name
        self.forward = []
        self.backward = []


class Graphlet:
    def __init__(self, name, num_of_levels):
        self.name = name
        self.levels = [[] for i in range(num_of_levels)]

    def __repr__(self):
        result = "Graphlet for %s:" % self.name
        for i in range(len(self.levels)):
            result += "\n\tlvl %d - %s" % (i+1, [node.name for node in self.levels[i]])

        return result


def get_ports_from_info(p_summ):
    return p_summ.info.split(" ")[0].split("\\xe2\\x86\\x92")


def get_from_list(obj_list, obj_name):
    for obj in obj_list:
        if obj.name == obj_name:
            return obj
    return None


def get_host_graphlets(cap_file):
    graphlet_list = []
    for packet in cap_file:
        graphlet = get_from_list(graphlet_list, packet.source)
        if graphlet is None:
            graphlet = Graphlet(packet.source, 5)
            src_node = Node(packet.source)
            graphlet.levels[0].append(src_node)
            graphlet_list.append(graphlet)

        proto_node = get_from_list(graphlet.levels[1], packet.protocol)
        if proto_node is None:
            proto_node = Node(packet.protocol)
            proto_node.backward.append(src_node)
            src_node.forward.append(proto_node)
            graphlet.levels[1].append(proto_node)

        dst_node = get_from_list(graphlet.levels[2], packet.destination)
        if dst_node is None:
            dst_node = Node(packet.destination)
            dst_node.backward.append(proto_node)
            proto_node.forward.append(dst_node)
            graphlet.levels[2].append(dst_node)

        src_port, dst_port = get_ports_from_info(packet)
        src_port_node = get_from_list(graphlet.levels[3], src_port)
        if src_port_node is None:
            src_port_node = Node(src_port)
            src_port_node.backward.append(dst_node)
            dst_node.forward.append(src_port_node)
            graphlet.levels[3].append(src_port_node)

        dst_port_node = get_from_list(graphlet.levels[4], dst_port)
        if dst_port_node is None:
            dst_port_node = Node(dst_port)
            dst_port_node.backward.append(src_port_node)
            src_port_node.forward.append(dst_port_node)
            graphlet.levels[4].append(dst_port_node)

    return graphlet_list


def get_host_graphlets_full_cap(cap_file):
    graphlet_list = []
    seen_flows = set()
    for packet in cap_file:
        if float(packet.time) < 60:
            seen_flows.add((packet.source, packet.destination))
            continue

        if (packet.source, packet.destination) or (packet.source, packet.destination) in seen_flows:
            continue

        # first time we encountered this flow (not including first 60 secs), destination is host
        graphlet = get_from_list(graphlet_list, packet.destination)
        if graphlet is None:
            graphlet = Graphlet(packet.destination, 5)
            dst_node = Node(packet.destination)
            graphlet.levels[0].append(dst_node)
            graphlet_list.append(graphlet)

        proto_node = get_from_list(graphlet.levels[1], packet.protocol)
        if proto_node is None:
            proto_node = Node(packet.protocol)
            proto_node.backward.append(dst_node)
            dst_node.forward.append(proto_node)
            graphlet.levels[1].append(proto_node)

        src_node = get_from_list(graphlet.levels[2], packet.source)
        if src_node is None:
            src_node = Node(packet.source)
            src_node.backward.append(proto_node)
            proto_node.forward.append(src_node)
            graphlet.levels[2].append(src_node)

        src_port, dst_port = get_ports_from_info(packet)
        dst_port_node = get_from_list(graphlet.levels[3], dst_port)
        if dst_port_node is None:
            dst_port_node = Node(dst_port)
            dst_port_node.backward.append(src_node)
            src_node.forward.append(dst_port_node)
            graphlet.levels[3].append(dst_port_node)

        src_port_node = get_from_list(graphlet.levels[4], src_port)
        if src_port_node is None:
            src_port_node = Node(dst_port)
            src_port_node.backward.append(dst_port_node)
            dst_port_node.forward.append(src_port_node)
            graphlet.levels[4].append(src_port_node)

    return graphlet_list


# feature name map:
# n - number of nodes
# o - number of one degree nodes
# myu - average degree
# alpha - max degree
# beta - back degree of alpha
def get_graphlet_features(graphlet):
    result = {}
    for i in range(len(graphlet.levels)):
        result["n%d" % (i+1)] = len(graphlet.levels[i])
        if i < len(graphlet.levels) - 1:
            result["o%d_%d" % (i+1, i+2)] = 0
            result["alpha%d_%d" % (i+1, i+2)] = 0
            tot = 0.0
            for node in graphlet.levels[i]:
                tot += len(node.forward)
                if len(node.forward) == 1:
                    result["o%d_%d" % (i+1, i+2)] += 1
                if len(node.forward) > result["alpha%d_%d" % (i+1, i+2)]:
                    result["alpha%d_%d" % (i+1, i+2)] = len(node.forward)
                    alpha1 = node
            result["myu%d_%d" % (i+1, i+2)] = tot/len(graphlet.levels[i])
            result["beta%d_%d" % (i+1, i+2)] = len(alpha1.backward)
        if i > 0:
            result["o%d_%d" % (i+1, i)] = 0
            result["alpha%d_%d" % (i+1, i)] = 0
            tot = 0.0
            for node in graphlet.levels[i]:
                tot += len(node.backward)
                if len(node.backward) == 1:
                    result["o%d_%d" % (i+1, i)] += 1
                if len(node.backward) > result["alpha%d_%d" % (i+1, i)]:
                    result["alpha%d_%d" % (i+1, i)] = len(node.backward)
                    alpha2 = node
            result["myu%d_%d" % (i+1, i)] = tot/len(graphlet.levels[i])
            result["beta%d_%d" % (i+1, i)] = len(alpha2.forward)

    return result


# TODO - remove display filter - only TCP connection.. and use full cap
# TODO - can use get_host_graphlets_full_cap for long cap (significantly longer than 60 secs)
capture_summaries = pyshark.FileCapture("Test28_Id1_Stream1_100.pcap", only_summaries=True, display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 1")
graphlet_list = get_host_graphlets(capture_summaries)
feature_dict = {}
for graphlet in graphlet_list:
    feature_dict[graphlet.name] = get_graphlet_features(graphlet)
