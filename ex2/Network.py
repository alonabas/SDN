__author__ = 'alonabas'

from priority_dict import *
from RoutingTable import *


class RouterInterface:
    def __init__(self, ip, mask, mac):
        temp_ip = str(ip).split('.')
        temp_mask = str(mask).split('.')
        temp_network = [int(part1) & int(part2) for part1, part2 in zip(temp_ip, temp_mask)]
        self.network = '.'.join([str(port) for port in temp_network])
        self.network = IPAddr(self.network)
        self.ip = IPAddr(ip)
        self.mask = IPAddr(mask)
        self.mac = mac

    def match(self, ip_address):
        return ip_address.inNetwork(self.network, self.mask)

    def __str__(self):
        str1 = 'Network IP: %s, Network Mask: %s, IP address: %s, MAC adddress: %s' % (str(self.network),
                                                                                       str(self.mask), str(self.ip),
                                                                                       str(self.mac))
        return str1


class EdgeData:
    def __init__(self, id1, port1, id2, port2, cost):
        self.router1 = (id1, port1)
        self.router2 = (id2, port2)
        self.cost = cost

    def __str__(self):
        id1, port1 = self.router1
        id2, port2 = self.router2
        str1 = 'Router %d, Port %d <-> Router %d, Port %d, Cost: %d' % (id1, port1, id2, port2, self.cost)
        return str1


class NodeData:
    def __init__(self, router_id):
        self.id = router_id
        self.interfaces = {}

    def add_interface(self, port, router_interface):
        self.interfaces[port] = router_interface

    def __str__(self):
        str1 = 'Router ID: %d\n' % self.id
        str2 = '\n'.join(['Port: %d, Inteface: %s' % (port, str(self.interfaces[port])) for port in self.interfaces])
        return str1 + str2


class Network:
    __metaclass__ = SingletonType

    def __init__(self):
        self.graph = Graph()
        config_file = open(CONFIG_FILENAME)
        # config_file = open('/Users/alonabas/Dropbox/theorysem/ex2/config')
        lines = config_file.readlines()
        self.networks = {}
        status = 1
        index_start = 0
        while status == 1:
            index_end = lines.index('\n', index_start)
            data = [line for line in lines[index_start:index_end]]
            if data[0].startswith('router'):
                # is router
                router_id = int((data[0].replace('router', '')).strip())
                node_data = NodeData(router_id)
                number_ports = int((data[1].replace('ports', '')).strip())
                for i in range(number_ports):
                    # port
                    port = int((data[i*4+2].replace('port', '')).strip())
                    ip = (data[i*4+3].replace('ip', '')).strip()
                    mask = (data[i*4+4].replace('mask', '')).strip()
                    mac = (data[i*4+5].replace('mac', '')).strip()
                    router_interface = RouterInterface(ip, mask, mac)
                    node_data.add_interface(port, router_interface)
                    network = (router_interface.network, router_interface.mask)
                    if network not in self.networks:
                        self.networks[network] = []
                    self.networks[network].append(router_id)
                self.graph.add_node(router_id, node_data)
            elif data[0].__eq__('link\n'):
                left = ((data[1].replace('left', '').strip()).split(','))
                right = ((data[2].replace('right', '').strip()).split(','))
                cost = int(data[3].replace('cost', '').strip())
                left_id = int(left[0].strip())
                left_port = int(left[1].strip())
                right_id = int(right[0].strip())
                right_port = int(right[1].strip())
                edge_data = EdgeData(left_id, left_port, right_id, right_port, cost)
                self.graph.add_edge(left_id, right_id, edge_data)
            else:
                status = 0
            index_start = index_end + 1

    def compute_dijkstra(self, src_router):
        dist = {}
        previous = {}
        result = {}
        queue = priority_dict()
        queue[src_router] = 0
        #according to http://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
        while queue:
            v = queue.smallest()
            dist[v] = queue[v]
            queue.pop_smallest()
            if v is None:
                break
            neighbours = [w for w in self.graph.nodes if self.graph.get_edge(w, v) is not None]
            for w in neighbours:
                temp_dist = dist[v] + self.graph.get_edge(w, v).cost
                if w in dist:
                    if temp_dist < dist[w]:
                        raise ValueError % "Dijkstra: found better path to already-final vertex"
                elif w not in queue or temp_dist < queue[w]:
                    queue[w] = temp_dist
                    previous[w] = v
            queue.update()
        for router in dist:
            if router != src_router:
                neighbour = router
                while previous[neighbour] != src_router:
                    neighbour = previous[neighbour]
                result[router] = neighbour
        return result

    def compute_ospf(self):
        routes = {}
        for router in self.graph.nodes:
            routes[router] = self.compute_dijkstra(router)
        return routes

    def get_routing_table(self, router):
        table = RoutingTable()
        #subnets of current router
        this_router = self.graph.nodes[router]
        for port in this_router.interfaces:
            destination = (port, this_router.interfaces[port].mac, None)
            table.add(this_router.interfaces[port].network, this_router.interfaces[port].mask, destination)
        #subnets in other router
        routes = self.compute_ospf()
        for network in self.networks:
            #find routers of that subnet
            for cur_router_id in self.networks[network]:
                if cur_router_id != router:
                    next_hop_router_id = routes[router][cur_router_id]
                    edge_data = self.graph.get_edge(router, next_hop_router_id)
                    (router1_id, port1_id) = edge_data.router1
                    (router2_id, port2_id) = edge_data.router2
                    if router1_id == router:
                        output_port = port1_id
                        input_port = port2_id
                    else:
                        output_port = port2_id
                        input_port = port1_id
                    output_port_mac = self.graph.nodes[router].interfaces[output_port].mac
                    next_hop_ip = self.graph.nodes[next_hop_router_id].interfaces[input_port].ip
                    destination = (output_port, output_port_mac, next_hop_ip)
                    table.add(network[0], network[1], destination)
        return table

    def print_graph(self):
        for edge in self.graph.edges:
            data = list(edge)
            print str(self.graph.nodes[data[0]])
            print str(self.graph.nodes[data[1]])
            print str(self.graph.get_edge(data[0], data[1]))

a = Network()
b = a.get_routing_table(101)
b.lookup('10.0.0.1')
