"""
The Hebrew University of Jerusalem - School of Computer Science
Workshop in Communication Networks - Spring 2014
Solution for Exercise 1, Part 1 - OpenFlow Learning Switch

This code is based on the official POX OpenFlow Tutorial
"""
from threading import Lock
from of_router_imports import *
from priority_dict import *


log = core.getLogger()


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
            destination = (port, None)
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
                    next_hop_ip = self.graph.nodes[next_hop_router_id].interfaces[input_port].ip
                    destination = (output_port, next_hop_ip)
                    table.add(network[0], network[1], destination)
        return table

    def print_graph(self):
        for edge in self.graph.edges:
            data = list(edge)
            print str(self.graph.nodes[data[0]])
            print str(self.graph.nodes[data[1]])
            print str(self.graph.get_edge(data[0], data[1]))


class Subnet:
    def __init__(self, ip, mask):
        self.network = ip
        self.mask = mask

    def __eq__(self, other):
        return other.network == self.network and other.mask == self.mask

    def __hash__(self):
        return hash((str(self.network), str(self.mask)))

    def match(self, ip):
        return ip.inNetwork(self.network, self.mask)

    def __str__(self):
        string = '{IP}/{mask}'.format(IP=str(self.network), mask=str(self.mask))
        return string


class RoutingTable:

    def __init__(self):
        self.table = {}

    def add(self, address, mask, destination):
        subnet = Subnet(address, mask)
        if subnet not in self.table:
            self.table[subnet] = destination

    def lookup(self, address):
        # in subnet
        temp = [subnet for subnet in self.table if subnet.match(IPAddr(address))]
        if not temp:
            return None, None
        return self.table[temp[0]]

    def __str__(self):
        string = ['%s -> port: %d, next hop ip: %s' % (str(subnet), self.table[subnet][0], str(self.table[subnet][1]))
                  for subnet in self.table]
        return '\n'.join(string)


class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    TIME_WAITING_ARP = 3  # max TTL
    TIME_NONE = 5
    TIME_ARP = 3600
    TIMER_INTERVAL = 3

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        # Switch ID is at connection.dpid, use util.dpidToStr(connection.dpid)
        # Information about the switch: connection.features
    
        # This binds our PacketIn event listener
        connection.addListeners(self)
        self.mac_to_port = {}

        # maps an IP address to a 2-tuple of (mac_address, timestamp) where mac_address is the MAC address associated
        # with the IP address according to the ARP reply, and timestamp is the time the ARP reply was received.
        self.arp_cache = {}
        # maps an IP address to a 3-tuple of (packet, packet-in, timestamp) where packet and packet_in are the data
        # packet and its enclosing openflow message that are to be buffered until an ARP reply arrives
        self.waiting_arp_requests = {}
        self.lock = Lock()
        if connection.dpid in range(100, 200):
            self.timer = Timer(self.TIMER_INTERVAL, self.clean_arp_cache, recurring=False)
            self.timer.start()

    def send_packet_multiple_ports(self, buffer_id, raw_data, out_ports, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that.  Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data
    
        # Add an action to send to the specified port
        for out_port in out_ports:
            action = of.ofp_action_output(port = out_port)
            msg.actions.append(action)
    
        # Send message to switch
        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in):
        """
        Implement switch-like behavior.
        """
        # Learn the port for the source MAC
        src = packet.src
        dst = packet.dst
        switch_name = "s" + str(self.connection.dpid)
        
        log.debug(switch_name+": "+str(src)+" --> "+str(dst))
        
        if src in self.mac_to_port and packet_in.in_port != self.mac_to_port[src]:
            # send a message to the switch to remove the old flow entry
            log.debug(switch_name + ": removed the flow entry for mac " + str(src) + " from switch s" +
                      str(self.connection.dpid))
            fm = of.ofp_flow_mod()
            fm.command = of.OFPFC_DELETE
            fm.match.dl_dst = src
            self.connection.send(fm)
            
        # set the new port to mac_to_port
        self.mac_to_port[src] = packet_in.in_port        
    
        if dst in self.mac_to_port:
            out_port = self.mac_to_port[dst]
            log.debug(switch_name + ": Installing entry (In_Port: " + str(packet_in.in_port) + ", Src: " + str(src) +
                      ", Dst: " + str(dst) + ", Port: " + str(out_port) + ")...")
            
            fm = of.ofp_flow_mod()
            fm.match.in_port = packet_in.in_port
            fm.match.dl_src = src
            fm.match.dl_dst = dst
            
            if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
                fm.buffer_id = packet_in.buffer_id
            else:
                if packet_in.data is None:
                    return
                fm.data = packet_in.data
            
            # Add an action to send to the specified port
            action = of.ofp_action_output(port=out_port)
            fm.actions.append(action)
            
            # Send message to switch
            self.connection.send(fm)

        else:
            # Flood the packet out everything but the input port
            # This part looks familiar, right?
            log.debug('[Tutorial] Flooding packet from switch ' + str(self.connection.dpid))
            self.send_packet_multiple_ports(packet_in.buffer_id, packet_in.data, [of.OFPP_FLOOD], packet_in.in_port)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        # Avoid forwarding of LLDP packets
        if packet.type == ethernet.LLDP_TYPE: 
            return
        
        packet_in = event.ofp  # The actual ofp_packet_in message.
        
        # Comment out the following line and uncomment the one after
        # when starting the exercise.
        # self.act_like_hub(packet, packet_in)
        if self.connection.dpid in range(100, 200):
            self.act_like_router(packet, packet_in)
        # if is switch
        elif self.connection.dpid in range(200, 300):
            self.act_like_switch(packet, packet_in)

    def act_like_router(self, packet, packet_in):
        # treat arp
        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(packet, packet_in)
        # treat ip
        elif packet.type == ethernet.IP_TYPE:
            self.handle_ip(packet, packet_in)

    def clean_arp_cache(self):
        for (key, (packet, packet_in, timestamp)) in self.waiting_arp_requests.items():
            if (time.time() - timestamp) >= self.TIME_WAITING_ARP:
                self.lock.acquire()
                self.arp_cache[key] = (None, time.time())
                if key in self.waiting_arp_requests:
                    del self.waiting_arp_requests[key]
                self.lock.release()
                self.handle_ip(packet, packet_in)

        for (key, (mac, timestamp)) in self.arp_cache.items():
            if (mac is None and (time.time() - timestamp) >= self.TIME_NONE) or (time.time() - timestamp >=
                                                                                     self.TIME_ARP):
                self.lock.acquire()
                if key in self.arp_cache:
                    del self.arp_cache[key]
                self.lock.release()
        self.timer.start()

    def router_flow_mod(self, packet_in, ip_dst, actions):
        fm = of.ofp_flow_mod()
        # rule match
        fm.match = of.ofp_match()
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.in_port = packet_in.in_port
        fm.match.nw_dst = ip_dst
        if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
            # We got a buffer ID from the switch; use that
            fm.buffer_id = packet_in.buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if packet_in.data is None:
                # No raw_data specified -- nothing to send!
                return
            fm.raw_data = packet_in.data
        if actions is None:
            self.connection.send(fm)
            return
        for action in actions:
            fm.actions.append(action)
        self.connection.send(fm)

    def handle_ip(self, packet, packet_in):
        ip_dst = packet.payload.dstip
        ip_src = packet.payload.srcip
        log.debug('[r%d]: IP packet received, source IP: %s, destination IP: %s, TTL: %d' % (self.connection.dpid,
                                                                                             str(ip_src), str(ip_dst),
                                                                                             packet.payload.ttl))
        # Compute the routing table of the router,
        table = Network().get_routing_table(self.connection.dpid)
        # the destination port for the destination IP address from the routing table
        (port_to_next_hop, ip_next_hop) = table.lookup(ip_dst)
        # no route to requested IP address
        if port_to_next_hop is None:
            log.debug('[r%d]: Destination network is unreachable, destination IP %s' % (self.connection.dpid,
                                                                                        str(ip_dst)))
            # data of port that data recieved on
            port_data = Network().graph.nodes[self.connection.dpid].interfaces[packet_in.in_port]
            # The destination network is unreachable from this router. Send an ICMP Destination Network Unreachable
            # (type=3, code=0) message
            self.send_icmp(3, 0, ip_src, port_data.ip, packet.src, port_data.mac, packet_in.in_port, packet.payload)
            return
        # TTL is too small
        elif packet.payload.ttl < 2:
            log.debug('[r%d]: TTL exceeded, ip source %s, ip destination %s' % (self.connection.dpid, str(ip_src),
                                                                                str(ip_dst)))
            # data of port that data recieved on
            port_data = Network().graph.nodes[self.connection.dpid].interfaces[packet_in.in_port]
            # Packet should be dropped and an ICMP TTL Expired (type=11, code=0) message should be sent to the source
            # IP address.
            self.send_icmp(11, 0, ip_src, port_data.ip, packet.src, port_data.mac, packet_in.in_port, packet.payload)
            return
        # If destination IP is the same IP as the IP of this port
        elif ip_next_hop is None and port_to_next_hop == packet_in.in_port:
            # ip_next_hop is None when the next hop isn't defined
            # check if message is intended for this router
            port_data = Network().graph.nodes[self.connection.dpid].interfaces[packet_in.in_port]
            if port_data.ip == ip_dst:  # the packet is for this router interface:
                # the protocol is ICMP
                if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                    log.debug('[r%d]: ICMP ECHO Request received, source IP address: %s' % (self.connection.dpid,
                                                                                            str(ip_src)))
                    # it is an ICMP ECHO Request, send an ICMP reply.
                    # ICMP request sent to this port of router
                    if packet.payload.payload.type == 8:
                        self.send_icmp(0, 0, ip_src, ip_dst, packet.src, port_data.mac, packet_in.in_port,
                                       packet.payload)
                        return
                    else:
                        # another type of ICMP, ignore it, as we do not handle other ICMP types in this exercise.
                        return
                else:  # not ICMP
                    # some IP packet sent to this router
                    # send an ICMP Unreachable Port error message (type=3, code=3)
                    self.send_icmp(3, 3, ip_src, ip_dst, packet.src, port_data.mac, packet_in.in_port, packet.payload)
                    return
            else:  # packet has been received on this port is for this interface but ip is different
                # send flow to discard this type of packets
                log.debug('[r%d]: Flow is installed on router: IP %s -> IP %s, drop' % (self.connection.dpid,
                                                                                        str(ip_src), str(ip_dst)))
                self.router_flow_mod(packet_in, ip_dst, None)
                return
        elif ip_next_hop is None and port_to_next_hop != packet_in.in_port:
            # requested ip is other of this router interface or network
            port_data = Network().graph.nodes[self.connection.dpid].interfaces[port_to_next_hop]
            # packet destination is other interface of this router
            if port_data.ip == ip_dst:
                # the protocol is ICMP
                if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                    log.debug('[r%d]: ICMP ECHO Request received, source IP address: %s' % (self.connection.dpid,
                                                                                            str(ip_src)))
                    # it is an ICMP ECHO Request, send an ICMP reply.
                    # ICMP request sent to this port of router
                    if packet.payload.payload.type == 8:
                        self.send_icmp(0, 0, ip_src, port_data.ip, packet.src, port_data.mac, packet_in.in_port,
                                       packet.payload)
                        return
                    else:
                        # another type of ICMP, ignore it, as we do not handle other ICMP types in this exercise.
                        return
                else:  # not ICMP
                    # some IP packet sent to this router
                    # send an ICMP Unreachable Port error message (type=3, code=3)
                    log.debug('[r%d]: Destination port for IP packet is unreachable, ip source %s, ip destination %s' %
                              (self.connection.dpid, str(ip_src), str(ip_dst)))
                    self.send_icmp(3, 3, ip_src, ip_dst, packet.src, port_data.mac, packet_in.in_port, packet.payload)
                    return
            # the destination is the network device in one of this router's subnets
            elif port_data.match(ip_dst):
                # if mac of port dst is not in the arp_table, send arp to get the mac of destination device
                if ip_dst not in self.arp_cache:
                    log.debug('[r%d]: Destination Mac Unknown, source IP: %s, destination IP: %s. Arp will be send.' %
                              (self.connection.dpid, str(ip_src), str(ip_dst)))
                    # add waiting_arp_request
                    self.lock.acquire()
                    if ip_dst not in self.waiting_arp_requests:
                        self.waiting_arp_requests[ip_dst] = (packet, packet_in, time.time())
                    self.lock.release()
                    # send arp to destination port
                    log.debug('[r%d]: Sending ARP Request, destination IP address: %s, send to port %d' %
                              (self.connection.dpid, ip_dst, port_to_next_hop))
                    self.send_arp(arp.REQUEST, port_data.ip, ip_dst, EthAddr("FF:FF:FF:FF:FF:FF"),
                                  port_data.mac, port_to_next_hop, packet_in.in_port)
                    return
                else:
                    self.lock.acquire()
                    arp_entry = self.arp_cache[ip_dst]
                    # update timestamp
                    self.arp_cache[ip_dst] = (arp_entry[0], time.time())
                    self.lock.release()
                    # The destination IP address is in arp_cache but it is mapped to None
                    # it means that the destination host is unreachable type=3, code=1
                    if arp_entry[0] is None:
                        log.debug('[r%d]: Destination Host Unreachable, source IP: %s, destination IP: %s, TTL: %d' %
                                  (self.connection.dpid, str(ip_src), str(ip_dst), packet.payload.ttl))
                        self.send_icmp(3, 1, ip_src, port_data.ip, packet.src, port_data.mac, packet_in.in_port,
                                       packet.payload)
                        return
                    else:
                        mac_dst = arp_entry[0]
                        #send packet to mac in arp table
                        log.debug('[r%d]: Flow is installed on router: IP %s -> (IP %s, MAC %s), send to port %d, '
                                  'decrease TTL.' %
                                  (self.connection.dpid, str(ip_src), str(ip_dst), str(mac_dst), port_to_next_hop))

                        actions = [of.ofp_action_dl_addr.set_dst(mac_dst), nx.nx_action_dec_ttl(),
                                   of.ofp_action_output(port=port_to_next_hop)]  # destination
                        self.router_flow_mod(packet_in, ip_dst, actions)
                        return
        # send message to the next hop
        elif ip_next_hop is not None and port_to_next_hop != packet_in.in_port:
            log.debug('[r%d]: Flow is installed on router: IP %s -> IP %s, send to port %d, decrease TTL.' %
                                  (self.connection.dpid, str(ip_src), str(ip_dst), port_to_next_hop))
            actions = [nx.nx_action_dec_ttl(), of.ofp_action_output(port=port_to_next_hop)]  # destination
            self.router_flow_mod(packet_in, ip_dst, actions)
        else:
            # the port the packet came from is the next hop port
            pass

    def handle_arp(self, packet, packet_in):
        # parse packet
        arp_data = packet.payload
        arp_type = arp_data.opcode
        ip_src = arp_data.protosrc
        ip_dst = arp_data.protodst
        mac_src = arp_data.hwsrc
        if arp_type == arp.REQUEST:
            router_interface_data = Network().graph.nodes[self.connection.dpid].interfaces[packet_in.in_port]
            if router_interface_data.ip != ip_dst:  # packet wasn't intended for this interface
                return
            self.arp_cache[ip_src] = (mac_src, time.time())  # update the arp_cache
            # send ARP reply
            log.debug('[r%d]: Sending ARP Reply, destination IP address: %s, the port %d' % (self.connection.dpid,
                                                                                             str(ip_dst), packet_in.
                                                                                             in_port))
            self.send_arp(arp.REPLY, ip_dst, ip_src, mac_src, router_interface_data.mac, of.OFPP_IN_PORT, packet_in.
                          in_port)
        elif arp_type == arp.REPLY:
            log.debug('[r%d]: Received an ARP reply, source MAC address: %s, source IP address: %s, input port: %d' %
                      (self.connection.dpid, str(mac_src), str(ip_src), packet_in.in_port))
            router_interface_data = Network().graph.nodes[self.connection.dpid].interfaces[packet_in.in_port]
            if router_interface_data.ip != ip_dst:  # packet wasn't intended for this interface
                return
            self.lock.acquire()
            self.arp_cache[ip_src] = (mac_src, time.time())  # update the arp_cache
            self.lock.release()
            # send saved packets
            if ip_src in self.waiting_arp_requests:
                self.lock.acquire()
                packet_prev, packet_in_prev, timestamp = self.waiting_arp_requests[ip_src]
                del self.waiting_arp_requests[ip_src]
                self.lock.release()
                self.handle_ip(packet_prev, packet_in_prev)

    def send_arp(self, opcode, ip_src, ip_dst, mac_dst, mac_src, action_port, in_port):
        # send ARP reply
        my_arp = arp()
        my_arp.opcode = opcode  # arp.REPLY or arp.REQUEST
        my_arp.protodst = IPAddr(ip_dst)
        my_arp.protosrc = IPAddr(ip_src)
        my_arp.hwsrc = EthAddr(mac_src)
        my_arp.hwdst = EthAddr(mac_dst)
        # create ethernet frame
        my_ether = ethernet()
        my_ether.type = ethernet.ARP_TYPE  # packet.ARP_TYPE
        my_ether.src = my_arp.hwsrc
        my_ether.dst = my_arp.hwdst
        my_ether.set_payload(my_arp)
        msg = of.ofp_packet_out()
        msg.data = my_ether.pack()
        action = of.ofp_action_output(port=action_port)  # may be of.OFPP_IN_PORT
        msg.in_port = in_port
        msg.actions.append(action)
        self.connection.send(msg)

    def send_icmp(self, tp, code, dest_ip, src_ip, dest_mac, src_mac, my_port, orig_packet):
        # Should be able to send echo reply (tp=0,code=0), destination unreachable
        # (tp=3,code=0(network unreachable)/1(host unreachable)/3(port unreachable)), TTL expired (tp=11,code=0)
        msg = None
        if tp == 0:
            p = orig_packet.payload
            while p is not None and not isinstance(p, echo):
                p = p.next
            if p is None:
                return
            r = echo(id=p.id, seq=p.seq)
            r.set_payload(p.next)
            msg=icmp(type=0, code=0)
            msg.set_payload(r)
        elif tp == 3:
            msg = icmp()
            msg.type = 3
            msg.code = code
            d = orig_packet.pack()
            d = d[:orig_packet.hl * 4 + 8]
            d = struct.pack("!HH", 0,0) + d
            msg.payload = d
        elif tp == 11:
            msg = icmp()
            msg.type = 11
            msg.code = 0
            d = orig_packet.pack()
            d = d[:orig_packet.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d
            msg.payload = d

        # Make the IP packet around it
        ipp = ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = IPAddr(src_ip)
        ipp.dstip = IPAddr(dest_ip)

        # Ethernet around that...
        e = ethernet()
        e.src = EthAddr(src_mac)
        e.dst = EthAddr(dest_mac)
        e.type = e.IP_TYPE

        # Hook them up...
        ipp.payload = msg
        e.payload = ipp

        # send this packet to the switch
        log.debug('[r%d] Sending ICMP TYPE %d for IP %s on port %d' % (self.connection.dpid, tp, dest_ip, my_port))
        self.send_packet_multiple_ports(None, e, [my_port], of.OFPP_NONE)


def launch():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)

