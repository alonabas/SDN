""" 
OpenFlow Exercise - Sample File
This file was created as part of the course Workshop in Communication Networks
in the Hebrew University of Jerusalem.

This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from utils import *
from Discovery import *
from priority_dict import *
from random import *
log = core.getLogger()


class SwitchSwitch:
    """
    Class that define the full active connection: list from first side
    and link from second side and the time this connection is alive
    """
    def __init__(self, switch1, switch2):
        self.switch1 = switch1
        self.switch2 = switch2

    def __eq__(self, other):
        return other.switch1 == self.switch1 and other.switch2 == self.switch2

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.switch1, self.switch2))

    def __str__(self):
        string = '{switch1} <-> {switch2}'.format(switch1=str(self.switch1), switch2=str(self.switch2))
        return string

class SpanningTree:
    
    __metaclass__ = SingletonType
    
    def __init__(self):
        self.switches = []  # used to save all switches
        self.connections = {}  # used to save all active connections
        self.legal_connections = []  # save the active links found by STP
        self.unused_ports = []  # save the forbidden ports
        self.all_connections = []
        self.hosts = {}
        self.nexts = {}
    
    def calculate_spanning_tree(self, discovery):
        self.connections = {}
        self.switches = [switch for switch in discovery.links]
        self.switches.sort()
        # add links
        for switch in self.switches:
            # sort by switch ID
            self.connections[switch] = [connection if connection.link1.switch == switch else connection.swap()
                                        for connection in discovery.connections if
                                        connection.link1.switch == switch or connection.link2.switch == switch]
            # sorted by switch id of the other side of link
            self.connections[switch].sort(key=lambda x: x.link2.switch, reverse=False)
        # call Kruscal
        self.kruscal()

    def kruscal(self):
        # create set
        child_list = {}
        # make set
        old_cons = list(self.legal_connections)
        old_unused = list(self.unused_ports)
        self.legal_connections = []
        for switch in self.switches:
            child_list[switch] = UnionFind.RootElm() # each node is root
            UnionFind.make_set(child_list[switch])
        
        # switches list is sorted so first member is the Root - the one with minimal switch ID
        for switch in self.switches:
            # check all neighbours of current switch if they don't create loop - add them
            # the neighbours also sorted by their id
            for conn in self.connections[switch]:
                other_switch = conn.link2.switch
                if switch in child_list and other_switch in child_list and UnionFind.find(child_list[switch]) != UnionFind.find(child_list[other_switch]):
                    UnionFind.union(child_list[switch],child_list[other_switch])
                    self.legal_connections.append(conn)

        self.all_connections = []
        for switch in self.connections:
            self.all_connections = self.all_connections + self.connections[switch]
        self.all_connections = list(set(self.all_connections))
        # list of forbidden ports
        self.unused_ports = [conn for conn in self.all_connections if conn not in self.legal_connections]
        for conn in self.unused_ports:
            if conn not in old_unused:
                # log.debug('Link %s disabled by spanning tree' % (str(conn)))
                pass
        for conn in self.legal_connections:
            if conn not in old_cons and conn not in self.unused_ports:
                # log.debug('Link %s enabled by spanning tree' % (str(conn)))
                pass

                    
    def __str__(self):
        data = [str(conn) for conn in self.legal_connections]
        return ', '.join(data)

    def add_host(self, mac, switch_id):
        self.hosts[mac] = switch_id

    def clear_hosts(self, mac):
        if mac in self.hosts:
            del self.hosts[mac]

    def find_path(self):
        for switch in self.switches:
            self.find_length(switch)


    def find_length(self, switch):
        # run djakstra
        dist = {}
        previous = {}
        queue = priority_dict()
        queue[switch] = 0
        #according to http://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
        while queue:
            v = queue.smallest()
            dist[v] = queue[v]
            queue.pop_smallest()
            if v is None:
                break
            if v in self.connections:
                neighbours = self.connections[v]
                for w in neighbours:
                    if w.link1.switch == v:
                        w = w.link2.switch
                    else:
                        w = w.link1.switch
                    temp_dist = dist[v] + 1
                    if w in dist:
                        if temp_dist < dist[w]:
                            raise ValueError % "Dijkstra: found better path to already-final vertex"
                    elif w not in queue or temp_dist < queue[w] or temp_dist == queue[w]:
                        queue[w] = temp_dist
                        if w not in previous:
                            previous[w] = []
                        previous[w].append(v)
                queue.update()
        for other_switch in dist:
            if other_switch != switch:
                self.nexts[SwitchSwitch(other_switch, switch)] = previous[other_switch]

    def random_out(self, switch, host):
        if host not in self.hosts:
            return None
        host_switch = self.hosts[host]
        # vals = [val for val in self.nexts if val.switch1 == switch and val.switch2 == host_switch]
        temp = SwitchSwitch(switch, host_switch)
        if temp not in self.nexts:
            return None
        val = self.nexts[SwitchSwitch(switch, host_switch)]
        next_switch = choice(val)
        log.debug('Switch %d, next switch %d'% (switch, next_switch))
        port = [connection
                if connection.link2.switch == switch and connection.link1.switch == next_switch
                else connection.swap()
                for connection in self.all_connections if
                (connection.link1.switch == switch and connection.link2.switch == next_switch)
                or (connection.link2.switch == switch and connection.link1.switch == next_switch)]
        if port:
            return port[0]
        return None
