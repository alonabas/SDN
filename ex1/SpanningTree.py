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
log = core.getLogger()


class SpanningTree:
    
    __metaclass__ = SingletonType
    
    def __init__(self):
        self.switches = []  # used to save all switches
        self.connections = {}  # used to save all active connections
        self.legal_connections = []  # save the active links found by STP
        self.unused_ports = [] # save the forbidden ports
    
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

        all_connections = []
        for switch in self.connections:
            all_connections = all_connections + self.connections[switch]
        all_connections = list(set(all_connections))
        # list of forbidden ports
        self.unused_ports = [conn for conn in all_connections if conn not in self.legal_connections]
        for conn in self.unused_ports:
            if conn not in old_unused:
                log.debug('Link %s disabled by spanning tree' % (str(conn)))
        for conn in self.legal_connections:
            if conn not in old_cons and conn not in self.unused_ports:
                log.debug('Link %s enabled by spanning tree' % (str(conn)))

                    
    def __str__(self):
        data = [str(conn) for conn in self.legal_connections]
        return ', '.join(data)
