""" 
OpenFlow Exercise - Sample File
This file was created as part of the course Workshop in Communication Networks
in the Hebrew University of Jerusalem.

This code is based on the official OpenFlow tutorial code.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from utils import *
import time
from pox.lib.packet.lldp import lldp, chassis_id, port_id, ttl, end_tlv
from pox.lib.packet.ethernet import ethernet
from threading import Lock
from SpanningTree import *
log = core.getLogger()


class Link:
    """
    Class that defines the one side connection: switch ID and port
    """
    def __init__(self, switch, port):
        self.switch = switch
        self.port = port

    def __eq__(self, other):
        return other.port == self.port and other.switch == self.switch
    
    def __hash__(self):
        return hash(id(self))
    
    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        string = '(Switch {ID}, Port {port})'.format(ID=self.switch, port=self.port)
        return string


class Connection:
    """
    Class that define the full active connection: list from first side
    and link from second side and the time this connection is alive
    """
    def __init__(self, link1, link2):
        self.link1 = link1
        self.link2 = link2
        self.timestamp = time.time()
    
    def update_timestamp(self):
        self.timestamp = time.time()

    def swap(self):
        self.link1, self.link2 = self.link2, self.link1
        return self
    
    def get_time(self):
        return time.time() - self.timestamp
    
    def __eq__(self, other):
        return (other.link1 == self.link1 and other.link2 == self.link2) or \
               (other.link1 == self.link2 and other.link2 == self.link1)
    
    def __ne__(self, other):
        return not (self == other)
    
    def __hash__(self):
        return hash(id(self))
    
    def __str__(self):
        string = '{link1} <-> {link2}'.format(link1=str(self.link1), link2=str(self.link2))
        return string


class SwitchConnections:
    """
    Class that defines switch with all it's connections,
    sends packets
    """

    # timer for LLDP
    TIMER = 1

    def __init__(self, switch_id):
        self.lock = Lock()  # used to make operations on ports atomic
        # lock is required becouse times uses different thread and access the ports
        self.switch_id = switch_id
        self.ports = []
        self.timer = Timer(self.TIMER, self.timer_handler, recurring=False)  # starts the timer
        self.timer.stop()
    
    def add_connection(self, port_src, mac_src, connection):
        # if connection is already in lits
        if any(port.port_src == port_src and port.mac_src == mac_src for port in self.ports):
            return
        self.lock.acquire()
        # add connection: atomic
        self.ports.append(Port(port_src, mac_src, self.switch_id, connection))
        self.lock.release()
    
    def delete(self):
        # remove timer
        self.timer.stop()
        # remove ports
        self.lock.acquire()
        del(self.ports[:]) # delete all ports (in case the whole switch is down)
        self.lock.release()

    def delete_link(self, port):
        self.lock.acquire()
        # remove ports that are down
        self.ports = [curPort for curPort in self.ports if curPort != port]
        self.lock.release()

    def timer_handler(self):
        try:
            # remove timer
            self.timer.stop()
            # send LLDPS
            self.send_lldp()
        except KeyboardInterrupt:
            pass

    def send_lldp(self):
        # send packets to all switch ports
        for port in self.ports:
            ether_frame = port.create_lldp()
            pkt = of.ofp_packet_out(action=of.ofp_action_output(port=port.port_src))
            pkt.data = ether_frame
            port.connection.send(pkt)
        # open timer
        self.timer.start()

    def __str__(self):
        string = [str(port) for port in self.ports]
        return ', '.join(string)


class Port:
    """
        Class that creates the LLDP packet and parses 
    """
    RECEIVER_MAC = '\x01\x80\xc2\x00\x00\x0e'
    LLDP_TTL = 1
    
    def __init__(self, port_src, mac_src, switch_id, connection):
        self.connection = connection
        self.port_src = port_src
        self.mac_src = mac_src
        self.switch_id = switch_id
    
    def create_lldp(self):
        lldp_frame = lldp()
        # add switch ID
        ch_id = chassis_id(subtype=1, id=str(self.switch_id))
        lldp_frame.add_tlv(ch_id)
        # add port id
        po_id = port_id(subtype=2, id=str(self.port_src))
        lldp_frame.add_tlv(po_id)
        # add time to live
        tt = ttl(ttl=Port.LLDP_TTL)
        lldp_frame.add_tlv(tt)
        # end
        lldp_frame.add_tlv(end_tlv())
        
        # add LLDP to ethernet payload
        eth = ethernet(src=self.mac_src, dst=Port.RECEIVER_MAC, type=ethernet.LLDP_TYPE)
        eth.payload = lldp_frame
        return eth
    
    @staticmethod
    def parse_lldp(packet):
         # retrieve from LLDP packet sender's port and switch ID
        lldp_frame = packet.payload
        
        ch_id = int(lldp_frame.tlvs[0].id)
        po_id = int(lldp_frame.tlvs[1].id)
        return [ch_id, po_id]
    
    def __str__(self):
        string = '<%d,%d>' % (self.switch_id, self.port_src)
        return string


class Discovery:
    
    __metaclass__ = SingletonType
    
    TIME = 6 # ttl of connection
    INTERVAL = 3 # time between the check of connections

    def __init__(self):
        self.connections = []  # used to save links from switch to switch
        self.links = {}  # used to save all active ports in switch to send LLPD

        # add listeners
        core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
        core.openflow.addListenerByName("ConnectionDown", self._handle_ConnectionDown)
        core.openflow.addListenerByName("PortStatus", self._handle_PortStatus)
        core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)

        # timer for links
        self.timer = Timer(self.INTERVAL, self._scan_timestamps, recurring=False)
        self.timer.start()
        self.lock = Lock() # lock used to make opperations atomic
        self.observers = []
    
    def add_observer(self, observer):
        self.observers.append(observer)
    
    def notify_all(self):
        stp = SpanningTree()
        stp.calculate_spanning_tree(self)
        for observer in self.observers:
            observer.update_stp()
    
    def _handle_ConnectionUp(self, event):
        
        # install the rule to each switch: forward LLDP packets to controller
        log.debug('Rule instalation: LLDP packets any -> any send to controller')
        action = of.ofp_action_output(port=of.OFPP_CONTROLLER)
        fm = of.ofp_flow_mod()
        # rule match: LLDP
        fm.match = of.ofp_match()
        fm.dl_type = ethernet.LLDP_TYPE
        fm.actions.append(action)
        
        # send LLDP packet to all ports
        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:
                # add links to list of ports that will be send LLDP packets on
                if event.dpid not in self.links:
                    self.links[event.dpid] = SwitchConnections(event.dpid)
                # add all UP links to the list of link to send LLDP
                self.links[event.dpid].add_connection(p.port_no, p.hw_addr, event.connection)
    
        self.links[event.dpid].send_lldp()
        # no need to rebuild spanning tree: to make port active we must recieve LLDP

    def _handle_ConnectionDown(self, event):
        # delete switch and all of it's ports from list of links
        self.links[event.dpid].delete()
        del(self.links[event.dpid])
        # remove all connections from list of active connections per switch
        self.lock.acquire()
        self.connections = [conn for conn in self.connections if
                            conn.link1.switch != event.dpid and conn.link2.switch != event.dpid]
        self.lock.release()
        self.notify_all()

    def _handle_PortStatus(self, event):
        # link is down
        if event.ofp.desc.config == 1:
            log.debug('Link removed: (Switch %d, Port %d) port changed to down' % (event.dpid, event.ofp.desc.port_no))
            # delete port from list of links
            self.links[event.dpid].delete_link(event.ofp.desc.port_no)
            link = Link(event.dpid, event.ofp.desc.port_no)
            # remove all connections of this port from list of active connections
            self.lock.acquire()
            self.connections = [conn for conn in self.connections if conn.link1 != link and conn.link2 != link]
            self.lock.release()
            self.notify_all() # build spanning tree
        else:  # link is up
            if event.dpid not in self.links:
                self.links[event.dpid] = SwitchConnections(event.dpid) # add switch id not there
            # add port to alive links of the switch
            self.links[event.dpid].add_connection(event.ofp.desc.port_no, event.ofp.desc.hw_addr, event.connection)
            # send lldp to this port
            port_to_send = [port for port in self.links[event.dpid].ports if port.connection == event.connection and port.port_src == event.ofp.desc.port_no and port.mac_src == event.ofp.desc.hw_addr and port.switch_id == event.dpid]
            for port in port_to_send:
                ether_frame = port.create_lldp()
                pkt = of.ofp_packet_out(action=of.ofp_action_output(port=port.port_src))
                pkt.data = ether_frame
                port.connection.send(pkt)
            # no need to rebuild spanning tree: to make port active we must recieve LLDP
            # so if link is up wait for LLDP on link and after that rebuild tree


    def _handle_PacketIn(self, event):
        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            return
        if packet.type != ethernet.LLDP_TYPE:
            return
        # add connection to list of links if not there
        
        [sender_id, sender_port] = Port.parse_lldp(packet)
        conn = Connection(Link(event.dpid, event.port), Link(sender_id, sender_port))
        
        if not any(conn == connection for connection in self.connections):
            log.debug('New link found: %s' % (conn))
            # this link is new one so add it to links
            self.lock.acquire()
            self.connections.append(conn)
            self.lock.release()
            self.notify_all()
        # update timestamp
        else:
            current_connection = [connection for connection in self.connections if connection == conn]
            current_connection[0].update_timestamp()

    def _scan_timestamps(self):
        try:  # if ctrl^c pressed
            self.timer.stop()
            bad_links = [connection for connection in self.connections if connection.get_time() >= self.TIME]
            for connection in bad_links:
                log.debug('Link removed: %s not found for a long time' % str(connection))
                self.lock.acquire()
                self.connections.remove(connection)
                self.lock.release()
            
            self.timer.start()
            if not not bad_links:  # if links were removed
                # update STP
                self.notify_all()
                pass
        except KeyboardInterrupt:
            self.lock.release()
            pass