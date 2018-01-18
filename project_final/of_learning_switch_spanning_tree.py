""" 
OpenFlow Exercise - Sample File
This file was created as part of the course Workshop in Communication Networks
in the Hebrew University of Jerusalem.

This code is based on the official OpenFlow tutorial code.
"""

from pox.lib.packet import *
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
from SpanningTree import *
from ecmp_enhancer import *
from Discovery import Discovery
from pox.lib.packet.lldp import lldp, chassis_id, port_id, ttl, end_tlv
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()
from ecmp_enhancer import *

class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        
        self.connection = connection
        self.stp = SpanningTree()
        # create list of active ports for each switch
        self.ports_use = [port.port_no for port in self.connection.features.ports if port.port_no < of.OFPP_MAX]
        self.ports_use.sort()
        self.host_ports = []
        # create mac table
        self.mac_table = {}
        self.ecmp = Enhancer()
        discovery = Discovery()
        discovery.add_observer(self) # listen to the events of LLDP
        # This binds our PacketIn event listener
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        # ignore lldp packets
        if event.parsed.type == ethernet.LLDP_TYPE:
            return
        # act like switch
        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch
        self.act_like_switch(packet, packet_in)

    def send_packet(self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """
        # We tell the switch to take the packet with id buffer_if from in_port 
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
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
        if out_port == of.OFPP_FLOOD:
            # send to all active ports according to STP
            for outPort in self.ports_use:
                if outPort != in_port:
                    action = of.ofp_action_output(port=outPort)
                    msg.actions.append(action)
        else:
            action = of.ofp_action_output(port=out_port)
            msg.actions.append(action)
        # Send message to switch
        self.connection.send(msg)
    
    def _handle_PortStatus(self, event):
        # link is down
        if event.ofp.desc.config == 1:
            # delete ports from list
            if event.ofp.desc.port_no in self.ports_use:
                self.ports_use.remove(event.ofp.desc.port_no)
        else: #link is up
            self.ports_use.append(event.ofp.desc.port_no)

    def update_stp(self):
        """
        Update the list of active ports according to Spanning Tree
        """

        # add active links from calculated spanning tree
        ports_to_remove = [conn.link1.port if conn.link1.switch == self.connection.dpid else conn.link2.port
                           for conn in self.stp.unused_ports if
                           conn.link1.switch == self.connection.dpid or conn.link2.switch == self.connection.dpid]
        ports_to_add = [conn.link1.port if conn.link1.switch == self.connection.dpid else
                        conn.link2.port for conn in self.stp.legal_connections if
                        conn.link1.switch == self.connection.dpid or conn.link2.switch == self.connection.dpid]
        all_switch_ports = [conn.link1.port if conn.link1.switch == self.connection.dpid else
                        conn.link2.port for conn in self.stp.all_connections if
                        conn.link1.switch == self.connection.dpid or conn.link2.switch == self.connection.dpid]

        self.ports_use = [port for port in self.ports_use if port not in ports_to_remove]
        # append lists, the ports STP give us doen't contain HOST links
        self.ports_use = list(set(self.ports_use + ports_to_add))
        self.host_ports = [port for port in self.ports_use if port not in all_switch_ports]
        # delete flows that send data to non active links
        self.stp.find_path()

    def act_like_switch(self, packet, packet_in):
        """
        Implement switch behaviour
        """
        
        # Check if Source changed it's location
        if packet.src in self.mac_table and self.mac_table[packet.src] != packet_in.in_port:
            # remove rules where this MAC is destination
            self.delete_flow_mod_by_mac_dst(packet.src)
            if packet_in.in_port in self.host_ports:
                self.stp.clear_hosts(packet.src)
                self.ecmp.remove_host(packet)

        if packet_in.in_port in self.host_ports and packet.src not in self.mac_table:
            self.stp.add_host(packet.src, self.connection.dpid)
            self.ecmp.add_host(packet.src, packet_in.in_port, self.connection.dpid)

        # Add packet.src and packet_in.in_port to switch table, if exists - update
        self.mac_table[packet.src] = packet_in.in_port

        # if packet.dst not in table - flood
        if packet.dst not in self.mac_table:
            # log.debug('MAC_dst %s is not in mac table. Flood packet.' % (str(packet.dst)))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

        # if is tcp or udp
        if isinstance(packet, ethernet):
            l3_p = packet.next
            if isinstance(l3_p, ipv4):
                l4_p = l3_p.next
                if isinstance(l4_p, udp) or isinstance(l4_p, tcp):
                    port = self.ecmp.get_next(self.connection.dpid, l3_p.srcip, l3_p.dstip, l4_p.srcport, l4_p.dstport, l3_p.protocol, packet.dst, packet.src)
                    log.warning( "Tuple recieved: ipsrc %s, ipdst %s, portsrc %d, portdst %d, protocol %d", l3_p.srcip, l3_p.dstip, l4_p.srcport,l4_p.dstport, l3_p.protocol)
                    if port is None or port == of.OFPP_FLOOD:
                        if packet.dst in self.mac_table:
                            port = self.mac_table[packet.dst]
                            # self.send_packet(packet_in.buffer_id, packet_in.data, port, packet_in.in_port)
                            self.create_flow(l3_p.srcip, l3_p.dstip, l4_p.srcport, l4_p.dstport, l3_p.protocol, port, packet_in, packet)
                        else:
                            for my_port in self.host_ports:
                                self.send_packet(packet_in.buffer_id, packet_in.data, my_port, packet_in.in_port)
                    else:
                        self.create_flow(l3_p.srcip, l3_p.dstip, l4_p.srcport, l4_p.dstport, l3_p.protocol, port, packet_in, packet)
                    return

        if packet.dst in self.mac_table and self.mac_table[packet.dst] not in self.ports_use:
            # if port defined in mac table is forbidden - flood and delete entry from mac table
            del self.mac_table[packet.dst]
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        elif packet.dst in self.mac_table:
            # install rule
            self.send_packet(packet_in.buffer_id, packet_in.data, self.mac_table[packet.dst], packet_in.in_port)

    def create_flow(self, ip_src, ip_dst, port_src, port_dst, protocol, port, packet_in, packet):
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_proto = protocol
        fm.match.nw_dst = IPAddr(ip_dst)
        fm.match.nw_src = IPAddr(ip_src)
        fm.match.tp_dst = port_dst
        fm.match.tp_src = port_src
        if tuple(ip_src, ip_dst, port_src, port_dst, protocol, None, None) in self.ecmp.elephants:
            log.debug('Install elephant flow on switch %d', self.connection.dpid)
            fm.priority = 20
        else:
            log.debug('Install mice flow on switch %d', self.connection.dpid)
            fm.priority = 10
        fm.idle_timeout = 200
        fm.hard_timeout = 550
        action = of.ofp_action_output(port=port)
        fm.actions.append(action)
        self.connection.send(fm)


def launch():
    """
    Starts the component
    """
    # When we get flow stats, print stuff out
    def handle_flow_stats(event):
        for f in event.stats:
            flow_temp = tuple(f.match.nw_src, f.match.nw_dst, f.match.tp_src, f.match.tp_dst, f.match.nw_proto, None, None)
            fl = [flow for flow in ecmp.flows if flow == flow_temp]
            if fl:
                if f.byte_count > 0:
                    fl[0].add_counter(f.byte_count)
                else:
                    if fl[0].set_idle() == 40: # delete
                        ecmp.remove_flow(fl[0])

    def _timer_func ():
        for connection in core.openflow._connections.values():
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def start_switch(event):
        # log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.register('discovery', Discovery()) # register LLDP discovery
    core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
    ecmp = Enhancer()
    # timer set to execute every five seconds
    Timer(5, _timer_func, recurring=True)

