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
from Discovery import Discovery
from SpanningTree import *
log = core.getLogger()


class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        
        self.connection = connection

        # create list of active ports for each switch
        self.ports_use = [port.port_no for port in self.connection.features.ports if port.port_no < of.OFPP_MAX]
        self.ports_use.sort()
        # create mac table
        self.mac_table = {}
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

    def send_flow_mod_by_in_port(self, in_port, action, buffer_id, raw_data, packet):
        """
        Send flow to switch
        """
        fm = of.ofp_flow_mod()
        # rule match
        fm.match = of.ofp_match()
        fm.match.dl_src = packet.src
        fm.match.dl_dst = packet.dst
        fm.match.in_port = in_port
        log.debug('Rule instalation: port_in %d, MAC_src %s, port_out %d, MAC_dst: %s' % (in_port,str(packet.src), action.port ,str(packet.dst)))
        if buffer_id != -1 and buffer_id is not None:
            # Valid buffer ID was sent from switch, we do not need to encapsulate raw data in response
            fm.buffer_id = buffer_id
        else:
            if raw_data is not None:
                # No valid buffer ID was sent but raw data exists, send raw data with flow_mod
                fm.data = raw_data
        fm.actions.append(action)
        
        # Send message to switch
        self.connection.send(fm)


    def act_like_hub(self, packet, packet_in):
        """
        Implement hub-like behavior -- send all packets to all ports besides
        the input port.
        """
  
        ### We want to output to all ports -- we do that using the special
        ### of.OFPP_FLOOD port as the output port.  (We could have also used
        ### of.OFPP_ALL.)

        ### Useful information on packet_in:
        ### packet_in.buffer_id   - The ID of the buffer (packet data) on the switch
        ### packet_in.data        - The raw data as sent by the switch
        ### packet_in.in_port     - The port on which the packet arrived at the switch

        # log.debug('Flooding packet')
        ### We may either send the packet to switch and tell it to flood it
        # self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        ### Or we may write a method that installs a permanent rule to flood such
        ### packets in the switch: 
        # self.add_flood_rule_to_flowtable(packet_in.buffer_id, packet_in.data, packet_in.in_port)
        pass
    
    def _handle_PortStatus(self, event):
        # link is down
        if event.ofp.desc.config == 1:
            # delete ports from list
            if event.ofp.desc.port_no in self.ports_use:
                self.ports_use.remove(event.ofp.desc.port_no)
                # delete flows
                self.delete_flow_mod_by_port(event.ofp.desc.port_no)
        else: #link is up
            self.ports_use.append(event.ofp.desc.port_no)

    def delete_flow_mod_by_port(self, port):
        log.debug('Delete flows: (Switch %d, Port %d) -> any and any -> (Switch %d, Port %d)' % (self.connection.dpid,port,self.connection.dpid,port))
        # delete from mac table
        delete = [mac for mac in self.mac_table if self.mac_table[mac] == port]
        for port_del in delete:
            del self.mac_table[port_del]
        fm = of.ofp_flow_mod()
        # rule match
        fm.match = of.ofp_match()
        fm.command = of.OFPFC_DELETE
        # delete as destination port
        action = of.ofp_action_output(port=port)
        fm.actions.append(action)
        # Send message to switch
        self.connection.send(fm)
        
        # delete as in port
        fm1 = of.ofp_flow_mod()
        # rule match
        fm1.match = of.ofp_match()
        fm1.match.in_port = port
        fm1.command = of.OFPFC_DELETE
        self.connection.send(fm1)
    
    def delete_flow_mod_by_mac_dst(self, mac_dst):
        """
        Delete flows from switch by destination mac address
        """
        log.debug('Delete flows: any -> MAC_dst %s' % (str(mac_dst)))
        # delete from mac table
        if mac_dst in self.mac_table:
            del self.mac_table[mac_dst]
        # rule match
        fm = of.ofp_flow_mod()
        # delete rules for given when destination is given source MAC that changed its location
        fm.match = of.ofp_match()
        fm.match.dl_dst = mac_dst
        # delete all flows with specified destination
        fm.command = of.OFPFC_DELETE
        # Send message to switch
        self.connection.send(fm)
        for connection in core.openflow.connections:  # _connections.values() before betta
            connection.send(fm)

    def update_stp(self):
        """
        Update the list of active ports according to Spanning Tree
        """
        stp = SpanningTree()
        # add active links from calculated spanning tree
        ports_to_remove = [conn.link1.port if conn.link1.switch == self.connection.dpid else conn.link2.port
                           for conn in stp.unused_ports if
                           conn.link1.switch == self.connection.dpid or conn.link2.switch == self.connection.dpid]
        ports_to_add = [conn.link1.port if conn.link1.switch == self.connection.dpid else
                        conn.link2.port for conn in stp.legal_connections if
                        conn.link1.switch == self.connection.dpid or conn.link2.switch == self.connection.dpid]
                        
        self.ports_use = [port for port in self.ports_use if port not in ports_to_remove]
        # append lists, the ports STP give us doen't contain HOST links
        self.ports_use = list(set(self.ports_use + ports_to_add))
        
        # delete flows that send data to non active links
        for port in ports_to_remove:
            self.delete_flow_mod_by_port(port)

    def act_like_switch(self, packet, packet_in):
        """
        Implement switch behaviour
        """
        
        # Check if Source changed it's location
        if packet.src in self.mac_table and self.mac_table[packet.src] != packet_in.in_port:
            # remove rules where this MAC is destination
            self.delete_flow_mod_by_mac_dst(packet.src)
        
        # Add packet.src and packet_in.in_port to switch table, if exists - update
        self.mac_table[packet.src] = packet_in.in_port
        # if packet.dst not in table - flood
        if packet.dst not in self.mac_table:
            log.debug('MAC_dst %s is not in mac table. Flood packet.' % (str(packet.dst)))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        elif packet.dst in self.mac_table and self.mac_table[packet.dst] not in self.ports_use:
            # if port defined in mac table is forbidden - flood and delete entry from mac table
            del self.mac_table[packet.dst]
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        else:
            # install rule
            action = of.ofp_action_output(port=self.mac_table[packet.dst])  # destination
            self.send_flow_mod_by_in_port(packet_in.in_port, action, packet_in.buffer_id, packet_in.data, packet)


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.register('discovery', Discovery()) # register LLDP discovery
