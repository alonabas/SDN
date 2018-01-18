__author__ = 'alonabas'

from SpanningTree import *
from pox.lib.addresses import IPAddr
from Discovery import *

log = core.getLogger()

THRESHOLD = 700

class tuple:
    def __init__(self, ip_src, ip_dst, port_src, port_dst, protocol, mac_dst, mac_src):

        self.ip_src = str(ip_src)
        self.ip_dst = str(ip_dst)
        self.port_src = port_src
        self.port_dst = port_dst
        self.protocol = protocol
        self.counter = 0
        self.mac_dst = mac_dst
        self.mac_src = mac_src
        self.idle = 0

    def add_counter(self, size):
        self.counter = self.counter + size
        self.idle = 0

    def set_idle(self):
        self.idle = self.idle + 1
        return self.idle

    def is_elephant(self):
        if self.counter > THRESHOLD:
            return 1
        else:
            return 0

    def __eq__(self, other):
        return self.ip_src == other.ip_src and self.ip_dst == other.ip_dst and self.port_src == other.port_src and \
            self.port_dst == other.port_dst and self.protocol == other.protocol

    def __hash__(self):
        return hash((self.ip_dst, self.ip_src, self.port_src, self.port_dst, self.protocol))

    def __ne__(self, other):
        return not (self == other)

class Status:
    def __init__(self):
        self.status = 0
        self.changed = 0
        self.converged = 0
        self.demand = 0
        self.old_demand = 0
        self.rl = 1

class Enhancer:

    __metaclass__ = SingletonType

    def __init__(self):
        self.hosts = {}
        self.flows = {}
        self.elephants = {}
        self.stp = SpanningTree()
        self.usage_table = {}

    def create_links(self):
        for conn in self.stp.all_connections:
            self.usage_table[conn] = 1

    def remove_flow(self, flow):
        if flow in self.elephants:
            for switch in self.flows[flow]:
                port = self.flows[flow][switch]
                cell = [con for con in self.usage_table if (con.link1.switch == switch and con.link1.port == port) or
                        (con.link2.switch == switch and con.link2.port == port)]
                if cell:
                    self.usage_table[cell[0]] = self.usage_table[cell[0]] + self.elephants[flow].demand
            del self.elephants[flow]
        del self.flows[flow]
        self.delete_flow(flow)


    def delete_flow(self, flow):
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_proto = flow.protocol
        fm.match.nw_dst = IPAddr(flow.ip_dst)
        fm.match.nw_src = IPAddr(flow.ip_src)
        fm.match.tp_dst = flow.port_dst
        fm.match.tp_src = flow.port_src
        fm.command = of.OFPFC_DELETE
        for connection in core.openflow.connections:  # _connections.values() before betta
            connection.send(fm)

    def create_new_flow(self, flow, mac_dst, mac_src):
        # generate path
        found = 0
        stp = SpanningTree()
        self.flows[flow] = {}
        switch_id = self.stp.hosts[mac_src]
        while found == 0:
            connection = stp.random_out(switch_id, mac_dst)
            if connection is not None:
                if switch_id == connection.link2.switch:
                    port = connection.link2.port
                    next_switch = connection.link1.switch
                elif switch_id == connection.link1.switch:
                    port = connection.link1.port
                    next_switch = connection.link2.switch
                self.flows[flow][switch_id] = port
                switch_id = next_switch
            else:
                found = 1
                if mac_dst in self.hosts:
                    self.flows[flow][switch_id] = self.hosts[mac_dst].port
                else:
                    self.flows[flow][switch_id] = of.OFPP_FLOOD

    def add_host(self, mac, port, switch_id):
        self.hosts[mac] = Link(switch_id, port)

    def remove_host(self, mac):
        if mac in self.hosts:
            del self.hosts[mac]

    def get_next(self, switch_id, ip_src, ip_dst, port_src, port_dst, protocol, mac_dst, mac_src):
        flow_temp = tuple(ip_src, ip_dst, port_src, port_dst, protocol, mac_dst, mac_src)
        if flow_temp not in self.flows:
            log.debug('Create new flow for mice: ip_src: %s, ip_dst: %s, protocol: %d, port_src: %d, port_dst: %d' %
                      (ip_src, ip_dst, protocol, port_src, port_dst))
            self.create_new_flow(flow_temp, mac_dst, mac_src)
        else:
            my_flow = [flow for flow in self.flows if flow == flow_temp]
            if my_flow:
                my_flow = my_flow[0]
            if my_flow.is_elephant() == 1 and my_flow not in self.elephants:
                log.debug('Create new flow for elephant: ip_src: %s, ip_dst: %s, protocol: %d, port_src: %d, port_dst: %d'
                          % (ip_src, ip_dst, protocol, port_src, port_dst))
                self.check_flows()
                return self.get_advanced_next(switch_id, my_flow)
            elif my_flow.is_elephant() == 1 and my_flow in self.elephants:
                return self.get_advanced_next(switch_id, my_flow)
            elif my_flow.is_elephant() == 0:
                return self.get_simple_next(switch_id, my_flow)


    def get_simple_next(self, switch_id, flow):
        if switch_id in self.flows[flow]:
            return self.flows[flow][switch_id]
        return of.OFPP_FLOOD

    def get_advanced_next(self, switch_id, flow):
        if switch_id in self.flows[flow]:
            return self.flows[flow][switch_id]
        else:
            return of.OFPP_FLOOD

    def check_flows(self):
        for flow in self.flows:
            if flow.is_elephant() == 1 and flow not in self.elephants:
                self.elephants[flow] = Status()
        self.estimate_demands()
        self.schecdule()

    def estimate_demands(self):
        for flow in self.elephants:
            self.elephants[flow].old_demand = self.elephants[flow].demand
        cont = 1
        while cont:
            for h in self.hosts:
                if self.est_src(h) == 0:
                    cont = 0
            for h in self.hosts:
                if self.est_dst(h) == 0:
                    cont = 0
        for flow in self.elephants:
            # update usage table
            for switch in self.flows[flow]:
                port = self.flows[flow][switch]
                cell = [con for con in self.usage_table if (con.link1.switch == switch and con.link1.port == port) or
                        (con.link2.switch == switch and con.link2.port == port)]
                if cell:
                    self.usage_table[cell[0]] = self.usage_table[cell[0]] + self.elephants[flow].old_demand - self.elephants[flow].demand

    def est_src(self, host):
        changed = 0
        df = 0
        nu = 0
        for flow in self.elephants:
            if flow.mac_src == host:
                if self.elephants[flow].converged == 1:
                    df = df + self.elephants[flow].demand
                else:
                    nu = nu+1
        if nu == 0:
            es = 1
        else:
            es = (1.0 - df)/nu
        for flow in self.elephants:
            if flow.mac_src == host:
                if self.elephants[flow].converged == 0:
                    self.elephants[flow].demand = es
                    changed = 1
        return changed

    def est_dst(self, host):
        changed_final = 0
        dt = 0
        ds = 0
        nr = 0
        for flow in self.elephants:
            if flow.mac_dst == host:
                self.elephants[flow].rl = 1
                dt = dt + self.elephants[flow].demand
                nr = nr + 1
        if dt < 0:
            return
        if nr == 0:
            es = 1
        else:
            es = 1.0/nr
        changed = 1
        while changed:
            changed = 0
            nr = 0
            for flow in self.elephants:
                if flow.mac_dst == host and self.elephants[flow].rl == 1:
                    if self.elephants[flow].demand < es:
                        ds = ds + self.elephants[flow].demand
                        self.elephants[flow].rl = 0
                        changed = 1
                    else:
                        nr = nr + 1
            if nr == 0:
                es = 1
            else:
                es = (1.0 - ds)/nr
        for flow in self.elephants:
            if flow.mac_dst == host and self.elephants[flow].rl == 1:
                self.elephants[flow].demand = es
                changed_final = 1
                self.elephants[flow].converged = 1
        return changed_final

    def create_smart_flows(self, flow):
        # generate path
        found = 0
        flows_temp = {}
        switch_id = self.stp.hosts[flow.mac_src]
        if flow.mac_dst not in self.stp.hosts:
            return None
        host_switch = self.stp.hosts[flow.mac_dst]
        while found == 0:
            if switch_id == host_switch:
                return
            val = self.stp.nexts[SwitchSwitch(switch_id, host_switch)]
            for next_switch in val:
                con = [connection
                    if connection.link2.switch == switch_id and connection.link1.switch == next_switch
                    else connection.swap()
                    for connection in self.stp.all_connections if
                    (connection.link1.switch == switch_id and connection.link2.switch == next_switch)
                    or (connection.link2.switch == switch_id and connection.link1.switch == next_switch)]
                if con:
                    if (con[0] in self.usage_table and self.usage_table[con[0]] >= self.elephants[flow].demand) or con[0] not in self.usage_table:
                        if con[0] not in self.usage_table:
                            self.usage_table[con[0]] = 2
                        if switch_id == con[0].link2.switch:
                            port = con[0].link2.port
                            next_switch = con[0].link1.switch
                        elif switch_id == con[0].link1.switch:
                            port = con[0].link1.port
                            next_switch = con[0].link2.switch
                        flows_temp[switch_id] = port
                        self.usage_table[con[0]] = self.usage_table[con[0]] - self.elephants[flow].demand
                        switch_id = next_switch
                        break
                else:
                    found = 1
                    if flow.mac_dst in self.hosts:
                        flows_temp[switch_id] = self.hosts[flow.mac_dst].port
                    else:
                        flows_temp[switch_id] = of.OFPP_FLOOD
                    break
        self.flows[flow] = flows_temp

    def schecdule(self):
        for flow in self.elephants:
            if self.elephants[flow].status == 0:
                # choose path
                self.create_smart_flows(flow)
                self.elephants[flow].status == 1
