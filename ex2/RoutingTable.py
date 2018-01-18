__author__ = 'alonaba'


from of_router_imports import *

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
            return None, None, None
        return self.table[temp[0]]

    def __str__(self):
        string = ['%s -> port: %d, mac: %s, next hop: %s' % (str(subnet), self.table[subnet][0], str(self.table[subnet][1]),
                                      str(self.table[subnet][2])) for subnet in self.table]
        return '\n'.join(string)