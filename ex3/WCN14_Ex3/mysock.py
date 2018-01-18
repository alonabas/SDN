import socket
import struct
import random

MYSOCK_MAX_PACKET_SIZE = 4096

MYSOCK_TIMEOUT = 30.0

MYSOCK_LOSS_PROB = 0.0
MYSOCK_REORDER_PROB = 0.0

class mysock_msg:
    def __init__(self, srcIp, dstIp, data):
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.data = data

class mysock:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(MYSOCK_TIMEOUT)

    def bind(self, local_addr, local_port):
        self.sock.bind((local_addr, local_port))
        self.local_addr = local_addr
        self.local_port = local_port

    def sendto(self, data, remote_addr, remote_port):
        self.sock.sendto(data, (remote_addr, remote_port))

    def recv(self):
        reorder = False
        (data, addr) = self.sock.recvfrom(MYSOCK_MAX_PACKET_SIZE)
        while random.random() < MYSOCK_LOSS_PROB:
            (data, addr) = self.sock.recvfrom(MYSOCK_MAX_PACKET_SIZE)
        if random.random() < MYSOCK_REORDER_PROB:
            reorder = True
            data1 = data
            addr1 = addr
            (data, addr) = self.sock.recvfrom(MYSOCK_MAX_PACKET_SIZE)

        if addr is not None:
            (rem_addr, rem_port) = addr
            return mysock_msg(rem_addr, self.local_addr, data)
        if reorder and addr1 is not None:
            (rem_addr, rem_port) = addr1
            return mysock_msg(rem_addr, self.local_addr, data1)
        return None

    def close(self):
        self.sock.close()
