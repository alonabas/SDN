# Michael Shnaiderman mshnai93
# Alona Basovich      alonaba

import struct
from logger import Logger
from mysock import mysock
import math
from random import *
from threading import *
from utils import *
import select
import time

STCP_STATE_CLOSED = 0
STCP_STATE_LISTEN = 1
STCP_STATE_SYN_SENT = 2
STCP_STATE_SYN_RCVD = 3
STCP_STATE_ESTAB = 4
STCP_STATE_FIN_WAIT_1 = 5
STCP_STATE_FIN_WAIT_2 = 6
STCP_STATE_CLOSE_WAIT = 7
STCP_STATE_LAST_ACK = 8
STCP_STATE_CLOSING = 9
STCP_STATE_TIME_WAIT = 10

STCP_PACKET_HEADER_STRUCT = "!2H2I4H"
STCP_PACKET_HEADER_LENGTH = struct.calcsize(STCP_PACKET_HEADER_STRUCT)
STCP_OPTIONS_STRUCT = "!%dI"

STCP_MSS = 512
TIMEOUT = 30
FLAG_ACK_MASK = 0x0800
FLAG_SYN_MASK = 0x04000
FLAG_FIN_MASK = 0x08000

log = Logger()


class stcp_packet:
    """
     Simple TCP Packet Representation.

     Header structure:
      0                   1                   2                   3   
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Source Port          |       Destination Port        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sequence Number                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Acknowledgment Number                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Data |           |U|A|P|R|S|F|                               |
     | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
     |       |           |G|K|H|T|N|N|                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           Checksum            |         Urgent Pointer        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          TCP Options                          |
     :          (4 or more bytes, in multiples of 4 bytes)           :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                             data                              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    @staticmethod
    def read_from_socket(sock):
        msg = sock.recv()
        (srcPort, dstPort, seqNum, ackNum, offset_reserved_flags, window, checksum, urgPtr) = \
            struct.unpack(STCP_PACKET_HEADER_STRUCT, msg.data[:STCP_PACKET_HEADER_LENGTH])
        offset = offset_reserved_flags & 0x0F
        ack = (offset_reserved_flags & FLAG_ACK_MASK) != 0
        syn = (offset_reserved_flags & FLAG_SYN_MASK) != 0
        fin = (offset_reserved_flags & FLAG_FIN_MASK) != 0
        options_words = offset - 5

        options = ''
        data_str = ''
        str_rest = msg.data[STCP_PACKET_HEADER_LENGTH:]

        if options_words > 0:
            options = struct.unpack(STCP_OPTIONS_STRUCT % options_words, str_rest[:(4 * options_words)])
            data_str = str_rest[(4 * options_words):]
        else:
            data_str = str_rest
        res = stcp_packet(srcIp=msg.srcIp, dstIp=msg.dstIp, srcPort=srcPort, dstPort=dstPort, seqNum=seqNum,
                          ackNum=ackNum, ack=ack, syn=syn, fin=fin, window=window, options=options, data=data_str)
        # log.debug("Parsed SCTP packet: " + str(res))
        return res

    def __init__(self, srcIp, dstIp, srcPort, dstPort, seqNum=0, ackNum=0, ack=False,
                 syn=False, fin=False, window=0, options="", data=""):
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.offset = 5 + int(math.ceil(len(options) / 4.0))
        self.ack = ack
        self.syn = syn
        self.fin = fin
        self.window = window
        self.options = options
        self.data = data
        self.checksum = 0

        self.ip_data = self.pack()
        self.ip_data_len = len(self.ip_data)

    def pack(self):
        offset_reserved_flags = self.offset | (FLAG_ACK_MASK if self.ack else 0) | (
            FLAG_SYN_MASK if self.syn else 0) | (FLAG_FIN_MASK if self.fin else 0)
        tcp_header = struct.pack('! 2H2I4H', self.srcPort, self.dstPort, self.seqNum, self.ackNum, \
                                 offset_reserved_flags, self.window, self.checksum, 0)
        return tcp_header + self.options + self.data

    def is_syn(self):
        return self.syn and not self.ack and not self.fin

    def is_syn_ack(self):
        return self.syn and self.ack and not self.fin

    def is_fin(self):
        return not self.syn and not self.ack and self.fin

    def is_ack(self):
        return not self.syn and self.ack and not self.fin

    def is_data(self):
        return not self.syn and not self.ack and not self.fin

    def __str__(self):
        return "STCP Packet: [srcIp=%s,dstIp=%s,srcPort=%d,dstPort=%d,seqNum=%d,ackNum=%d,offset=%d,ack=%s,syn=%s,\
                fin=%s,window=%d,data=\"%s\"]" % \
               (self.srcIp, self.dstIp, self.srcPort, self.dstPort, self.seqNum, self.ackNum, self.offset,
                "True" if self.ack else "False",
                "True" if self.syn else "False", "True" if self.fin else "False", self.window, self.data)


class stcp_socket:
    TIMER = 3

    def __init__(self, local_addr="", base=None):
        # Note: you may change this code...

        self.sock = mysock() if base is None else base.sock
        self.is_child = (base is not None)

        self.state = STCP_STATE_CLOSED
        self.local_addr = local_addr
        self.local_port = randrange(49152, 65535)
        self.packets = []
        self.unacked_packets = []
        self.sessions = {}

        self.seq_num_this = randint(1, 65535)  # random seqNum
        self.last_ack_num = 0
        self.seq_num_peer = 0

        self.remote_addr = ""
        self.remote_port = 0
        self.timer = None

        if self.is_child:
            log.debug('Created new connection: %s' % 'STCP_STATE_SYN_RCVD')
            self.state = STCP_STATE_SYN_RCVD
            self.remote_addr = base.remote_addr
            self.remote_port = base.remote_port
            self.timer = Timer(self.TIMER, self.timer_handler, recurring=False)
            self.timer.start()

        self.lock = Lock()

    def create_empty_pkt(self, ack=False, syn=False, fin=False, seqNum=None, ackNum=None, data=""):
        """
        Sample method that uses stcp_packet class.
        """
        if seqNum is None:
            seqNum = self.seq_num_this
        if ackNum is None:
            ackNum = self.seq_num_peer
        return stcp_packet(srcIp=self.local_addr, dstIp=self.remote_addr, srcPort=self.local_port,
                           dstPort=self.remote_port,
                           seqNum=seqNum, ackNum=ackNum, ack=ack,
                           syn=syn, fin=fin, window=0,
                           data=data)

    def bind(self, ip, port):
        self.sock.bind(ip, port)
        pass

    def listen(self):
        log.debug('State has been changed: %s -> %s' % ('STCP_STATE_CLOSED', 'STCP_STATE_LISTEN'))
        self.state = STCP_STATE_LISTEN
        # open thread that receives all the messages
        Thread(target=self.receive_all).start()
        pass

    def timer_handler(self):
        self.timer.stop()
        i = 0
        retransmitted = 0
        for (packet, timestamp) in self.unacked_packets:
            if time.time() - timestamp > 3:
                # resend packet and update timestamp
                self.unacked_packets[i] = (packet, time.time())
                packet.ackNum = self.seq_num_peer
                self.sock.sendto(packet.pack(), self.remote_addr, self.remote_port)
                retransmitted += 1
            i += 1
        if retransmitted > 0:
            log.debug('%d packets retransmitted' % retransmitted)
        self.timer.start()

    def receive_all(self):
        while self.state != STCP_STATE_CLOSED and self.state != STCP_STATE_TIME_WAIT:
            # if is server, state i
            socket_input = [self.sock.sock]
            input_ready, output_ready, except_ready = select.select(socket_input, [], [])
            for s in input_ready:
                packet = stcp_packet.read_from_socket(self.sock)
                ip_dst = packet.dstIp
                port_dst = packet.dstPort
                ip_src = packet.srcIp
                port_src = packet.srcPort
                if (ip_dst, port_dst, ip_src, port_src) in self.sessions:
                    self.sessions[(ip_dst, port_dst, ip_src, port_src)].treat_packet(packet)
                    if self.sessions[(ip_dst, port_dst, ip_src, port_src)].state == STCP_STATE_CLOSED:
                        # delete session
                        del self.sessions[(ip_dst, port_dst, ip_src, port_src)]
                else:
                    self.treat_packet(packet)

    def treat_packet(self, packet=None):
        if self.state == STCP_STATE_CLOSED:
            # do nothing
            pass

        elif self.state == STCP_STATE_ESTAB:
            # if is fin
            if packet.is_fin():
                log.debug('FIN received')
                # 1. send ACK and change state to close wait
                new_packet = self.create_empty_pkt(True, False, False)
                log.debug('ACK sent')
                self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_ESTAB', 'STCP_STATE_CLOSE_WAIT'))
                self.state = STCP_STATE_CLOSE_WAIT

                # stop timer and clear list of unsent data
                self.timer.stop()
                del self.unacked_packets[0:len(self.unacked_packets)]

                # 2. send fin and change state to last ack
                new_packet = self.create_empty_pkt(False, False, True)
                self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_ESTAB', 'STCP_STATE_LAST_ACK'))
                self.state = STCP_STATE_LAST_ACK
            elif packet.is_ack():
                # remove packets that this ACK acknowledges
                i = 0
                for (old_packet, timestamp) in self.unacked_packets:
                    if self.last_ack_num + len(old_packet.data) <= packet.ackNum:
                        self.last_ack_num += len(old_packet.data)
                        del self.unacked_packets[i]
                        i += 1
                    else:
                        break
            elif packet.is_data():
                # if previous packet lost do nothing
                if self.seq_num_peer < packet.seqNum:
                    return
                # if duplicate packet
                elif self.seq_num_peer > packet.seqNum:
                    # send ack with current s.n
                    new_packet = self.create_empty_pkt(True, False, False)
                    log.debug('ACK sent')
                    self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
                    return
                # new packet
                self.seq_num_peer = packet.seqNum + len(packet.data)
                # add packet to list of waiting packets
                self.lock.acquire()
                self.packets.append(packet)
                self.lock.release()
                # send ack
                new_packet = self.create_empty_pkt(True, False, False)
                log.debug('ACK sent')
                self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
            else:
                # ignore
                pass
        elif self.state == STCP_STATE_LISTEN:
            # treat only syn packets
            if packet.is_syn():
                log.debug('SYN received')
                self.lock.acquire()
                self.packets.append(packet)
                self.lock.release()

        elif self.state == STCP_STATE_SYN_RCVD:
            # accept only ack
            if packet.is_ack():
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_SYN_RCVD', 'STCP_STATE_ESTAB'))
                self.state = STCP_STATE_ESTAB
            pass

        elif self.state == STCP_STATE_LAST_ACK:
            # accept only ack
            if packet.is_ack():
                # stop timer
                self.timer.stop()
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_LAST_ACK', 'STCP_STATE_CLOSED'))
                self.state = STCP_STATE_CLOSED
            pass

        elif self.state == STCP_STATE_SYN_SENT:
            # must be synack
            if packet.is_syn_ack():
                # send ack
                self.seq_num_peer = packet.seqNum
                new_packet = self.create_empty_pkt(True, False, False)
                log.debug('ACK sent')
                self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_SYN_SENT', 'STCP_STATE_ESTAB'))
                self.state = STCP_STATE_ESTAB
            pass

        elif self.state == STCP_STATE_FIN_WAIT_1:
            # must be ack
            if packet.is_ack():
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_FIN_WAIT_1', 'STCP_STATE_FIN_WAIT_2'))
                self.state = STCP_STATE_FIN_WAIT_2
            pass

        elif self.state == STCP_STATE_FIN_WAIT_2:
            # must be fin
            if packet.is_fin():
                # remove timer
                self.timer.stop()
                log.debug('FIN received')
                log.debug('State has been changed: %s -> %s' % ('STCP_STATE_FIN_WAIT_2', 'STCP_STATE_TIME_WAIT'))
                # send ack
                new_packet = self.create_empty_pkt(True, False, False)
                log.debug('ACK sent')
                self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
                self.state = STCP_STATE_TIME_WAIT
                # open timer for 30 seconds and after than close connection
                timer = Timer(30, self.treat_packet, recurring=False)  # starts the timer
                timer.start()
            pass

        elif self.state == STCP_STATE_TIME_WAIT:
            log.debug('State has been changed: %s -> %s' % ('STCP_STATE_TIME_WAIT', 'STCP_STATE_CLOSED'))
            self.state = STCP_STATE_CLOSED
            if not self.is_child:
                self.sock.close()

    def accept(self):
        # if there are SYN packets
        if self.state != STCP_STATE_LISTEN:
            raise StcpSocketException('Socket is not in listen state')
            return
        while not self.packets:
            pass
        if self.packets:
            # packet is SYN
            self.lock.acquire()
            packet = self.packets.pop()
            self.lock.release()
            ip_dst = packet.dstIp
            port_dst = packet.dstPort
            ip_src = packet.srcIp
            port_src = packet.srcPort

            # create session
            session = stcp_socket(self.local_addr, self)
            session.state = STCP_STATE_SYN_RCVD
            session.remote_addr = ip_src
            session.remote_port = port_src

            # send synack
            session.seq_num_peer = packet.seqNum
            new_packet = session.create_empty_pkt(True, True, False)
            log.debug('SYNACK sent')
            session.sock.sendto(new_packet.pack(), session.remote_addr, session.remote_port)
            self.sessions[(ip_dst, port_dst, ip_src, port_src)] = session
            return self.sessions[(ip_dst, port_dst, ip_src, port_src)]

    def connect(self, ip, port):
        # after this method the connection is established
        self.remote_addr = ip
        self.remote_port = port
        # bind the socket to some local port
        # according to http://en.wikipedia.org/wiki/Port_%28computer_networking%29#Common_port_numbers
        self.sock.bind(ip, self.local_port)

        # send SYN
        new_packet = self.create_empty_pkt(False, True, False)
        self.sock.sendto(new_packet.pack(), self.remote_addr, self.remote_port)
        log.debug('State has been changed: %s -> %s' % ('STCP_STATE_CLOSED', 'STCP_STATE_SYN_SENT'))
        self.state = STCP_STATE_SYN_SENT

        # open thread for new messages
        thread = Thread(target=self.receive_all)
        thread.start()

        self.timer = Timer(self.TIMER, self.timer_handler, recurring=False)
        self.timer.start()
        pass

    def send(self, data):
        if self.state == STCP_STATE_CLOSED:
            raise StcpSocketException('Socket is closed')
            return
        while self.state != STCP_STATE_ESTAB:
            pass
        length = len(data)
        start = 0
        sent = False
        while not sent:
            if start + STCP_MSS >= length:
                part = data[start:]
                sent = True
            else:
                part = data[start:start + STCP_MSS]
            packet = self.create_empty_pkt(False, False, False, None, None, part)
            self.unacked_packets.append((packet, time.time()))  # save packet and it's timestamp
            self.sock.sendto(packet.pack(), self.remote_addr, self.remote_port)
            self.seq_num_this += len(part)
            start += STCP_MSS
            pass

    def recv(self, length, timeout=0):
        if self.state == STCP_STATE_CLOSED:
            raise StcpSocketException('Socket is closed')
            return
        read = 0
        data = ''
        while read < length:
            self.lock.acquire()
            if self.packets:
                packet = self.packets.pop()
                data = data + packet.data
                read += len(packet.data)
            self.lock.release()
        return data

    def close(self):
        if self.state == STCP_STATE_CLOSED:
            raise StcpSocketException('Socket is closed')
            return
        # send Fin
        packet = self.create_empty_pkt(False, False, True)
        self.sock.sendto(packet.pack(), self.remote_addr, self.remote_port)
        log.debug('State has been changed: %s -> %s' % ('STCP_STATE_ESTAB', 'STCP_STATE_FIN_WAIT_1'))
        self.state = STCP_STATE_FIN_WAIT_1

        # stop timer and clear list of unsent data
        self.timer.stop()
        del self.unacked_packets[0:len(self.unacked_packets)]


class StcpSocketException(Exception):
    def __init__(self, message):
        self.massage = message
