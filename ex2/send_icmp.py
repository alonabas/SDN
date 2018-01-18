def send_icmp(self, tp, code, dest_ip, dest_mac, dest_port, orig_packet):
    # Should be able to send echo reply (tp=0,code=0), destination unreachable (tp=3,code=0(network unreachable)/1(host unreachable)/3(port unreachable)), TTL expired (tp=11,code=0)

    msg = None
    if tp == 0:
        p = orig_packet.payload
        while p is not None and not isinstance(p, echo):
            p = p.next
        if p is None:
            return
        r = echo(id=p.id,seq=p.seq)
        r.set_payload(p.next)
        msg=icmp(type=0,code=0)
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
        d = struct.pack("!HH", 0,0) + d
        msg.payload = d

    # Make the IP packet around it
    ipp = ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    ipp.srcip = IPAddr(dest_port.ip)
    ipp.dstip = IPAddr(dest_ip)

    # Ethernet around that...
    e = ethernet()
    e.src = EthAddr(dest_port.mac)
    e.dst = EthAddr(dest_mac)
    e.type = e.IP_TYPE

    # Hook them up...
    ipp.payload = msg
    e.payload = ipp

    # send this packet to the switch
    log.debug('[r%d] Sending ICMP TYPE %d for IP %s on port %d' % (self.connection.dpid, tp, dest_ip, dest_port.port_id))
    self.send_packet_multiple_ports(None, e, [dest_port.port_id], of.OFPP_NONE)
