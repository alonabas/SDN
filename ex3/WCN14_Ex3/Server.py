from threading import Thread
from stcp import stcp_socket
import random

def test_server():
    s = stcp_socket()
    s.bind("127.0.0.1", 54321)
    s.listen()
    while True:
        s1 = s.accept()
        print 'Server: accepetd'
        ServerConnection(s1).start()


class ServerConnection(Thread):
    def __init__(self, sock):
        Thread.__init__(self)
        self.sock = sock

    def run(self):
        print "SERVER RECEIVED: " + self.sock.recv(120)
        self.sock.send("bye!! (%d)" % random.randint(1,100))
        self.sock.recv(5)
        self.sock.close()


test_server()