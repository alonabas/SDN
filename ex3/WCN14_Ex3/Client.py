import time
from stcp import stcp_socket
from threading import *

def test_client():
    # print '%s ' % (current_thread().getName())
    s = stcp_socket()
    s.connect("127.0.0.1", 54321)
    #s.send("hello")
    s.send("hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello  hellohellohellohellohellohellohello")
    time.sleep(10)
    print "CLIENT RECEIVED: " + s.recv(5)
    s.close()

test_client()
# for x in [1,2,3]:
#     Thread(name='my_service%d'%(x),target=test_client()).start()
    # print 't%s ' % (current_thread())
