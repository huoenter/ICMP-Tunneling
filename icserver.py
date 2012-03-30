import socket, sys, icmp

p = icmp.ICMPPacket()
duf = p.create(0, 88, 0, 0, 'Sent from the server.')
print socket.gethostname()
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
for x in xrange(5):
	buf = s.recv(1024)
	p.parse(buf, True)
	print str(buf[28:])
#	s.sendto(duf, ('localhost', 22))
