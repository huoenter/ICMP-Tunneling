import socket
import icmp

ic = socket.getprotobyname('icmp')
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, ic)
p = icmp.ICMPPacket()
buf = p.create(8, 88, 55557, 0, 'Sent from the Client')
print 'haha'
for x in xrange(5):
	s.sendto(buf, ('chenhuo.org', 22))
