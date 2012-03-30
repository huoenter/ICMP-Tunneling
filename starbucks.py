import socket
import time
import icmp
import threading
import sys

BUFFER_SIZE = 2048 
DEBUG = False
DRINKER = 88
TARGET = 87
ICMPID = 50614
count = -1
ic = socket.getprotobyname('icmp')

def wrap(data, code, ident):
	p = icmp.ICMPPacket()
	global count
	count += 1
	return p.create(0, code, ident, count, data)

#-------------------------------
#Now just wanna solve local:-1 local:22
class I2T_pipe(threading.Thread):
	'''This thread listens to an ICMP socket. For the initializtion,
	   the address of the 1st ICMP packet will be used when the ICMP
	   socket acts as a forwarder.
	   Basically, it relays ICMP packets to the established TCP port.

	   Precondition: source is an ICMP socket binded to ''.
	                 sink is a TCP socket has not connect to any yet.
					 TCP_ADDRESS is the address for the tcp to connect.
	  Note: I think the tcp socket has to be connected to the target port
	  		AFTER the 1st ICMP packet is receive. So as to forward a SYN
			or other stuffs to the target. Otherwise, the drinker cannot
			get the initialization info from the target port.
	'''
	def __init__(self, source, sink, TCP_ADDRESS):
		threading.Thread.__init__(self)
		self.source, self.sink = source, sink
		self.TCP_ADDRESS = TCP_ADDRESS

	def run(self):
		reverseReady = False
		first = True
		name = threading.currentThread().getName() + str(self.__class__)
		if DEBUG: print 'START %s' % name
		while True:
			buf = self.source.recv(BUFFER_SIZE)
			if not buf: break
			p = icmp.ICMPPacket()
			data = p.parse(buf, DEBUG)
			#code, address, ident, data = rip(buf)
			global ICMPID
			ICMPID = p.id
			code = int(p.code)
			address = socket.inet_ntoa(p.src)
			if int(code) != DRINKER: continue
			if not reverseReady:
				if DEBUG: print '%s: Got the 1st ICMP packet.' % name
				self.sink.connect((self.TCP_ADDRESS))
				if DEBUG: print '%s: TCP ESTABLISHED: %s -> %s' % (name, self.sink.getsockname(), self.sink.getpeername())
				T2I_pipe(self.sink, self.source, address).start()
				time.sleep(1)
				reverseReady = True
				first = False
			else:
				self.sink.send(data)
#			else:
#				if DEBUG: print '%s: Got an ICMP packet not from the drinker' % name
				if DEBUG: 
					print '%s: ICMP from %s RELAYto %s -> %s' % \
						(name, address, self.sink.getsockname(), self.sink.getpeername())

class T2I_pipe(threading.Thread):
	'''This thread has a readily tcp connection to port 22 on target.
	   It has an IP address that tells where the ICMP socket to relay
	   the TCP packets to.
	   Why a 22 in ICMP_ADDRESS is unknown. (Any number will do)

	   Precondition: source is a connected TCP socket.
	   				 sink is an ICMP socket which send packets to ICMP_ADDRESS.
	'''
	def __init__(self, source, sink, ICMP_ADDRESS):
		threading.Thread.__init__(self)
		self.source, self.sink = source, sink
		self.ICMP_ADDRESS = ICMP_ADDRESS

	def run(self):
		name = threading.currentThread().getName() + str(self.__class__)
		if DEBUG: print 'START %s' % name
		while True:
			buf = self.source.recv(BUFFER_SIZE)
			if not buf: break
			data = wrap(buf, TARGET, ICMPID)
			self.sink.sendto(data, (self.ICMP_ADDRESS, 22))
			if DEBUG: print '%s: %s -> %s RELAYto ICMP sendto %s.' % \
						(name, self.source.getpeername(), self.source.getsockname(), self.ICMP_ADDRESS)

#---------------------------------

class Pinhole():
	'''This is a solution for: python <name> local:-1 local:22'''
	def __init__(self, listen, send):
		self.listen, self.send = listen, send

	def run(self):
		source = socket.socket(socket.AF_INET, socket.SOCK_RAW, ic)
		fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		source.bind(('', 22))
		I2T_pipe(source, fwd, (self.send[0], self.send[1])).start()

#########################DRINKER######################
class Pipe_T2I(threading.Thread):
	'''This thread listens on drinker's port and send ICMP to the 
	   target.
	'''
	def __init__(self, source, sink, ICMP_ADDRESS):
		threading.Thread.__init__(self)
		self.source, self.sink = source, sink
		self.ICMP_ADDRESS = ICMP_ADDRESS

	def run(self):
		name = threading.currentThread().getName() + str(self.__class__)
		if DEBUG: print 'START %s' % name
		self.source.listen(5)
		newsock, address = self.source.accept()
		if DEBUG: print '%s: Got a connection: %s->%s' % \
					(name, newsock.getpeername(), newsock.getsockname())
		Pipe_I2T(self.sink, newsock).start()
		time.sleep(1)
		signal = wrap('Halo', DRINKER, 50614)
		self.sink.sendto(signal, (self.ICMP_ADDRESS, 22))
		if DEBUG: print '%s: Send ICMP SYN signal to %s' % (name, self.ICMP_ADDRESS)
		while True:
			buf = newsock.recv(BUFFER_SIZE)
			if not buf: break
			global ICMPID
			data = wrap(buf, DRINKER, ICMPID)
			self.sink.sendto(data, (self.ICMP_ADDRESS, 22))
			if DEBUG: print '%s: %s -> %s RELAYto ICMP -> %s' % \
					(name, newsock.getpeername(), newsock.getsockname(), self.ICMP_ADDRESS)

class Pipe_I2T(threading.Thread):
	'''Precondition: source is an ICMP socket. 
					 sink is a connected tcp socket.
		In this thread,
		it receives from the target ICMP socket and relay the packet 
		to the tcp socket.
	'''
	def __init__(self, source, sink):
		threading.Thread.__init__(self)
		self.source, self.sink = source, sink

	def run(self):
		name = threading.currentThread().getName() + str(self.__class__)
		if DEBUG: print 'START %s' % name
		while True:
			buf = self.source.recv(BUFFER_SIZE)
			if not buf: break
			p = icmp.ICMPPacket()
			data = p.parse(buf, DEBUG)
			code = int(p.code)	
			address = socket.inet_ntoa(p.src)
			if int(code) != TARGET: continue
			self.sink.send(data)
			if DEBUG: print '%s: ICMP from %s RELAYto %s -> %s' % \
					(name, address, self.sink.getsockname(), self.sink.getpeername())
		
	
class Holepin():
	'''This is a solution for: python <name> local:1234 chenhuo.org:-1'''
	def __init__(self, listen, send):
		self.listen, self.send = listen, send

	def run(self):
		source = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		source.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		fwd = socket.socket(socket.AF_INET, socket.SOCK_RAW, ic)
		fwd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		source.bind(('', self.listen[1]))
		Pipe_T2I(source, fwd, self.send[0]).start()
		

if __name__ == '__main__':
	listen = (sys.argv[1].split(':')[0], int(sys.argv[1].split(':')[1]))
	send   = (sys.argv[2].split(':')[0], int(sys.argv[2].split(':')[1]))
	if listen[1] < 0: Pinhole(listen, send).run()
	else: Holepin(listen, send).run()
