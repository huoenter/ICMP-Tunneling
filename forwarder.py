import sys, socket, time, threading, icmp
LOGGING = True
loglock = threading.Lock()
addr = ''
def log(s, *a):
	if LOGGING:
		loglock.acquire()
		try:
			print '%s:%s' % (time.ctime(), (s % a))
			sys.stdout.flush()
		finally:
			loglock.release()

class PipeThread(threading.Thread):
	pipes = []
	pipeslock = threading.Lock()

	def wrap(self, data):
		packet = icmp.ICMPPacket()
		buf = packet.create(8, 88, 0, 0, data)
		return buf

	def rip(self, data):
		packet = icmp.ICMPPacket()
		buf = packet.parse(data, True)
		return buf
	
	def __init__(self, source, sink):
		threading.Thread.__init__(self)
		self.source = source
		self.sink = sink
		self.pipeslock.acquire()
		try: self.pipes.append(self)
		finally: self.pipeslock.release()
		self.pipeslock.acquire()
		try: pipes_now = len(self.pipes)
		finally: self.pipeslock.release()
		log('%s pipes now active', pipes_now)

	def run(self):
		while True:
			try:
				data = self.source.recv(1024)
				if not data: 
					print 'No data!'
					break
				if self.source.type == 1:
					print '=> receiving a tcp packet'
					data = self.wrap(data)
					print '=> tcp packet got wrapped'
				else:
					print '<= receiving an ICMP packet'
					data = self.rip(data)
					print '<= ICMP header got ripped'
				if self.sink.type == 3:
					self.sink.sendto(data, (addr, 22))
					print '=> send a wrapped packet'
				else:
					self.sink.send(data)
					print '<= send a ripped packet'
			except:
				print 'Exception!!'
				raise
				break
		log('%s terminateing', self)
		
		self.pipeslock.acquire()
		try: self.pipes.append(self)
		finally: self.pipeslock.release()
		self.pipeslock.acquire()
		try: pipes_left = len(self.pipes)
		finally: self.pipeslock.release()
		log('%s pipes still active', pipes_left)

class Pinhole(threading.Thread):
	def __init__(self, port, host, sendICMP):
		threading.Thread.__init__(self)
		self.sendICMP = sendICMP
		self.host = host
		self.port = port
		self.tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.icmpsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, \
								socket.getprotobyname('icmp'))
		if self.sendICMP:
			self.source = self.tcpsock
			print 'Listen to port %s' % port
			self.source.bind(('', port))
			self.source.listen(5)
			self.source, address = self.source.accept()
			self.sink = self.icmpsock
			self.sink.connect((self.host, 22))
		else:
			self.source = self.icmpsock
			self.source.bind((socket.gethostname(), 22))
			self.sink = self.tcpsock
			self.host = 'localhost'
			self.sink.connect((self.host, self.port))

	def run(self):
		PipeThread(self.source, self.sink).start()
		PipeThread(self.sink, self.source).start()

if __name__ == '__main__':
	print 'Starting Pinhole port forwarder/redirector'
	import sys
	try:
		port = int(sys.argv[1])
		newhost = sys.argv[2]
		log('Redirecting: localhost: %s --ICMP--> %s', port, newhost)
		addr = newhost
		sendICMP = True
	except ValueError:
		port = int(sys.argv[2])
		newhost = sys.argv[1]
		log('Redirecting: %s --ICMP--> localhost: %s', newhost, port)
		addr = newhost
		sendICMP = False
	except IndexError:
		print 'Usage: %s port newhost [newhost]' % sys.argv[0]
		sys.exit(1)
	Pinhole(port, newhost, sendICMP).start()
