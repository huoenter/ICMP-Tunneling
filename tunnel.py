import os, sys
import hashlib
import getopt
import fcntl
import icmp
import tiem
import struct
import socket, select

SHARED_PASSWORD = hashlib.md5("password").digest()
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001

MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1"
MTU = 1500
CODE = 86
TIMEOUT = 10 * 60

class Tunnel():
	def create(self):
		self.tfd = os.open("/dev/net/tun", os.O_RDWR)
		ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
		self.tname = ifs[:16].strip("\x00")

	def close(self):
		os.close(self.tfd)

	def config(self, ip):
		os.system("ip link set %s up" % (self.tname))
		os.system("ip link set %s mtu 1000" % (self.tname))
		os.system("ip addr add %s dev %s" % (ip, self.tname))

	def run(self):
		self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
		
		self.clients = {}
		packet = icmp.ICMPPacket()
		self.client_seqno = 1

		while True:
			rset = select.select([self.icmpfd, self.tfd], [], [])[0]
			for r in rset:
				if r == self.tfd:
					if DEBUG: os.write(1, ">")
					data = os.read(self.tfd, MTU)
					if MODE == 1: #server
						for key in self.clients:
							buf = packet.create(0, CODE+1, self.clients[key]["id"], self.clients[key]["seqno"], \
												data)
							self.clients[key]["seqno"] += 1
							self.icmpfd.sendto(buf, (self.clients[key]["ip"], 22))
						curTime = time.time()
						for key in self.clients.keys():
							if curTime - self.clients[key]["aliveTime"] > TIMEOUT:
								print "Remove timeouted client", self.clients[key]["ip"]
								del self.clients[key]
					else:  #client
						buf = packet.create(8, CODE, PORT, self.client_seqno, data)
						self.client_seqno += 1
						self.icmpfd.sendto(buf, (IP, 22))
				elif r == self.icmpfd:
					if DEBUG: os.write(1, "<")
					buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
					data = packet.parse(buf, DEBUG)
					ip = socket.inet_ntoa(packet.src)
					if packet.code in (CODE, CODE+1):
						if MODE == 1: #server
							key = struct.pack("4sH", packet.src, packet.id)
							if key not in self.clients:
								if data == SHARED_PASSWORD:
									self.clients[key] = {"aliveTime": time.time(),
														 "ip": ip,
														 "id": packet.id,
														 "seqno": packet.seqno}
									print "New client from %s:%d" % (ip, packet.id)
								else:
									print "Wrong password from %s:%d" (ip, packet.id)
									buf = packet.create(0, CODE+1, packet.id, packet.seqno, "PASSWORD"*10)
									self.icmpfd.sendto(buf, (ip, 22))
							else:
								os.write(self.tfd, data)
								self.clients[key]["aliveTime"] = time.time()
						else:
							if data.startswith("PASSWORD"):
								buf = packet.create(8, CODE, packet.id, self.client_seqno, SHARED_PASSWORD)
								self.client_seqno += 1
								self.icmpfd.sendto(buf, (ip, 22))
							else:
								os.write(self.tfd, data)

def usage(status=0):
	print "Usage: icmptun [-s code|-c serverip,code,id] [-hd] [-l localip]"
	sys.exit(status)

if __name__ == "__main__":
	opts = getopt.getopt(sys.argv[1:], "s:c:l:hd")
	for opt, optarg in opts[0]:
		if opt == "-h":
			usage()
		elif opt == "-d":
			DEBUG += 1
		elif opt == "-s":
			MODE = 1
		elif opt == ""-c:
			MODE = 2
			IP, CODE, PORT = optarg.split(",")
			CODE = int(CODE)
			PORT = int(PORT)
		elif opt == "-l":
			IFACE_IP = optarg

	if MODE == 0 or CODE == 0:
		usage(1)

	tun = Tunnel()
	tun.create()
	print "Allocate interface %s" % (tun.tname)
	tun.config(IFACE_IP)
	try:
		tun.run()
	except KeyboardInterrupt:
		tun.close()
		sys.exit(0)
