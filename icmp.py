import socket
import binascii
import struct
import ctypes

BUFFER_SIZE = 8192

class IPPacket():
	def _checksum(self, data):
		if len(data) % 2:
			odd_byte = ord(data[-1])
			data = data[:-1]
		else:
			odd_byte = 0
		words =struct.unpack("!%sH" %(len(data)/2), data)
		total = 0
		for word in words:
			total += word
		else:
			total += odd_byte
		total = (total>>16) + (total & 0xffff)
		total += total>>16
		return ctypes.c_ushort(~total).value

	def parse(self, buf, debug = True):
		self.ttl, self.proto, self.chksum = struct.unpack("!BBH", buf[8:12])
		self.src, self.dst = buf[12:16], buf[16:20]
		if debug:
			print "parse IP ttl=", self.ttl, "proto=", self.proto, "src=", socket.inet_ntoa(self.src), \
			"dst=", socket.inet_ntoa(self.dst)

class ICMPPacket(IPPacket):
	def parse(self, buf, debug = True):
		IPPacket.parse(self, buf, debug)
		self.type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])
		if debug:
			print "parse ICMP type=", self.type, "code=", self.code, "id=", self.id, "seqno=", self.seqno
		return buf[28:]

	def create(self, type_, code, id_, seqno, data):
		packfmt = "!BBHHH%ss" % (len(data))
		args = [type_, code, 0, id_, seqno, data]
		args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))
		return struct.pack(packfmt, *args)
