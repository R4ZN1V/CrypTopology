import socket
import names
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

#this is the collaborator script.
#it gets as a parameter to the command line the path to the file of key of his MAC signature


class collaborator:
	def __init__(self):
		#initilizes the collaborator ip and port
		self.ip = "localhost"
		self.port = names.COLL_PORT
		#reads the path to the key of signature
		if len(sys.argv) > 1:
			f = open(str(sys.argv[1]),"r")
			self.k_out = f.read()[0:-1]
			f.close()
		#open a UDP socket to collaborator
		self.sock = socket.socket(names.IP, names.UDP) 
		self.sock.bind((self.ip, self.port))
		while True:
			#starts collaborator operation
			self.collaborator_op()

	def sign_data(self,data,ip):
		#adds client ip to the string
		mesg = data + "ip:" + ip
		print "collaborator signs on: "+mesg
		#signs on the final message
		h = hmac.HMAC(self.k_out, hashes.SHA256(), backend=default_backend())
		h.update(bytes(mesg))
		sig = h.finalize()
		return sig

	#main operation of collaborator
	def collaborator_op(self):
		data, addr=self.sock.recvfrom(5000)
		ip = addr[0]
		#client_ip = watch out if you run the client, one of the collaborators and server on same machine########
		sid=data
		#signs on data
		sig = self.sign_data(sid,ip)
		#sends the signature back to the client
		self.sock.sendto(sig,addr)



print "activating collaborator..."
my_col = collaborator()
my_col.sock.close()
