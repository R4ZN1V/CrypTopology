import socket
import names
import sys
import random
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#this is the client script

class client:
	def __init__(self):
		#initilization of client: opens socket with the server
		self.ip = names.SERVER_IP
		self.port = names.SERVER_PORT		
		self.sock = socket.socket(names.IP, names.UDP) 

	#this function makes the keys of client: k,k_auth,k_out and sid
	def make_keys(self):
		self.sid = random.randint(0,sys.maxint)
		self.k = os.urandom(256)
		backend = default_backend()
		salt = bytes(self.k)
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
		self.k_auth = kdf.derive("Authentication")
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
		self.k_out = kdf.derive("Client_Key")

	#this is the encryption function, it gets makes the init message (without the "init" header)
	#and encrypts it according to the RSA public key
	def create_encrypt_mesg(self):
		#format: [sid]|[k]
		data = str(self.sid)+"|"+str(self.k)
		#encrypts it
		with open(names.PUBLIC_KEY_PATH, "rb") as key_file:
			public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())
			key_file.close()
		encrypt = public_key.encrypt(data,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
		return encrypt

	#this function gets the data and signs the data as the next format:
	#[original data]sid:[sid]signature:[signature([original data]sid:[sid])]
	def sign_data(self,string):
		h = hmac.HMAC(self.k_auth, hashes.SHA256(), backend=default_backend())
		data = string + "sid:" + str(self.sid)
		h.update(bytes(data))
		orig = h.finalize()
		return data + "signature:" + orig

	#this is a boolean function that validates data according the format of the function above
	#it checks if the signature correct and if the sid matches the current sid
	def validate_sig(self,data):
		a = data.split("signature:")
		mesg = a[0]
		sig = a[1]
		h = hmac.HMAC(self.k_auth, hashes.SHA256(), backend=default_backend())
		h.update(bytes(mesg))
		orig = h.finalize()
		if orig == sig:
			a = mesg.split("sid:")
			if int(a[1]) == int(self.sid):
				return True
			else:
				return False
		else:
			return False

	#this function gets ip string and makes a list of ip
	def string2list(self,string):
		ip_list = []
		ip=""
		for char in string:
			if char == '|':
				ip_list.append(ip)
				ip=""
			else:
				ip = ip+char
		ip_list.remove("")
		return ip_list

	#this function gets ip list of collaborators and sends each one the sid to authenticate
	#it then returns a dictionary of ip to return message of the collaborator (the signature)
	def authenticate_ip(self,ip_list):
		#opens a UDP socket to contact collaborators
		ip2auth = {}
		sock = socket.socket(names.IP, names.UDP)
		#for each ip send the sid
		for ip in ip_list:
			sock.sendto(str(self.sid),(ip,names.COLL_PORT))
		#recieve as the length of ip messages (the iteration over ip_list is just for length, not for actual ip)
		for ip in ip_list:
			data, addr=sock.recvfrom(5000)
			#puts auth of ip inside
			ip2auth[addr[0]] = data
		return ip2auth

	#gets the dictionary of collaborators-signatures (out put of the above function)
	#and creates a string to send the server
	def auth_list(self,ip2auth):
		string='|||'
		for a in ip2auth:
			string = string+a+'-'+ip2auth[a]+'|||'
		return string

	#this is the main function
	def connect_network(self):
		#make keys of client
		self.make_keys()
		buff = self.create_encrypt_mesg()
		#sends the init message to the server
		self.sock.sendto("init"+buff,(self.ip,self.port))
		#recieves list of ip
		ip_string = self.sock.recv(5000)
		#validates that the message is from the server
		if self.validate_sig(ip_string):
			ip_string = ip_string.split("sid:")[0]
			ip_list = self.string2list(ip_string)
			#waits for auth
			ip2auth=self.authenticate_ip(ip_list)
			authentications = self.auth_list(ip2auth)
			signed_auth = self.sign_data(authentications)
			self.sock.sendto(signed_auth,(self.ip,self.port))
		else:
			sys.exit("not a valid signature")
		#waits for ack from server
		mesg = self.sock.recv(5000)
		if self.validate_sig(mesg) and mesg[0:3] == "ACK":
			print "connection succed"




print "activating client..."
my_client = client()
my_client.connect_network()
my_client.sock.close()





