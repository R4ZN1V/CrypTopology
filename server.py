import socket
import names
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#this is the server script.
#it gets as a parameter to the command line the path to the file of collaborators ip and keys
#the format of the collaborators map line is:
#in each line for each collaborator:
#<collaborator_ip>-<collaborator_key>

class server:
	#this function gets the path to file and creates a map of collaborators ip to collaborator key
	def file2coll_list(self,file_name):
		#opens the file
		with open (file_name, "r") as myfile:
			#the format is each line is: <collaborator_ip>-<collaborator_key>
    			data = myfile.readlines()
			myfile.close()
		is_ip = True
		ip = ""
		sig = ""
		for row in data:
			ip = ""
			sig = ""
			for char in row:
				if is_ip:
					if char != '-':
						ip = ip+char
					else:
						is_ip = False
				else:
					if char != '\n':
						sig = sig+char
					else:
						is_ip = True
			self.coll_list[ip] = sig
		self.coll_list.pop('\n', None)

	
	def __init__(self,file_name):
		self.coll_list = {}
		#set collaborator list according to file
		self.file2coll_list(file_name)
		#TO YEHONATAN: here you need to initalize the graph of topology
		#opens a UDP socket for server
		self.sock = socket.socket(names.IP, names.UDP) 
		self.ip = "127.0.0.1"
		self.port= names.SERVER_PORT
		self.sock.bind((self.ip, self.port))

	#this function decrypts the init message according to RSA key
	def decrypt_text(self,text):
		#open file of private key
		with open(names.PRIVATE_KEY_PATH, "rb") as key_file:
			private_key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
			key_file.close()
		#decrypts the text
		decrypt = private_key.decrypt(text,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
		return decrypt

	#this function gets the text as sid|k and returns tuple of sid and k
	def text_to_keys(self,text):
		sid = ""
		k = ""
		passed = False
		for char in text:
			if passed:
				k = k + char
			else:
				if char == "|":
					passed = True
					continue
				sid = sid + char
		return (sid,k)

	#this function gets sid,key and data and signs the data as the next format:
	#[original data]sid:[sid]signature:[signature([original data]sid:[sid])]
	def sign_data(self,sid,key,data):
		h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
		data = data + "sid:" + str(sid)
		h.update(bytes(data))
		a = h.finalize()
		final_mesg = data + "signature:" + a
		return final_mesg

	#this is a boolean function that validates data according the format of the function above
	#it checks if the signature correct and if the sid matches the current sid
	def validate_sig(self,data,k_auth,sid):
		a = data.split("signature:")
		mesg = a[0]
		sig = a[1]
		h = hmac.HMAC(k_auth, hashes.SHA256(), backend=default_backend())
		h.update(bytes(mesg))
		orig = h.finalize()
		if orig == sig:
			a = mesg.split("sid:")
			if int(a[1]) == int(sid):
				return True
			else:
				return False
		else:
			return False
	
	#makes k_auth and k_out according to k	
	def make_client_keys(self,k):
		backend = default_backend()
		salt = bytes(k)
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
		k_auth = kdf.derive("Authentication")
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
		k_out = kdf.derive("Client_Key")
		return  (k_auth,k_out)

	#makes a string of collaborators ip ready to send
	def make_list(self):
		ret=""
		if not self.coll_list:
			return ret
		else:
			for a in self.coll_list:
				ret = ret+"|"+a
			return ret+'|' 

	#this function takes data from the user that claimed to be signed by collaborator and validate according to ip if signature is true
	def check_current_ip(self,coll_ip,client_ip,data,sid):
		#the key of current ip
		try:
			key = self.coll_list[coll_ip]
		except KeyError:
			sys.exit("unvalid collaborator ip from user")
		#create string and signs it to validate sig from client
		h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
		to_check = str(sid) + "ip:" + client_ip
		h.update(bytes(to_check))
		orig = h.finalize()
		#if the sig matches return true
		if bytes(orig) == bytes(data):
			return True
		else:
			return False

	#iterates on list from client and validates signature for each on
	#if the list is ok according to number of collaborator return True, otherwise False
	def check_auth(self,string,sid,client_ip):
		valid_colls_counter = 0
		#list format is |||ip-sig|||...
		ip_to_sig_list = string.split("|||")
		ip_to_sig_list.remove("")
		ip_to_sig_list.remove("")
		for entity in ip_to_sig_list:
			col_ip, sig = entity.split("-",1)
			if not self.check_current_ip(col_ip,client_ip,sig,sid):
				return False
			else:
				valid_colls_counter += 1

		num_colls_need_for_validation = 0
		if (names.n_A == -1):
			num_colls_need_for_validation = len(self.coll_list)
		else:
			num_colls_need_for_validation = names.n_A
		if valid_colls_counter == num_colls_need_for_validation:
			return True
		else:
			return False

	#sends signed ack message to user
	def send_ack(self,addr,sid,k_auth):
		mesg = "ACK"
		signed_ack = self.sign_data(sid,k_auth,mesg)
		self.sock.sendto(signed_ack,addr)

	#this function adds the new client to data base if accepted the connection
	#the code is inside a note for tests
        def add_signature_to_server(self,client_ip,sig):
		#self.coll_list[client_ip] = sig
		pass

	#this function mannages the session with user (main function)
        def start_client_session(self):
		#waits for receving init message
		data, addr = self.sock.recvfrom(5000)
		client_ip = addr[0]
		#client_ip = watch out if you run the client, one of the collaborators and server on same machine########
		if data[0:4] == "init":
			cyphertext = data[4:]
			#decrypts user keys inside init message
			decrypt_data = self.decrypt_text(cyphertext)
			(sid,k) = self.text_to_keys(decrypt_data)
			#makes keys according to k
			(k_auth,k_out) = self.make_client_keys(k)
			#make list of collaborators ip as a string for user
			con_list = self.make_list()
			#signs the list
			signed_list = self.sign_data(sid,k_auth,con_list)
			#sends the signed list to client
			self.sock.sendto(signed_list,addr)
			#timeout for return signatures from client
			self.sock.settimeout(4*names.TIMEOUT)
			try:
				data, addr = self.sock.recvfrom(5000)
			except socket.timeout:
				print "TIMEOUT"
				return False
			self.sock.settimeout(None)
			#validates signature of user on return list of sigs from collaborators
			if self.validate_sig(data,k_auth,sid):
				data = data.split("sid:")[0]
				#checks if signatures from collaborators are true
				if self.check_auth(data,sid,client_ip):
					#send ack to client
					self.send_ack(addr,sid,k_auth)
					#add k_out as sig of new collaborator
					self.add_signature_to_server(client_ip,k_out)
					print "SUCCESS"
					return True
				else:
					print "ALERT"
					return False






print "activating server..."
my_server = server(sys.argv[1])
while True:
	my_server.start_client_session()
my_server.sock.close()
