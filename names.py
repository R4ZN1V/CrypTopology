#this file includes global variabels of the protocol
import socket

#protocol server port
SERVER_PORT = 101

#protocol collaborator port
COLL_PORT = 102

#server's ip
SERVER_IP = "127.0.0.1"

#protocol runs on UDP
UDP = socket.SOCK_DGRAM

#protocol runs on IP
IP = socket.AF_INET

#timeout definition
TIMEOUT = 10

#number of collaborators
n_A = -1

#path to client RSA public key
PUBLIC_KEY_PATH = "public_key"

#path to server RSA private key
PRIVATE_KEY_PATH = "private_key"
