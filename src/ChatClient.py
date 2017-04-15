#Assign list to the internal dictionary in receive message
#ESTAB KEY in receive func
import sys
import socket
import Message
import threading
import getpass
#import config
import Crypt_Functions as CF

PRIME_SIZE = 1024
g = 2


class Client():

    def __init__(self):

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    
        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)	
		
	self.server_port=Message.SERVER_PORT
	self.server_ip=Message.SERVER_IP
	self.username=None
	self.online_users={} #maps a username to its respective ip and port in the form of tuple (ip,port)
	self.session_keys={} #has public key of the users that the current user has communicated with
	self.public_keys={} # stores the public keys of the teh chat users temporarily and deletes it once the session has been established
	try:
	    self.server_public_key=# To Do
	    self.private_key=# To Do	
	except Exception as e:
	    print 'Error with public/private key :', e
            exit(1)

    def login(self):
	#gets the username and password and sends it to the server to get verified
	self.username=raw_input(">Username: ")
	password=getpass.getpass(">Password: ")
	#encrypt with servers public key which will have its details in the configuration file
	
	# SRP authentication
	
	#safe prime
	N = CF.generate_prime(PRIME_SIZE)
	# SRP client
	SRP_client = CF.SRP_client(self.username, password, self, g, N)	
	# login msg encrypted with server public key
	login_msg = SRP_client.srp_client_login_msg()

	self.send_packet(self.server_ip,self.server_port,Message.Message(SIGN-IN,self.username, login_msg)
	
	# receive reply from server.
	# TODO
	B, salt = get_reply()
	try:
		Key = SRP_client.srp_create_session_key(B, salt)

		if Key:
			self.session_keys['server'] = Key
		else:
			print "!! Login Unsuccessfull"
			exit(1)
	except Exception as e:
		print "!! Login Unsuccessfull"
	

    def logout(self):
	#will send a logout message to the server so that server will remove the current user from the online list
	self.send_packet(self.server_ip,self.server_port,Message.Message(EXIT,self.username).json)
	
    def list_users(self):
	#will send a list user message to the server which will return all the online users
	self.send_packet(self.server_ip,self.server_port,Message.Message(LIST,self.username).json)
	
    def peer_chat(self,ip,port,chat_message):
	#sends the desired message to the fellow chat peer
	self.send_packet(ip,port,Message.Message(MESSAGE,self.username,chat_message).json)
	
    def send_packet(self,ip,port,message):
	#it sends all type of packets to the desired destination. It is used by all the other functions to send the desired message
	self.sock.sendto(message,(ip,port))

    def get_pub_key_from_server(self,username):
	#request the public key of the chat user from the server
	self.send_packet(ip,port,Message.Message(GET_PUB_KEY,self.username,username).json)
			 
    def tcp_establish_key_listener(self,ip,port):
		#create a tcp server
		tcp_socket = socket.socket()         # Create a socket object
		host = socket.gethostname() # Get local machine name
		port = 12345                # Reserve a port for your service.
		tcp_socket.bind((host, port))        # Bind to the port
		tcp_socket.listen(1)
		conn, addr = s.accept()     # Establish connection with client.
   		conn.send('Thank you for connecting')
		conn.close() 
		tcp_socket.close	 
		self.send_packet(ip,port,Message.Message(ESTAB_KEY,self.username,tcp_port).json) #self reports its own tcp_port to the user on the other end
		#wait for connection to establish and key establishment to be done
		#close the tcp connection 	 
	
    def tcp_establish_key_sender(self,ip,port):
		#opens a tcp port	
		tcp_socket.connect((host, port))
		print tcp_socket.recv(1024)
		tcp_socket.close 	 
		#sends a connection response to the listener	
		#closes the connection	 
			 
    def establish_key(self,username,ip,port,msg):
	#establishes the key with the fellow chat user
	self.get_pub_key_from_server(username)
	while not self.key_present(username,"PUBLIC"):
		pass
	self.tcp_establish_key_listener(ip,port)
	self.peer_chat(ip,port,msg)
			 
    def send_message(self):
	#it is the controller fr the send_packet function
	while True:
		user_input=raw_input(self.username+" > ").split(' ')
		if user_input[0].lower()=="list":
			self.list_users()
		elif user_input[0].lower()=="send":
			ip,port=self.resolve_username(user_input[1])
			if not self.key_present(user_input[1],"SESSION"):
        			try:
	    				threading.Thread(target=self.establish_key,args=(user_input[1],ip,port,user_input[2])).start()
        			except Exception as e:
            				print 'Error while creating threads :', e		 
			else: 
				self.peer_chat(ip,port,user_input[2])
		elif user_input[0].lower()=="exit":
			self.logout()
			exit(0)	
		else:
			print 'Use the following commands: 1) list 2) send USERNAME MESSAGE 3) exit'
	
    def resolve_username(self,user):
	#maps the username to the ip address and port to whom the message is being sent
	ip,port=self.online_users[user]
	return ip,port
			 
    def key_present(username,_key):
	if _key=="PUBLIC":
		if username in self.public_keys:
			return True
		return False
	
	if username in self.session_keys:
		return True
	return False
			 
    def receive_message(self):
	#it will receive all kinds of messages and will display the results to the user 
	while True:
		input_message,addr=self.sock.recvfrom(1024)
		input_message=UnMessage(input_message)
		if input_message.get_type==LIST:
			#Assign it to the dictionary
		elif input_message.get_type==MESSAGE:
			print "<"+input_message.get_name()+" sent a message at "+input_message.get_time()+"> "+input_message.get_message()
		elif input_message.get_type==ESTAB_KEY:
        		try:
	    			threading.Thread(target=self.tcp_establish_key_sender,args=(addr[0],input_message.get_message())).start()
        		except Exception as e:
            			print 'Error while creating threads :', e			 
		else:
			"Message received in an unknown format"	
			 
    def create_threads(self):
	#this function creates the send_message and receive message threads so that chats can happen simultaneously. 
        try:
	    threading.Thread(target=self.send_message).start()
	    threading.Thread(target=self.receive_message).start()
	    
        except Exception as e:
            print 'Error while creating threads :', e
            exit(1)
	
#start of the main parent execution function for the client chat file
def main():
	client=Client()
	client.login()
	client.create_threads()		
		
main()
