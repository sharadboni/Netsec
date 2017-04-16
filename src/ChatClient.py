#tcp diffie hellman not in message unmessage format.
#have to delete session keys once a user log outs
import sys
import socket
import Message
import threading
import getpass
import json
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

	# read server.config
	with open("../data/server.config","r") as f:

		kf = json.load(f)

		
	self.server_port = int(kf['server_port'])
	self.server_ip = kf["server_ip"]
	self.username=None
	self.online_users={} #maps a username to its respective ip and port in the form of tuple (ip,port)
	self.ip_port_users={} #reverse mapping of (ip,port) to users
	self.session_keys={} #has public key of the users that the current user has communicated with
	self.public_keys={} # stores the public keys of the teh chat users temporarily and deletes it once the session has been established
	try:
	    self.server_public_key=kf["server_pubkey"] # server public key path
	    #self.private_key= # no need 	
	except Exception as e:
	    print 'Error with public/private key :', e
            exit(1)

    def login(self):

	#gets the username and password and sends it to the server to get verified
	self.username=raw_input(">Username: ")
	password=getpass.getpass(">Password: ")
	#encrypt with servers public key which will have its details in the configuration file

	print "logging in ..."	
	# SRP authentication
	
	# SRP client
	SRP_client = CF.SRP_client(self.username, password, self)	
	# login msg encrypted with server public key
	login_msg = SRP_client.srp_client_login_msg()

	print "sending srp login msg with username, A , N"
	#self.send_packet( self.server_ip , self.server_port, Message.Message(Message.LOGIN,self.username, login_msg).json )
	self.send_packet( self.server_ip , self.server_port, Message.Message(Message.LOGIN,self.username, self.public_keys, self.session_keys,'server', login_msg).encrypted_message )
	
	print 'Waiting for srp login reply...'
	srp_reply, addr=self.sock.recvfrom(1024)
	srp_reply = json.loads(srp_reply)	
	print 'SRP login reply with B and salt:', srp_reply

	B = srp_reply['msg']['B']
	salt = srp_reply['msg']['salt']
	
	try:
		print "generating key..."
		Key = SRP_client.srp_create_session_key(B, salt)
	
		if Key:
			self.session_keys['server'] = Key
			print "key : ", Key
		else:
			print "!! Login Unsuccessfull"
			exit(1)
	except Exception as e:
		print e
		print "!! Login Unsuccessfull"
	
    def get_key_for_encryption(self,type,name):
	if type=="public":
		return public_keys[name]
	return session_keys[name]

    def logout(self):
	#will send a logout message to the server so that server will remove the current user from the online list
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.EXIT,self.username, self.public_keys, self.session_keys,'server').encrypted_message)
	
    def list_users(self):
	#will send a list user message to the server which will return all the online users
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.LIST,self.username, self.public_keys, self.session_keys,'server').encrypted_message)
	
    def peer_chat(self,ip,port,chat_message,username):
	#sends the desired message to the fellow chat peer
	self.send_packet(ip,port,Message.Message(Message.MESSAGE,self.username,self.public_keys, self.session_keys,username,chat_message).encrypted_message)
	
    def send_packet(self,ip,port,message):
	#it sends all type of packets to the desired destination. It is used by all the other functions to send the desired message
	self.sock.sendto(message,(ip,port))

    def get_pub_key_from_server(self,username):
	#request the public key of the chat user from the server
	self.send_packet(ip,port,Message.Message(Message.GET_PUB_KEY,self.username,self.public_keys, self.session_keys,'server',username).encrypted_message)
			 
    def tcp_establish_key_listener(self,ip,port,username):
		#create a tcp server
		tcp_socket = socket.socket()         # Create a socket object
		host = socket.gethostname() # Get local machine name
		port = 12345                # Reserve a port for your service.
		tcp_socket.bind((host, port))        # Bind to the port
		tcp_socket.listen(1)
		p=generate_prime(n=1024)
		df=CF.Diffie_Hellman(p,2)	 
		conn, addr = tcp_socket.accept()     # Establish connection with client.
   		conn.send((df.get_public_key(),p))
		shared_key=df.df_key_exchange(tcp_socket.recv(1024))
		self.shared_keys[username]=shared_key	 
		conn.close() 
		tcp_socket.close	 
		self.send_packet(ip,port,Message.Message(ESTAB_KEY,self.username,self.public_keys, self.session_keys,username,tcp_port).encrypted_message) #self reports its own tcp_port to the user on the other end
		#wait for connection to establish and key establishment to be done
		#close the tcp connection 	 
	
    def tcp_establish_key_sender(self,ip,port,username):
		#opens a tcp port	
		tcp_socket.connect((host, port))
		(public_key,p)=tcp_socket.recv(1024)
		df=CF.Diffie_Hellman(p,2)
		tcp_socket.send(df.get_public_key())
		shared_key=df.df_key_exchange(tcp_socket.recv(1024))
		self.shared_keys[username]=shared_key	 
		tcp_socket.close 	 
		#sends a connection response to the listener	
		#closes the connection	 
			 
    def establish_key(self,username,ip,port,msg):
	#establishes the key with the fellow chat user
	self.get_pub_key_from_server(username)
	while not self.key_present(username,"PUBLIC"):
		pass
	self.tcp_establish_key_listener(ip,port,username)
	self.peer_chat(ip,port,msg,username)
			 
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

    def resolve_ip_port(self,addr):
	#maps ip address and port to username from whom the message has come	
	username=self.ip_port_users[addr]
	return username

    def user_to_ips(self):
	temp_ip_port_users={}	
	for i in self.online_users.keys():
		temp_ip_port_users[self.online_users[i]]=i
	self.ip_port_users=temp_ip_port_users
	
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
		user=self.resolve_ip_port(addr)
		input_message=Message.UnMessage(input_message,user)
		if input_message.get_type()==LIST:
			self.online_users=input_message.get_message()
			threading.Thread(target=self.user_to_ips).start()
		elif input_message.get_type()==MESSAGE:
			print "<"+user+" sent a message at "+input_message.get_time()+"> "+input_message.get_message()
		elif input_message.get_type()==ESTAB_KEY:
        		try:
	    			threading.Thread(target=self.tcp_establish_key_sender,args=(addr[0],input_message.get_message(),input_message.get_username())).start()
        		except Exception as e:
            			print 'Error while creating threads :', e
		elif input_message.get_type()==PUB_KEY:
			 self.public_keys[input_message.get_username()]=input_message.get_message()
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
	#client.create_threads()		
		
main()
