import sys
import socket
import Message
import threading
import getpass
import json
import Crypt_Functions as CF
import time

PRIME_SIZE = 1024
g = 2 #diffie hellman parameter

public_keys = {}
class Client():

    def __init__(self):
	#formation of socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	#exception handling if the socket is not made correctly    
        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)	

	# read server.config
	with open("../data/server.config","r") as f:

		kf = json.load(f)
	
	self.server_port = int(kf['server_port'])
	self.server_ip = kf["server_ip"]
	
	#print int(kf['server_port']), kf["server_ip"] 
	self.username=None
	self.online_users={'server_9090':['127.0.0.1', 9090]} #maps a username to its respective ip and port in the form of tuple (ip,port)
	self.ip_port_users={('127.0.0.1',9090):'server_9090'} #reverse mapping of (ip,port) to users
	self.session_keys={} #has public key of the users that the current user has communicated with
	# self.public_keys={} # stores the public keys of the the chat users temporarily and deletes it once the session has been established
	try:
	    self.server_public_key=kf["server_pubkey"] # server public key path
	    #self.private_key= # no need 	
	except Exception as e:
	    print 'Error with public/private key :', e
            exit(1)

	self.SRP_client = None
	self.loggedin = False

    def login(self):

	#gets the username and password and sends it to the server to get verified
	self.username=raw_input(">Username: ")
	password=getpass.getpass(">Password: ")
	
	print "logging in ..."	
	# SRP authentication
	
	# SRP client
	self.SRP_client = CF.SRP_client(self.username, password)	
	# login msg encrypted with server public key
	login_msg = self.SRP_client.srp_client_login_msg()

	print "sending srp login msg with username, A , N" # , login_msg
	self.send_packet( self.server_ip , self.server_port, Message.Message(Message.LOGIN,self.username, msg=login_msg).json )
	#self.send_packet( self.server_ip , self.server_port, Message.Message(Message.LOGIN,self.username, self.public_keys, self.session_keys,'server', login_msg).encrypted_message )
	
	print 'Waiting for srp login reply...'

	t = time.time()

	while not self.loggedin:
		
		if time.time() - t > 15:
			return False
		try:
			self.sock.settimeout(15.0)

			srp_reply, addr=self.sock.recvfrom(1024)
	
			self.sock.settimeout(None)
		except Exception as e:
			print "LOGIN TIMEOUT!"
			return False
		srp_reply = json.loads(srp_reply)
		if srp_reply['type'] == Message.SRP_REPLY:
    
        		server_session_key, A, B = self.create_srp_key(srp_reply)
    
   	             	if server_session_key == "SRP_KEY_ERROR":
        	     		print "Login Error!!!"
                        	return False

                s = str(A) + str(B)+str(server_session_key)
                m_1 = unicode(CF.hash_sha256(s),errors='replace')
		print 'Sending Message.SRP_VERIFICATION_1'	
		self.send_packet( self.server_ip , self.server_port, Message.Message(Message.SRP_VERIFICATION_1,self.username, msg=m_1).json) 
                
		print 'Waiting for Message.SRP_VERIFICATION_2'
		srp_verify, addr=self.sock.recvfrom(1024)
		m_2 = unicode(CF.hash_sha256(str(json.loads(login_msg)['A']) + str(CF.hash_sha256(m_1.encode('ascii', 'ignore'))) + str(server_session_key)), errors='replace')
		if m_2 == json.loads(srp_verify)['msg']:
			self.loggedin = True
		else:
			return False

		
	return True
    def create_srp_key(self, srp_reply):

#	srp_reply, addr=self.sock.recvfrom(1024)
	#srp_reply = json.loads(srp_reply)	

	B = srp_reply['msg']['B']
	salt = srp_reply['msg']['salt']
	
	try:
		print "generating key..."
		Key = self.SRP_client.srp_create_session_key(B, salt)
	
		if Key:
			self.session_keys['server'] = Key
		else:
			print "!! Login Unsuccessfull"
			return "SRP_KEY_ERROR"
	except Exception as e:
		print e
		print "!! Login Unsuccessfull"
		return "SRP_KEY_ERROR"
	return Key, self.SRP_client.A, B 
	
    def get_key_for_encryption(self,type,name):
	if type=="public":
		return public_keys[name]
	return session_keys[name]

    def logout(self):
	#will send a logout message to the server so that server will remove the current user from the online list
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.LOGOUT,self.username,'server'))
	exit(0)

    #redundant function list_users won't be used now updates will be broadcasted after a user logs out.	
    def list_users(self):
	#will send a list user message to the server which will return all the online users
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.LIST,self.username, self.public_keys, self.session_keys,'server').encrypted_message)
	
    def peer_chat(self,ip,port,chat_message,username):
	#sends the desired message to the fellow chat peer
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.MESSAGE,self.username,self.public_keys, self.session_keys,username,chat_message).encrypted_message)
	
    def send_packet(self,ip,port,message):
	#it sends all type of packets to the desired destination. It is used by all the other functions to send the desired message
	self.sock.sendto(message,(ip,port))

    def get_pub_key_from_server(self,username):
	#request the public key of the chat user from the server
	self.send_packet(self.server_ip,self.server_port,Message.Message(Message.GET_PUB_KEY,self.username,username).json)
    
    #tcp_establish_key_listener function helps in the establishment of the shared session key			 
    def tcp_establish_key_listener(self,ip,port,username):
		#create a tcp server
		tcp_socket = socket.socket()         # Create a socket object
		#host = socket.gethostname() # Get local machine name
		host='localhost' #for testing
		port = 12345                # Reserve a port for your service.
		tcp_socket.bind((host, port))        # Bind to the port
		tcp_socket.listen(1)
		#p=CF.generate_prime(n=1024) for practical purposes
		p=11 #for testing
		g=2 # for testing
		self.send_packet(ip,port,Message.Message(ESTAB_KEY,self.username,self.public_keys, self.session_keys,username,tcp_port).encrypted_message) #self reports its own tcp_port to the user on the other end
		conn, addr = tcp_socket.accept()     # Establish connection with client.
		df=CF.Diffie_Hellman(p,g)
		pub_k=df.get_public_key()
   		conn.send(json.dumps({'p':p,'g':g,'public_key':pub_k}))
		data=json.loads(conn.recv(1024))
		public_key=data['public_key'] 
		public_key = CF.serialization.load_pem_public_key(str(public_key), backend=CF.default_backend())
		shared_key=shared_key=df.df_key_exchange(public_key)
		self.shared_keys[username]=shared_key	 
		conn.close() 
		tcp_socket.close	 
		#wait for connection to establish and key establishment to be done
		#close the tcp connection 	 
		
    #tcp_establish_key_sender function helps in the establishment of the shared session key	
    def tcp_establish_key_sender(self,ip,port,username):
		#opens a tcp port
		ip='localhost' #for testing purposes
		tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		tcp_socket.connect((ip, port))
		data=json.loads(tcp_socket.recv(1024))
		p=data['p']
		public_key=str(data['public_key'])
		g=data['g']
		print public_key
		df=CF.Diffie_Hellman(p,g)
		pub_k=df.get_public_key()
		tcp_socket.send(json.dumps({'public_key':pub_k}))
		public_key = CF.serialization.load_pem_public_key(public_key, backend=CF.default_backend()) 
		shared_key=df.df_key_exchange(public_key)
		self.shared_keys[username]=shared_key	 
		tcp_socket.close 	 		
		#sends a connection response to the listener	
		#closes the connection	 
			 
    def establish_key(self,username,ip,port,msg):
	#establishes the key with the fellow chat user
	self.get_pub_key_from_server(username)

	while not self.key_present(username,"PUBLIC"):

		#print 'establishing keys '
		pass
	self.tcp_establish_key_listener(ip,port,username)
	self.peer_chat(ip,port,msg,username)
			 
    def send_message(self):
	#it is the controller fr the send_packet function
	while True:
		user_input=raw_input(self.username+" > ").split(' ')
		if user_input[0].lower()=="list":
			# print self.online_users.keys()
			print self.online_users.keys()
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
	#creates a reverse mapping list of online users	
	temp_ip_port_users={}	
	for i in self.online_users.keys():
		temp_ip_port_users[self.online_users[i]]=i
	self.ip_port_users=temp_ip_port_users

    #below function deletes a user from the intenal lists like online_users,session_keys,public_keys,ip_port_users once receiving a broadcast from the server that the user has logged out
    def delete_user(self,user):
	for i in user.keys():
		del self.online_users[i]
		if i in self.session_keys:
			del self.session_keys[i]
		if i in self.public_keys:	
			del self.public_keys[i]
	for j in user.values():
		del self.ip_port_users[i]	
    
    #finds if the session key or public key is present in the internal mappings 
    def key_present(self, username,_key):
	if _key=="PUBLIC":
		if username in public_keys:
			return True
		return False
	
	if username in self.session_keys:
		return True
	return False
			 
    def receive_message(self):
	global public_keys
	#it will receive all kinds of messages and will display the results to the user 
	while True:
		input_message,addr=self.sock.recvfrom(1024)
		user=self.resolve_ip_port(addr)

		# TODO
		# decryption
		input_message=Message.UnMessage_no_encryption(input_message)
		if input_message.get_type() == Message.LIST:
			user_to_delete=input_message.get_message()
			self.delete_user(user_to_delete)
			#threading.Thread(target=self.user_to_ips).start() have to call this in srp
		elif input_message.get_type() == Message.MESSAGE:
			print "<"+user+" sent a message at "+input_message.get_time()+"> "+input_message.get_message()
		elif input_message.get_type() == Message.ESTAB_KEY:
        		try:
	    			threading.Thread(target=self.tcp_establish_key_sender,args=(addr[0],input_message.get_message(),input_message.get_username())).start()
        		except Exception as e:
            			print 'Error while creating threads :', e
		elif input_message.get_type() == Message.PUB_KEY:

			public_keys[input_message.get_username()]= input_message.get_message()['pub_key']

		elif input_message.get_type() == Message.UPDATE_LIST:
			self.online_users = input_message.msg
			
			self.online_users['server_9090'] = ['127.0.0.1', 9090]
		else:
			print "Message received in an unknown format"	
			 
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
	if client.login():
		print 'Logged in'
		client.create_threads()		
	else:
		print "Login not successfull"
main()
