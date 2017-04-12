#Assign list to the internal dictionary in receive message
import sys
import socket
import Message
import threading
import getpass
#import config

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
	self.send_packet(self.server_ip,self.server_port,Message.Message(SIGN-IN,self.username,password).json)
	
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
	
    def send_message(self):
	#it is the controller fr the send_packet function
	while True:
		user_input=raw_input(self.username+" > ").split(' ')
		if user_input[0].lower()=="list":
			self.list_users()
		elif user_input[0].lower()=="send":# have to see how to relate the usernames with the ip and port
			ip,port=self.resolve_username(user_input[1])
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

    def receive_message(self):
	#it will receive all kinds of messages and will display the results to the user 
	while True:
		input_message,addr=client.recvfrom(1024)
		input_message=UnMessage(input_message)
		if input_message.get_type==LIST:
			#Assign it to the dictionary
		elif input_message.get_type==MESSAGE:
			print "<"+input_message.get_name()+" sent a message at "+input_message.get_time()+"> "+input_message.get_message()
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
	authentication_results=client.receive_message()
	If ""!=authentication_results: 	#yet to be done
		pass
	else:
		print 'Wrong Credentials..!!'
		exit(1)
	client.create_threads()		
		
main()
