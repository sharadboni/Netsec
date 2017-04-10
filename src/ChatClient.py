import sys
import socket
import datetime
import json
import Message
import threading
import getpass
#import config

class Client():

    def __init__(self, port):

        try:

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    self.server_port=Message.SERVER_PORT
	    self.server_ip=Message.SERVER_IP
	    self.target_ip=None
	    self.target_port=None

        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)
	
    def login(self):
	#gets the username and password and sends it to the server to get verified
	username=raw_input(">Username: ")
	password=getpass.getpass(">Password: ")
	#encrypt with servers public key which will have its settings in the configuration file
	self.send_message(self.server_ip,self.server_port,Message.Message(SIGN-IN,userame+" "+password).json)
	
    def logout(self):
	#will send a logout message to the server so that server will remove the current user from the online list
	self.send_message(self.server_ip,self.server_port,Message.Message(EXIT).json)
	
    def list_users(self):
	#will send a list user message to the server which will return all the online users
	self.send_message(self.server_ip,self.server_port,Message.Message(LIST).json)
	
    def peer_chat(self,ip,port,chat_message):
	#sends the desired message to the fellow chat peer
	self.send_message(ip,port,Message.Message(MESSAGE,chat_message).json)
	
    def send_message(self,ip,port,message):
	#it sends all type of messages to the desired destination. It is used by all the other functions to send the desired message
	    self.sock.sendto(message,(ip,port))
		
    def receive_message(self):
	#it will receive all kinds of messages and will display the results to the user 
	    pass
	
    def parse_args(self): 
	
