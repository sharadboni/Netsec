import sys
import socket
import datetime
import json
import Message
import threading
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
	
    def login(self,username,password):
	#encrypt with servers public key which will have its settings in the configuration file
	self.send_message(self.server_ip,self.server_port,Message.Message(SIGN-IN,userame+" "+password).json)
	
    def logout(self):
	self.send_message(self.server_ip,self.server_port,Message.Message(EXIT).json)
	
    def list_users(self):
	self.send_message(self.server_ip,self.server_port,Message.Message(LIST).json)
	
    def send_message(self,ip,port,message):
	    self.sock.sendto(message,(ip,port))
		
    def receive_message(self):
	    pass
	
    def parse_args(self): 
     args=sys.argv[1:]
     for i in xrange(0,len(args),2):

	      if args[i]=="-u":

		      username=args[i+1]

	      elif args[i]=="-p":

		      password=args[i+1]
     if username=="" or password=="":

          print 'chatclient.py -u username -p password'

          sys.exit(2)
