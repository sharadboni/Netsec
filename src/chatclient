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
	    self.server_port=SERVER_PORT
	    self.server_ip=SERVER_IP
	    self.target_ip=None
	    self.target_port=None

        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)
	
    def login(username,password):
	    pass
    def send_message():
	    pass
    def receive_message():
	    pass
    def parse_args(): 
     args=sys.argv[1:]
     for i in xrange(0,len(args),2):

	      if args[i]=="-u":

		      username=args[i+1]

	      elif args[i]=="-p":

		      password=args[i+1]



      if username=="" or password=="":

          print 'chatclient.py -u username -p password'

          sys.exit(2)
