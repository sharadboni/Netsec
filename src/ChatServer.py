# ahmet
# ChatServer.py

import sys
import socket
import datetime
import json
import Message


class Server():

    # init with the port number provided
    def __init__(self, port):

        try:

            self.user_list = []

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.sock.bind(("localhost", port))

        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)


        # user db (usernames,salts)
        self.user_db = None
        # client db (client, public key)
        self.client_db = None


    # SRP
    def user_login():
        pass

    def user_req_message(A, B):
        pass

    # DH
    def create_session_key(A, B):
        pass
