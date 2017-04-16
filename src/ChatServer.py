# Sharad,Ahmet
# ChatServer.py

import sys
import socket
import datetime
import json
import Message
import Crypt_Functions as CF
import multiprocessing


class Msg_Worker(multiprocessing.Process):

    def __init__(self, server):
        multiprocessing.Process.__init__(self)

        self.sock = server.sock
        # multiprocessing queue to store active user info
        self.queue = server.msg_queue

    def run(self):

        while True:

            try:
                # msg and source ip-port
                cipher, addr = self.sock.recvfrom(4096)

                # TODO decrypt msg

                self.queue.put(cipher)

            except Exception as e:
                print 'Error while receiving a message', e


class Server():

    # init with the port number provided
    def __init__(self, port):

        # public, private key paths
        self.sk = None
        self.pk = None

        # TODO, port managing
        try:

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.sock.bind(("localhost", port))

        except Exception as e:
            print 'Error while creating the socket :', e
            exit(1)


        # user db (usernames,salts)
        self.user_db = None
        # client db (client, public key)
        self.client_db = None

        self.msg_queue = multiprocessing.Queue()

        # worker waits for msg and puts in to queue for further process
        self.msg_worker = Msg_Worker(self)

        print "Worker started"
        self.msg_worker.start()


        self.session_keys = {}
        self.online_users = {}


    def msg_handler(self):

        plain = self.msg_queue.get()


        #plain = CF.rsa_dec_der(msg, "/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/keys/server_keys/key.pem")


        msg = json.loads(plain)  # Message.UnMessage(plain)
        print msg

        if msg['type'] == Message.LOGIN:
            self.user_SRP_login(msg['msg'])
        # TODO, call thread for msg types

        # ...

    # SRP
    def user_SRP_login(self, login_msg):

        # TODO
        # get user login msg = {'username': self.username, 'A': self.A, 'N': self.N}

        SRP_server = CF.SRP_server()
        print login_msg
        login_msg = json.loads(login_msg)
        key = SRP_server.srp_server_accept_login(login_msg['username'], login_msg['A'], login_msg['N'])

        print "session key :", key
        # TODO
        # verify proof of session key

        self.session_keys[login_msg['username']] = key

    # user requested list of users
    def user_list_request(self, user):
        pass

    # A wants to talk with B
    def user_comm_request(self, A, B):
        pass

    # generate session key between A, B
    def genereta_session_key(self, A, B):
        pass

if __name__ == '__main__':
    server = Server(9090)
    server.msg_handler()

