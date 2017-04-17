# Sharad,Ahmet
# ChatServer.py

import sys
import os
import socket
import datetime
import json
import Message
import Crypt_Functions as CF
import multiprocessing

KEY_ERROR = "KEY NOT FOUND!"

class Server():

    # init with the port number provided
    def __init__(self, port):

        self.username = 'server_' + str(port)
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

        self.msg_queue = multiprocessing.Queue()

        # worker waits for msg and puts in to queue for further process
        self.msg_worker = Message.Msg_Worker(self, self.sock, self.msg_queue)

        print "Worker started"
        self.msg_worker.start()

        # keeps username:session_key
        self.online_users = {}

        # sessionkeys for all users
        self.public_keys = "../data/keys/user_keys/"

    def msg_handler(self):

        plain, addr = self.msg_queue.get()

        # plain = CF.rsa_dec_der(msg, "/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/keys/server_keys/key.pem")

        msg = json.loads(plain)  # Message.UnMessage(plain)

        if msg['type'] == Message.LOGIN:
            # self.user_SRP_login(msg['msg'], addr)
            print msg

        elif msg['type'] == Message.LIST:
            # self.user_list_request()
            print msg

        elif msg['type'] == Message.GET_PUB_KEY:
            # self.user_get_key_req(A,B)
            print msg

    # SRP
    def user_SRP_login(self, login_msg, addr):

        # TODO
        # get user login msg = {'username': self.username, 'A': self.A, 'N': self.N}

        SRP_server = CF.SRP_server()

        login_msg = json.loads(login_msg)
        srp_reply, v = SRP_server.srp_server_accept_login(login_msg['username'], login_msg['A'], login_msg['N'])

        key = SRP_server.srp_server_sessio_key(login_msg['A'], login_msg['N'], v)

        ctr = os.urandom(16)
        nounce = os.urandom(16)
        srp_reply['Nounce':CF.aes_ctr(nounce, key, ctr), 'ctr': ctr]
        self.send_packet(addr[0], int(addr[1]), Message.Message(Message.SRP_REPLY, self.username, srp_reply).json)

        



        # TODO
        # verify proof of session key

        # self.session_keys[login_msg['username']] = key

    def send_packet(self, ip, port, message):
      #it sends all type of packets to the desired destination. It is used by all the other functions to send the desired message
        self.sock.sendto(message, (ip, port))

    # user requested list of users
    def user_list_request(self, user):
        pass

    # A wants to talk with B
    def user_get_key_req(self, A, B):
        pass

    def send_update(self):
        pass

    # get user key
    def get_pub_key_of_user(self, username):

        f = self.public_keys + 'username' + '/key_pub.pem'

        pub = ''
        with open(f, 'r') as pf:
            pub = pf.read()
        if pub == '':
            return KEY_ERROR
        else:
            return pub


if __name__ == '__main__':
    server = Server(9090)
    # server.msg_handler()

