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
import time

KEY_ERROR = "KEY NOT FOUND!"
USER_ALREADY_LOGGED_IN = "USER_ALREADY_LOGGED_IN"
WRONG_USERNAME_PASSWORD = "WRONG_USERNAME_PASSWORD_PAIR"
LOGIN_SUCCESSFUL = "Login successful "
VALIDATION_TIME_OUT = "VALIDATION_TIME_OUT"


class Validation_Worker(multiprocessing.Process):

    def __init__(self, server):

        self.server = server

    def run(self):
        print 'Validation worker started running'

        while True:
            if not self.server.validation_queue.empty():

                task = self.server.validation_queue.get()






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
        self.validation_queue = multiprocessing.Queue()

        # worker waits for msg and puts in to queue for further process
        self.msg_worker = Message.Msg_Worker(self, self.sock, self.msg_queue)

        print "Worker started"
        self.msg_worker.start()

        # keeps username:session_key
        self.online_users = {}

        # users waiting for validation
        self.waiting_validation = {}

        self.srp_sessionkeys = {}

        # sessionkeys for all users
        self.public_keys = "../data/keys/user_keys/"

    def msg_handler(self):

        plain, addr = self.msg_queue.get()

        # plain = CF.rsa_dec_der(msg, "/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/keys/server_keys/key.pem")

        msg = json.loads(plain)  # Message.UnMessage(plain)

        if msg['type'] == Message.LOGIN:
            # self.user_SRP_login(msg['msg'], addr)
            print msg

        # no need fir list
        # elif msg['type'] == Message.LIST:
        #     # self.user_list_request()
        #     print msg

        elif msg['type'] == Message.GET_PUB_KEY:
            # self.user_get_key_req(A,B)
            print msg

        elif msg['type'] == Message.SRP_VALIDATION_1:
            self.validation_queue.put(msg['msg'])

        elif msg['type'] == Message.LOGOUT:
            print msg

    # SRP
    def user_SRP_login(self, login_msg, addr):

        # TODO
        # get user login msg = {'username': self.username, 'A': self.A, 'N': self.N}

        login_msg = json.loads(login_msg)

        # check username
        if login_msg['username'] == '' or login_msg['username']:

            self.send_error(WRONG_USERNAME_PASSWORD)
            return

        if login_msg['username'] in self.online_users.keys():
            self.send_error(USER_ALREADY_LOGGED_IN)
            return

        if login_msg['A'] % login_msg['N'] == 0:
            self.send_error(WRONG_USERNAME_PASSWORD)
            return

        SRP_server = CF.SRP_server()

        srp_reply, v = SRP_server.srp_server_accept_login(login_msg['username'], login_msg['A'], login_msg['N'])

        key = SRP_server.srp_server_sessio_key(login_msg['A'], login_msg['N'], v)
        self.srp_sessionkeys[login_msg['username']]

        # verify key
        
        self.send_packet(addr[0], int(addr[1]), Message.Message(Message.SRP_REPLY, self.username, srp_reply).json)

        m_1 = str(login_msg['A']) + str(srp_reply['B']) + str(key)

        h = CF.hash_sha256(str(login_msg['A']) + str(CF.hash_sha256(m_1)) + str(key))
        self.waiting_validation[login_msg['username']] = (0, h)

        t = time.time()
        while self.waiting_validation[login_msg['username']] == 0:

            if t - time.time() > 15:
                self.send_error(VALIDATION_TIME_OUT)
                return

        # validation pass

        self.online_users[login_msg['username']] = addr
        # send update
        self.send_update()


        # validation, addr = self.sock.recvfrom(1024)

        # if validation['msg']['Nounce_reply'] != nounce:
        #     self.send_error(WRONG_USERNAME_PASSWORD)
        #     return


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

