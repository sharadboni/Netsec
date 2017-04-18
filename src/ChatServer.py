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
import sqlite3

KEY_ERROR = "KEY NOT FOUND!"
USER_ALREADY_LOGGED_IN = "USER_ALREADY_LOGGED_IN"
WRONG_USERNAME_PASSWORD = "WRONG_USERNAME_PASSWORD_PAIR"
LOGIN_SUCCESSFUL = "Login successful "
VERIFICATION_TIME_OUT = "VERIFICATION_TIME_OUT"
USER_NOT_ONLINE_NOTEXIST = "User is not online or does not exist"


# class Verification_Worker(multiprocessing.Process):

#     def __init__(self, server):
        
#         multiprocessing.Process.__init__(self)
#         # self.verification_queue = verification_queue
#         # self.waiting_verification = waiting_verification
#         self.server = server
#     def run(self):
        
#         print 'Verification worker started running'

#         while True:

#             if not self.server.verification_queue.empty():

#                 task = self.server.verification_queue.get()

#                 print 'task: ', task['msg']
#                 print waiting_verification[task['username']][1]
#                 if task['msg'] == waiting_verification[task['username']][1]:

#                     waiting_verification[task['username']] = (True, waiting_verification[task['username']][1], self.task['msg'])



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

        # keeps username:session_key
        # self.online_users = {}

        # users waiting for verification
        # self.waiting_verification = {}

        self.srp_sessionkeys = {}

        # sessionkeys for all users
        self.public_keys = "../data/keys/user_keys/"

        self.msg_queue = multiprocessing.Queue()
        self.verification_queue = multiprocessing.Queue()

        self.online_users = {}
        self.online_users_queue = multiprocessing.Queue()

        # worker waits for msg and puts in to queue for further process
        self.msg_worker = Message.Msg_Worker(self.sock, self.msg_queue)
        print "Worker started"
        self.msg_worker.start()

        # workers validate srp keys
        # self.ver_worker = Verification_Worker(self)
        # self.ver_worker.start()

    def msg_handler(self):

        if self.msg_queue.empty():
            return

        plain, addr = self.msg_queue.get()

        msg = json.loads(plain)  # Message.UnMessage(plain)

        if msg['type'] == Message.LOGIN:

            p = multiprocessing.Process(target=self.user_SRP_login, args=(msg['msg'], addr, self.online_users_queue,))
            p.start()
            # p.join()

        elif msg['type'] == Message.GET_PUB_KEY:
            
            self.user_get_key_req(msg)
    

        elif msg['type'] == Message.SRP_VERIFICATION_1:
            print "Got SRP_VERIFICATION_1"

            self.verification_queue.put(msg)

        elif msg['type'] == Message.LOGOUT:
            print msg

    # SRP
    def user_SRP_login(self, login_msg, addr, queue):

        # get user login msg = {'username': self.username, 'A': self.A, 'N': self.N}

        # db check
        login_msg = json.loads(login_msg)

        conn = sqlite3.connect(
            '../data/DBs/users.db')
        c = conn.cursor()

        c.execute('SELECT COUNT(*) FROM users WHERE username=(?)', (login_msg['username'],))
        res = c.fetchone()[0]

        if res == 0:
            self.send_error(WRONG_USERNAME_PASSWORD)
            return False

        # check username
        if login_msg['username'] == '' or not login_msg['username']:

            self.send_error(WRONG_USERNAME_PASSWORD)
            return False

        if self.check_user(login_msg['username']):  # login_msg['username'] in self.online_users.keys():
            self.send_error(USER_ALREADY_LOGGED_IN)
            return False

        if login_msg['A'] % CF.primes[login_msg['N']] == 0:
            self.send_error(WRONG_USERNAME_PASSWORD)
            return False

        SRP_server = CF.SRP_server()

        srp_reply, v = SRP_server.srp_server_accept_login(login_msg['username'], login_msg['A'], login_msg['N'])

        print 'Generating key ...'
        key = SRP_server.srp_server_sessio_key(login_msg['A'], login_msg['N'], v)
        self.srp_sessionkeys[login_msg['username']] = key

        # verify key
        print "sending SRP_REPLY"
        self.send_packet(addr[0], int(addr[1]), Message.Message(Message.SRP_REPLY, self.username, srp_reply).json)

        #  verification
        s = str(login_msg['A']) + str(srp_reply['B']) + str(key)
        m_1 = unicode(CF.hash_sha256(s), errors='replace')

        # h = CF.hash_sha256(str(login_msg['A']) + str(CF.hash_sha256(m_1)) + str(key))

        print "Waiting for verification..."

        t = time.time()
        while True:

            if time.time() - t > 15:

                self.send_error(VERIFICATION_TIME_OUT)

                return False
            if not self.verification_queue.empty():

                task = self.verification_queue.get()

                if task['username'] != login_msg['username']:
                    self.verification_queue.put(task)
                    continue
                else:
                    if task['msg'] == m_1:
                        print "passed verification ."

                        h = unicode(CF.hash_sha256(str(login_msg['A']) + str(CF.hash_sha256(m_1.encode('ascii', 'ignore'))) + str(key)), errors='replace')
                        self.send_packet(addr[0], int(addr[1]), Message.Message(Message.SRP_REPLY, self.username, msg=h).json)
                        break
                    else:

                        print "SRP Verification failed"
                        return False
        # verification pass

        queue.put((login_msg['username'], addr))
        # print (login_msg['username'], addr)
        # send update
        time.sleep(1)

        self.send_update()

        return True

    def send_packet(self, ip, port, message):
      #it sends all type of packets to the desired destination. It is used by all the other functions to send the desired message
        self.sock.sendto(message, (ip, port))

    # user requested list of users
    # def user_list_request(self, user):
    #     pass

    # A wants to talk with B
    def user_get_key_req(self, msg):

        user_B = msg['msg']
        user_A = msg['username']
        if not self.check_user(msg['username']):
            self.send_error(USER_NOT_ONLINE_NOTEXIST)
            return

        pub_b = self.get_pub_key_of_user(user_B)

        if not pub_b:
            self.send_error(KEY_ERROR)
            return

        resp = {'username': user_B, 'pub_key': pub_b}
        addr = self.online_users[user_A]
        self.send_packet(addr[0], int(addr[1]), Message.Message(Message.PUB_KEY, self.username, resp).json)

    def send_update(self):
        
        # print self.online_users_queue.get()

        print 'Sending update...'
        #user_list = self.online_users.keys()

        onlines = {}

        while not self.online_users_queue.empty():

            u = self.online_users_queue.get()
            print u
            onlines[u[0]] = (u[1][0], u[1][1])

        self.online_users = onlines
        for i in onlines.keys():
            addr = onlines[i]
            self.send_packet(addr[0], int(addr[1]), Message.Message(Message.UPDATE_LIST, self.username, onlines).json)
            self.online_users_queue.put((i, onlines[i]))

    def check_user(self, uname):
        onlines = {}
        while not self.online_users_queue.empty():

            u = self.online_users_queue.get()
            print u
            onlines[u[0]] = (u[1][0], u[1][1])
        
        for i in onlines.keys():
            self.online_users_queue.put((i, onlines[i]))

        if uname not in onlines.keys():
            return False
        return True

    # get user key
    def get_pub_key_of_user(self, username):

        f = self.public_keys + username + '/key_pub.pem'

        pub = ''
        with open(f, 'r') as pf:
            pub = pf.read()
        if pub == '':
            return KEY_ERROR
        else:
            return pub

    def send_error(self, msg):
        print msg


if __name__ == '__main__':
    server = Server(9090)
    while True:
        server.msg_handler()

