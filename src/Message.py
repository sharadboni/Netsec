#planning to encrypt and decrypt the messages here only in the classes Message and UnMessage
#estab key phases "no of sequences" ? how to handle that

import time
import json
import Crypt_Functions
import multiprocessing


# message types
LOGIN = 'LOGIN'
LIST = 'LIST'
MESSAGE = 'MESSAGE'
LOGOUT = 'LOGOUT'
EXIT = 'EXIT'
COMM_REQ = 'COMMUNICATION-REQUEST'

GET_PUB_KEY='GET_KEY'
ESTAB_KEY='ESTAB_KEY'


# waits for coming messages and puts them into a queue
class Msg_Worker(multiprocessing.Process):

    def __init__(self, sock, queue):

        self.sock = sock
        # multiprocessing queue to store active user info
        self.queue = queue

    def run(self):

        while True:

            try:
                # msg and source ip-port
                msg, addr = self.sock.recvfrom(4096)

                self.queue.put((msg, addr))



class Message():

    def __init__(self, _type, username, msg=None):

        self.type = _type
        self.msg = msg
        self.time = time.time()
        self.username=username
        self.json = json.dumps(
            {'type': self.type,'username': self.username, 'msg': self.msg, 'time': self.time})
    
    def encrypt_msg():
        pass
    

class UnMessage():
    
    def __init__(self,data):
        self.json = json.loads(data)
        self.type = self.json['type']
        self.msg = self.json['msg']
        self.time = self.json['time']
        self.username=self.json['username']
        
    def get_message(self):
        return self.msg
    
    def get_type(self):
        return self.type
    
    def get_time(self):
        return self.time
    
    def get_username(self):
        return self.username
    
    def decrypt_msg(self):
        pass
