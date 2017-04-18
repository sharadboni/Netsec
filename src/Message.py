# planning to encrypt and decrypt the messages here only in the classes Message and UnMessage
# estab key phases "no of sequences" ? how to handle that

import time
import json
import Crypt_Functions as CF
import multiprocessing
import os

BLOCK_SIZE = 16

# message types
# msg to server-client
LOGIN = 'LOGIN'
SRP_REPLY = 'SRP_REPLY'
# validation for shared key
SRP_VERIFICATION_1 = 'SRP_VERIFICATION - 1'
SRP_VERIFICATION_2 = 'SRP_VERIFICATION - 2'

LIST = 'LIST'
LOGOUT = 'LOGOUT'
PUB_KEY = 'PUB_KEY'
GET_PUB_KEY = 'GET_KEY'
UPDATE_LIST = "UPDATE_LIST"

# clint-client
MESSAGE = 'MESSAGE'
ESTAB_KEY = 'ESTAB_KEY'


# waits for coming messages and puts them into a queue
class Msg_Worker(multiprocessing.Process):

    def __init__(self, sock, queue):

        multiprocessing.Process.__init__(self)

        self.sock = sock
        # multiprocessing queue to store active user info
        self.queue = queue

    def run(self):

        while True:

            try:
                # msg and source ip-port
                msg, addr = self.sock.recvfrom(4096)

                self.queue.put((msg, addr))
            except Exception as e:
                print 'Error while receiving a message', e


class Message():

    def __init__(self, _type, username, msg=None):

        self.type = _type
        self.msg = msg
        self.time = time.time()
        self.username = username
        self.json = json.dumps(
            {'type': self.type, 'username': self.username, 'msg': self.msg, 'time': self.time})
        # self.encrypted_message = self.encrypt_msg(self.json, _type, to, public_keys, session_keys)

    def encrypt_msg(self, message, type, to, public_keys, session_keys):
        if type != ESTAB_KEY:
            ctr = os.urandom(BLOCK_SIZE)
            return json.dumps({'encrypted_message': CF.aes_ctr(message, session_keys[to], ctr), 'ctr': ctr})
        else:
            return json.dumps({'encrypted_message': CF.rsa_enc_der2(message, public_keys[to])})

    def get_message(self):
        return self.msg

    def get_type(self):
        return self.type

    def get_time(self):
        return self.time

    def get_username(self):
        return self.username


def UnMessage(data, user, public_keys, session_keys):

    json_data = json.loads(data)
    if 'ctr' in data:
        key = session_keys[user]
        json_data = CF.aes_ctr_decrypt(
            data['encrypted_message'], key, data['ctr'])
    else:
        key = public_keys[user]
        # write function for it in CF
        json_data = CF.rsa_dec_der2(data['encrypted_message'], key)
    msg = Message.Message(json_data['type'], json_data[
                          'username'], msg=json_data['msg'])
    msg.time = json_data['time']
    return msg


def UnMessage_no_encryption(data):

    data = json.loads(data)
    msg = Message(data['type'], data['username'])

    msg.msg = data['msg']
    msg.json = data
    msg.time = data['time']

    return msg
