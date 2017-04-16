#planning to encrypt and decrypt the messages here only in the classes Message and UnMessage
#estab key phases "no of sequences" ? how to handle that

import time
import json
import Crypt_Functions as CF
import multiprocessing
import os


# message types
LOGIN = 'LOGIN'
SRP_REPLY = 'SRP_REPLY'
LIST = 'LIST'
MESSAGE = 'MESSAGE'
LOGOUT = 'LOGOUT'
EXIT = 'EXIT'
COMM_REQ = 'COMMUNICATION-REQUEST'
PUB_KEY='PUB_KEY'
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
            except Exception as e:
                print i 


class Message():

    def __init__(self, _type, username, public_keys, session_keys, to=None, msg=None):

        self.type = _type
        self.msg = msg
        self.time = time.time()
        self.username=username
        self.json = json.dumps(
            {'type': self.type,'username': self.username, 'msg': self.msg, 'time': self.time})
        self.encrypted_message=self.encrypt_msg(self.json,_type,to,public_keys, session_keys)
    
    def encrypt_msg(self,message,type,to,public_keys, session_keys):
        if type!=ESTAB_KEY:
            ctr=os.urandom(BLOCK_SIZE)        
            return json.dumps({'encrypted_message': CF.aes_ctr(message,session_keys[to],ctr),'ctr': ctr})
        else:
            return json.dumps({'encrypted_message':CF.rsa_enc_der2(message,public_keys[to])})  
            
            
    def get_message(self):
        return self.msg
    
    def get_type(self):
        return self.type
    
    def get_time(self):
        return self.time
    
    def get_username(self):
        return self.username

def UnMessage(data,user,public_keys, session_keys):
                             
    json_data = json.loads(data)
    if 'ctr' in data:                          
        key=session_keys[user]                          
        json_data=CF.aes_ctr_decrypt(data['encrypted_message'], key, data['ctr'])
    else:
        key=public_keys[user]
        json_data=CF.rsa_dec_der2(data['encrypted_message'],key) # write function for it in CF
    msg=Message.Message(json_data['type'],json_data['username'],msg=json_data['msg'])
    msg.time=json_data['time']
    return msg                                     
        
                              
