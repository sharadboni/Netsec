# ahmet
# ChatServer.py

import time
import json

# message types
SIGNIN = 'SIGN-IN'
LIST = 'LIST'
MESSAGE = 'MESSAGE'
EXIT = 'EXIT'


class Message():

    def __init__(self, _type, msg=None):

        self.type = _type
        self.msg = msg
        self.time = time.time()

        self.json = json.dumps(
            {'type': self._type, 'msg': self.msg, 'time': self.time})

    def print_msg(self):
        self.json=json.loads(self.json)
        print self.json[msg]
        

    def get_msg(self):
        return self.json
        
