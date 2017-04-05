# ahmet
# ChatServer.py

import datetime
import json

# message types
SIGNIN = 'SIGN-IN'
LIST = 'LIST'
MESSAGE = 'MESSAGE'
EXIT = 'EXIT'


class Message():

    def __init__(self, _type, msg, time):

        self.type = _type
        self.msg = msg
        self.time = time

        self.json = json.dumps(
            {'type': self._type, 'msg': self.msg, 'time': self.time})

    def print_msg(self):
        print self.json

    def get_msg(self):
        return self.json
        