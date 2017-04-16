# __author__="ahmet"

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import sqlite3
import Crypt_Functions as CF
import random
import string
import os

names = ["Apple",
         "Apricot",
         "Avocado",
         "Banana",
         "Bilberry",
         "Blackberry",
         "Blackcurrant",
         "Blueberry",
         "Boysenberry",
         "Currant",
         "Cherry",
         "Cherimoya",
         "Cloudberry",
         "Coconut",
         "Cranberry",
         "Cucumber",
         "Custard_apple",
         "Damson",
         "Date",
         "Fig"]


def user_db():
    conn = sqlite3.connect('/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/DBs/users.db')
    conn.text_factory = str
    c = conn.cursor()

    # Create table
    c.execute('''CREATE TABLE users
                 ( username text, verifier text, salt text, N int)''')

    with open('/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/DBs/passwd', 'w') as f:
        for i in names:

            passwd = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

            u = CF.SRP_client(i, passwd, None)

            username, v, salt, N = u.srp_client_pass_verf()

            print >>f, (username, passwd, salt)
            c.execute('''Insert into users Values (?,?,?,?)''',
                      (i, str(v), str(salt), N))

    conn.commit()

    conn.close()


def user_keys():

    keys = "/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/keys/user_keys/"

    for i in names:
        folder = keys + i + '/'
        cmd = "mkdir " + folder
        os.system(cmd)

        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())

        pem_s = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.PKCS8,
                                          encryption_algorithm=serialization.NoEncryption())

        public_key = private_key.public_key()

        pem_p = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        fp = folder + "key_pub.pem"
        fs = folder + "key.pem"

        with open(fp, 'w') as f:
            f.write(pem_p)

        with open(fs, 'w') as f:
            f.write(pem_s)


user_db()
# user_keys()