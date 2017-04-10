# __author__="ahmet"


import sqlite3
import Crypt_Functions as CF
import random
import string

conn = sqlite3.connect('../data/users.db')
conn.text_factory = str
c = conn.cursor()

# Create table
c.execute('''CREATE TABLE users
             ( username text, verifier text, salt text)''')


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
         "Custard apple",
         "Damson",
         "Date",
         "Fig"]


for i in names:

    passwd_hash = str(CF.hash_sha256(''.join(random.choice(
        string.ascii_uppercase + string.digits) for _ in range(8))))

    salt = ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for _ in range(8))

    print(i, passwd_hash, salt)
    c.execute('''Insert into users Values (?,?,?)''',
              (i, passwd_hash, salt))


conn.commit()

conn.close()
