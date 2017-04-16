from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding2
from cryptography.hazmat.primitives.asymmetric import dh

import json
import random
import sqlite3

# BLOCK_SIZE = 16
# key = os.urandom(BLOCK_SIZE)
# iv = os.urandom(BLOCK_SIZE)
# ctr = os.urandom(BLOCK_SIZE)


primes = {
    1: 19621298066850337857478699045394325778741082739973738988600404138807927771152170116856209472735374654773751009311573340321898323141773929682665082016025852581807821308849212027776256899420230702461481268340421287887194663649374795299604357796854151380687368657057703214429294037216677507203977075411517433108927665959008627454288609296134711017711116479541485965730075906625271932295550935470350401627189135578524959066271232933050948465220062020116891686842941117474067215376903213356802885144747529652804563615511956689720234363007911891679963811617850843244676888483259597511140973722879427540766001285564103986643,
    2: 31452058910902001295835475455719109965301182497403915339971179610230065348069513190122800648044627131042147306227494120530545646921185805726714356133296290660840085600584077583337203773355853551539071364579006047033567618982335597060591708588255762520581821411612128363811953586906665900202301277511269836618688695335368462338405364494590322098121071024548141884607680120274590611787607426141602619014147398379555739840110665621241953520546772029308251265607784875020138656179295609345970710356792539976549577165233747821315187241307737744444663233248791093356345935693512946961880817139529222155397318170827979446451,
    3: 20799987851779905002020475552407224483421941313626823198247254915518640760165717243133605443780040509784376902045520924599475814879279363341074812727152207336182680147250611263909861111067455847477246988991709103622974589189738242144093371036511066147198085425034837317786408925827299995826933571970693046447206600278971913781771913686546056303488805320720925486430368439924457952263815076151666691240675472429961539979329150370198783700826577038061223377760270520965563743904210235299191630328551322779419040122913036944539076876202570399906229910919802200630431612251718471499380183856826785898654778083600500275751,
    4: 20951208739547899211606443412524293846142421698432766730462690634694730696849860313722943209411597699913614953228574695543047082341551604208158319066196493416849902943041710557972125912664511521985971342704059410902195768172992487846837953268995370002251150051497442274739660337007958758543459574907360718009517903755163197284094265450683857732061343335705432148757804670983198403184245172524196312333191861454094879530929373194007613290212514827815131497882524345830691963790164073894527214930471695192986514119567904573785056495226196896347561411994615464948353210940500954473869115985623996221001072214720243695947,
    5: 25983877076687711671007182625491243028423932541864608864423949650219298962656408236948494820074929752869551611772077707337085046670547025868184131834192185589381726298626089313997672074501416356956337735972621915003840049643221163409378349001693893873067762607531075214736877469432431394064746920417031563463977397517415259343867585070082883167380062657820406889965072933470945158506904015675012237102972043407831168718401546224518227879277439469532116364183015396208546641171464499284329259109970565454992744510975788977287513757949290987430176234727104958190706677724308120229807216241684715334099515754727128350423}


def aes_ctr(msg, key, ctr):

    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(msg) + encryptor.finalize()

    return cipher_text


def aes_ctr_decrypt(cipher_text, key, ctr):
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    msg = decryptor.update(cipher_text) + decryptor.finalize()

    return msg


def hmac_sha256(msg, key):

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    return h.finalize()


def rsa_enc_der(msg, pk_path):
    with open(pk_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend())

    ciphertext = public_key.encrypt(
        msg,
        padding2.OAEP(
            mgf=padding2.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ciphertext


def rsa_enc_der2(msg, pk):

    public_key = serialization.load_pem_public_key(
        str(pk), backend=default_backend())

    ciphertext = public_key.encrypt(
        msg,
        padding2.OAEP(
            mgf=padding2.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ciphertext


def rsa_dec_der(ciphertext, sk_path):

    with open(sk_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())

    msg = private_key.decrypt(
        ciphertext,
        padding2.OAEP(
            mgf=padding2.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return msg

def rsa_dec_der2(ciphertext, pk):

    private_key = serialization.load_pem_private_key(
            str(pk),
            password=None,
            backend=default_backend())

    msg = private_key.decrypt(
        ciphertext,
        padding2.OAEP(
            mgf=padding2.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return msg



class Diffie_Hellman:

    # generate prime with generate_prime
    def __init__(self, p, g):

        # 2048bit primes
        # generator = 2
        self.pn = dh.DHParameterNumbers(p, g)
        self.parameters = self.pn.parameters(default_backend())
        # dh.generate_parameters(
        #     generator=2, key_size=2048, backend=default_backend())
        self.private = self.parameters.generate_private_key()
        self.public = self.private.public_key()

    def get_private_key(self):
        """ Return the private key (a) """
        return self.private

    def get_public_key(self):
        return self.public

    # amirali
    def check_other_public_key(self, other_contribution):
        # check if the other public key is valid based on NIST SP800-56
        # 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2

        if 2 <= other_contribution and other_contribution <= self.p - 2:
            if pow(other_contribution, (self.p - 1) // 2, self.p) == 1:
                return True
        return False

    def df_key_exchange(self, peer_public_key):
        shared_key = self.private.exchange(peer_public_key)

        return shared_key

    # create diffie-hellman values
    # encrypt it with public key of B
    # return encrypted {g^a}_pk-receiver


def hash_sha256(inp):

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(inp)
    return digest.finalize()


# generate prime number using isPrime
def generate_prime(n=1024):

    p = pow(2, n - 1) + 1
    while not isPrime(p):
        # n += 2
        p = random.randint(pow(2, n - 1), pow(2, n) - 1)
    return p


def decompose(p):

    dec = p - 1
    r = 0

    while not dec & 1:

        r += 1
        dec /= 2

    u = (p - 1) / pow(2, r)

    return r, u


def isPrime(p):

    t = 20  # strength

    if p == 1:
        return False
    if not p & 1:  # even
        return False

    # if perfect power
    # if isPerfectPower(p):
    #     return False
    r, u = decompose(p)

    for i in xrange(t):

        a = random.randint(1, p - 1)

        k = pow(a, u, p)

        if k != 1 and k != p - 1:

            for j in xrange(1, r + 1):
                n = pow(2, j) * u

                k = pow(a, n, p)

                if k != p - 1:
                    return False
    return True


def cryptrand(Num, n=1024):
    return random.SystemRandom().getrandbits(n) % Num


# SRP implementation
class SRP_server():

    def __init__(self):

        self.g = 2
        # self.N = N

        

    def srp_server_accept_login(self, username, client_A, client_N):

        # 2
        # TODO
        # get salt and pass verifier for username from db

        conn = sqlite3.connect(
            '/Users/ahmet/Documents/6.2/net_sec/final_project/Netsec/data/DBs/users.db')
        c = conn.cursor()

        c.execute('SELECT * FROM users WHERE username=(?)', (username,))
        res = c.fetchone()
        print res
        u, v, s, N = res

        # v = 'verification'
        salt = s  # self.get_salt_username(username)

        b = cryptrand(Num=client_N, n=64)

        N_g = str(client_N) + str(self.g)

        k = hash_sha256(N_g)

        B = (int(k.encode('hex'), 16) * v + pow(self.g, b, client_N)) % client_N

        return B, salt
        # send B, salt

    def srp_server_sessio_key(self, client_A , B, v):
    # 3
        u = hash_sha256(client_A + B)

    # 5
        session_key = hash_sha256(pow(client_A * pow(v, u, self.N), b, self.N))

        return session_key

    # TODO
    # verify proof of session key


class SRP_client():

    def __init__(self, username, password, client):

        self.client = client

        self.g = 2
        self.N = random.randint(1, 5)
        self.A = ''

        self.username = username
        self.password = password

        self.session_key = 'key'

    def srp_client_pass_verf(self):

        # password verifier generation
        safe_prime = primes[self.N]
        salt = cryptrand(Num=safe_prime, n=64)

        # x, private
        pass_code = str(salt) + self.username + ':' + self.password
        x = hash_sha256(pass_code)

        # pass verifier
        v = pow(self.g, int(x.encode('hex'), 16), safe_prime)

        # DB ENTRY   <username,password verifier(v), salt, salt_creation_date>
        return self.username, v, salt, self.N

    def srp_client_login_msg(self):

        # get username(I), password

        # self.username = raw_input('Enter Username: ')
        # self.password = getpass.getpass('Enter password: ')

        # 1
        msg = ''
        try:
            safe_prime = primes[self.N]
            a = cryptrand(Num=safe_prime)
            self.A = pow(self.g, a, safe_prime)

            msg = {'username': self.username, 'A': self.A, 'N': self.N}

        except Exception as e:

            print e
            exit(1)

        return json.dumps(msg)

    def srp_create_session_key(self, B, salt):

        server_B = B

    # 3 Random scrambling parameter

        u = hash_sha256(self.A + server_B)

    # 4

        pass_code = salt + self.username + ':' + self.password
        x = hash_sha256(pass_code)

        self.session_key = hash_sha256(
            pow(server_B - self.k * pow(self.g, x, self.N), a + u * x, self.N))

    # TODO
    # send proof of session key
