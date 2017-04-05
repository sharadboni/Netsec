from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding2
from cryptography.hazmat.primitives.asymmetric import dh

import os

# BLOCK_SIZE = 16
# key = os.urandom(BLOCK_SIZE)
# iv = os.urandom(BLOCK_SIZE)
# ctr = os.urandom(BLOCK_SIZE)


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
        public_key = serialization.load_der_public_key(
        key_file.read(),
        backend=default_backend() )

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
        private_key = serialization.load_der_private_key(
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


def df_key_exchange(peer_public_key):

    parameters = dh.generate_parameters(
        generator=2, key_size=2048, backend=default_backend())

    private_key = parameters.generate_private_key()
    shared_key = private_key.exchange(peer_public_key)
    return shared_key


def srp():
    pass

