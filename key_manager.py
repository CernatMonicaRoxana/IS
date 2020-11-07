from os import urandom
import encryption_modes
from Crypto.Cipher import AES

ecb_key = urandom(32)
ofb_key = urandom(32)
init_v = urandom(16)


shared_key = urandom(32)

mode_ecb = encryption_modes.ECB(ecb_key)
mode_ofb = encryption_modes.OFB(ofb_key, init_v)


def encrypt_ecb_key():
    return mode_ecb.enrypt(ecb_key)


def encrypt_ofb_key():
    return mode_ofb.encrypt(ofb_key)


print("[ECB] Encrypted key: {}".format(encrypt_ecb_key()))
print("[OFB] Encrypted key: {}".format(encrypt_ofb_key()))
