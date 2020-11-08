from os import urandom
import encryption_modes
import socket_operations as so
import socket

ecb_key = urandom(32)
ofb_key = urandom(32)
init_v = urandom(16)


shared_key = b'\xfc\x05.>\x7f\xdfL\x10\xe1x]ir\x98\xa9:\xb6\xa6\xa0\xe1m\xda\xbct\xa6\xb40\xfe\x16\xab\x82e'

mode_ecb = encryption_modes.ECB(ecb_key)
mode_ofb = encryption_modes.OFB(ofb_key, init_v)


def encrypt_ecb_key():
    return mode_ecb.encrypt(ecb_key)


def encrypt_ofb_key():
    return mode_ofb.encrypt(ofb_key)


print("[ECB] Encrypted key: {}".format(encrypt_ecb_key()))
print("[OFB] Encrypted key: {}".format(encrypt_ofb_key()))


def send_key(conn):
    conv_mode = so.recv_header(conn)
    if conv_mode == b"ecb":
        so.send_header(conn, encrypt_ecb_key())
        print('Sent ECB key')
    elif conv_mode == b"ofb":
        so.send_header(conn, encrypt_ofb_key())
        print('Sent OFB key')
    else:
        print('Received bad mode: ', conv_mode)


def main():
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sck.bind(('127.0.0.1', 3001))
    sck.listen(10)
    while True:
        conn, addr = sck.accept()
        print('Received connection from', addr)
        send_key(conn)


if __name__ == '__main__':
    main()

