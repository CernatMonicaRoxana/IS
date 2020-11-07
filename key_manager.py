from os import urandom
import encryption_modes
import socket

ecb_key = urandom(32)
ofb_key = urandom(32)
init_v = urandom(16)


shared_key = urandom(32)

mode_ecb = encryption_modes.ECB(ecb_key)
mode_ofb = encryption_modes.OFB(ofb_key, init_v)


def encrypt_ecb_key():
    return mode_ecb.encrypt(ecb_key)


def encrypt_ofb_key():
    return mode_ofb.encrypt(ofb_key)


print("[ECB] Encrypted key: {}".format(encrypt_ecb_key()))
print("[OFB] Encrypted key: {}".format(encrypt_ofb_key()))


def send_key(conn):
    conv_mode = conn.recv(3)
    if conv_mode == b"ECB":
        conn.sendall(encrypt_ecb_key())
    elif conv_mode == b"OFB":
        conn.sendall(encrypt_ofb_key())


def main():
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sck.bind(('127.0.0.1', 3001))
    sck.listen(10)
    while True:
        conn, _ = sck.accept()
        send_key(conn)


if __name__ == '__main__':
    main()

