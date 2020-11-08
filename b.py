import socket

import encryption_modes as em
import socket_operations as so

PORT = 3003
PORT_KM = 3001

shared_key = b'\xfc\x05.>\x7f\xdfL\x10\xe1x]ir\x98\xa9:\xb6\xa6\xa0\xe1m\xda\xbct\xa6\xb40\xfe\x16\xab\x82e'
shared_cipher = em.ECB(shared_key)


def get_conn():
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sck.bind(('127.0.0.1', PORT))
    sck.listen()
    conn, _ = sck.accept()
    sck.close()
    return conn


def get_key(mode: bytes):
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.connect(("127.0.0.1", PORT_KM))
    so.send_header(sck, mode)
    print('Sent mode to KM, waiting for key')
    conv_key_enc = so.recv_header(sck)
    conv_key = shared_cipher.decrypt(conv_key_enc)
    print('Got key!')
    return conv_key


def ecb_conv(sck, key):
    cipher = em.ECB(key)

    print('Waiting for message... ')
    msg_enc = so.recv_header(sck)
    msg = cipher.decrypt(msg_enc)

    print('Message:', msg.decode('utf-8'))

    reply = input("Enter reply: ")
    reply_enc = cipher.encrypt(reply)
    so.send_header(sck, reply_enc)


def ofb_conv(sck, key):
    recv_iv = so.recv_header(sck)
    send_iv = so.recv_header(sck)

    recv_cipher = em.OFB(key, recv_iv)
    send_cipher = em.OFB(key, send_iv)

    print('Waiting for message... ')
    msg_enc = so.recv_header(sck)
    msg = recv_cipher.decrypt(msg_enc)

    print('Message:', msg.decode('utf-8'))

    reply = input("Enter reply: ")
    reply_enc = send_cipher.encrypt(reply)
    so.send_header(sck, reply_enc)


def main():
    conn = get_conn()
    mode = so.recv_header(conn)
    key = get_key(mode)

    if mode == b'ecb':
        print('Starting ECB conversation')
        ecb_conv(conn, key)
    else:
        print('Starting OFB conversation')
        ofb_conv(conn, key)

    conn.close()


if __name__ == '__main__':
    main()
