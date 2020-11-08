import encryption_modes as em
import socket_operations as so
import socket

PORT_KM = 3001
PORT_B = 3003
PORT_A = 3002

shared_key = b'\xfc\x05.>\x7f\xdfL\x10\xe1x]ir\x98\xa9:\xb6\xa6\xa0\xe1m\xda\xbct\xa6\xb40\xfe\x16\xab\x82e'
shared_cipher = em.ECB(shared_key)


def get_conversation_mode():
    allowed_modes = {"ecb", "ofb"}
    mode = input("Enter what mode you would like to choose: [ECB] or [OFB]: ")
    if mode.lower() not in allowed_modes:
        print("Not a valid mode")
    return mode.lower()


def get_key(mode: str):
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.connect(("127.0.0.1", PORT_KM))
    so.send_header(sck, bytes(mode, 'utf-8'))
    print('Sent mode to KM, waiting for key')
    conv_key_enc = so.recv_header(sck)
    conv_key = shared_cipher.decrypt(conv_key_enc)
    print('Got key!')
    return conv_key


def ecb_conv(sck, key):
    cipher = em.ECB(key)

    msg = input("Enter message: ")
    msg_enc = cipher.encrypt(msg)
    so.send_header(sck, msg_enc)

    print('Sent message, awaiting reply...')

    reply_enc = so.recv_header(sck)
    reply = cipher.decrypt(reply_enc)
    print("Reply:", reply.decode('utf-8'))


def ofb_conv(sck, key):
    pass


def start_conv(mode, key):
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.connect(("127.0.0.1", PORT_B))
    so.send_header(sck, bytes(mode, 'utf-8'))

    if mode == 'ecb':
        ecb_conv(sck, key)
    else:
        ofb_conv(sck, key)

    sck.close()


def main():
    mode = get_conversation_mode()
    key = get_key(mode)
    start_conv(mode, key)


if __name__ == '__main__':
    main()
