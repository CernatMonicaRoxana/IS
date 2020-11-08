import encryption_modes
import socket

PORT_KM = 3001
PORT_B = 3003
PORT_A = 3002


def send_header_fixed(sock, buff):
    header = len(buff)
    while header > 0:
        try:
            written = sock.sendall(header)
            header -= written
        except Exception as e:
            print(e)


def recv_header_fixed(sock, buff):
    buffer = bytes()
    while len(buffer) < buff:
        try:
            read = sock.recv(buff - len(buffer))
            buffer += read
        except Exception as e:
            print(e)
    return buffer


