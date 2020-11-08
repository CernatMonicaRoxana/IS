import socket


def send_header(sock, message):
    header = len(message)
    sock.sendall(header.to_bytes(4, "big"))
    sock.sendall(message)


def recv_fixed(sock, size):
    buffer = b""
    while len(buffer) < size:
        buffer += sock.recv(size - len(buffer))
    return buffer


def recv_header(sock):
    header = int.from_bytes(recv_fixed(sock, 4), 'big')
    return recv_fixed(sock, header)
