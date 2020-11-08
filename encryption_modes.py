from Crypto.Cipher import AES
from os import urandom


def pad(text: bytes) -> bytes:
    if len(text) % 16 == 0:
        return text
    pad_len = 16 - (len(text) % 16)
    pad_chr = b'\x00'
    return text + pad_len * pad_chr


def unpad(text: bytes) -> bytes:
    return text.rstrip(b'\x00')


class ECB:
    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plain_text):
        if isinstance(plain_text, str):
            plain_text = bytes(plain_text, 'utf-8')
        plain_text = pad(plain_text)
        plain_blocks = [plain_text[i:i + 16] for i in range(0, len(plain_text), 16)]
        encr_blocks = [self.cipher.encrypt(block) for block in plain_blocks]
        encr = b''.join(encr_blocks)
        return encr

    def decrypt(self, crypto_text):
        crypto_blocks = [crypto_text[i:i + 16] for i in range(0, len(crypto_text), 16)]
        decr_blocks = [self.cipher.decrypt(block) for block in crypto_blocks]
        decr = b''.join(decr_blocks)
        return unpad(decr)


class OFB:
    def __init__(self, key, iv):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.iv = iv
        self.key_stream = self.cipher.encrypt(self.iv)
        self.pos = 0

    def encrypt(self, plain_text):
        if isinstance(plain_text, str):
            plain_text = bytes(plain_text, 'utf-8')
        cipher_text = b''

        for plain_byte in plain_text:
            if self.pos < 16:
                cipher_text += bytes([self.key_stream[self.pos] ^ plain_byte])
                self.pos += 1
            else:
                self.key_stream = self.cipher.encrypt(self.key_stream)
        return cipher_text

    def decrypt(self, ciphertext):
        return self.encrypt(iphertext)


def test():
    ecb_key = urandom(32)
    ecb = ECB(ecb_key)
    ecb_plaintext = input("Enter a text to encrypt with AES in ECB mode: ")
    ecb_encrypted = ecb.encrypt(ecb_plaintext)
    print("[ECB] Encrypted: {}".format(ecb_encrypted))
    print("[ECB]Decrypted: {}".format(ecb.decrypt(ecb_encrypted)))

    ofb_key = urandom(32)
    init_v = urandom(16)
    ofb_enc, ofb_dec = OFB(ofb_key, init_v), OFB(ofb_key, init_v)
    ofb_plaintext = input("Enter a text to encrypt with AES in OFB mode: ")
    ofb_encrypted = ofb_enc.encrypt(ofb_plaintext)
    print("[OFB] Encrypted: {}". format(ofb_encrypted))
    print("[OFB] Decrypted: {}".format(ofb_dec.encrypt(ofb_encrypted).decode("utf-8")))


if __name__ == '__main__':
    test()
