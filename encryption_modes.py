from os import urandom

from Crypto.Cipher import AES

ecb_key = urandom(32)
ofb_key = urandom(32)

iv = urandom(16)


def padding(text):
    if len(text) % 16 == 0:
        return text
    pad = 16 - (len(text) % 16)
    pad_chr = b'\x00'
    return text.encode('utf-8') + pad * pad_chr


def unpadding(text):
    return text.decode('utf-8').rstrip('\x00')


class ECB:
    def __init__(self, ecb_key):
        self.key = ecb_key
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def enrypt(self, plain_text):
        plain_text = padding(plain_text)
        plain_blocks = [plain_text[i:i + 16] for i in range(0, len(plain_text), 16)]
        encr_blocks = [self.cipher.encrypt(block) for block in plain_blocks]
        encr = b''.join(encr_blocks)
        return encr

    def decrypt(self, crypto_text):
        crypto_blocks = [crypto_text[i:i + 16] for i in range(0, len(crypto_text), 16)]
        decr_blocks = [self.cipher.decrypt(block) for block in crypto_blocks]
        decr = b''.join(decr_blocks)
        return unpadding(decr)


class OFB:
    def __init__(self, ofb_key):
        self.key = ofb_key
        self.iv = iv
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.key_block = self.cipher.encrypt(iv)





ecb = ECB(ecb_key)
plaintext = input("Enter a text to encrypt with Aes in ecb mode: ")
encrypted = ecb.enrypt(plaintext)
print("Encrypted: {}".format(encrypted))
print("Decrypted: {}".format(ecb.decrypt(encrypted)))
