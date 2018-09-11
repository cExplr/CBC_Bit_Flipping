# BASED OFF https://www.youtube.com/watch?v=aoXO5TxN3GQ
import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def xor(a,b):
    ba1 = bytearray(a)
    ba2 = bytearray(b)
    ba3 = bytearray()
    for i in range(len(ba1)):
        ba3.append(ba1[i]^ba2[i])
    return ba3

class AES_CBC(object):
    def __init__(self, key=get_random_bytes(32)):
        self.key = key
        self._cipher = AES.new(key)

    def _add_padding(self, data):
        # According to PCKS#5  if you have nothing to pad  with, padd it anyways
        #  Else PAD WITH THE BYTE VALUE OF HOW MANY PADDINGS
        padding = 16-(len(data)%16)
        return data + bytearray([padding for _ in range(padding)])

    def _split_blocks(self, data):
        length = len(data)
        blocks=[]
        for i in range(length/16):
            blocks.append(data[i*16 : (i+1)*16])
        # print(blocks)
        return blocks
    def _strip_padding(self, data):
        data = bytearray(data)
        checkedPadding = data[-1]
        for byte in data[len(data) - checkedPadding :]:
            if byte != checkedPadding:
                raise ValueError("INVALID PADDING ...")
        return str(data[:len(data) - checkedPadding])

    def encrypt(self, plaintext):
        plaintext = self._add_padding(bytearray(plaintext))
        plaintext_blocks = self._split_blocks(plaintext)
        iv = get_random_bytes(16)
        print("iv generated : " + iv)
        ciphertext_blocks = []
        for i, block in enumerate(plaintext_blocks):
            if i==0:
                ciphertext_blocks.append(iv)
                ciphertext_blocks.append(self._cipher.encrypt(str(xor(iv,block))))
            else:
                ciphertext_blocks.append(self._cipher.encrypt(str(xor(ciphertext_blocks[i],block))))
        return base64.b64encode("".join(ciphertext_blocks))

    def decrypt(self, ciphertext):
        ciphertext = bytearray(base64.b64decode(ciphertext))
        ciphertext_blocks = self._split_blocks(ciphertext)
        plaintext_blocks =  []
        for i, block in enumerate(ciphertext_blocks):
            if i == 0 :
                continue
            plaintext_blocks.append(str(xor(self._cipher.decrypt(str(block)), ciphertext_blocks[i-1])))
        return self._strip_padding("".join(plaintext_blocks))


a = AES_CBC()
enc = (a.encrypt("Flag{W0w_CbC_B1tfl1pp1ng5_fUN!!}"))
print(enc)
dec = a.decrypt(enc)
print(dec)
