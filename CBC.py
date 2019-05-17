from Crypto.Cipher import AES
from Crypto.Util import Padding
from base64 import b64encode


block_size = AES.block_size # 16 byte

# hàm xor
def xor(xs, ys):
  if (len(xs) >= len(ys)):
    s = ''.join([hex(int(x, 16) ^ int(y, 16))[2:] for (x, y) in zip(xs[:len(ys)], ys)])
  else:
    s = ''.join([hex(int(x, 16) ^ int(y, 16))[2:] for (x, y) in zip(xs, ys[:len(xs)])])
  return s

# giải mã CBC
def decryptCBC (key, ciphertext):
	ciphers = []
	length = int(len(ciphertext)/block_size)
	plaintext = ''
	for i in range(length):
		if (i == 0):
			IV = ciphertext[0:32]
		else:
			ciphers.append(ciphertext[(32*i) : 32*(i+1)])
			
	key_byte = bytes.fromhex(key)
	cipher = AES.new(key_byte, AES.MODE_ECB)
		
	for i in range (len(ciphers)):
		di = cipher.decrypt(bytes.fromhex(ciphers[i])).hex()
		if (i == 0):
			mi = xor(IV, di)
		else:
			mi = xor(ciphers[i-1], di)
		plaintext = plaintext + mi
	plaintext = Padding.unpad(bytes.fromhex(plaintext), block_size).decode('utf-8')
	return plaintext

# giải mã CTR
def decryptCTR(key, ciphertext):
	ciphers = []
	length = int(len(ciphertext)/block_size)
	plaintext = ''
	for i in range(length):
		if (i == 0):
			IV = int(ciphertext[0:32],16)
		else:
			c = ciphertext[32:]
			ciphers = list(c[j:j + 32] for j in range(0, len(c), 32))	

	key_byte = bytes.fromhex(key)
	cipher = AES.new(key_byte, AES.MODE_ECB)
	for i in range(len(ciphers)):
		IVi = IV + i
		e = cipher.encrypt(bytes.fromhex(hex(IVi)[2:])).hex()
		m = xor(ciphers[i], e)
		plaintext = plaintext + m
	plaintext = ''.join([chr(int(plaintext[i:i + 2], 16)) for i in range(0, len(plaintext), 2)])
	return plaintext

k1 = '140b41b22a29beb4061bda66b6747e14'
c1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
k2 = '140b41b22a29beb4061bda66b6747e14'
c2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'


k3 = '36f18357be4dbd77f050515c73fcf9f2'
c3 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
k4 = '36f18357be4dbd77f050515c73fcf9f2'
c4 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'

print('---- Giải mã CBC: ---- ')
print (decryptCBC(k1,c1)) 
print (decryptCBC(k2,c2)) 
print('\n---- Giải mã CTR: ---- ')
print (decryptCTR(k3,c3))   
print (decryptCTR(k4,c4)) 