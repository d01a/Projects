import os 
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding

if __name__ == "__main__":

    plaintext = b'test string'


    key = os.urandom(256 // 8)

    # create AES ECB cipher object 
    aes_ecb_cipher = Cipher(AES(key=key) , ECB())

    # enc

    ciphertext = aes_ecb_cipher.encryptor().update(plaintext)
    print(f'CipherText: {ciphertext}')

    # dec
    # will work only if the block cipher is a multiple block size
    recovered_plaintext = aes_ecb_cipher.decryptor().update(ciphertext)
    print(f'Recovered PlainText: {recovered_plaintext}')

    # fixing this problem with adding a padding bytes 

    block_padder = padding.PKCS7(AES.block_size).padder()
    padded_text = block_padder.update(plaintext) + block_padder.finalize()

    print(f'padded text: {padded_text}')

    ciphertext = aes_ecb_cipher.encryptor().update(padded_text)
    print(f'padded cipher: {ciphertext}')

    padded_recovered_text = aes_ecb_cipher.decryptor().update(ciphertext)
    print(f'recovered with padding: {padded_recovered_text}')


    # remove padding 
    block_unpadder = padding.PKCS7(AES.block_size).unpadder() 
    recovered_plaintext = block_unpadder.update(padded_recovered_text) + block_unpadder.finalize()
    print(f'recovered without padding: {recovered_plaintext}')

    assert(recovered_plaintext == plaintext)




