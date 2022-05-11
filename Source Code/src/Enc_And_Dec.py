from Cryptodome.Cipher import DES3, AES


def enc_image_AES(input_data, key, iv, filepath):
    cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
    enc_data = cfb_cipher.encrypt(input_data)

    enc_file = open(filepath + "/encrypted.enc", "wb")
    enc_file.write(enc_data)
    enc_file.close()


def dec_image_AES(input_data, key, iv, filepath):
    cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
    plain_data = cfb_decipher.decrypt(input_data)

    output_file = open(filepath + "/output.png", "wb")
    output_file.write(plain_data)
    output_file.close()


def enc_image_Triple_DES(input_data, key, filepath):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=b'0')
    enc_data = cipher.encrypt(input_data)

    enc_file = open(filepath + "/encrypted.enc", "wb")
    enc_file.write(enc_data)
    enc_file.close()


def dec_image_Triple_DES(input_data, key, filepath):
    #  Cipher with integration of Triple DES key, MODE_EAX for Confidentiality & Authentication
    #  and nonce for generating random / pseudo random number which is used for authentication protocol
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=b'0')
    plain_data = cipher.decrypt(input_data)

    output_file = open(filepath + "/Decrypted.jpg", "wb")
    output_file.write(plain_data)
    output_file.close()
