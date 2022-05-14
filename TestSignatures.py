from EC_Encryption import Crypt, Encryptor
data = "hello there!".encode("utf-8")

crypt = Crypt("my_password")  # create a Crypt object using a password
public_key = crypt.public_key  # this is the public key you should share with others
signature = crypt.Sign(data)  # creating a signature for data


encryptor = Encryptor(public_key)
# checking the validity of data's signature using the signer's public key
assert(encryptor.VerifySignature(data, signature))
