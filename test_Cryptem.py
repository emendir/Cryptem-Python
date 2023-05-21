"""Test for deprecated CamelCase module version"""
import tempfile
import os
import shutil
from Cryptem import Crypt, Encryptor
from termcolor import colored
BREAKPOINTS = False
PYTEST = True


def mark(success, message):
    """Returns a check or cross character depending on the input success."""
    if success:
        mark = colored("✓", "green")
    else:
        mark = colored("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    print(mark, message)
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


def test_crypt_Encryption():
    crypt = Crypt("my_password")
    plaintext = "Hello there!".encode()
    cipher = crypt.Encrypt(plaintext)
    assert isinstance(cipher, bytes), f"Crypt.Encrypt did not return a bytearray; {type(cipher)}"
    Decrypted = crypt.Decrypt(cipher)
    assert isinstance(
        Decrypted, bytes), f"Crypt.Decrypt did not return a bytearray: {type(Decrypted)}"

    mark(Decrypted == plaintext, "Crypt Encryption/Decryption")


def test_crypt_file_Encryption():
    crypt = Crypt("my_password")

    tempdir = tempfile.mkdtemp()
    Encrypted_file_path = os.path.join(tempdir, "Encrypted")
    Decrypted_file_path = os.path.join(tempdir, "Decrypted")
    crypt.EncryptFile("ReadMe.md", Encrypted_file_path)
    assert os.path.exists(Encrypted_file_path), "Crypt.EncryptFile did not create file"
    crypt.DecryptFile(Encrypted_file_path, Decrypted_file_path)
    assert os.path.exists(Decrypted_file_path), "Crypt.DecryptFile did not create file"
    with open("ReadMe.md", "r") as file:
        org_content = file.read()
        with open(Decrypted_file_path, "r") as file:
            Decrypted_content = file.read()
            shutil.rmtree(tempdir)
            mark(org_content == Decrypted_content, "Crypt file Encryption/Decryption")


def test_crypt_Signing():
    crypt = Crypt("my_password")
    data = "Hello there!".encode()
    Signature = crypt.Sign(data)
    assert isinstance(Signature, bytes), f"Crypt.Sign did not return a bytearray; {type(cipher)}"

    mark(crypt.VerifySignature(data, Signature) and not crypt.VerifySignature(
        data+b"!", Signature), "Crypt Signing/verification")


def test_Encryptor_Encryption():
    crypt = Crypt("my_password")
    plaintext = "Hello there!".encode()
    encryptor = Encryptor(crypt.public_key)
    cipher = encryptor.Encrypt(plaintext)
    assert isinstance(
        cipher, bytes), f"encryptor.Encrypt did not return a bytearray; {type(cipher)}"
    Decrypted = crypt.Decrypt(cipher)
    assert isinstance(
        Decrypted, bytes), f"encryptor.Decrypt did not return a bytearray: {type(Decrypted)}"

    mark(Decrypted == plaintext, "Encryptor Encryption/Decryption")


def test_Encryptor_file_Encryption():
    crypt = Crypt("my_password")
    encryptor = Encryptor(crypt.public_key)

    tempdir = tempfile.mkdtemp()
    Encrypted_file_path = os.path.join(tempdir, "Encrypted")
    Decrypted_file_path = os.path.join(tempdir, "Decrypted")
    encryptor.EncryptFile("ReadMe.md", Encrypted_file_path)
    assert os.path.exists(Encrypted_file_path), "encryptor.EncryptFile did not create file"
    crypt.DecryptFile(Encrypted_file_path, Decrypted_file_path)
    assert os.path.exists(Decrypted_file_path), "Crypt.DecryptFile did not create file"
    with open("ReadMe.md", "r") as file:
        org_content = file.read()
    with open(Decrypted_file_path, "r") as file:
        Decrypted_content = file.read()
    shutil.rmtree(tempdir)
    mark(org_content == Decrypted_content, "Encryptor file Encryption/Decryption")


def test_Encryptor_Signing():
    crypt = Crypt("my_password")
    encryptor = Encryptor(crypt.public_key)
    data = "Hello there!".encode()
    Signature = crypt.Sign(data)
    assert isinstance(Signature, bytes), f"Crypt.Sign did not return a bytearray; {type(cipher)}"

    mark(encryptor.VerifySignature(data, Signature) and not encryptor.VerifySignature(
        data+b"!", Signature), "Encryptor Signature verification")


def run_tests():
    test_crypt_Encryption()
    test_crypt_file_Encryption()
    test_crypt_Signing()
    test_Encryptor_Encryption()
    test_Encryptor_file_Encryption()
    test_Encryptor_Signing()


if __name__ == '__main__':
    PYTEST = False
    run_tests()
