import tempfile
import os
import shutil
from cryptem import Crypt, Encryptor
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


def test_crypt_encryption():
    crypt = Crypt("my_password")
    plaintext = "Hello there!".encode()
    cipher = crypt.encrypt(plaintext)
    assert isinstance(cipher, bytes), f"Crypt.encrypt did not return a bytearray; {type(cipher)}"
    decrypted = crypt.decrypt(cipher)
    assert isinstance(
        decrypted, bytes), f"Crypt.decrypt did not return a bytearray: {type(decrypted)}"

    mark(decrypted == plaintext, "Crypt encryption/decryption")


def test_crypt_file_encryption():
    crypt = Crypt("my_password")

    tempdir = tempfile.mkdtemp()
    encrypted_file_path = os.path.join(tempdir, "encrypted")
    decrypted_file_path = os.path.join(tempdir, "decrypted")
    crypt.encrypt_file("ReadMe.md", encrypted_file_path)
    assert os.path.exists(encrypted_file_path), "Crypt.encrypt_file did not create file"
    crypt.decrypt_file(encrypted_file_path, decrypted_file_path)
    assert os.path.exists(decrypted_file_path), "Crypt.decrypt_file did not create file"
    with open("ReadMe.md", "r") as file:
        org_content = file.read()
        with open(decrypted_file_path, "r") as file:
            decrypted_content = file.read()
            shutil.rmtree(tempdir)
            mark(org_content == decrypted_content, "Crypt file encryption/decryption")


def test_crypt_signing():
    crypt = Crypt("my_password")
    data = "Hello there!".encode()
    signature = crypt.sign(data)
    assert isinstance(signature, bytes), f"Crypt.sign did not return a bytearray; {type(cipher)}"

    mark(crypt.verify_signature(data, signature) and not crypt.verify_signature(
        data+b"!", signature), "Crypt signing/verification")


def test_encryptor_encryption():
    crypt = Crypt("my_password")
    plaintext = "Hello there!".encode()
    encryptor = Encryptor(crypt.public_key)
    cipher = encryptor.encrypt(plaintext)
    assert isinstance(
        cipher, bytes), f"Encryptor.encrypt did not return a bytearray; {type(cipher)}"
    decrypted = crypt.decrypt(cipher)
    assert isinstance(
        decrypted, bytes), f"Encryptor.decrypt did not return a bytearray: {type(decrypted)}"

    mark(decrypted == plaintext, "Encryptor encryption/decryption")


def test_encryptor_file_encryption():
    crypt = Crypt("my_password")
    encryptor = Encryptor(crypt.public_key)

    tempdir = tempfile.mkdtemp()
    encrypted_file_path = os.path.join(tempdir, "encrypted")
    decrypted_file_path = os.path.join(tempdir, "decrypted")
    encryptor.encrypt_file("ReadMe.md", encrypted_file_path)
    assert os.path.exists(encrypted_file_path), "Encryptor.encrypt_file did not create file"
    crypt.decrypt_file(encrypted_file_path, decrypted_file_path)
    assert os.path.exists(decrypted_file_path), "Crypt.decrypt_file did not create file"
    with open("ReadMe.md", "r") as file:
        org_content = file.read()
    with open(decrypted_file_path, "r") as file:
        decrypted_content = file.read()
    shutil.rmtree(tempdir)
    mark(org_content == decrypted_content, "Encryptor file encryption/decryption")


def test_encryptor_signing():
    crypt = Crypt("my_password")
    encryptor = Encryptor(crypt.public_key)
    data = "Hello there!".encode()
    signature = crypt.sign(data)
    assert isinstance(signature, bytes), f"Crypt.sign did not return a bytearray; {type(cipher)}"

    mark(encryptor.verify_signature(data, signature) and not encryptor.verify_signature(
        data+b"!", signature), "Encryptor signature verification")


def run_tests():
    test_crypt_encryption()
    test_crypt_file_encryption()
    test_crypt_signing()
    test_encryptor_encryption()
    test_encryptor_file_encryption()
    test_encryptor_signing()


if __name__ == '__main__':
    PYTEST = False
    run_tests()
