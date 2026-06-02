import os
import argparse
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import IDEA
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

BLOCK_SIZE = 64  # Размер блока IDEA в битах
KEY_SIZE = 16    # Длина ключа IDEA в байтах (128 бит)


def generate_keys(sym_path, pub_path, priv_path):
    """Режим 1: Генерация и сериализация ключей."""
    print("[1] Генерация ключей...")
    sym_key = os.urandom(KEY_SIZE)
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Сохранение RSA ключей
    os.makedirs(os.path.dirname(pub_path) or '.', exist_ok=True)
    os.makedirs(os.path.dirname(priv_path) or '.', exist_ok=True)
    
    with open(pub_path, 'wb') as f:
        f.write(public_key.public_bytes(serialization.Encoding.PEM, 
                                        serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(priv_path, 'wb') as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))

    # Шифрование симметричного ключа RSA
    encrypted_sym = public_key.encrypt(
        sym_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), 
                          algorithm=hashes.SHA256(), label=None)
    )
    with open(sym_path, 'wb') as f:
        f.write(encrypted_sym)
    print("[OK] Ключи сгенерированы и сохранены.")


def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def decrypt_sym_key(sym_enc_path, priv_path):
    priv_key = load_private_key(priv_path)
    with open(sym_enc_path, 'rb') as f:
        enc_sym = f.read()
    return priv_key.decrypt(
        enc_sym,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), 
                          algorithm=hashes.SHA256(), label=None)
    )


def encrypt_file(input_path, output_path, sym_enc_path, priv_path):
    """Режим 2: Шифрование данных."""
    print("[2] Шифрование файла...")
    sym_key = decrypt_sym_key(sym_enc_path, priv_path)

    with open(input_path, 'rb') as f:
        data = f.read()

    # Паддинг до кратности блоку (64 бита)
    padder = padding.ANSIX923(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(BLOCK_SIZE // 8)  # 8 байт
    cipher = Cipher(IDEA(sym_key), modes.CBC(iv))
    ciphertext = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    print("[OK] Файл зашифрован.")


def decrypt_file(input_path, output_path, sym_enc_path, priv_path):
    """Режим 3: Дешифрование данных."""
    print("[3] Дешифрование файла...")
    sym_key = decrypt_sym_key(sym_enc_path, priv_path)

    with open(input_path, 'rb') as f:
        iv = f.read(BLOCK_SIZE // 8)
        ciphertext = f.read()

    cipher = Cipher(IDEA(sym_key), modes.CBC(iv))
    padded_data = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

    unpadder = padding.ANSIX923(BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(data)
    print("[OK] Файл расшифрован.")


def main():
    parser = argparse.ArgumentParser(description="Гибридная криптосистема (RSA + IDEA)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Режим дешифрования')

    parser.add_argument('--sym-key', help='Путь для зашифрованного симметричного ключа')
    parser.add_argument('--pub-key', help='Путь для открытого ключа')
    parser.add_argument('--priv-key', help='Путь для закрытого ключа')
    parser.add_argument('--input', help='Путь к входному файлу')
    parser.add_argument('--output', help='Путь для выходного файла')
    parser.add_argument('--enc-sym-key', help='Путь к зашифрованному симметричному ключу')

    args = parser.parse_args()

    if args.generation:
        if not all([args.sym_key, args.pub_key, args.priv_key]):
            parser.error("Для генерации укажите --sym-key, --pub-key, --priv-key")
        generate_keys(args.sym_key, args.pub_key, args.priv_key)
    elif args.encryption:
        if not all([args.input, args.output, args.enc_sym_key, args.priv_key]):
            parser.error("Для шифрования укажите --input, --output, --enc-sym-key, --priv-key")
        encrypt_file(args.input, args.output, args.enc_sym_key, args.priv_key)
    elif args.decryption:
        if not all([args.input, args.output, args.enc_sym_key, args.priv_key]):
            parser.error("Для дешифрования укажите --input, --output, --enc-sym-key, --priv-key")
        decrypt_file(args.input, args.output, args.enc_sym_key, args.priv_key)


if __name__ == "__main__":
    main()