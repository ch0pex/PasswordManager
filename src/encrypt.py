"""Este modulo contiene todas las funciones necesarias para generar hashes, encriptar y desencriptar informacion"""
import os
import sys
import binascii
#from dotenv import load_dotenv

from cryptography.exceptions import InvalidKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes


#load_dotenv(".venv/priv.env")
# SYSTEM_PASS = os.getenv("SYSTEM_PASS").encode("utf-8") # Se obtiene la contraseña del sistema
SYSTEM_PASS = "a42c17fbfbd918a69114fbda91942b4b788611e7b18a16bb0471a3f48fee82dc".encode("utf-8") # Contraseña del sistema

def create_hash(password, custom_salt=None) -> str:
    """Devuelve el hash concatenado con el salt"""
    salt = os.urandom(16) if custom_salt is None else binascii.unhexlify(custom_salt)  # Salt aleatorio o custom salt
    byte_password = password.encode("utf-8")  # Pass a bytes
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = binascii.hexlify(kdf.derive(byte_password))  # Se hashea la contraseña
    return key.decode("utf-8") + binascii.hexlify(salt).decode("utf-8")  # Devuelve el hash concatenado con el salt


def verify_password(password, input_pass) -> bool:
    """Funcion que verifica la contraseña input, con la contraseña almacenada."""
    first_hash = create_hash(input_pass, custom_salt=password[64:]).encode("utf-8")  # Primer hash
    salt = binascii.unhexlify(password[64:])  # El salt esta concatenado al hash
    byte_password = binascii.unhexlify(password[:64])
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    # Se verifica hasheando por segunda vez
    try:
        kdf.verify(first_hash, byte_password)
        return True
    except InvalidKey:
        return False


def pad(value: str) -> bytes:
    """Funcion para paddear la informacion de tal forma que la longitud de la informacion coincida
    con un multiplo del tamaño del bloque usado en el cifrado"""
    padder = padding.PKCS7(128).padder()
    return padder.update(value.encode("utf-8")) + padder.finalize()


def unpad(padded_value: bytes) -> str:
    """Funcion para quitar a la informacion desencriptada el pad con el que fue encriptada previamente"""
    padder = padding.PKCS7(128).unpadder()
    value = padder.update(padded_value) + padder.finalize()
    return value.decode("utf-8")


def symm_encrypt(value: str, key: str) -> str:
    """Se encripta la informacion pasada por value con la clave simetrica key y se devuelve"""
    iv = os.urandom(16)  # Se genera un iv aleatorio para el modo CBC
    key_byte = binascii.unhexlify(key)
    cipher = Cipher(algorithms.AES(key_byte), modes.CBC(iv))
    encryptor = cipher.encryptor()
    #  Se hace un pad de la informacion y se encripta
    encrypted_data = encryptor.update(pad(value)) + encryptor.finalize()
    return binascii.hexlify(iv).decode("utf-8") + binascii.hexlify(encrypted_data).decode("utf-8")


def symm_decrypt(value: str, key: str) -> str:
    """Devuelve los datos desencriptados usando la clave introducida por parametro"""
    iv = binascii.unhexlify(value[:32])  # EL IV esta almacenado en los primeros 16 bytes de la informacion
    key_byte = binascii.unhexlify(key)
    cipher = Cipher(algorithms.AES(key_byte), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decyrpted_data = decryptor.update(binascii.unhexlify(value[32:])) + decryptor.finalize()
    return unpad(decyrpted_data)  # Se devuelve la informacion sin el pad


################################################
# Funciones para firmar y verificacion de PKI  #
################################################
def get_SYSTEM_private_key():
    """Obtiene la clave privada del sistema"""
    try:  
        with open("PKI/SYSTEM/Systemkey.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password= SYSTEM_PASS,
            ) 
        return private_key
    except FileNotFoundError:
        print("Clave privada del sistema ausente o dañada")
        sys.exit()
 


def get_SYSTEM_public_key():
    """Obtiene la clave publica del sistema"""
    try:
        with open("PKI/SYSTEM/Systemcert.pem", "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read())
    except FileNotFoundError:
        print("Clave publica del sistema ausente o dañada")
        sys.exit()

    return cert.public_key()


def sys_sign_user(expression: str) -> str: 
    """El sistema firma la expresion pasada por parametro"""
    system_private_key = get_SYSTEM_private_key()
    signature = system_private_key.sign(
        expression.encode("utf-8"),
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
    return binascii.hexlify(signature).decode("utf-8")



def verify_JSON_signature(json)-> bool:
    """Funcion que verifica el contenido del JSON comparandolo 
        con la firma, tambien comprueba que la firma sea veridica"""
        
    if len(json["signature"]) != 256: 
        return False  
      
    try: 
        verify_PKI("SYSTEM")
    except: 
        return False
    
    content = f"Usuario: {json['username']}\nContraseña: {json['password']}\nContraseñas guardadas: {json['stored_passwords']}"  
    RSA_public_key = get_SYSTEM_public_key()
    
    try:
        RSA_public_key.verify(
            binascii.unhexlify(json["signature"]),
            content.encode("utf-8"),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
        return True
    except InvalidSignature:
        return False


def verify_PKI(entity_name):
    """Funcion recursiva que verifica la entidad pasada por parametro
        hasta la raiz del arbol PKI"""
    
    with open(f"PKI/{entity_name}/{entity_name}cert.pem", "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    issuer_name = cert.issuer.rdns[4]._attributes[0].value
    with open(f"PKI/{issuer_name}/{issuer_name}cert.pem", "rb") as cert_file:
        issuer_cert = x509.load_pem_x509_certificate(cert_file.read())
    issuer_public_key = issuer_cert.public_key()

    issuer_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        asymmetric_padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )    
    if entity_name != issuer_name: # Si no es la raiz del arbol PKI se llama a la funcion recursivamente
        verify_PKI(issuer_name) 
    
    
    