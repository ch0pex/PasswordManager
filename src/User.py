"""Modulo que contiene la clase Usuario"""


from encrypt import create_hash
from encrypt import symm_encrypt
from encrypt import symm_decrypt
from encrypt import sys_sign_user
from encrypt import verify_PKI

from data_manage import store_user


class User:
    """Clase usuario que almacena en memoria los datos cifrados del usuario logueado para su procesado"""

    def __init__(self, username, password, stored_passwords=None, stored_messages = None, salt=None):
        """La clase usuario se puede crear introduciendo solo el usuario y la contraseña en caso de un usuario nuevo.
        En caso de que el usuario ya existiera en el JSON le pasamos como argumentos las contraseñas almacenadas y
        el salt de la contraseña"""

        # Creamos un primer hash de la contraseña
        first_hash = create_hash(password) if salt is None else create_hash(password, salt)
        self.username: str = username
        # Clave de cifrado simetrico en hexadecimal, es el primer hash de la pass sin el salt 32 bytes
        self.__key: str = first_hash[:64]
        # La contraseña se almacena hasheando por segunda vez password tanto en memoria como en el JSON
        self.__password: str = create_hash(first_hash, first_hash[64:])
        # Diccionario de las contraseñas cifradas guardadas por el usuario
        self.__stored_passwords: dict = stored_passwords

        
    def __signature(self) -> str: 
        """Devuelve la firma del JSON en el que se almacenara el usuario"""
        return sys_sign_user(str(self))
        
    def to_dict(self) -> dict:
        """Devuelve como un diccionario la contraseña de inicio de sesion y las contraseñas guardadas,
        estos son los datos que se persisten en el JSON junto con el nombre de usuario"""
    
        return {"username": self.username, "password": self.__password, "stored_passwords": self.__stored_passwords, "signature": self.__signature()}

    def __find_pass(self, input_name):
        """Encuentra la clave cifrada de self.__storage equivalente a input_name """
        if self.__stored_passwords is None:
            return None  # Storage esta vacio
        for name_password, password in self.__stored_passwords.items():
            # Desciframos clave a clave del diccionario storage y lo comparamos con input_name
            if symm_decrypt(name_password, self.__key) == input_name:
                return name_password  # Si existe en el diccionario devuelve la clave cifrada
        return None  # La contraseña no exite



    def read_all_passwords(self):
        """Muestra por pantalla todas las contraseñas que tiene el usuario"""
        if self.__stored_passwords is None:  # Si el storage esta vacio
            print("No hay contraseñas guardadas todavía")
            return
        print("Estas son todas sus contraseñas almacenadas")
        for name, password in self.__stored_passwords.items():
            # Las contraseñas se descifran en el momento que se muestran por pantalla
            print(
                f"{symm_decrypt(name, self.__key)}: {symm_decrypt(password, self.__key)}")

    def find_pass_by_name(self, input_name):
        """Muestra por pantalla la contraseña pedida por el usuario"""
        encrypted_name = self.__find_pass(input_name)  # Clave cifrada
        if encrypted_name is None:  # Si no existe input_name en storage
            print("No existe una contraseña con ese nombre. Intentelo de nuevo")
            return
        # Se muestra por pantalla la contraseña pedida
        print("Contraseña solicitada:")
        print(
            f"{input_name}: {symm_decrypt(self.__stored_passwords[encrypted_name], self.__key)}")

    def add_pass(self, password_name, password):
        """Añade la contraseña introducida por el usuario a storage"""
        if self.__stored_passwords is None:  # Si storage es None crea un diccionario
            self.__stored_passwords = {}
        # Si la contraseña ya existe no se puede añadir
        elif self.__find_pass(password_name) is not None:
            print("La contraseña introducida ya existe, si desea puede modificarla seleccionando la opcion 4.")
            return
        # Se cifran tanto el nombre de la contraseña como la contraseña en si
        self.__stored_passwords[symm_encrypt(password_name, self.__key)] = symm_encrypt(
            password, self.__key)
        store_user(self)  # Se actualiza la informacion del usuario en el JSON
        print("Contraseña introducida correctamente")

    def modify_password(self, input_name, input_pass):
        """Modifica la contraseña introducida (input_name) con un nuevo valor (input_pass)"""
        encrypted_name = self.__find_pass(input_name)
        if encrypted_name is None:  # Si no existe input_name en storage
            print("La contraseña introducida no existe, intentelo de nuevo")
            return
        self.__stored_passwords[encrypted_name] = symm_encrypt(input_pass, self.__key)
        store_user(self)  # Se actualiza la informacion del usuario en el JSON
        print("Contraseña introducida correctamente")

    def rem_pass(self, input_name):
        """Elimina la contraseña introducida por el usuario"""
        encrypted_name = self.__find_pass(input_name)
        if encrypted_name is None:
            print("La contraseña introducida no existe, intentelo de nuevo")
            return
        try:
            self.__stored_passwords.pop(encrypted_name)
            store_user(self) 
            print("Contraseña eliminada correctamente")
        except KeyError:
            print("La contraseña introducida no existe, por lo que no se puede eliminar")
        
    def verify_system_signature(self): 
        """Verifica la firma del gestor"""
        try: 
            verify_PKI("SYSTEM") # la funcion verify_PKI lanza una excepcion si la firma no es valida
            print("La firma del sistema ha sido verificada correctamente y es fiable ✓")
        except: 
            print("La firma del sistema no es fiable ✗")
        
        

    