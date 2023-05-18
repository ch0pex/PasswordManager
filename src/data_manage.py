import json
import os
import io
import sys

from encrypt import verify_password
from encrypt import verify_JSON_signature

# Path de json con los usuarios y contraseñas cifrados.
USER_DATA_PATH = None


def init_user_db(username):
    """Crea el archivo JSON donde se guardarán los datos del usuario"""
    try:
        with io.open(f"{USER_DATA_PATH}Users/{username}.json", "w") as db_file:
            db_file.write(json.dumps({}))
    except FileExistsError:
        print("Algo fue mal y la aplicación no pudo crear el archivo de datos")
        sys.exit()


def store_user(user):
    """Guarda el usuario en el JSON"""
    try:
        with open(f"{USER_DATA_PATH}Users/{user.username}.json", "r+", encoding="utf-8", newline="") as file:
            json.dump(user.to_dict(), file, indent=2)
            file.truncate()
    except FileNotFoundError:
        print("Algo ha ido mal, no se ha podido guardar el usuario, base de datos corrupta.")
        sys.exit()
    return user


def create_user(user): 
    """Función que crea un usuario y lo guarda en el JSON"""
    if check_username(user.username):  
        print("El usuario ya existe, introduzca un nombre distinto")
        return
    init_user_db(user.username)  # Creamos el archivo JSON con los datos del usuario 
    store_user(user)  # Guardamos el usuario en el JSON
    return user 


def delete_user(user):
    print(f"rm {USER_DATA_PATH}Users/{user.username}.json")
    os.remove(f"{USER_DATA_PATH}Users/{user.username}.json")
       


def get_user(username, password):
    """Si la contraseña, usuario y firma del JSON son correctos, devuelve el usuario"""
        
    if not check_username(username): 
        print("El usuario no existe")
        return None
    
    try: 
        with open(f"Users/{username}.json", "r+", encoding="utf-8", newline="") as file:
            json_user = json.load(file)
    except FileNotFoundError: 
        print("Algo ha ido mal, no se ha podido guardar el usuario, base de datos corrupta.")
        return None
    
    if verify_JSON_signature(json_user): # Verificamos la firma del JSON
        print("Los datos del usuario han sido modificados, la firma no coincide") 
        return None

    
    if not check_password(username, password):
        print("La contraseña es incorrecta")
        return None
    
    from User import User  
    return User(username, password, json_user["stored_passwords"], salt=json_user["password"][64:])
   

def check_username(username) -> bool:
    """Comprueba si el usuario existe"""
    if not os.path.isfile(f"{USER_DATA_PATH}Users/{username}.json") or not os.access(f"Users/{username}.json", os.R_OK):
        return False
    return True


def check_password(username, password) -> bool:
    """Comprueba que la password de username es correcta"""
    try: 
        with open(f"{USER_DATA_PATH}Users/{username}.json", "r", encoding="utf-8", newline="") as file:
            data = json.load(file)        
    except FileNotFoundError:
        print("Algo ha ido mal, no se ha podido guardar el usuario, base de datos corrupta.")
        return False
    
    if verify_password(data["password"], password):
        return True
    return False
