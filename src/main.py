import os
import re
import sys
from getpass import getpass
from User import User
from data_manage import  create_user, get_user, delete_user


def header():
    os.system("cls" if os.name in ('nt', 'dos') else 'clear')
    print("###################################################")
    print("#                                                 #")
    print("#       Practica 1 - Gestor de contraseñas        #")
    print("#                                                 #")
    print("###################################################")


def option_input() -> int:
    """Comprueba que el input del usuario es un numero entero, en caso contrario devuelve -1"""
    try:
        option = int(input(f"Elige una opcion: "))
        return option
    except ValueError:
        print(f"Tipo de dato no valido.", end=" ")
        return (-1)


def main_menu(current_user):
    """Menu principal con todas las funcionalidades de un usuario"""    
    header()
    print(f"Bienvenido a tu gestor de contraseñas {current_user.username}")
    print("1.- Ver todas mis contraseñas")
    print("2.- Buscar una contreseña por nombre")
    print("3.- Guardar nueva contraseña")
    print("4.- Modificar contraseña existente")
    print("5.- Eliminar contraseña")
    print("6 - Validar firma del sistema")
    print("7.- Borrar usuario ")
    print("8.- Cerrar sesion")
    print("9.- Salir")

    while current_user:
        option = option_input()
        
        if option == 1: # Ver todas mis contraseñas
            user.read_all_passwords()

        elif option == 2: # Buscar una contreseña por nombre
            password_name = input("Introduzca el nombre de la contraseña que desea buscar: ")
            current_user.find_pass_by_name(password_name)

        elif option == 3: # Guardar nueva contraseña
            password_name = input("Introduzca el nombre de la contraseña que desea guardar: ")
            password = getpass("Introduzca la contraseña: ")
            current_user.add_pass(password_name, password)

        elif option == 4: # Modificar contraseña existente
            password_name = input("¿Qué contraseña desea modificar?: ")
            new_value = input("Introduzca la nueva contraseña: ")
            current_user.modify_password(password_name, new_value)

        elif option == 5: # Eliminar contraseña
            password_name = input("¿Qué contraseña deseas eliminar?: ")
            if input("¿Estas seguro?(y/n): ").upper() == "Y":
                current_user.rem_pass(password_name)
            else:
                print(f"No se borrará la contraseña: {password_name}")

        elif option == 6: # Verificar firma del gestor
            current_user.verify_system_signature()

        elif option == 7: # Borrar usuario
            if input("¿Estas seguro?(y/n): ").upper() == "Y":
                delete_user(current_user)
                current_user = None
            else:
                print(f"No se borrará el usuario: {current_user.username}")

        elif option == 8: # Cerrar sesion
            current_user = None

        elif option == 9:  # Salir
            sys.exit()
            
        else: # Opcion no valida
            print("Por favor introduzca un numero del 1 al 8")


def start_create_session_menu():
    """Menu para crear o iniciar sesion"""
    current_user = None

    header()
    print("1.- Iniciar sesion.")
    print("2.- Crear usuario.")
    print("3.- Salir.")

    while current_user is None:
        option = option_input()
        
        if option == 1: # Iniciar sesion
            username = input("Introduzca su nombre de usuario: ")
            password = getpass("Introduzca su contraseña: ")
            current_user = get_user(username, password)
            
        elif option == 2: # Crear usuario
            username = input("Introduzca su nombre de usuario: ")
            pattern_user = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
            while not pattern_user.match(username):
                print("El nombre de usuario no es valido.")
                username = input("Introduzca su nombre de usuario: ")
            password = getpass("Introduzca su contraseña: ")
            pattern_pass= re.compile("^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$")
            while not pattern_pass.match(password):
                print("Mínimo 8 caracteres, sin espacios, al menos una letra, un dígito y un carácter especial ")
                password = getpass("Introduzca su contraseña: ")
            current_user = create_user(User(username, password))
            
        elif option == 3: # Salir
            sys.exit()
        else:
            print("Por favor introduzca un numero de 1 a 3")
    return current_user


if __name__ == "__main__":
    os.system("cls" if os.name in ('nt', 'dos') else 'clear')
    while True:
        user = start_create_session_menu()
        main_menu(user)

