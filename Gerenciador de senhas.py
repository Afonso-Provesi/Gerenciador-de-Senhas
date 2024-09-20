import random
import math
import os

# Conjuntos de caracteres permitidos
LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
NUMBERS = '0123456789'
SPECIAL_CHARACTERS = '!@#$%^&*()-_=+[]{};:,.<>?/|'

LENGTH = 16  # Tamanho da senha
MIN_UPPERCASE = 2
MIN_SPECIAL = 2

def generatePassword():
    if LENGTH < (MIN_UPPERCASE + MIN_SPECIAL):
        raise ValueError("O comprimento da senha deve ser maior ou igual à soma de caracteres especiais e maiúsculos necessários.")

    # Garantir a presença de caracteres especiais e maiúsculos
    password_chars = [
        random.choice(SPECIAL_CHARACTERS) for _ in range(MIN_SPECIAL)
    ] + [
        random.choice(UPPERCASE) for _ in range(MIN_UPPERCASE)
    ]

    # Preencher o restante com caracteres aleatórios
    remaining_length = LENGTH - len(password_chars)
    all_characters = LOWERCASE + UPPERCASE + NUMBERS + SPECIAL_CHARACTERS
    password_chars += [random.choice(all_characters) for _ in range(remaining_length)]

    # Embaralhar a senha para garantir a aleatoriedade
    random.shuffle(password_chars)

    # Converter a lista de caracteres em uma string
    return ''.join(password_chars)

def crypto(password, key):
    const = math.factorial(15) - math.factorial(9) + math.factorial(4)
    for i in range(len(password)):
        key_byte = key[i % len(key)]
        password[i] = (password[i] + key_byte + int(math.cos(i) - math.sin(i) / const * math.cos(i))) % 256
    return password

def decrypt(password, key):
    const = math.factorial(15) + math.factorial(9) - math.factorial(4)
    for i in range(len(password)):
        key_byte = key[i % len(key)]
        password[i] = (password[i] - key_byte - int(math.cos(i) + math.sin(i) / const * math.cos(i))) % 256
    return password

def addPassword(account, website):
    # Gerar uma senha que atenda aos requisitos
    password_str = generatePassword()
    print(f"Generated password: {password_str}")  # Exibe a senha gerada

    # Converter a senha em bytes
    password_bytes = bytearray(password_str.encode('utf-8'))

    # Criptografar a senha
    key = bytearray(b"12345678")
    encrypted_password = crypto(password_bytes, key)

    # Salvar a senha no arquivo
    try:
        with open("Senhas.txt", "a") as original:
            original.write(f"Website name: {website}\n")
            original.write(f"Account Name: {account}\n")
            original.write(f"Password: {encrypted_password.hex()}\n")  # Armazena a senha criptografada em formato hexadecimal
    except Exception as e:
        print(f"Ocorreu um erro ao adicionar a senha: {e}")

def getPassword(account, website):
    if not os.path.exists("Senhas.txt"):
        print("Arquivo de senhas não encontrado.")
        return

    try:
        with open("Senhas.txt", "r") as original:
            lines = original.readlines()
            for i in range(0, len(lines), 4):  # Cada entrada tem 4 linhas
                site_line = lines[i].strip()
                account_line = lines[i + 1].strip()
                password_line = lines[i + 2].strip()

                site = site_line.split(": ")[1]
                account_name = account_line.split(": ")[1]
                
                if site == website and account_name == account:
                    password_hex = password_line.split(": ")[1]
                    print(f"Senha criptografada encontrada: {password_hex}")  # Debug
                    
                    # Converter a senha criptografada de volta para bytearray
                    encrypted_password = bytearray.fromhex(password_hex)
                    
                    # Descriptografar
                    key = bytearray(b"12345678")
                    decrypted_password = decrypt(encrypted_password, key)
                    
                    # Converter de volta para string
                    recovered_password = decrypted_password.decode('utf-8')
                    print(f"Senha recuperada para {website}: {recovered_password}")
                    return recovered_password
            print("Senha não encontrada.")
    except Exception as e:
        print(f"Ocorreu um erro ao recuperar a senha: {e}")

def main():
    userChoice = int(input("Options:\n1 - Register a new password\n2 - Get your password\n\n"))
    
    if userChoice == 1:
        site = input("Type here the website you are using this password: ")
        account = input("What's your account in the website?: ")
        addPassword(account, site)
    elif userChoice == 2:
        site = input("Type here the website you are using this password: ")
        account = input("What's your account in the website?: ")
        password = getPassword(account, site)
    else:
        print("Invalid option")
    
if __name__ == "__main__":
    main()