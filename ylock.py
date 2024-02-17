import os
import hashlib


def encrypt_file(file_path, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    with open(file_path, 'rb+') as file:
        header_data = file.read(64)
        file.seek(0)
        file.write(hashed_password.encode())

    with open(file_path, 'ab+') as file:
        file.seek(0, 2)
        file.write(header_data)

    encrypted_file_path = file_path + '.ylock'
    os.rename(file_path, encrypted_file_path)
    print("Decryption success!")


def decrypt_file(file_path, password):
    with open(file_path, 'rb+') as file:
        stored_hash = file.read(64).decode()

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        original_file_name = None
        if stored_hash == hashed_password:
            file.seek(-64, 2)
            data = file.read()
            file.truncate()
            file.seek(0)
            file.write(data)
            original_file_name = os.path.splitext(file_path)[0]
            print("Decryption success!")
        else:
            print("Password is incorrect!")
            return 1
        
    if original_file_name:
        os.rename(file_path, original_file_name)
    
    return 0


if __name__ == "__main__":
    while(1):
        print('1. Encryption   2. Decryption   3. Exit')
        chose = input('Choose 1 or 2?\n')
        if chose == '3':
            break
        file_path = input('Enter you file path:\n')
        password = input('Enter you password:\n')
        if chose == '1':
            encrypt_file(file_path, password)
        elif chose == '2':
            while(decrypt_file(file_path, password)):
                password = input('Enter you password:\n')


