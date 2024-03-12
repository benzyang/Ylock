import os
import hashlib
import logging
import secrets
import subprocess


# 随机生成8位16进制
def generate_random_hex(length):
    return secrets.token_hex(length // 2)

def encrypt_file(file_path, password, keep):
    # 计算密码的MD5哈希值
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    encrypted_file_path = file_path + '.ylock'
    if keep:
        output_file = encrypted_file_path
    else:
        os.rename(file_path, encrypted_file_path)
        file_path = encrypted_file_path

    with open(file_path, 'rb+') as file:
        data = file.read(len(hashed_password) // 2).hex()

        # 执行异或运算
        xor_result = int(data, 16) ^ int(hashed_password, 16)
        result_hex = format(xor_result, f'0{len(data)}x')

        # 将十六进制字符串转换为字节串
        result_bytes = bytes.fromhex(result_hex)

        if keep:
            with open(output_file, 'wb') as out_file:
                out_file.seek(0)
                out_file.write(result_bytes)
                data_o = data = file.read()
                out_file.write(data_o)

                # 在文件末尾追加随机生成的内容
                random_hex = generate_random_hex(8)
                out_file.write(bytes.fromhex(f'ffff10{hashed_password}0200000000{random_hex}00000020'))
        else:
            file.seek(0)
            file.write(result_bytes)

            # 在文件末尾追加随机生成的内容
            random_hex = generate_random_hex(8)
            file.seek(0, 2)
            file.write(bytes.fromhex(f'ffff10{hashed_password}0200000000{random_hex}00000020'))        

        
def decrypt_file(file_path, password):
    with open(file_path, 'rb+') as file:
        # 计算密码的哈希值
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        # 定位存储哈希的位置
        file.seek(-45, 2)
        stored_hash = file.read().hex()
        stored_hash = stored_hash[:-26]

        original_file_name = None

        # 验证密码
        if stored_hash == hashed_password:
            file.seek(0)
            data = file.read(len(hashed_password) // 2).hex()

            # 解密
            xor_result = int(data, 16) ^ int(hashed_password, 16)
            result_hex = format(xor_result, f'0{len(data)}x')
            result_bytes = bytes.fromhex(result_hex)

            # 写入文件并截断
            file.seek(0)
            file.write(result_bytes)
            file.seek(-48, 2)
            file.truncate()
            original_file_name = os.path.splitext(file_path)[0] # 提取文件名
        else:
            print("Password is incorrect!")
            return 1
        
    if original_file_name:
        base_name, extension = os.path.splitext(original_file_name)
        counter = 1
        while os.path.exists(original_file_name):
            original_file_name = f"{base_name} ({counter}){extension}"
            counter += 1
        os.rename(file_path, original_file_name)

    return 0


def encrypt_file_txt(file_path, password, keep):
    # 计算密码的MD5哈希值
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    encrypted_file_path = file_path + '.ylock'
    if keep:
        output_file = encrypted_file_path
    else:
        os.rename(file_path, encrypted_file_path)
        file_path = encrypted_file_path

    with open(file_path, 'rb+') as file:
        data = file.read().hex()
        hashed_password_sh = hashed_password * (len(data) // len(hashed_password)) + hashed_password[:len(data) % len(hashed_password)]

        # 执行异或运算
        xor_result = hex(int(data, 16) ^ int(hashed_password_sh, 16))

        # 将十六进制字符串转换为字节串
        result_bytes = bytes.fromhex(xor_result[2:])

        if keep:
            with open(output_file, 'wb') as out_file:
                out_file.seek(0)
                out_file.write(result_bytes)

                # 在文件末尾追加随机生成的内容
                random_hex = generate_random_hex(8)
                # out_file.seek(0, 2)
                out_file.write(bytes.fromhex(f'ffff10{hashed_password}0200000000{random_hex}00000020'))
        else:
            file.seek(0)
            file.write(result_bytes)

            # 在文件末尾追加随机生成的内容
            random_hex = generate_random_hex(8)
            file.seek(0, 2)
            file.write(bytes.fromhex(f'ffff10{hashed_password}0200000000{random_hex}00000020'))

        
def decrypt_file_txt(file_path, password):
    with open(file_path, 'rb+') as file:
        # 计算密码的哈希值
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        # 定位存储哈希的位置
        file.seek(-45, 2)
        stored_hash = file.read().hex()
        stored_hash = stored_hash[:-26]

        original_file_name = None

        # 验证密码
        if stored_hash == hashed_password:
            file.seek(0)
            data = file.read().hex()
            # 读取文件内容直到 'ffff10'
            index = data.index('ffff10')
            data = data[:index]
            hashed_password_sh = hashed_password * (len(data) // len(hashed_password)) + hashed_password[:len(data) % len(hashed_password)]

            # 解密
            result = hex(int(data, 16) ^ int(hashed_password_sh, 16))
            result_bytes = bytes.fromhex(result[2:])

            # 写入文件并截断
            file.seek(0)
            file.write(result_bytes)
            file.truncate()
            original_file_name = os.path.splitext(file_path)[0] # 提取文件名
        else:
            print("Password is incorrect!")
            return 1
    
    if original_file_name:
        base_name, extension = os.path.splitext(original_file_name)
        counter = 1
        while os.path.exists(original_file_name):
            original_file_name = f"{base_name} ({counter}){extension}"
            counter += 1
        os.rename(file_path, original_file_name)

    return 0


def getfilepath():
    while True:
        file_paths = input('Enter your file path (Separate files with spaces):\n')
        exist = 0

        # 按空格分隔文件路径
        file_paths_list = file_paths.split()

        # 合并由双引号括起来的文件路径
        file_paths = []
        i = 0
        while i < len(file_paths_list):
            if file_paths_list[i].startswith('"'):
                path = file_paths_list[i][1:]  # 去除开头的双引号
                i += 1
                while not file_paths_list[i].endswith('"'):
                    path += ' ' + file_paths_list[i]
                    i += 1
                path += ' ' + file_paths_list[i][:-1]  # 去除结尾的双引号
                file_paths.append(path)
            elif file_paths_list[i].startswith("'"):
                path = file_paths_list[i][1:]  # 去除开头的双引号
                i += 1
                while not file_paths_list[i].endswith("'"):
                    path += ' ' + file_paths_list[i]
                    i += 1
                path += ' ' + file_paths_list[i][:-1]  # 去除结尾的双引号
                file_paths.append(path)
            else:
                file_paths.append(file_paths_list[i])
            i += 1

        for path in file_paths:
            if os.path.exists(path):
                exist += 1
                continue
        
        if exist != len(file_paths):
            print("File does not exist. Please enter a valid file path.")
        else:
            break

    return file_paths


def add_empty_line_to_log(log_file):
    # 打开文件进行读取
    with open(log_file, 'r') as file:
        # 读取文件的所有行
        lines = file.readlines()

        # 检查文件是否为空
        if not lines:
            return

        # 获取文件的最后两行，并去除末尾的换行符
        last_two_lines = [line.rstrip('\n') for line in lines[-2:]]

        # 如果最后两行都是空行，则关闭文件
        if all(line == '' for line in last_two_lines):
            return

    # 打开文件进行写入
    with open(log_file, 'a') as file:
        # 添加一个空行
        file.write('\n')



if __name__ == "__main__":
    log_file = 'ylock.log'
    subprocess.run(['attrib', '+h', log_file], check=True, shell=True)
    # 配置日志记录器
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

    while True:
        print('-----------------------------------------------------------------------------------')
        print('1. Encryption   2. Decryption   3. Encryption while keeping original file   4. Exit')

        # 选择
        chose = input('Choose 1, 2 or 3?\n')
        if chose == '4' or chose == 'exit' or chose == 'Exit' or chose == 'EXIT':
            break

        # 输入文件路径
        print('--------------------------------------------------')
        file_paths = getfilepath()

        # 输入密码
        print('-------------------')
        password = input('Enter you password:\n')

        if chose == '1':
            for file_path in file_paths:
                if file_path.endswith('.txt'):
                    encrypt_file_txt(file_path, password, False)
                else:
                    encrypt_file(file_path, password, False)
            print("Encryption success!")
            logging.info(f'Encryption - {password}.')
            logging.info(f'{file_paths}.')
        elif chose == '3':
            for file_path in file_paths:
                if file_path.endswith('.txt'):
                    encrypt_file_txt(file_path, password, True)
                else:
                    encrypt_file(file_path, password, True)
            print("Encryption success!")
            logging.info(f'Encryption while keeping original file - {password}.')
            logging.info(f'{file_paths}.')
        elif chose == '2':
            for file_path in file_paths:
                if file_path.endswith('.txt.ylock'):
                    while(decrypt_file_txt(file_path, password)):
                        password = input('Enter you password:\n')
                else:
                    while(decrypt_file(file_path, password)):
                        password = input('Enter you password:\n')
            print("Decryption success!")
            logging.info(f'Decryption - {password}.')
            logging.info(f'{file_paths}.')
    
    add_empty_line_to_log(log_file)
    subprocess.run(['attrib', '+h', log_file], check=True, shell=True)



# 保留原文件



