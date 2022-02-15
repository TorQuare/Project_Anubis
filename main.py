import random
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256, SHA512
from Crypto.Util import Padding
import base64


class UserCrypto:

    def __init__(self):
        print("init")

    def pass_crypto_mode_hash(self, string):
        result = None
        try:
            sha_512 = SHA512.new(data=string.encode('utf-8')).hexdigest()
            sha_256 = SHA256.new(data=string.encode('utf-8')).hexdigest()
            result = UserCrypto.md5_code_return_only(sha_256 + sha_512)
        except SyntaxError:
            return False
        return result

    @staticmethod
    def md5_code_return_only(string):
        result = MD5.new(data=string.encode('utf-8')).hexdigest()
        return result

    @staticmethod
    def vector_gen(string):
        iterator = 0
        iv = ""
        check_if_int = string[0].isnumeric()
        if not check_if_int:
            for i in string:
                if iterator % 2 == 0:
                    iv += i
                iterator += 1
        else:
            for i in string:
                if 6 <= iterator <= 11:
                    iv += i
                if 19 <= iterator <= 28:
                    iv += i
                iterator += 1
        return iv.encode('utf-8')

    def aes_block_mode(self, encrypt, code, string):
        key = UserCrypto.md5_code_return_only(code).encode('utf-8')
        iv = UserCrypto.vector_gen(key.decode('utf-8'))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        result = None
        try:
            if encrypt:
                string_enc = Padding.pad(string.encode('utf-8'), AES.block_size)
                result = base64.b64encode(cipher.encrypt(string_enc)).decode('utf-8')
            if not encrypt:
                string_enc = base64.b64decode(string.encode('utf-8'))
                result = Padding.unpad(cipher.decrypt(string_enc), AES.block_size).decode('utf-8')
            return result
        except SyntaxError:
            return False  # wymyślić globalny problem w razie exception
        except ValueError:
            print("Inncorrect key aes_block_mode")
            return False

    @staticmethod
    def code_gen():
        code = []
        result = ""
        for i in range(5):
            if i == 0:
                value = random.randint(1, 9)
            else:
                value = random.randint(0, 9)
            code.append(value)
            if i >= 2:
                while code[i] == code[i - 1] and code[i] == code[i - 2]:
                    code[i] = random.randint(0, 9)
        for j in code:
            result += str(j)
        return result


class MediaCrypto(UserCrypto):

    def aes_stream_mode(self, encrypt, login_32, string):
        key = login_32.encode('utf-8')
        iv = UserCrypto.vector_gen(key.decode('utf-8'))
        cipher = AES.new(key, AES.MODE_CFB, iv)
        result = ""
        try:
            if encrypt:
                result = base64.b64encode(cipher.encrypt(string.encode('utf-8'))).decode('utf-8')
            if not encrypt:
                string_enc = base64.b64decode(string.encode('utf-8'))
                result = cipher.decrypt(string_enc).decode('utf-8')
        except SyntaxError:
            return False  # wymyślić globalny problem w razie exception
        except ValueError:
            print("Inncorrect key aes_block_mode")
            return False
        return result

    @staticmethod
    def key_code_shaker(code):
        result = ""
        code_array = list(map(int, str(code)))
        pre_code = []
        key_code = []
        pre_code_iterator = 0
        flag = 0
        flag_ex = False
        while len(key_code) != 3:
            iterator = 0
            if flag:
                code_array[0] += 3
                if code_array[0] >= 10:
                    code_array[0] -= 8
            flag += 1
            if flag > 10:  # flaga blokująca niesończoną pętle
                flag_ex = True
                break
            for value in range(4):
                if value != 0 and value != 1:
                    if code_array[0] % value == 0:
                        for i in code_array:
                            if code_array[iterator] % value == 0:
                                pre_code.append(i)
                                pre_code_iterator += 1
                            iterator += 1
                        iterator = 0
                    elif code_array[0] % value == 1:
                        for i in code_array:
                            if code_array[iterator] % value == 1:
                                pre_code.append(i * 2)
                                if pre_code[pre_code_iterator] >= 10:
                                    pre_code[pre_code_iterator] = pre_code[pre_code_iterator] - 9
                                pre_code_iterator += 1
                            iterator += 1
                        iterator = 0
            for i in reversed(pre_code):
                key_code.append(i)
            while len(key_code) > 3:
                if len(key_code) % 2 == 0 or len(key_code) % 3 == 0:
                    key_code.pop(1)
                else:
                    if key_code[2] % 2 == 0:
                        key_code.pop(4)
                        key_code.pop(0)
                    else:
                        key_code.pop(2)
            for i in key_code:
                if key_code[iterator] == 0:
                    key_code[iterator] = code_array[0]
                iterator += 1
        if flag_ex:
            return False
        for i in key_code:
            result += str(int(i))
        return result

    @staticmethod
    def login_code_gen(iteration, string):
        result = string
        for i in range(iteration):
            result = MediaCrypto.md5_code_return_only(result)
        return result

    # metoda zwracająca specjalny znak który zostanie dodany
    @staticmethod
    def ascii_mark_string(index, code):
        add_method = 0
        add_symbol_value = 0
        ascii_add_method = [[33, 47], [58, 64], [91, 96], [123, 126]]
        for i in range(6):
            if i != 0 and i != 1:
                if index % i == 0:
                    add_method += 1
            if add_method > 3:
                add_method = 2
        add_method -= 1
        flag = 0
        while add_symbol_value < ascii_add_method[add_method][0]:
            add_symbol_value = ascii_add_method[add_method][1] - code
            if add_symbol_value < ascii_add_method[add_method][0]:
                add_symbol_value += 2
            if flag > 10:
                add_symbol_value = ascii_add_method[add_method][1]
                break
            flag += 1
        return chr(add_symbol_value)

    # PROJECT ANUBIS
    # metoda zwracająca pozycję w której ma zostać dodany ciąg znaków
    # @staticmethod
    # def ascii_position_add(string):
    #     string_arr = list(string)
    #     add_position = 0
    #     for i in range(len(string_arr)):
    #         if i != 0 and i < len(string_arr):
    #             if len(string_arr) % i == 0:
    #                 add_position = i
    #     return add_position

    @staticmethod
    def add_to_string(encrypt, mark_flag, index, code, string):
        key_code = list(map(int, str(code)))
        sorted_key_code = list(map(int, str(code)))
        sorted_key_code.sort()
        value = 0
        result = string
        ascii_add_method = [[48, 57], [65, 90], [97, 122]]
        ascii_key_mode = []
        iterator = 0
        if mark_flag:
            mark = MediaCrypto.ascii_mark_string(index, key_code[1])
        else:
            mark = ""
            value += 1
        for i in key_code:
            value += i
        if encrypt:
            result += mark
            for i in range(sorted_key_code[3]):
                if value % 2 == 0 or value % 3 == 1:
                    ascii_key_mode.append(1)
                    value -= 3
                elif value % 3 == 0 or value % 2 == 1:
                    ascii_key_mode.append(2)
                    value += 5
                else:
                    ascii_key_mode.append(0)
                    value = value * 2
            for i in ascii_key_mode:
                if i == 0:
                    result += chr(ascii_add_method[i][0] + key_code[iterator])
                else:
                    if key_code[iterator] * sorted_key_code[iterator] <= 25:
                        curr_val = key_code[iterator] * sorted_key_code[iterator]
                        result += chr(ascii_add_method[i][0]+curr_val)
                    else:
                        result += chr(ascii_add_method[i][0]+key_code[iterator])
                iterator += 1
                if iterator > 4:
                    iterator = 0
        return result

    def test_enc(self, encrypt, code, login, string):
        key_code = list(map(int, str(MediaCrypto.key_code_shaker(code))))
        login_32 = []
        step = [0, 2, 1]
        if encrypt:
            step.sort()
        value = 0
        stream_iteration = 2
        for i in key_code:
            login_32.append(MediaCrypto.login_code_gen(i, login))
            value += i
        key_code.sort()
        if value % 2 == 0:
            block_iteration = stream_iteration
        elif value % 3 == 0:
            stream_iteration += 1
            block_iteration = 1
        else:
            block_iteration = 1
        for i in step:
            if i == 0:
                for j in range(stream_iteration):
                    string = MediaCrypto.aes_stream_mode(self, encrypt, login_32[j], string)
            if i == 1:
                for j in range(block_iteration):
                    string = MediaCrypto.aes_block_mode(self, encrypt, login_32[j], string)
            if i == 2 and block_iteration < 2:
                for j in range(stream_iteration - 1):
                    string = MediaCrypto.aes_stream_mode(self, encrypt, login_32[j], string)
        print(string, "  \n", len(string), "  ", key_code, "  test")
        return string

    def enc_string_gen(self, encrypt, code, index, login, string):
        result = ""
        correct_string = string
        mark_flag = True
        if encrypt:
            while len(result) < 160:
                result = MediaCrypto.test_enc(self, encrypt, code, login, correct_string)
                if len(result) < 160:
                    correct_string = MediaCrypto.add_to_string(encrypt, mark_flag, index, code, correct_string)
                    mark_flag = False
            return result
