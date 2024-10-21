import tkinter as tk
from tkinter import messagebox
import itertools
import time

# S-DES算法实现
class SDES:
    def __init__(self):
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.Left_Shift_1 = [2, 3, 4, 5, 1]
        self.Left_Shift_2 = [3, 4, 5, 1, 2]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        self.SBox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
        self.SBox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
        self.SPBox = [2, 4, 3, 1]

    def permute(self, data, table):
        return ''.join([data[i - 1] for i in table])

    def left_shift(self, data, n):
        return data[n:] + data[:n]

    def generate_keys(self, key):
        permuted_key = self.permute(key, self.P10)
        left, right = permuted_key[:5], permuted_key[5:]
        left = self.left_shift(left, 1)
        right = self.left_shift(right, 1)
        k1 = self.permute(left + right, self.P8)
        left = self.left_shift(left, 2)
        right = self.left_shift(right, 2)
        k2 = self.permute(left + right, self.P8)
        return k1, k2

    def xor(self, a, b):
        return ''.join(['1' if x != y else '0' for x, y in zip(a, b)])

    def sbox_lookup(self, sbox, value):
        row = int(value[0] + value[3], 2)
        col = int(value[1] + value[2], 2)
        return '{0:02b}'.format(sbox[row][col])

    def f_function(self, data, key):
        expanded = self.permute(data, self.EP)
        xored = self.xor(expanded, key)
        sbox1_out = self.sbox_lookup(self.SBox1, xored[:4])
        sbox2_out = self.sbox_lookup(self.SBox2, xored[4:])
        combined = sbox1_out + sbox2_out
        return self.permute(combined, self.SPBox)

    def encrypt_block(self, plaintext, key):
        keys = self.generate_keys(key)
        ip_data = self.permute(plaintext, self.IP)
        l0, r0 = ip_data[:4], ip_data[4:]
        f_result = self.f_function(r0, keys[0])
        swapped = r0 + self.xor(l0, f_result)
        l1, r1 = swapped[:4], swapped[4:]
        f_result = self.f_function(l1, keys[1])
        ciphertext = self.permute(self.xor(r1, f_result) + l1, self.IP_inv)
        return ciphertext

    def decrypt_block(self, ciphertext, key):
        keys = self.generate_keys(key)
        ip_data = self.permute(ciphertext, self.IP)
        l0, r0 = ip_data[:4], ip_data[4:]
        f_result = self.f_function(r0, keys[1])
        swapped = r0 + self.xor(l0, f_result)
        l1, r1 = swapped[:4], swapped[4:]
        f_result = self.f_function(l1, keys[0])
        plaintext = self.permute(self.xor(r1, f_result) + l1, self.IP_inv)
        return plaintext

    def ascii_to_binary(self, ascii_str):
        return ''.join(['{0:08b}'.format(ord(c)) for c in ascii_str])

    def binary_to_ascii(self, binary_str):
        return ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])

    def encrypt(self, plaintext, key):
        binary_plaintext = self.ascii_to_binary(plaintext)
        blocks = [binary_plaintext[i:i+8] for i in range(0, len(binary_plaintext), 8)]
        encrypted_blocks = [self.encrypt_block(block, key) for block in blocks]
        return self.binary_to_ascii(''.join(encrypted_blocks))

    def decrypt(self, ciphertext, key):
        binary_ciphertext = self.ascii_to_binary(ciphertext)
        blocks = [binary_ciphertext[i:i+8] for i in range(0, len(binary_ciphertext), 8)]
        decrypted_blocks = [self.decrypt_block(block, key) for block in blocks]
        return self.binary_to_ascii(''.join(decrypted_blocks))

    def bruteforce(self, plaintext, ciphertext):
        start_time = time.time()
        found_keys = []
        for key in itertools.product('01', repeat=10):
            key_str = ''.join(key)
            test_ciphertext = self.encrypt(plaintext, key_str)
            if test_ciphertext == ciphertext:
                found_keys.append(key_str)
        end_time = time.time()
        return found_keys, end_time - start_time

# GUI界面
class SDESApp:
    def __init__(self, master):
        self.master = master
        self.sdes = SDES()
        self.create_widgets()

    def create_widgets(self):
        self.label_mode = tk.Label(self.master, text="请选择模式:")
        self.label_mode.pack()
        self.mode_var = tk.IntVar()
        self.mode_var.set(1)
        self.mode_encrypt = tk.Radiobutton(self.master, text="加密", variable=self.mode_var, value=1)
        self.mode_decrypt = tk.Radiobutton(self.master, text="解密", variable=self.mode_var, value=2)
        self.mode_bruteforce = tk.Radiobutton(self.master, text="暴力破解", variable=self.mode_var, value=3)
        self.mode_ascii = tk.Radiobutton(self.master, text="ASCII字符串", variable=self.mode_var, value=4)
        self.mode_encrypt.pack()
        self.mode_decrypt.pack()
        self.mode_bruteforce.pack()
        self.mode_ascii.pack()

        self.label_plaintext = tk.Label(self.master, text="明文/密文:")
        self.label_plaintext.pack()
        self.entry_plaintext = tk.Entry(self.master, width=50)
        self.entry_plaintext.pack()

        self.label_key = tk.Label(self.master, text="密钥:")
        self.label_key.pack()
        self.entry_key = tk.Entry(self.master, width=50)
        self.entry_key.pack()

        self.execute_button = tk.Button(self.master, text="执行", command=self.execute)
        self.execute_button.pack()

        self.label_result = tk.Label(self.master, text="结果:")
        self.label_result.pack()
        self.entry_result = tk.Entry(self.master, width=50)
        self.entry_result.pack()

    def execute(self):
        mode = self.mode_var.get()
        plaintext = self.entry_plaintext.get()
        key = self.entry_key.get()

        if mode == 1:  # 加密
            if len(plaintext) * 8 % 8 == 0 and len(key) == 10:
                ciphertext = self.sdes.encrypt(plaintext, key)
                self.entry_result.delete(0, tk.END)
                self.entry_result.insert(0, ciphertext)
            else:
                messagebox.showerror("错误", "请输入8位ASCII字符和10位二进制密钥")
        elif mode == 2:  # 解密
            if len(plaintext) * 8 % 8 == 0 and len(key) == 10:
                decrypted_text = self.sdes.decrypt(plaintext, key)
                self.entry_result.delete(0, tk.END)
                self.entry_result.insert(0, decrypted_text)
            else:
                messagebox.showerror("错误", "请输入8位ASCII字符和10位二进制密钥")
        elif mode == 3:  # 暴力破解
            if len(plaintext) * 8 % 8 == 0 and len(plaintext) * 8 == len(plaintext) * 8:
                found_keys, duration = self.sdes.bruteforce(plaintext, self.entry_plaintext.get())
                if found_keys:
                    messagebox.showinfo("成功", f"找到密钥: {found_keys}\n耗时: {duration:.2f}秒")
                else:
                    messagebox.showinfo("失败", "未找到匹配的密钥")
            else:
                messagebox.showerror("错误", "请输入8位ASCII字符和10位二进制密钥")
        elif mode == 4:  # ASCII字符串
            if len(key) == 10:
                if self.mode_var.get() == 1:
                    ciphertext = self.sdes.encrypt(plaintext, key)
                    self.entry_result.delete(0, tk.END)
                    self.entry_result.insert(0, ciphertext)
                elif self.mode_var.get() == 2:
                    decrypted_text = self.sdes.decrypt(plaintext, key)
                    self.entry_result.delete(0, tk.END)
                    self.entry_result.insert(0, decrypted_text)
            else:
                messagebox.showerror("错误", "请输入10位二进制密钥")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("S-DES 加解密工具")
    app = SDESApp(root)
    root.mainloop()