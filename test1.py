import tkinter as tk
from tkinter import messagebox
import itertools

# 定义置换表
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
S1 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]


# 合并数组函数
def merge(num, x, y):
    n = len(x)
    num[:n] = x
    num[n:] = y


# 置换函数
def change(z1, z2, P):
    z2[:] = [z1[p - 1] for p in P]


# 二进制整数型转字符型函数
def intz(n):
    return '1' if n else '0'


# 子密钥生成
def key(mkey, k1, k2):
    mkey1 = [mkey[p - 1] for p in P10]
    temp1, temp2 = mkey1[:5], mkey1[5:]

    # 左移一位
    temp1.append(temp1.pop(0))
    temp2.append(temp2.pop(0))
    mkey1 = temp1 + temp2
    k1[:] = [mkey1[p - 1] for p in P8]

    # 再次左移一位
    temp1.append(temp1.pop(0))
    temp2.append(temp2.pop(0))
    mkey1 = temp1 + temp2
    k2[:] = [mkey1[p - 1] for p in P8]


# 加密主过程
def DES(temp, k1, Rm, Lm1):
    Lm, Rm[:] = temp[:4], temp[4:]
    Rm1 = [Rm[EP[i] - 1] for i in range(8)]
    Rm1 = ['0' if Rm1[i] == k1[i] else '1' for i in range(8)]

    x1, y1 = (int(Rm1[1]) * 2 + int(Rm1[2])), (int(Rm1[0]) * 2 + int(Rm1[3]))
    x2, y2 = (int(Rm1[5]) * 2 + int(Rm1[6])), (int(Rm1[4]) * 2 + int(Rm1[7]))

    s0, s1 = S0[y1][x1], S1[y2][x2]
    Rm1 = [intz((s0 >> (3 - i)) & 1) for i in range(2)] + [intz((s1 >> (1 - i)) & 1) for i in range(2)]

    Rm2 = [Rm1[P4[i] - 1] for i in range(4)]
    Lm1[:] = ['0' if Lm[i] == Rm2[i] else '1' for i in range(4)]


# 将ASCII字符串转换为二进制字符串
def ascii_to_binary_string(ascii_str):
    return ''.join(f'{ord(c):08b}' for c in ascii_str)


# 将二进制字符串转换为ASCII字符串
def binary_string_to_ascii(binary_str):
    return ''.join(chr(int(binary_str[i:i + 8], 2)) for i in range(0, len(binary_str), 8))


def encrypt(mkey, m):
    k1, k2 = ['0'] * 8, ['0'] * 8
    key(mkey, k1, k2)
    temp = ['0'] * 8
    change(m, temp, IP)
    Rm, Lm1 = ['0'] * 4, ['0'] * 4
    DES(temp, k1, Rm, Lm1)
    m1 = ['0'] * 8
    merge(m1, Rm, Lm1)
    Rm1, Lm11 = ['0'] * 4, ['0'] * 4
    DES(m1, k2, Rm1, Lm11)
    mw = ['0'] * 8
    merge(mw, Lm11, Rm1)
    mw1 = ['0'] * 8
    change(mw, mw1, IP_1)
    return ''.join(mw1)


def decrypt(mkey, m):
    k1, k2 = ['0'] * 8, ['0'] * 8
    key(mkey, k1, k2)
    temp = ['0'] * 8
    change(m, temp, IP)
    Rm, Lm1 = ['0'] * 4, ['0'] * 4
    DES(temp, k2, Rm, Lm1)
    m1 = ['0'] * 8
    merge(m1, Rm, Lm1)
    Rm1, Lm11 = ['0'] * 4, ['0'] * 4
    DES(m1, k1, Rm1, Lm11)
    mw = ['0'] * 8
    merge(mw, Lm11, Rm1)
    mw1 = ['0'] * 8
    change(mw, mw1, IP_1)
    return ''.join(mw1)


def find_key(m, mw):
    mkey = ['0'] * 10
    k1, k2 = ['0'] * 8, ['0'] * 8
    Rm, Lm1 = ['0'] * 4, ['0'] * 4
    found = False

    for i in range(1024):
        key(''.join(mkey), k1, k2)
        temp = ['0'] * 8
        change(m, temp, IP)
        DES(temp, k1, Rm, Lm1)
        m1 = ['0'] * 8
        merge(m1, Rm, Lm1)
        DES(m1, k2, Rm1, Lm11)
        mw1 = ['0'] * 8
        merge(mw1, Lm11, Rm1)
        change(mw1, mw11, IP_1)
        if mw == ''.join(mw11):
            return ''.join(mkey)

        # 增加密钥
        for j in range(9, -1, -1):
            if mkey[j] == '0':
                mkey[j] = '1'
                break
            else:
                mkey[j] = '0'

    return None


def process_text(choose1, mkey, mm):
    key(mkey, k1, k2)

    binaryM = ascii_to_binary_string(mm)
    result = []

    for i in range(0, len(binaryM), 8):
        cut = list(binaryM[i:i + 8])
        temp = ['0'] * 8
        change(cut, temp, IP)
        Rm, Lm1 = ['0'] * 4, ['0'] * 4
        DES(temp, k1 if choose1 == 1 else k2, Rm, Lm1)
        m1 = ['0'] * 8
        merge(m1, Rm, Lm1)
        Rm1, Lm11 = ['0'] * 4, ['0'] * 4
        DES(m1, k2 if choose1 == 1 else k1, Rm1, Lm11)
        mw = ['0'] * 8
        merge(mw, Lm11, Rm1)
        mw1 = ['0'] * 8
        change(mw, mw1, IP_1)
        result.append(chr(int(''.join(mw1), 2)))

    return ''.join(result)


def on_encrypt():
    mkey = key_entry.get()
    m = plaintext_entry.get()
    if len(mkey) != 10 or len(m) != 8:
        messagebox.showerror("Error", "Key must be 10 bits and plaintext must be 8 bits.")
        return
    result = encrypt(mkey, m)
    result_label.config(text=f"Encrypted Text: {result}")


def on_decrypt():
    mkey = key_entry.get()
    m = ciphertext_entry.get()
    if len(mkey) != 10 or len(m) != 8:
        messagebox.showerror("Error", "Key must be 10 bits and ciphertext must be 8 bits.")
        return
    result = decrypt(mkey, m)
    result_label.config(text=f"Decrypted Text: {result}")


def on_find_key():
    m = plaintext_entry.get()
    mw = ciphertext_entry.get()
    if len(m) != 8 or len(mw) != 8:
        messagebox.showerror("Error", "Plaintext and ciphertext must be 8 bits.")
        return
    result = find_key(m, mw)
    if result:
        result_label.config(text=f"Found Key: {result}")
    else:
        result_label.config(text="No corresponding key found.")


def on_process_text():
    choose1 = int(text_option.get())
    mkey = key_entry.get()
    mm = text_entry.get()
    if len(mkey) != 10:
        messagebox.showerror("Error", "Key must be 10 bits.")
        return
    result = process_text(choose1, mkey, mm)
    result_label.config(text=f"Processed Text: {result}")


# 创建主窗口
root = tk.Tk()
root.title("Simplified DES")

# 创建输入框和标签
tk.Label(root, text="Key (10 bits)").grid(row=0, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=0, column=1)

tk.Label(root, text="Plaintext (8 bits)").grid(row=1, column=0)
plaintext_entry = tk.Entry(root)
plaintext_entry.grid(row=1, column=1)

tk.Label(root, text="Ciphertext (8 bits)").grid(row=2, column=0)
ciphertext_entry = tk.Entry(root)
ciphertext_entry.grid(row=2, column=1)

tk.Label(root, text="Text").grid(row=3, column=0)
text_entry = tk.Entry(root)
text_entry.grid(row=3, column=1)

# 创建选项
text_option = tk.IntVar(value=1)
tk.Radiobutton(root, text="Encryption", variable=text_option, value=1).grid(row=4, column=0)
tk.Radiobutton(root, text="Decryption", variable=text_option, value=2).grid(row=4, column=1)

# 创建按钮
tk.Button(root, text="Encrypt", command=on_encrypt).grid(row=5, column=0)
tk.Button(root, text="Decrypt", command=on_decrypt).grid(row=5, column=1)
tk.Button(root, text="Find Key", command=on_find_key).grid(row=6, column=0)
tk.Button(root, text="Process Text", command=on_process_text).grid(row=6, column=1)

# 创建结果显示标签
result_label = tk.Label(root, text="")
result_label.grid(row=7, column=0, columnspan=2)

# 运行主循环
root.mainloop()
