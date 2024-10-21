import tkinter as tk
from tkinter import messagebox
import time


# S-DES functions
def permute(key, table):
    return ''.join([key[i - 1] for i in table])


def left_shift(key, shift_num):
    return key[shift_num:] + key[:shift_num]


def generate_subkeys(key):
    p10_table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8_table = [6, 3, 7, 4, 8, 5, 10, 9]
    ls1_table = [2, 3, 4, 5, 1]
    ls2_table = [3, 4, 5, 1, 2]

    key = permute(key, p10_table)
    key_left, key_right = key[:5], key[5:]

    key_left = left_shift(key_left, 1)
    key_right = left_shift(key_right, 1)
    k1 = permute(key_left + key_right, p8_table)

    key_left = left_shift(key_left, 1)
    key_right = left_shift(key_right, 1)
    k2 = permute(key_left + key_right, p8_table)

    return k1, k2


def xor(a, b):
    return ''.join(['1' if a[i] != b[i] else '0' for i in range(len(a))])


def sbox_lookup(sbox, bits):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1:3], 2)
    return '{0:02b}'.format(sbox[row][col])


def F_function(block, subkey):
    ep_box = [4, 1, 2, 3, 2, 3, 4, 1]
    s0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    s1 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
    sp_box = [2, 4, 3, 1]

    expanded_block = permute(block, ep_box)
    xored_block = xor(expanded_block, subkey)
    left_sbox_output = sbox_lookup(s0, xored_block[:4])
    right_sbox_output = sbox_lookup(s1, xored_block[4:])
    combined_output = left_sbox_output + right_sbox_output
    return permute(combined_output, sp_box)


def encrypt(plaintext, key):
    ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv_table = [4, 1, 3, 5, 7, 2, 8, 6]

    k1, k2 = generate_subkeys(key)
    plaintext = permute(plaintext, ip_table)
    left, right = plaintext[:4], plaintext[4:]

    temp = F_function(right, k1)
    left = xor(left, temp)

    right, left = left, right

    temp = F_function(right, k2)
    left = xor(left, temp)

    ciphertext = permute(left + right, ip_inv_table)
    return ciphertext


def decrypt(ciphertext, key):
    ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv_table = [4, 1, 3, 5, 7, 2, 8, 6]

    k1, k2 = generate_subkeys(key)
    ciphertext = permute(ciphertext, ip_table)
    left, right = ciphertext[:4], ciphertext[4:]

    temp = F_function(right, k2)
    left = xor(left, temp)

    right, left = left, right

    temp = F_function(right, k1)
    left = xor(left, temp)

    plaintext = permute(left + right, ip_inv_table)
    return plaintext


# ASCII string handling
def ascii_to_bin(ascii_str):
    return ''.join(format(ord(char), '08b') for char in ascii_str)


def bin_to_ascii(bin_str):
    return ''.join(chr(int(bin_str[i:i + 8], 2)) for i in range(0, len(bin_str), 8))


def encrypt_ascii(plaintext, key):
    binary_plaintext = ascii_to_bin(plaintext)
    ciphertext = ''
    for i in range(0, len(binary_plaintext), 8):
        block = binary_plaintext[i:i + 8]
        ciphertext += encrypt(block, key)
    return ciphertext


def decrypt_ascii(ciphertext, key):
    plaintext = ''
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        plaintext += decrypt(block, key)
    return bin_to_ascii(plaintext)


# Brute force attack
def brute_force(ciphertext, known_plaintext):
    start_time = time.time()
    for key in range(2048):
        key_bin = format(key, '010b')
        decrypted_text = decrypt_ascii(ciphertext, key_bin)
        if decrypted_text == known_plaintext:
            end_time = time.time()
            time_taken = end_time - start_time
            return key_bin, time_taken
    return None, None


# Closed test
def closed_test(ciphertext, known_plaintext):
    keys = []
    start_time = time.time()
    for key in range(1024):
        key_bin = format(key, '010b')
        decrypted_text = decrypt_ascii(ciphertext, key_bin)
        if decrypted_text == known_plaintext:
            keys.append(key_bin)
    end_time = time.time()
    time_taken = end_time - start_time
    return keys, time_taken


# GUI
def gui():
    def on_encrypt():
        plaintext = txt_input.get().strip()
        key = key_input.get().strip()
        if len(key) == 10:
            try:
                ciphertext = encrypt(plaintext, key)
                txt_output.delete(0, tk.END)
                txt_output.insert(0, ciphertext)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please enter a valid 10-bit key")

    def on_decrypt():
        ciphertext = txt_input.get().strip()
        key = key_input.get().strip()
        if len(key) == 10:
            try:
                plaintext = decrypt(ciphertext, key)
                txt_output.delete(0, tk.END)
                txt_output.insert(0, plaintext)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please enter a valid 10-bit key")

    def on_brute_force():
        ciphertext = txt_input.get().strip()
        known_plaintext = known_plaintext_input.get().strip()
        if len(ciphertext) % 8 != 0 or len(known_plaintext) % 8 != 0:
            messagebox.showerror("Error", "Invalid input lengths")
            return

        key, time_taken = brute_force(ciphertext, known_plaintext)
        if key:
            messagebox.showinfo("Brute Force Result", f"Key found: {key}\nTime taken: {time_taken:.2f} seconds")
        else:
            messagebox.showerror("Brute Force Result", "Key not found")

    def on_closed_test():
        ciphertext = txt_input.get().strip()
        known_plaintext = known_plaintext_input.get().strip()
        if len(ciphertext) % 8 != 0 or len(known_plaintext) % 8 != 0:
            messagebox.showerror("Error", "Invalid input lengths")
            return

        keys, time_taken = closed_test(ciphertext, known_plaintext)
        if keys:
            result = "\n".join(keys)
            messagebox.showinfo("Closed Test Result", f"Keys found:\n{result}\nTime taken: {time_taken:.2f} seconds")
        else:
            messagebox.showerror("Closed Test Result", "No keys found")

    root = tk.Tk()
    root.title("S-DES Encryption/Decryption and Analysis")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    tk.Label(frame, text="Input:").grid(row=0, column=0, padx=10, pady=5)
    txt_input = tk.Entry(frame, width=50)
    txt_input.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(frame, text="Key (10-bit):").grid(row=1, column=0, padx=10, pady=5)
    key_input = tk.Entry(frame, width=10)
    key_input.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(frame, text="Known Plaintext:").grid(row=2, column=0, padx=10, pady=5)
    known_plaintext_input = tk.Entry(frame, width=50)
    known_plaintext_input.grid(row=2, column=1, padx=10, pady=5)

    btn_encrypt = tk.Button(frame, text="Encrypt", command=on_encrypt)
    btn_encrypt.grid(row=3, column=0, padx=10, pady=5)

    btn_decrypt = tk.Button(frame, text="Decrypt", command=on_decrypt)
    btn_decrypt.grid(row=3, column=1, padx=10, pady=5)

    btn_brute_force = tk.Button(frame, text="Brute Force", command=on_brute_force)
    btn_brute_force.grid(row=3, column=2, padx=10, pady=5)

    btn_closed_test = tk.Button(frame, text="Closed Test", command=on_closed_test)
    btn_closed_test.grid(row=3, column=3, padx=10, pady=5)

    tk.Label(frame, text="Output:").grid(row=4, column=0, padx=10, pady=5)
    txt_output = tk.Entry(frame, width=50)
    txt_output.grid(row=4, column=1, padx=10, pady=5)

    root.mainloop()


if __name__ == "__main__":
    gui()
