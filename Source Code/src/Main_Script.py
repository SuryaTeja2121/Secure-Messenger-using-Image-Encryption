import tkinter as tk
from tkinter.filedialog import *
import tkinter.messagebox
import hashlib

from Cryptodome.Cipher import DES3

import Enc_And_Dec
import os
import send2trash


def pass_alert():
    tkinter.messagebox.showinfo("Password Alert", "Password cannot be empty.")


def wrong_password():
    tkinter.messagebox.showinfo(
        "Incorrect Password", "You have entered a wrong password. Hence, the encrypted file is deleted.")
    send2trash.send2trash("encrypted.enc")
    quit()


def encrypt_AES():
    global file_path_e
    enc_pass_AES = passg.get()
    if enc_pass_AES == "":
        pass_alert()
    else:
        # LOAD THE IMAGE
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        # GENERATE KEY & INITIALIZATION VECTOR
        hash = hashlib.sha256(enc_pass.encode())
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        print("Encoding key is: ", key)

        input_file = open(filename, 'rb')
        input_data = input_file.read()
        input_file.close()
        Enc_And_Dec.enc_image_AES(input_data, key, iv, file_path_e)
        tkinter.messagebox.showinfo("Encryption Alert", "Encryption ended successfully. File stored as: encrypted.enc")


def decrypt_AES():
    global file_path_e
    global enc_pass_AES
    enc_pass_AES = passg.get()
    if enc_pass_AES == "":
        pass_alert()
    else:
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        hash = hashlib.sha256(enc_pass.encode())
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        input_file = open(filename, 'rb')
        input_data = input_file.read()
        input_file.close()
        Enc_And_Dec.dec_image_AES(input_data, key, iv, file_path_e)
        tkinter.messagebox.showinfo("Decryption Alert", "Decryption ended successfully File Stored as: output.png")


def encrypt_Triple_DES():
    global file_path_e
    global enc_pass
    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        # LOAD THE IMAGE
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        # GENERATE KEY & INITIALIZATION VECTOR
        key_hash = hashlib.md5(enc_pass.encode('ascii')).digest()

        # Adjust key parity of generated Hash Key for Final Triple DES Key
        tdes_key = DES3.adjust_key_parity(key_hash)
        print("Encoding key is: ", tdes_key)

        input_file = open(filename, 'rb')
        input_data = input_file.read()
        input_file.close()
        Enc_And_Dec.enc_image_Triple_DES(input_data, tdes_key, file_path_e)
        tkinter.messagebox.showinfo(
            "Encryption Alert", "Encryption ended successfully. The file stored as : 'encrypted.enc'")


def decrypt_Triple_DES():
    global file_path_e
    enc_pass_decrypt = passg.get()
    if enc_pass_decrypt == "":
        pass_alert()

    if enc_pass_decrypt != enc_pass:
        wrong_password()
    else:
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        key_hash = hashlib.md5(enc_pass.encode('ascii')).digest()

        # Adjust key parity of generated Hash Key for Final Triple DES Key
        tdes_key = DES3.adjust_key_parity(key_hash)

        input_file = open(filename, 'rb')
        input_data = input_file.read()
        input_file.close()
        Enc_And_Dec.dec_image_Triple_DES(input_data, tdes_key, file_path_e)
        tkinter.messagebox.showinfo(
            "Decryption Alert", "Decryption successful. File Stored as : Decrypted.jpg")


print("Enter the following choice:")
print("1 : AES")
print("2 : Triple DES")

choice = int(input())

if choice == 1:
    top = tk.Tk()
    top.geometry("600x300")
    top.resizable(0, 0)
    top.title("Team - DYNAMIC DUDES")
    top.configure(bg='white smoke')

    title = "Project - Image Encryption using AES"
    header = "Created by Team - Dynamic Dudes"
    msgtitle = Message(top, text=title, fg="red")
    msgtitle.config(font=('helvetica', 20, 'bold'), width=600)
    msgtitle.pack()
    msgtitle1 = Message(top, text=header, fg="blue")
    msgtitle1.config(font=('helvetica', 14, 'bold'), width=600)
    msgtitle1.pack()

    sp = "---------------------------------------------------------------------"
    sp_title = Message(top, text=sp, fg="purple")
    sp_title.config(font=('arial', 12, 'bold'), width=650)
    sp_title.pack()

    passlabel = Label(
        top, text="Enter   Encryption  (or)  Decryption   Key:", fg="brown", font=('Helvetica', 12, 'bold'))
    passlabel.pack()
    passg = Entry(top, show="*", width=40)
    passg.config(highlightthickness=1.5,
                 highlightbackground="brown", font=('arial', 16))
    passg.pack()

    encrypt = Button(top, text="Encrypt", fg='green', font='sans 16 bold',
                     width=15, height=2, command=encrypt_AES(), relief="solid")
    encrypt.pack(side=LEFT)
    decrypt = Button(top, text="Decrypt", fg="red", font='sans 16 bold',
                     width=15, height=2, command=decrypt_AES(), relief="solid")
    decrypt.pack(side=RIGHT)
    top.mainloop()

elif choice == 2:
    top = tk.Tk()
    top.geometry("600x300")
    top.resizable(0, 0)
    top.title("Team - DYNAMIC DUDES")
    top.configure(bg='white smoke')

    title = "Project - Image Encryption using Triple DES"
    header = "Created by Team - Dynamic Dudes"
    msgtitle = Message(top, text=title, fg="red")
    msgtitle.config(font=('helvetica', 20, 'bold'), width=600)
    msgtitle.pack()
    msgtitle1 = Message(top, text=header, fg="blue")
    msgtitle1.config(font=('helvetica', 14, 'bold'), width=600)
    msgtitle1.pack()

    sp = "---------------------------------------------------------------------"
    sp_title = Message(top, text=sp, fg="purple")
    sp_title.config(font=('arial', 12, 'bold'), width=650)
    sp_title.pack()

    passlabel = Label(
        top, text="Enter   Encryption  (or)  Decryption   Key:", fg="brown", font=('Helvetica', 12, 'bold'))
    passlabel.pack()
    passg = Entry(top, show="*", width=40)
    passg.config(highlightthickness=1.5,
                 highlightbackground="brown", font=('arial', 16))
    passg.pack()

    encrypt = Button(top, text="Encrypt", fg='green', font='sans 16 bold',
                     width=15, height=2, command=encrypt_Triple_DES, relief="solid")
    encrypt.pack(side=LEFT)
    decrypt = Button(top, text="Decrypt", fg="red", font='sans 16 bold',
                     width=15, height=2, command=decrypt_Triple_DES, relief="solid")
    decrypt.pack(side=RIGHT)
    top.mainloop()
