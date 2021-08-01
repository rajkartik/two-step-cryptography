from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
import key_gen

import time
import collections
import string
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import random, sys
from Crypto.Util import number
import base64 #This module provides data encoding and decoding as specified in RFC 3548.
import os #The OS module in Python provides a way of using operating system dependent functionality.
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sym_key_gen
import SymmetricEncryption
root = Tk()
root.geometry('800x520')
root.title('Encryption-Decryption')
#root.resizable(width=False,height=False)
root.configure(background="lightgreen")
msg=str()

def about_prog(event=None):
    messagebox.showwarning("About","THIS APP IS MADE BY KARTIK AND ASLAM")

def sym_prog(event=None):
    print(sym_key_gen.random_key)
    print("printing modified symmetric key: ",SymmetricEncryption.key)
    messagebox.showwarning("symmetric","symmetric key is generated")

def asym_prog(event=None):
    key_gen.main()
    messagebox.showwarning("Asymmetric key","keys generated")

def quit_app(event="<Button-1>", name=root):
    name.destroy()
tail=str()
def openfile(event=None):
	root.filepath = askopenfilename()
	openfile.head, openfile.tail = os.path.split(root.filepath)   #extracting filename from file path
	return openfile.tail


def symmetric_encrypt(event=None):
	fileObj = open(openfile.tail,'r')
	start = time.time()
	content = fileObj.read()
	msg = bytes(content, 'utf-8')
	token = SymmetricEncryption.f.encrypt(msg)
	end = time.time()
	symmetric_encrypt.calc_time_enc = end - start
	messagebox.showwarning("encrypted","encryption complete")
	return symmetric_encrypt.calc_time_enc


def symmetric_decrypt(event=None):
	fileObj = open(openfile.tail, 'r')
	content = fileObj.read()
	msg = bytes(content, 'utf-8')
	token = SymmetricEncryption.f.encrypt(msg)
	with open("enc_fil1.txt", 'w') as file:
		file.write(str(token))
		file.close()
	start = time.time()
	result = SymmetricEncryption.f.decrypt(token)
	with open("dec_file.txt", 'w') as file:
		file.write(str(result))
		file.close()
	end = time.time()
	symmetric_decrypt.calc_time_dec = end - start

	messagebox.showwarning("encrypted","decryption complete")
	return symmetric_decrypt.calc_time_dec

# ASYMMETRIC ENCRYPTION OF KEY i.e. CIPHER KEY
def assym_key_enc():
    publicvalue = number.getRandomRange(2 ** (128 - 1), 2 ** (128))
    f = Fernet(SymmetricEncryption.key)

    KeyMsg = str(publicvalue).encode('utf-8')
    assym_key_enc.tokenMsg = f.encrypt(KeyMsg)

    #PRINTING CIPHER-TEXT
    print("\nPRINTING CIPHER-KEY::")
    print(assym_key_enc.tokenMsg)



    # DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

    # Variables Used
    sharedPrime = 23  # p i.e. public key
    sharedBase = 5    # g i.e. public key

    aliceSecret = random.randint(1,101)  # Private Key Selected,a
    bobSecret = random.randint(1,101)  # Private Key Selected,b

    # Begin
    print("Publicly Shared Variables:")
    print("    Publicly Shared Prime: ", sharedPrime)
    print("    Publicly Shared Base:  ", sharedBase)

    # Alice Sends Bob A = g^a mod p
    A = (sharedBase ** aliceSecret) % sharedPrime
    print("\n  Alice Sends Over Public Chanel: ", A)

    # Bob Sends Alice B = g^b mod p
    B = (sharedBase ** bobSecret) % sharedPrime
    print("\n Bob Sends Over Public Chanel: ", B )

    print("\n------------\n")
    print("Privately Calculated Shared Secret:")
    # Alice Computes Shared Secret: s = B^a mod p
    assym_key_enc.aliceSharedSecret = (B ** aliceSecret) % sharedPrime
    print("    Alice Shared Secret: ", assym_key_enc.aliceSharedSecret)

    # Bob Computes Shared Secret: s = A^b mod p
    bobSharedSecret = (A ** bobSecret) % sharedPrime
    #print("    Bob Shared Secret: ", bobSharedSecret)

    # ENCRYPTION USING DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

    #password = b"password"
    #Password is the master password from which a derived key is generated
    #password = SymmetricKeyGeneration.random_key
    password = str(assym_key_enc.aliceSharedSecret).encode('utf-8')

    #print("password=",password)

    salt = os.urandom(8)
    """(Password-Based Key Derivation Function 2) are key derivation functions with a sliding computational cost, 
    aimed to reduce the vulnerability of encrypted keys to brute force attacks. 
    """
    #PBKDF2 applies a pseudorandom function, such as hash-based message authentication code (HMAC)
    #kdf is the generated derived key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #PRF=pseudo random function
        length=32,#length=32 is fixed . #desired bit-length of the derived key
        salt=salt, #salt is a sequence of bits, known as a cryptographic salt
        iterations=100000,#number of iterations desired
        backend=default_backend()
        )
    assym_key_enc.key = base64.urlsafe_b64encode(kdf.derive(password))

    #PRINTING SYMMETRIC KEY
    #print("\nPRINTING SYMMETRIC KEY::")
    #print(key)

    #with open("SymmetricKey.txt",'w') as file:
    #file.write(key)
    #file.close()
    f = Fernet(assym_key_enc.key)

    msg =  str(assym_key_enc.aliceSharedSecret).encode('utf-8')
    token = f.encrypt(msg)

    #PRINTING CIPHER-TEXT
    #print("\nPRINTING CIPHER-TEXT::")
    #print(token)


# DECRYPTION USING DIFFIE HELLMAN KEY EXCHANGE ALGORITHM
def assym_key_dec(event=None):
    f = Fernet(assym_key_enc.key)
    msg = str(assym_key_enc.aliceSharedSecret).encode('utf-8')
    token = f.encrypt(msg)
    result=f.decrypt(token)

    #PRINTING DECRYPTED TEXT
    #print("\nPRINTING DECRYPTED KEY::")
    #print(result)

    # ASYMMETRIC DECRYPTION OF CIPHER KEY

    resultMsg=assym_key_enc.tokenMsg.decode('utf-8')
    #PRINTING DECRYPTED TEXT
    print("\nPRINTING DECRYPTED SYMMETRIC KEY USING ASYMMETRIC KEY USING DEFFIE HELLMAN::")
    print(resultMsg)
    print("\nPRINTING DECRYPTED SYMMETRIC KEY USING ASYMMETRIC KEY::")
    print(SymmetricEncryption.key)


def count_letters(filename, case_sensitive=False):
    with open(filename, 'r') as f:
        original_text = f.read()
    if case_sensitive:
        alphabet = string.ascii_letters
        text = original_text
    else:
        alphabet = string.ascii_lowercase + string.digits + string.punctuation
        text = original_text.lower()
    alphabet_set = set(alphabet)
    count_letters.counts = collections.Counter(c for c in text if c in alphabet_set)
    # counts = collections.Counter(c for c in text if c in alphabet )

    # print("total:", sum(counts.values()))
    return count_letters.counts

#symmetric_encrypt()
#symmetric_decrypt()
def cal():

    cal.b = symmetric_encrypt.calc_time_enc
    cal.c = symmetric_decrypt.calc_time_dec
    cal.a = dict()
    cal.d=dict()
    cal.a = count_letters(openfile.tail)
    cal.no_of_char = sum(a.values())
    cal.d=count_letters('enc_fil1.txt')
    cal.no_of_char1=sum(d.values())

def graph_file_enc():
    data = str(cal.no_of_char) + "," + str(int(float(cal.b) * 1000))

    with open("SymmetricKey1.txt", 'a') as file:
        file.write(data + '\n')
        file.close()

def graph_file_dec():
    data = str(cal.no_of_char1) + "," + str(int(float(cal.c) * 1000))

    with open("SymmetricKey2.txt", 'a') as file:
        file.write(data + '\n')
        file.close()

#graph_file_enc()
#graph_file_dec()

fig = plt.figure()

def animate(i):
    pullData = open("SymmetricKey1.txt", "r").read()
    dataArray = pullData.split('\n')
    ax1 = fig.add_subplot(1, 1, 1)
    # print(dataArray)
    xar = []
    yar = []
    for eachLine in dataArray:
        if len(eachLine) > 1:
            x, y = eachLine.split(',')
            xar.append(int(x))
            yar.append(int(y))
    ax1.clear()
    ax1.plot(xar, yar)


def plot():
    ani = animation.FuncAnimation(fig, animate, interval=1000)
    plt.show()


menubar = Menu(root)
#File menu
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="New", accelerator='Ctrl+N', compound=LEFT, underline=0)
filemenu.add_command(label="choose", accelerator='Ctrl+O', compound=LEFT, underline=0,command=openfile)
filemenu.add_command(label="Exit", accelerator='Alt+F4',command=quit_app)
menubar.add_cascade(label="File", menu=filemenu)

#Edit menu
editmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Edit", menu=editmenu)
editmenu.add_separator()
editmenu.add_command(label="Cut", compound=LEFT, accelerator='Ctrl+X')
editmenu.add_command(label="Copy", compound=LEFT,  accelerator='Ctrl+C')
editmenu.add_command(labe="Paste", compound=LEFT,  accelerator='Ctrl+V')
editmenu.add_separator()

#View menu

viewmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="View", menu=viewmenu)
#we define a color scheme dictionary containg name and color code as key value pair

#About menu
aboutmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="About",menu=aboutmenu)
aboutmenu.add_command(label="About",command=about_prog)
aboutmenu.add_command(label="Help")

root.config(menu=menubar)


#################################################



ttk.Label(root, text="Select a file", font=("courier new", 15, 'bold')).grid(row=3,column=0,padx=10,sticky=W)
ttk.Label(root, text="Generate Asymmetric Key", font=("courier new", 15, 'bold')).grid(row=1, column=0, padx=6, sticky=W)
ttk.Label(root, text="Generate Symmetric Key ", font=("courier new", 15, 'bold')).grid(row=2, column=0, padx=6, sticky=W)
b3=Button(root,text="Browse",width=10,bg="coral",fg='brown',command=openfile)

b1=Button(root,text="Gen_Ass_Key ",width=10,bg="coral",command=asym_prog)
ttk.Label(root, text="WELCOME TO THIS PROJECT", font=("comic sans ms", 25, 'bold')).grid(row=0, column=2, padx=6, sticky=N)
b2=Button(root, text="Gen_Sym_Key", width=10, bg="coral",command=sym_prog)
ttk.Label(root, text="Click to Encrypt File ", font=("courier new", 15, 'bold')).grid(row=4, column=0, padx=6, sticky=W)
ttk.Label(root, text="Click to Encrypt Symmetric key", font=("courier new", 15, 'bold ')).grid(row=5, column=0, padx=6, sticky=W)
ttk.Label(root, text="Click to Decrypt Symmetric key", font=("courier new", 15, 'bold ')).grid(row=6, column=0, padx=6, sticky=W)
ttk.Label(root, text="Click to Decrypt File", font=("courier new", 15, 'bold ')).grid(row=7, column=0, padx=6, sticky=W)

title = ttk.Label(root, text="Performance Measure_Enc", font=("comic sans ms", 15, 'bold'))
b4=Button(root,text="ENCRYPT",width=10,bg="coral",command=symmetric_encrypt)
b5=Button(root, text="Encrypt key", width=10, bg="coral",command=assym_key_enc)
b6=Button(root, text="Decrypt key", width=10, bg="coral",command=assym_key_dec)
b7=Button(root, text="DECRYPT", width=10, bg="coral",command=symmetric_decrypt)

b8=Button(root, text="DRAW GRAPH ", width=10, command=plot)
b10=Button(root, text="CANCEL ", width=10, command=quit_app, bg="red")
title.grid(row=8,column=0,padx=0,pady=0,sticky=W)

b1.grid(row=1,column=2,padx=6,pady=10)
b2.grid(row=2,column=2,padx=6,pady=10)
b3.grid(row=3,column=2,padx=6,pady=10)
b4.grid(row=4,column=2,padx=6,pady=10)
b5.grid(row=5,column=2,padx=6,pady=10)
b10.grid(row=15,column=19,padx=6,pady=10)
b6.grid(row=6,column=2,padx=6,pady=10)
b7.grid(row=7,column=2,padx=6,pady=10)
b8.grid(row=8,column=2,padx=6,pady=10)

root.mainloop()

#print(tail)