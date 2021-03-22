import logging
import os
import socket
import ssl
import threading
import mariadb
from Crypto.Random import get_random_bytes


def serverMain():
    print("Starting It's so easy Server...")
    logging.basicConfig(filename="itsSoEasyServer.log", level=logging.DEBUG)
    logging.info('Initialized Logging')
    # try:
    newUserKey, initVector = generateClientKey()
    testUser = os.urandom(16).hex()
    setClientAndKeyToDB(testUser, newUserKey, initVector)
    setClientPayed(testUser)
    key = getClientKeyFromDB(testUser)
    print("Test-Users Key and IV: " + str(key))
    removeClientAndKeyFromDB(testUser)
    logging.info("Initialized Database and connection successful")
    print("Database successful initialized")
    # except:
    #    logging.fatal("Error encountered while connecting to database\n Is the MariaDB Server started?")
    runConnection()


def connectDB():
    try:
        conn = mariadb.connect(
            user="itsSoEasy",
            password="toor",
            host="host-ip",
            port=3306,
            database="itsSoEasy"
        )
        return conn

        # print(cur.execute("SELECT * FROM clients"))
    except mariadb.Error as e:
        logging.fatal("Error connecting to MariaDB Platform: %s" % e)


# correct way to generate keys?
def generateClientKey():
    key = get_random_bytes(32).hex()
    iv = get_random_bytes(16).hex()
    return key, iv


def setClientAndKeyToDB(user, key, iv):
    conn = connectDB()
    cur = conn.cursor()
    cur.execute("INSERT INTO clients (userIdentity, userKey, userIV, additional) VALUES (?, ?, ?, ?)",
                (user, key, iv, "False"))
    conn.commit()
    conn.close()
    return


def getClientKeyFromDB(user):
    key, iv = "", ""
    conn = connectDB()
    cur = conn.cursor()
    cur.execute("SELECT userKey, userIV FROM clients WHERE userIdentity=? AND additional=?", (user, "True"))
    client = cur.fetchall()
    conn.close()
    for cont, cont1 in client:
        key, iv = cont, cont1
    print(key + " " + iv)
    return key, iv


def removeClientAndKeyFromDB(user):
    conn = connectDB()
    cur = conn.cursor()
    cur.execute("DELETE FROM clients WHERE userIdentity=?", (user,))
    conn.commit()
    conn.close()
    return True


def setClientPayed(user):
    conn = connectDB()
    cur = conn.cursor()
    cur.execute("UPDATE clients SET additional=? WHERE userIdentity=?", ("True", user))
    conn.commit()
    conn.close()
    return True


def handleClient(clientConnStream):
    # try:
    # print("handleClient")
    data = clientConnStream.recv(1024).decode()
    print(data)
    mode, userIdentity, additional = data.split("-!-")
    print(mode), print(userIdentity), print(additional)
    if int(mode) == 0:
        data = "OK"
        clientConnStream.send(data.encode())
        if not getClientKeyFromDB(userIdentity):
            # print("0-!-True")
            clientConnStream.send("0-!-True".encode())
        else:
            clientConnStream.send("0-!-False".encode())

    elif int(mode) == 1:
        newUserKey, initVector = generateClientKey()
        setClientAndKeyToDB(str(userIdentity), newUserKey, initVector)
        clientConnStream.send(
            (str(1) + "-!-" + str(userIdentity) + "-!-" + newUserKey + "--KEY-PROCEDURE--" + initVector).encode())

    elif int(mode) == 2:
        setClientPayed(str(userIdentity))
        clientConnStream.send((str(2) + "-!-" + userIdentity + "-!-" + "True").encode())

    elif int(mode) == 3:
        userKey, iVector = getClientKeyFromDB(str(userIdentity))
        clientConnStream.send(
            (str(3) + "-!-" + str(userIdentity) + "-!-" + userKey + "--KEY-PROCEDURE--" + iVector).encode())

    elif int(mode) == 4:
        if removeClientAndKeyFromDB(str(userIdentity)):
            clientConnStream.send((str(4) + "-!-" + "" + "-!-" + "Success").encode())

    # finally:
    clientConnStream.close()
    logging.info("Connection closed")
    print("Connection closed!")
    return


def runConnection():
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('certs/cert.pem', 'certs/key.pem')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        PORT = 6666
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.bind(('0.0.0.0', PORT))
        sock.listen(1)
        print("Server started successful!\nListening on Port: %s\n" % PORT)

        while True:
            try:
                sock = context.wrap_socket(sock, server_side=True)
                conn, addr = sock.accept()
                print("Connected to: " + str(addr))
                logging.info("Connected to: " + str(addr))
                newClient = threading.Thread(target=handleClient, args=(conn,))
                newClient.start()
            except KeyboardInterrupt:
                exit(0)
            except:
                print("Error while connecting")

    finally:
        return


if __name__ == '__main__':
    serverMain()
