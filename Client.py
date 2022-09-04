#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
from multiprocessing import Queue
import pickle

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet


class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def __init__(self, queue):
        self.queue = queue
        super().__init__()

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    # print("trying to receive")
                    s = item.recv(1024)
                    if s != '':
                        chunk = s
                        self.queue.put(chunk)
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"
    
    def __init__(self, queue):
        self.queue = queue
        super().__init__()

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            # host = input("Enter the server IP \n>>")
            # port = int(input("Enter the server Destination Port\n>>"))
            host = "localhost"
            port = 5535
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        #print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server(self.queue)
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()

        #Geração e envio da chave pública
        key = RSA.generate(2048)
        self.private_key_export = key.export_key('PEM')
        self.public_key_export = key.publickey().exportKey('PEM')

        to_send = {}
        to_send["PUB"] = self.public_key_export
        dataString = pickle.dumps(to_send)
        self.client(host, port, dataString)

        #Geração da chave simétrica
        # self.sym_key = Fernet.generate_key()
        self.sym_key = None

        printIn = True
        while 1:
            if printIn:
                print(">>", end="")
                sys.stdout.flush()
                printIn = False
            
            read, write, err = select.select([sys.stdin.fileno()], [], [], 1)
            for item in read:
                msg = input()
                if msg == 'exit':
                    break
                if msg == '':
                    continue
                if self.sym_key is None:
                    print("Chave simétrica ainda não definida - não existem outros usuários conectados")
                    printIn = True
                    continue

                msg = user_name + ': ' + msg
                f = Fernet(self.sym_key)
                encrypted = f.encrypt(msg.encode())
                to_send = {}
                to_send["MSG"] = encrypted
                dataString = pickle.dumps(to_send)
                self.client(host, port, dataString)
                printIn = True

            while True:
                try:
                    msg = self.queue.get(block=False)
                    try:
                        data = pickle.loads(msg)
                        #Ao receber uma chave publica, responde com a chave simétrica
                        #criptografada
                        if "PUB" in data:
                            rsa_public_key = RSA.importKey(data["PUB"])
                            rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
                            if self.sym_key is None:
                                print("Gerando chave simétrica")
                                self.sym_key = Fernet.generate_key()

                            encrypted_sym_key = rsa_public_key.encrypt(self.sym_key)
                            to_send = {}
                            to_send["SYM"] = encrypted_sym_key
                            dataString = pickle.dumps(to_send)
                            self.client(host, port, dataString)
                            print("Chave publica recebida, respondendo com a chave simetrica")
                        
                        if "SYM" in data:
                            rsa_private_key = RSA.importKey(self.private_key_export)
                            rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
                            decrypted_text = rsa_private_key.decrypt(data["SYM"])
                            print("Chave simétrica recebida: ", decrypted_text)
                            if self.sym_key is None:
                                self.sym_key = decrypted_text
                            elif self.sym_key != decrypted_text:
                                print("ERRO: cliente já tinha chave simétrica e recebeu uma diferente")
                        
                        if "MSG" in data:
                            f = Fernet(self.sym_key)
                            decrypted = f.decrypt(data["MSG"])
                            print(decrypted.decode())
                    except:
                        print(msg.decode())
                except:
                    break
        return (1)


if __name__ == '__main__':
    print("Starting client")
    q = Queue()
    cli = Client(q)
    cli.start()