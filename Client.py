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
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet

pubcode = SHA256.new("PUB".encode("UTF-8")).hexdigest()
symcode = SHA256.new("SYM".encode("UTF-8")).hexdigest()
hashcode = SHA256.new("HASH".encode("UTF-8")).hexdigest()
signcode = SHA256.new("SIGN".encode("UTF-8")).hexdigest()
msgcode = SHA256.new("MSG".encode("UTF-8")).hexdigest()


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
                    s = item.recv(2048)
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
        # print("Connected\n")
        #user_name = input("Enter the User Name to be Used\n>>")
        user_name = "Allan"
        receive = self.sock
        time.sleep(1)
        srv = Server(self.queue)
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()

        # Geração e envio da chave pública
        self.key_pair = RSA.generate(2048)
        self.private_key_export = self.key_pair.export_key('PEM')
        self.public_key_export = self.key_pair.publickey().exportKey('PEM')

        to_send = {}
        to_send[pubcode] = self.public_key_export
        dataString = pickle.dumps(to_send)
        self.client(host, port, dataString)

        self.chave_simetrica = None

        printIn = True
        exit = False

        while not exit:
            if printIn:
                print(">>", end="")
                sys.stdout.flush()
                printIn = False

            read, write, err = select.select([sys.stdin.fileno()], [], [], 1)
            for item in read:
                msg = input()
                if msg == 'exit':
                    exit = True
                    break
                if msg == '':
                    continue
                if self.chave_simetrica is None:
                    print(
                        "Chave simétrica ainda não definida - não existem outros usuários conectados")
                    printIn = True
                    continue

                msg = user_name + ': ' + msg
                f = Fernet(self.chave_simetrica)
                mensagem_criptografada = f.encrypt(msg.encode())
                hash_mensagem = SHA256.new(msg.encode("UTF-8")).hexdigest()

                to_send = {}
                to_send[msgcode] = mensagem_criptografada
                to_send[hashcode] = hash_mensagem
                dataString = pickle.dumps(to_send)
                self.client(host, port, dataString)
                printIn = True

            while True:
                try:
                    msg = self.queue.get(block=False)
                    try:
                        data = pickle.loads(msg)
                    except Exception as e:
                        print("ERRO: não foi recebido um objeto pickle", e)
                        continue

                    # Ao receber uma chave publica, responde com a chave simétrica
                    # criptografada, assinatura digital da hash da chave e sua chave publica
                    if pubcode in data and symcode not in data:
                        # Mensagem sem chave simétrica representa o pedido de envio da chave simétrica
                        rsa_public_key = RSA.importKey(data[pubcode])
                        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
                        if self.chave_simetrica is None:
                            print("Gerando chave simétrica")
                            self.chave_simetrica = Fernet.generate_key()

                        chave_simetrica_criptografada = rsa_public_key.encrypt(
                            self.chave_simetrica)

                        hash_chave_simetrica = SHA256.new(self.chave_simetrica)
                        signer = PKCS115_SigScheme(self.key_pair)
                        assinatura = signer.sign(hash_chave_simetrica)

                        to_send = {}
                        to_send[symcode] = chave_simetrica_criptografada
                        to_send[signcode] = assinatura
                        to_send[pubcode] = self.public_key_export
                        dataString = pickle.dumps(to_send)
                        self.client(host, port, dataString)
                        print(
                            "Chave publica recebida, respondendo com a chave simetrica, assinatura e chave publica")

                    if symcode in data:  # Recebimento da chave simétrica, chave pública da origem e assinatura digital
                        if signcode not in data:
                            print(
                                "ERRO: assinatura digital da hash não foi enviada junto com a chave simétrica")
                            exit(0)

                        rsa_private_key = RSA.importKey(
                            self.private_key_export)
                        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
                        chave_simetrica_recebida = rsa_private_key.decrypt(
                            data[symcode])

                        pub_key_origem = RSA.importKey(data[pubcode])
                        hash_chave_simetrica = SHA256.new(
                            chave_simetrica_recebida)
                        verifier = PKCS115_SigScheme(pub_key_origem)

                        try:
                            verifier.verify(
                                hash_chave_simetrica, data[signcode])
                        except:
                            print("Assinatura digital inválida")
                            exit(0)

                        if self.chave_simetrica is None:
                            self.chave_simetrica = chave_simetrica_recebida
                        elif self.chave_simetrica != chave_simetrica_recebida:
                            print(
                                "ERRO: cliente já tinha chave simétrica e recebeu uma diferente")
                            if chave_simetrica_recebida > self.chave_simetrica:
                                self.chave_simetrica = chave_simetrica_recebida
                        print("Utilizando a chave: ", self.chave_simetrica)

                    if msgcode in data:  # Recebimento de mensagens, deve conter a hash
                        if hashcode not in data:
                            print("ERRO: mensagem sem hash")
                            exit(0)

                        f = Fernet(self.chave_simetrica)
                        mensagem_recebida = f.decrypt(data[msgcode])
                        hash_mensagem_recebida = SHA256.new(
                            mensagem_recebida).hexdigest()
                        if hash_mensagem_recebida != data[hashcode]:
                            print("ERRO: hash incorreta")
                            exit(0)

                        print(mensagem_recebida.decode())

                except:  # Fila de recebimento vazia
                    break

        return (1)


if __name__ == '__main__':
    print("Starting client")
    q = Queue()
    cli = Client(q)
    cli.start()
