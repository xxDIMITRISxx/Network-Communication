from os import times
import socket
import select
import os.path
import json
import sys
import base64
import zlib
import datetime
from binascii import crc32
from datetime import timezone
import hashlib
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Random import get_random_bytes
import time

#Global variables
FORMAT = 'utf-8'

''' Ask the user for a port on the machine to act for incoming connections 
    parameter info:
        Extra information to add in the print line
'''
def askPort(info):
    try:
        while True:
            port = int(input(f"Give port number {info} (1024-65535) :"))
            if port in range(1024, 65536):
                break
        return port
    except:
        print("An exception occured")

''' Ask the user for a file which contains the directory of individuals to contact '''
def askFileDirectory():
    while True:
        file = input("Give a file which contains the directory of individuals to contact : ")
        file_exists = os.path.exists(file)
        if file_exists:
            break
        else:
            print("No such file exists!")
    return file

""" Load the directories from a file """
def loadDirectories(file):
    f = open(file, 'r')
    directories = []
    for line in f:
        directory = json.loads(line)
        directories.append(directory)
    return directories


""" Creating json serialization for each directory """
def jsonSerialization(directories):
    json_list = []
    for directory in directories:
        json_list.append(json.dumps(directory))
    return json_list

""" loading the json serializations """
def jsonLoad(jsonDirectories):
    directories = []
    for directory in jsonDirectories:
        directories.append(json.loads(directory))
    return directories

""" returns the timestamp """
def utcTimestamp():
    dt = datetime.datetime.now(timezone.utc)
    utc_time = dt.replace(tzinfo=timezone.utc)
    utc_timestamp = str(utc_time.timestamp())
    return utc_timestamp

""" takes the message as input and return the crc value """
def crcVal(message):
    return zlib.crc32(message.encode(FORMAT))

""" takes a pdu and log it into the file """
def logging(pdu):
    file = open('logging.txt', 'a')
    pdus = pdu.decode(FORMAT)
    file.write(pdus)
    file.write("\n")
    file.close()

""" ---------------------------DH ---------------------------------"""
# Dan's Code

class DiffieHellman:
    ''' Class for Diffie Hellman key exchange protocol '''

    def __init__(self) -> None:
        # RFC 3526 - More Modular Exponential (MODP) Diffie-Hellman groups for 
        # Using the default group 14
        self.__prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.__generator = 2

        self.__priv_key = int.from_bytes(os.urandom(32), byteorder=sys.byteorder, signed=False)
        self.__pub_key = pow(self.__generator, self.__priv_key, self.__prime)
        self.__shared_secret = 0

    @property
    def private_key(self):
        ''' Returns the private key '''
        return self.__priv_key

    @property
    def private_key_bytes(self):
        ''' Retursn the private key as a bytes object '''
        return self.__priv_key.to_bytes(32, sys.byteorder)

    @property
    def public_key(self):
        ''' Returns the public key '''
        return self.__pub_key

    @property
    def public_key_bytes(self):
        ''' Returned shte public key as a bytes object '''

        key_bl = self.__pub_key.bit_length()
        offset = key_bl % 8
        if offset != 0:
            offset = 8 - offset
        key_bl += offset
        key_bl = int(key_bl / 8)
        return self.__pub_key.to_bytes(key_bl, sys.byteorder)

    @property
    def shared_secret(self):
        ''' The generated shared secret'''
        return self.__shared_secret

    @property
    def shared_secret_bytes(self):
        ''' The generated shared secret as bytes object'''
        return self.__shared_secret.to_bytes(32, sys.byteorder)

    def rekey(self):
        ''' Re-generates the private key and then regens the public key '''
        self.__priv_key = int.from_bytes(os.urandom(32), byteorder=sys.byteorder, signed=False)
        self.__pub_key = pow(self.__generator, self.__priv_key, self.__prime)
        self.__shared_secret = 0

    def validate_public_key(self, pub_key=None):
        ''' Validates a public key as per NIST SP800-56'''
        # check if the other public key is valid based on NIST SP800-56
        # 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2
        if pub_key == None:
            pub_key = self.public_key
        if pub_key >= 2 and pub_key <= self.__prime - 2:
            if pow(pub_key, (self.__prime - 1) // 2, self.__prime) == 1:
                return True
        return False

    def generate_shared_secret(self, other_pub_key):
        ''' Generates a shared secret with someone elese '''
        if self.validate_public_key(other_pub_key):
            ss_key = pow(other_pub_key, self.__priv_key, self.__prime)
            ss_key_bl = ss_key.bit_length()
            offset = ss_key_bl % 8
            if offset != 0:
                offset = 8 - offset
            ss_key_bl += offset
            ss_key_bl = int(ss_key_bl / 8)
            ss_key_bytes = ss_key.to_bytes(int(ss_key_bl), sys.byteorder)

            self.__shared_secret = hashlib.sha256(ss_key_bytes).digest()
            self.__shared_secret = int.from_bytes(self.__shared_secret, sys.byteorder)
            return self.__shared_secret
        else:
            raise Exception("Bad public key from the other party")

    def __str__(self):
        """ turn it in to a string"""
        out_str = "LU_DH: \n\tPriv: "
        out_str = out_str + f'{self.__priv_key:x}'
        out_str = out_str + "\n\tPub: "
        out_str = out_str + f'{self.__pub_key:x}'
        out_str = out_str + "\n\tShared: "
        out_str = out_str + f'{self.__shared_secret:x}'
        return out_str


""" -------------------------- DH --------------------------------- """

""" 
PDU class
    parameters:
        - pdu: PDU
        - pdu_recv: the PDU that the server is going to receive from clinet
        - pdu_ack: the PDU ack that the server is going to sent back to the client
        - FORMAT : constant format for the encode
        - timestamp: timestamp     
"""
class PDU():
    def __init__(self, User):
        # this is the message the client is sending
        self.pdu = None
        self.message = None
        self.user = User
        # self.crc = 0

    """ checks if the crc its the same """
    def crcChecker(self, pdus):
        pdu = json.loads(pdus)
        temp_crc = pdu['header']['crc']
        pdu['header']['crc'] = 0x00
        msg = json.dumps(pdu)
        crc_val = crcVal(msg)
        if crc_val == temp_crc:
            # print("crc value correct")
            self.crc = temp_crc
        else:
            print("wrong crc value")
            sys.exit()

    """ PDU for DH 1 """
    def pduDH1(self, username, public_key):
        timestamp = utcTimestamp()
        # public_key_encode = base64.b64encode(public_key).decode(FORMAT)
        pdu = {'header':{'msg_type': 'dh1', 'crc': 0x00, 'timestamp':timestamp}, 
        'body':{'key':public_key, 'user': username}}
        msg = json.dumps(pdu)
        crc_val = crcVal(msg)
        pdu['header']['crc'] = crc_val
        self.pdu = pdu
        msg_to_send = json.dumps(pdu).encode(FORMAT)
        logging(msg_to_send)
        print("DH 1: a -> b")
        print(msg_to_send.decode(FORMAT))
        return msg_to_send

    """ PDU for DH 2 """
    def pduDH2(self, public_key):
        timestamp = utcTimestamp()
        pdu = {'header':{'msg_type': 'dh2', 'crc': 0x00, 'timestamp':timestamp}, 
        'body':{'key':public_key}}
        msg = json.dumps(pdu)
        crc_val = crcVal(msg)
        pdu['header']['crc'] = crc_val
        self.pdu = pdu
        msg_to_send = json.dumps(pdu).encode(FORMAT)
        logging(msg_to_send)
        print("DH 2: b -> a")
        print(msg_to_send.decode(FORMAT))
        return msg_to_send

    """ function to return the public key from DH pdus """
    def returnPublicKey(self, pdu):
        msg = json.loads(pdu)
        pub_key = msg['body']['key']
        return pub_key

    """ PDU for the message """
    def pduMessage(self, message, enc_key):
        timestamp = utcTimestamp()
        pdu = {'header': {'msg_type':'text', 'crc': 0x00, 'timestamp': timestamp}, 'body':message, 
        'security': {'hmac':{'type':'SHA256', 'val':0x00}, 'enc_type': 'AES256-CBC'}}
        msg = (json.dumps(pdu))
        h_obj = HMAC.new(enc_key, digestmod=SHA256)
        h_obj.update(bytes(msg,FORMAT))
        hash_value = h_obj.hexdigest()
        pdu['security']['hmac']['val'] = hash_value
        crc_val = crcVal(msg)
        pdu['header']['crc'] = crc_val
        msg_to_send = json.dumps(pdu).encode(FORMAT)
        logging(msg_to_send)
        print("text: a -> b")
        print(msg_to_send.decode(FORMAT))
        return msg_to_send

    """ PDU for the ack message """
    def pduAck(self,pdu, enc_key):
        message = json.loads(pdu)
        message['header']['msg_type'] = 'ack'
        message['body'] = None
        message['header']['crc'] = 0x00
        msg = json.dumps(message)
        crc_val = crcVal(msg)
        message['header']['crc'] = crc_val
        secret_key = user.password.encode(FORMAT)
        h_obj = HMAC.new(enc_key, digestmod=SHA256)
        h_obj.update(bytes(msg,FORMAT))
        hash_value = h_obj.hexdigest()
        message['security']['hmac']['val'] = hash_value
        msg_to_send = json.dumps(message).encode(FORMAT)
        logging(msg_to_send)
        print("text ack: a -> b")
        print(msg_to_send.decode(FORMAT))
        return msg_to_send




""" User Class """
class User():
    def __init__(self):
        self.username = None
        self.password = None
        self.port = None
        self.ip = None
        self.directories = None

    """ Set all the directories as an instance of a user """
    def setDirectories(self, directories):
        self.directories = directories

    """ Initialize the data of the user with the username provided """
    def returnUserInfo(self, port):
        for directory in self.directories:
            if directory.get('port') == str(port):
                self.username = directory.get('username')
                self.password = directory.get('password')
                self.port = int(directory.get('port'))
                self.ip = directory.get('ip')
                return
        print("User does not exist!")

    """ Return a table with the remaining directories so the user can choose with which to comunicate """
    def returnOtherUsers(self):
        counter = 1
        print(f"{'User':>6} | {'Username':>20} | {'Ip':>15} | {'Port':>5} |")
        print(f"{'-' * 7}+{'-' * 22}+{'-' * 17}+{'-' * 7}+")
        for directory in self.directories:
            if directory.get('username') != self.username:
                print(f"{counter:>6} | {directory.get('username'):>20} | {directory.get('ip'):>15} | {directory.get('port'):>5} |")
                print(f"{'-' * 7}+{'-' * 22}+{'-' * 17}+{'-' * 7}+")
                counter += 1 
        return

    """ Return a table with the all the directories so the user can choose with which to comunicate 
    (same function as above, just this one prints all the directories!) """
    def returnAllUsers(self):
        counter = 1
        print(f"{'User':>6} | {'Username':>20} | {'Ip':>15} | {'Port':>5} |")
        print(f"{'-' * 7}+{'-' * 22}+{'-' * 17}+{'-' * 7}+")
        for directory in self.directories:
            print(f"{counter:>6} | {directory.get('username'):>20} | {directory.get('ip'):>15} | {directory.get('port'):>5} |")
            print(f"{'-' * 7}+{'-' * 22}+{'-' * 17}+{'-' * 7}+")
            counter += 1 
        return


""" Server Class """
class Server():   
    def __init__(self, User):
        self.port = None
        self.server_socket = None
        self.ip = None
        self.user = User
        self.setServerData()
        self.address = ((self.ip, self.port))
        self.shared_secret = None
        self.chap_secret = None

    def setServerData(self):
        self.port = self.user.port
        self.ip = self.user.ip

    """ Open the server socket.
        Wait either for incoming messages. or messages to be sent."""
    def openServer(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.address)
        self.server_socket.listen()
        while True:
            # try:
            print("[STARTING] server is starting...")
            print('+----------------------------------------------------------+')
            print('|- WAITING FOR MESSAGES ...                                |')
            print("|- Enter a message if you would like to send a message.    |")
            print("|- Enter 'close' if you would like to close the terminal.  |")
            print("+----------------------------------------------------------+")
            while True:
                read, write, exception = select.select([sys.stdin, self.server_socket], [], [])
                if sys.stdin in read:
                    keyboard = str(sys.stdin.readline().strip('\n'))
                    if keyboard == "close":
                        self.closeSocket()
                        sys.exit()
                    else:
                        """ Client stuff happening here """
                        print()
                        directories = self.user.directories
                        self.user.returnOtherUsers()
                        port = askPort("for destination")
                        client_user = User()
                        client_user.setDirectories(directories)
                        client_user.returnUserInfo(port)
                        client = Client(client_user)
                        """
                        Diffie Helman 1
                        """
                        pdu = PDU(client_user)
                        clientDH = DiffieHellman()
                        pub_key = clientDH.public_key
                        dh1 = pdu.pduDH1(self.user.username, pub_key)
                        client.sendMessage(dh1)
                        recv_message = client.recvMessage()
                        server_public_key = pdu.returnPublicKey(recv_message)
                        share_secret = clientDH.generate_shared_secret(server_public_key)
                        peer_share_secret = client.recvMessage()
                        if share_secret != int(peer_share_secret.decode(FORMAT)):
                            print("Share secret not the same")
                            sys.exit()
                        share_secret = str(share_secret)
                        """
                        Phase 2
                        """
                        user_secret = client_user.password.encode(FORMAT)
                        hmac = HMAC.new(user_secret, share_secret.encode(FORMAT), digestmod = SHA256)
                        encryption_key = hmac.digest()
                        hash = SHA256.new()
                        hash.update(encryption_key)
                        iv = hash.digest()[:16]
                        hash.update(iv)
                        hmac_key = hash.digest()
                        hash.update(hmac_key)
                        chap_secret = hash.digest()
                        """
                        Phase 4
                        """ 
                        message = keyboard.encode(FORMAT)
                        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
                        padtext = pad(message, 16, style='pkcs7')
                        ct_bytes = cipher.encrypt(padtext)
                        encrypted_message = base64.b64encode(ct_bytes).decode(FORMAT)
                        msg = pdu.pduMessage(encrypted_message, encryption_key)
                        client.sendMessage(msg)
                        recv_ack = client.recvMessage()
                        print("ACK message")
                        print(recv_ack)



                        client.clientClose()
                        break

                # Server stuff happening here
                elif self.server_socket in read:
                    conn, addr = self.server_socket.accept()
                    recv_message = conn.recv(1024)
                    print(f"message from other user : {recv_message}")
                    pdu = PDU(self.user)
                    pdu.crcChecker(recv_message)
                    """ 
                    Diffie Helman 2
                    """
                    serverDH = DiffieHellman()
                    pub_key = serverDH.public_key
                    dh2 = pdu.pduDH2(pub_key)
                    clients_public_key = pdu.returnPublicKey(recv_message)
                    share_secret = serverDH.generate_shared_secret(clients_public_key)
                    self.shared_secret = share_secret
                    conn.sendall(dh2)
                    conn.sendall(str(self.shared_secret).encode(FORMAT))
                    """
                    Phase 4
                    """
                    recv_message = conn.recv(1024)
                    print(recv_message)
                    share_secret = str(share_secret)
                    ack_message = pdu.pduAck(recv_message, share_secret.encode(FORMAT))
                    conn.sendall(ack_message)


                    conn.close()
                    break
            # except:
            #     print("Address already in use!")
        
    """ close the socket before it exits """
    def closeSocket(self):
        print('[TERMINATE] server is closing...')
        self.server_socket.close()


""" Client Class """
class Client():
    def __init__(self, User):
        self.user = User
        self.port = None
        self.ip = None
        self.setClientData()
        self.address = ((self.ip, self.port))
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.address)
    
    """ set the address of the client """
    def setClientData(self):
        self.port = self.user.port
        self.ip = self.user.ip
    
    """ sends a pdu message using the client.socket """
    def sendMessage(self, message):
        self.client_socket.sendall(message)

    """ receiving a pdu message from the server.socket """
    def recvMessage(self):
        response_message = self.client_socket.recv(1024)
        return response_message
    
    """ closing the client socket """
    def clientClose(self):
        self.client_socket.close()


if __name__ == "__main__":
    file_name = askFileDirectory()
    directories = loadDirectories(file_name)
    user = User()
    user.setDirectories(directories)
    user.returnAllUsers()
    info = "for incoming connections"
    port = askPort(info)
    user.returnUserInfo(port)
    server = Server(user)
    server.openServer()
