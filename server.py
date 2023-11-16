# server.py


import os
import socket
from constants import *
from network_protocol import ServerRequest, ServerResponse
from database import Database
from datetime import datetime
import uuid
from encryptor import Encryptor
from _thread import *
import threading
import crc_32
import struct

my_lock = threading.Lock()


def fetch_port():
    """ Gets the port from the file, default is 1357. """
    try:
        with open(PORT_FILE) as f:
            port = int(f.readline().strip())
    except Exception as e:
        print(f'Error opening port file: {e}')
        port = DEFAULT_PORT
    return port


class Server:

    def __init__(self) -> None:
        self.host = ""
        self.port = fetch_port()
        self.loggedUser = False
        self.database = Database()
        self.AESKey = ''
        self.readable_filename = ""
        self.prot_codes = {
            "REGISTER_REQUEST": 1025,
            "SEND_PUB_KEY": 1026,
            "LOGIN_REQUEST": 1027,
            "FILE_SEND": 1028,
            "CRC_OK": 1029,
            "CRC_INVALID_RETRY": 1030,
            "CRC_INVALID_EXIT": 1031,

            "REGISTER_SUCCESS": 2100,
            "REGISTER_ERROR": 2101,
            "PUB_KEY_RECEIVED": 2102,
            "FILE_OK_CRC": 2103,
            "MSG_RECEIVED": 2104,
            "LOGIN_SUCCESS": 2105,
            "LOGIN_ERROR": 2106,
            "GENERAL_ERROR": 2107
        }

    @staticmethod
    def send_packet(socket, buffer):
        """ Adds \0  to the buffer and sends it to the socket. """
        if len(buffer) < PACKET_SIZE:
            buffer += bytearray(PACKET_SIZE - len(buffer))  # Pad with \0

        socket.send(buffer)

    def read(self, conn):
        data = conn.recv(PACKET_SIZE)
        if data:
            self.handle_request(conn, data)

        my_lock.release()
        conn.close()

    def run(self):
        """
        Start running the server and listen for incoming connections.
        The infinite loop is contained here.
        """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f'Server is up! Running on port {self.port} and listening for connections..')
        except Exception as e:
            print(f'-F- Error occurred: {e}')
            return False

        while True:
            conn, addr = sock.accept()
            my_lock.acquire()
            print(f'Connection request was accepted from {addr[0]}:{addr[1]}')
            start_new_thread(self.read, (conn,))

    def handle_request(self, conn, data):
        """ This function handles the request from the client. """
        curr_request = ServerRequest()
        curr_request.l_endian_unpack(data)

        requested_service = curr_request.code

        if requested_service == self.prot_codes["REGISTER_REQUEST"]:
            self.register_user(conn, curr_request)
        elif requested_service == self.prot_codes["LOGIN_REQUEST"]:
            self.login_user(conn, curr_request)
        elif requested_service == self.prot_codes["SEND_PUB_KEY"] or self.prot_codes["FILE_SEND"]:
            status =self.upload_file(conn, curr_request)
            if status:
                print(f"Success! {self.readable_filename} was successfully uploaded to the server!")
                print("Reminder: Server is still listening for connections..\n")
        else:
            return

    def register_user(self, conn, curr_request):
        """ Registers user. If name exists, returns error.
            Otherwise, creates UUID, saves in memory and DB. """
        curr_response = ServerResponse(
            self.prot_codes["REGISTER_SUCCESS"], UUID_BYTES)
        user = curr_request.payload.decode('utf-8')
        try:
            if self.database.is_known_user(user):
                curr_response.code = self.prot_codes["REGISTER_ERROR"]
                curr_response.payloadSize = 0
                data = curr_response.little_endian_pack()
                print(f'-F Failed registering {user}. User already exists.')

            else:
                id = bytes.fromhex(uuid.uuid4().hex)
                self.database.register_client(id, user)
                self.database.set_last_seen(id, str(datetime.now()))
                curr_response.payload = id
                print(f'Successfully registered {user} with UUID of {id.hex()}.')
                data = curr_response.little_endian_pack()
        except Exception as e:
            curr_response.code = self.prot_codes["GENERAL_ERROR"]
            curr_response.payloadSize = 0
            data = curr_response.little_endian_pack()
            print(f'-F- Failed to register user - {e}.')
        self.send_packet(conn, data)

    def sendPubKey(self, conn, curr_request):
        """ Receives a public key, generates AES key, and sends it, only applies for new users. """
        enc = Encryptor()
        offset = curr_request.payloadSize - PUB_KEY_LEN
        username = curr_request.payload[:offset].decode('utf-8')
        pubkey = curr_request.payload[offset:]

        self.database.set_pubkey(curr_request.uuid, pubkey)

        print(f'Received request for AES key from {username}.')
        curr_response = ServerResponse(self.prot_codes["PUB_KEY_RECEIVED"], UUID_BYTES + MAX_AES_LEN)

        try:
            self.database.set_AES_Key(curr_request.uuid, enc.key)

            encAESKey = enc.encrypt_pub_key(enc.key, pubkey)
            curr_response.payload = curr_request.uuid + encAESKey
            data = curr_response.little_endian_pack()
            self.send_packet(conn, data)
            print(f'AES key successfully sent to {username}.')
            return enc.key
        except Exception as e:
            curr_response = ServerResponse(self.prot_codes["GENERAL_ERROR"], 0)  # No UUID if user didn't appear in DB
            data = curr_response.little_endian_pack()
            self.send_packet(conn, data)
            print(f'-F- Failed to send Pubkey: {e}.')

    def login_user(self, conn, curr_request):
        """ Logs in a user. If name doesn't exist and RSA not found, returns error.
            Otherwise, returns the UUID and AES key of the user. """
        enc = Encryptor()
        offset = curr_request.payloadSize
        username = curr_request.payload[:offset].decode('utf-8')
        user_info = self.database.get_user_info_from_db(
            username)  # Assume getUserInfo method retrieves the UUID and AES key for a given username
        try:
            if user_info:
                # User found in the database
                if 'PublicKey' in user_info:
                    user_uuid = user_info['UUID']
                    aes_key = user_info['AESKey']
                    self.AESKey = aes_key
                    enc_aes_key = enc.encrypt_pub_key(aes_key, user_info['PublicKey'])
                    # Payload size is the size of a UUID plus the size of an AES key
                    curr_response = ServerResponse(self.prot_codes["LOGIN_SUCCESS"], UUID_BYTES + MAX_AES_LEN)
                    # Sets the payload to the user's UUID concatenated with the AES key
                    curr_response.payload = user_uuid + enc_aes_key
                    self.loggedUser = True
                    print(f"Successfully logged in user {username}")
                else:
                    curr_response = ServerResponse(self.prot_codes["LOGIN_ERROR"], user_info['UUID'] if user_info[
                        'UUID'] else 0)  # Return UUID payload for login error, no payload if doesn't exist in DB
                    print(f"-F- Failed login attempt for {username}\n")
            else:
                # User was not found in database
                curr_response = ServerResponse(self.prot_codes["LOGIN_ERROR"], 0)  # No UUID if user didn't appear in DB
                print(f"-F- Login attempt failed for username: {username}. User does not exist in database.\n")

        except Exception as e:
            curr_response = ServerResponse(self.prot_codes["GENERAL_ERROR"], 0)  # No UUID if user didn't appear in DB
            print(f'-F- Failed to login user - {e}.')

        data = curr_response.little_endian_pack()
        self.send_packet(conn, data)  # Send response back to the client

    def upload_file(self, conn, curr_request):
        """ Handles upload of file, including encryption. """
        if curr_request.code == self.prot_codes["SEND_PUB_KEY"]:
            AESKey = self.sendPubKey(conn, curr_request)
            buffer = conn.recv(PACKET_SIZE)
            curr_request.l_endian_unpack(buffer)
        else:
            AESKey = self.AESKey
        crc_confirmed = False
        tries = 0

        while tries < MAX_TRIES and not crc_confirmed:
            if curr_request.code != self.prot_codes["FILE_SEND"]:
                return
            msg_size = curr_request.payload[:SIZE_UINT32_T]
            filename = curr_request.payload[SIZE_UINT32_T:SIZE_UINT32_T +
                                                          MAX_FILE_LEN].decode('utf-8')
            enc_content = curr_request.payload[SIZE_UINT32_T + MAX_FILE_LEN:]
            curr_payload_size = min(curr_request.payloadSize,
                                  PACKET_SIZE - REQ_HEADER_SIZE)

            size_left = curr_request.payloadSize - curr_payload_size
            while size_left > 0:
                tmp_Payload = conn.recv(PACKET_SIZE)
                curr_payload_size = min(size_left, PACKET_SIZE)
                enc_content += tmp_Payload[:curr_payload_size]
                size_left -= curr_payload_size

            wrapper = Encryptor()
            dec_content = wrapper.decrypt_AES(enc_content, AESKey)

            # Calculate checksum
            digest = crc_32.crc_32()
            digest.update(dec_content)
            checksum = digest.digest()

            # Send Response 2103
            res_payload_size = 2 * SIZE_UINT32_T + MAX_FILE_LEN
            new_response = ServerResponse(
                self.prot_codes["FILE_OK_CRC"], res_payload_size)
            new_response.payload = msg_size + filename.encode('utf-8')
            new_response.payload += struct.pack('<I', checksum)
            buffer = new_response.little_endian_pack()
            self.send_packet(conn, buffer)

            # Receive confirmation for CRC.
            buffer = conn.recv(PACKET_SIZE)
            curr_request.l_endian_unpack(buffer)
            if curr_request.code == self.prot_codes["CRC_OK"]:
                crc_confirmed = True
                print("CRC confirmed!")
            elif curr_request.code == self.prot_codes["CRC_INVALID_RETRY"]:
                tries += 1
                print("Failed to confirm CRC, waiting for user to try again.")
            elif curr_request.code == self.prot_codes["CRC_INVALID_EXIT"]:
                print("Failed to confirm CRC after total of 4 invalid CRC.\nFile transfer is not verified.")
                return
        # End of while loop

        final_result = ServerResponse(self.prot_codes["MSG_RECEIVED"], 0)
        buffer = final_result.little_endian_pack()

        if not os.path.exists('backup'):
            os.mkdir('backup')
        self.readable_filename = filename.split("\x00")[0]
        pathname = 'backup\\' + self.readable_filename
        print("Initiating backup for received file..")
        try:
            f = open(pathname, 'wb')
            f.write(dec_content)
            f.close()
            self.database.register_file(
                curr_request.uuid, self.readable_filename, pathname, 1)
            print(f'Successfully backed up file {self.readable_filename}.')
            self.send_packet(conn, buffer)
            return True
        except Exception as e:
            curr_response = ServerResponse(self.prot_codes["GENERAL_ERROR"], 0)  # No UUID if user didn't appear in DB
            buffer = curr_response.little_endian_pack()
            self.send_packet(conn, buffer)
            print(f'Error: Failed to write to backup - {e}.')
            return False
