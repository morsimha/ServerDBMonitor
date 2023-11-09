import socket
from protocol import Request, Response
from constants import *
from utils import *
from database import Database
from datetime import datetime
import uuid
from encryptor import Encryptor
from _thread import *
import threading
import crc
import struct

print_lock = threading.Lock()


class Server:
    MAX_TRIES = 3

    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.loggedUser = False
        self.database = Database(DB_NAME)
        self.AESKey = ''

    def read(self, conn):
        data = conn.recv(PACKET_SIZE)
        if data:
            self.handle_request(conn, data)

        print_lock.release()
        conn.close()

    def run(self):
        """
        Start running the server and listen for incoming connections.
        The infinite loop is contained here.
        """
        # if not self.database.createDatabase():
        #     print("Shutting down the server.")
        #     return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(
                f'Server is running on port {self.port}, listening for connections..')
        except Exception as e:
            print(f'Error occurred: {e}')
            return False

        while True:
            conn, addr = sock.accept()
            print_lock.acquire()
            print(f'Accepted connection from {addr[0]}:{addr[1]}')
            start_new_thread(self.read, (conn,))

    def handle_request(self, conn, data):
        """ This function handles the request from the client. """
        curr_request = Request()
        curr_request.little_endian_unpack(data)

        requested_service = curr_request.code

        if requested_service == request_code.REGISTER_REQUEST.value:
            self.register_user(conn, curr_request)
        elif requested_service == request_code.LOGIN_REQUEST.value:  # Handle login requests
            self.login_user(conn, curr_request)
        elif requested_service == request_code.PUB_KEY_SEND.value or request_code.FILE_SEND.value:
            self.fileUpload(conn, curr_request)
        else:
            return

    def register_user(self, conn, curr_request):
        """ Registers user. If name exists, returns error.
            Otherwise, creates UUID, saves in memory and DB. """
        curr_response = Response(
            ResponseCode.REGISTER_SUCCESS.value, UUID_BYTES)
        user = curr_request.payload.decode('utf-8')
        try:
            if self.database.isExistentUser(user):
                curr_response.code = ResponseCode.REGISTER_ERROR.value
                curr_response.payloadSize = 0
                data = curr_response.little_endian_pack()
                print(f'Error registering {user}, the user already exists')

            else:
                id = bytes.fromhex(uuid.uuid4().hex)
                self.database.registerClient(id, user)
                self.database.setLastSeen(id, str(datetime.now()))
                curr_response.payload = id
                print(f'Successfully registered {user} with UUID of {id.hex()}.')
                data = curr_response.little_endian_pack()
        except Exception as e:
            curr_response.code = ResponseCode.GENERAL_ERROR.value
            curr_response.payloadSize = 0
            data = curr_response.little_endian_pack()
            print(f'Error: Failed to register user - {e}.')
        sendPacket(conn, data)

    def sendPubKey(self, conn, currRequest):
        """ Receives a public key, generates AES key, and sends it, only applies for new users. """
        enc = Encryptor()
        offset = currRequest.payloadSize - PUB_KEY_LEN
        username = currRequest.payload[:offset].decode('utf-8')
        pubkey = currRequest.payload[offset:]

        self.database.setPubKey(currRequest.uuid, pubkey)

        print(f'Received request for AES key from {username}.')
        currResponse = Response(
            ResponseCode.PUB_KEY_RECEVIED.value, UUID_BYTES + MAX_AES_LEN)

        try:
            self.database.setAESKey(currRequest.uuid, enc.key)

            encAESKey = enc.encryptPubKey(enc.key, pubkey)
            currResponse.payload = currRequest.uuid + encAESKey
            data = currResponse.little_endian_pack()
            sendPacket(conn, data)
            print(f'AES key successfully sent to {username}.')
            return enc.key
        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            data = currResponse.little_endian_pack()
            sendPacket(conn, data)
            print(f'Error: Failed to send Pubkey - {e}.')


    def login_user(self, conn, curr_request):
        """ Logs in a user. If name doesn't exist and RSA not found, returns error.
            Otherwise, returns the UUID and AES key of the user. """
        enc = Encryptor()
        offset = curr_request.payloadSize
        username = curr_request.payload[:offset].decode('utf-8')
        user_info = self.database.getUserInfo(
            username)  # Assume getUserInfo method retrieves the UUID and AES key for a given username
        try:
            if user_info:
                # User found in the database
                if 'PublicKey' in user_info:
                    user_uuid = user_info['UUID']
                    aes_key = user_info['AESKey']
                    self.AESKey = aes_key
                    enc_aes_key = enc.encryptPubKey(aes_key, user_info['PublicKey'])
                    curr_response = Response(ResponseCode.LOGIN_SUCCESS.value,
                                            UUID_BYTES + MAX_AES_LEN)  # Payload size is the size of a UUID plus the size of an AES key
                    curr_response.payload = user_uuid + enc_aes_key  # Set the payload to the user's UUID concatenated with the AES key
                    self.loggedUser = True
                    print(f"Successfully logged in user {username} with UUID: {user_uuid.hex()}")
                else:
                    curr_response = Response(ResponseCode.LOGIN_ERROR.value, user_info['UUID'] if user_info['UUID'] else 0)  # Return UUID payload for login error, no payload if doesn't exist in DB
                    print(f"Failed login attempt with username: {username}")
            else:
                # User was not found in database
                curr_response = Response(ResponseCode.LOGIN_ERROR.value, 0)  # No UUID if user didn't appear in DB
                print(f"Login attempt failed for username: {username}. User does not exist in database.")

        except Exception as e:
            curr_response = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            print(f'Error: Failed to login user - {e}.')

        data = curr_response.little_endian_pack()
        sendPacket(conn, data)  # Send response back to the client

    def fileUpload(self, conn, currRequest):
        """ Handles upload of file, including encryption. """
        if currRequest.code == request_code.PUB_KEY_SEND.value:
            AESKey = self.sendPubKey(conn, currRequest)
            buffer = conn.recv(PACKET_SIZE)
            currRequest.little_endian_unpack(buffer)
        else:
            AESKey = self.AESKey
        crc_confirmed = False
        tries = 0

        while tries < Server.MAX_TRIES and not crc_confirmed:
            if currRequest.code != request_code.FILE_SEND.value:
                return
            contentSize = currRequest.payload[:SIZE_UINT32_T]
            filename = currRequest.payload[SIZE_UINT32_T:SIZE_UINT32_T +
                                                         MAX_FILE_LEN].decode('utf-8')
            enc_content = currRequest.payload[SIZE_UINT32_T + MAX_FILE_LEN:]
            currPayloadSize = min(currRequest.payloadSize,
                                  PACKET_SIZE - REQ_HEADER_SIZE)

            sizeLeft = currRequest.payloadSize - currPayloadSize
            while sizeLeft > 0:
                tempPayload = conn.recv(PACKET_SIZE)
                currPayloadSize = min(sizeLeft, PACKET_SIZE)
                enc_content += tempPayload[:currPayloadSize]
                sizeLeft -= currPayloadSize

            wrapper = Encryptor()
            dec_content = wrapper.decryptAES(enc_content, AESKey)

            # Calculate checksum
            digest = crc.crc32()
            digest.update(dec_content)
            checksum = digest.digest()

            # Send Response 2103
            resPayloadSize = 2 * SIZE_UINT32_T + MAX_FILE_LEN
            newResponse = Response(
                ResponseCode.FILE_OK_CRC.value, resPayloadSize)
            newResponse.payload = contentSize + filename.encode('utf-8')
            newResponse.payload += struct.pack('<I', checksum)
            buffer = newResponse.little_endian_pack()
            sendPacket(conn, buffer)

            # Receive confirmation for CRC.
            buffer = conn.recv(PACKET_SIZE)
            currRequest.little_endian_unpack(buffer)
            if currRequest.code == request_code.CRC_OK.value:
                crc_confirmed = True
                print("CRC confirmed, backing up the file.")
            elif currRequest.code == request_code.CRC_INVALID_RETRY.value:
                tries += 1
                print("Failed to confirm CRC, waiting for user to try again.")
            elif currRequest.code == request_code.CRC_INVALID_EXIT.value:
                print("Failed to confirm CRC after total of 4 invalid CRC.\nFile transfer is not verified.")
                return
        # End of while loop

        finalRes = Response(ResponseCode.MSG_RECEIVED.value, 0)
        buffer = finalRes.little_endian_pack()

        createDirectory('backup')
        dec_filename = filename.split("\x00")[0]
        pathname = 'backup\\' + dec_filename
        try:
            f = open(pathname, 'wb')
            f.write(dec_content)
            f.close()
            self.database.registerFile(
                currRequest.uuid, dec_filename, pathname, 1)
            # print(self.database.executeCommand("SELECT * FROM clients"))
            # print(self.database.executeCommand("SELECT * FROM files"))
            print(f'Successfully backed up file {dec_filename}.')
            sendPacket(conn, buffer)
        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            buffer = currResponse.little_endian_pack()
            sendPacket(conn, buffer)
            print(f'Error: Failed to write to backup - {e}.')
