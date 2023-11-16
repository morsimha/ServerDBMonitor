import struct
from constants import *


class ServerRequest:
    def __init__(self):
        self.uuid = 0
        self.version = SERVER_VER
        self.code = 0
        self.payloadSize = 0
        self.payload = b''

    def l_endian_unpack(self, data):
        """ Unpacks binary data received into the correct fields """
        try:
            self.uuid, self.version, self.code, self.payloadSize = struct.unpack(
                f'<{UUID_BYTES}sBHI', data[:REQ_HEADER_SIZE])
            info_to_extract = min(PACKET_SIZE -
                                REQ_HEADER_SIZE, self.payloadSize)
            self.payload = struct.unpack(
                f'<{info_to_extract}s', data[REQ_HEADER_SIZE:REQ_HEADER_SIZE + info_to_extract])[0]

        except Exception as e:
            print(e)


class ServerResponse:
    def __init__(self, code, payload_size):
        self.version = SERVER_VER
        self.code = code
        self.payloadSize = payload_size
        self.payload = b''

    def little_endian_pack(self):
        """ Packs the data into a struct according to the server's protocol """
        packed_data = struct.pack('<BHI', self.version,
                                 self.code, self.payloadSize)
        packed_data += self.payload
        return packed_data
