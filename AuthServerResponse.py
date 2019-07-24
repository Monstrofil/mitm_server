#!/usr/bin/python
# coding=utf-8
import json
import struct
from io import BytesIO

from Crypto.Cipher import Blowfish
from Crypto.Cipher._Blowfish import MODE_ECB

__author__ = "Aleksandr Shyshatsky"


def chunkify_string(string, length=8):
    """
    Split string into blocks with given max len.
    :type string: str
    :type length: int|long
    :rtype: tuple[int, str]
    """
    for i in range(0, len(string), length):
        yield i, string[0 + i:length + i]


class AuthServerResponse(object):
    def __init__(self, base_server_ip, base_server_port, session_id, payload, unknowntail):
        self._base_server_ip = base_server_ip
        self._base_server_port = base_server_port
        self._session_id = session_id
        self._payload = payload
        self._unknowntail = unknowntail

    def pack(self, blowfish_random, blowfish_key):
        payload = json.dumps(self._payload, separators=(',', ':'))
        packed = struct.pack(
            '>BBBBHHIB', *self._base_server_ip,
            self._base_server_port, 0, self._session_id,
            len(payload.encode('utf-8'))
        ) + payload.encode('utf-8') + self._unknowntail

        print('UNDERBLOWFISH', packed)

        blowfish = Blowfish.new(blowfish_key, MODE_ECB)

        previous_block = None
        encrypted_data = BytesIO()
        for index, chunk in chunkify_string(packed):
            if previous_block:
                # get two blocks, each 8 bytes long and xor them
                # then pack them back to string
                x, y = struct.unpack('qq', previous_block + chunk)
                new_block = struct.pack('q', x ^ y)
            else:
                new_block = chunk
            previous_block = chunk
            encrypted_block = blowfish.encrypt(new_block)
            encrypted_data.write(encrypted_block)
        return blowfish_random + encrypted_data.getvalue()
