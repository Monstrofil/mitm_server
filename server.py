#! /usr/bin/env python
# coding: utf-8
import json
import os
import struct
from io import BytesIO
from optparse import OptionParser
import socket
import logging
from struct import unpack
from threading import Thread
from time import sleep

from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Cipher._Blowfish import MODE_ECB
from Crypto.PublicKey import RSA

from AuthServerResponse import AuthServerResponse
from MercuryPacket import MercuryPacket

CLIENT_PUBLIC_KEY = r"C:\Games\World_of_Warships\res_packages\res_unpack\loginapp.pubkey"
BLOWFISH_KEY = None

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


def parse_args():
    parser = OptionParser()

    parser.add_option('--bind-address',
                      help='The address to bind, use 0.0.0.0 for all ip address.')
    parser.add_option('--port',
                      help='The port to listen, eg. 623.',
                      type=int)
    parser.add_option('--dst-ip',
                      help='Destination host ip, eg. 192.168.3.101.')
    parser.add_option('--dst-port',
                      help='Destination host port, eg. 623.',
                      type=int)

    return parser.parse_args()

(options, args) = parse_args()


def parse(data):
    packet = MercuryPacket().read(BytesIO(data))
    print(packet)
    return packet.payload


def decrypt_blowfish(io):
    blowfish = Blowfish.new(BLOWFISH_KEY, MODE_ECB)
    f = io.read()
    previous_block = None  # type: str
    decrypted_data = BytesIO()
    for z in range(0, len(f), 8):
        chunk = f[z: z + 8]
        decrypted_block = blowfish.decrypt(chunk)
        if previous_block:
            # get two blocks, each 8 bytes long and xor them
            # then pack them back to string
            x, y = struct.unpack('qq', decrypted_block + previous_block)
            decrypted_block = struct.pack('q', x ^ y)
        decrypted_data.write(decrypted_block)
        previous_block = decrypted_block
    payload = decrypted_data.getvalue()
    return payload


class GameServerMitm(Thread):
    def __init__(self, server_ip, server_port, real_server_ip, real_server_port):
        super().__init__()
        self._server_ip = server_ip
        self._server_port = server_port
        self._real_server_ip = real_server_ip
        self._real_server_port = real_server_port

    def run(self):
        sock_src = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_dst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_addr = (self._server_ip, self._server_port)
        dst_addr = (self._real_server_ip, self._real_server_port)
        sock_src.bind(recv_addr)

        while True:
            data, addr = sock_src.recvfrom(65565)
            logger.debug('received from {1}: {0!r}'.format(data, addr))
            print(data.hex())

            for i in range(30):
                f = BytesIO(data[i: ])
                if len(data[i:]) < 8:
                    continue
                try:
                    decrypted = decrypt_blowfish(f)
                    print('UNPACKED', i, decrypted, decrypted.hex())
                    print(decrypted.decode('utf-8', 'ignore'))
                except:
                    pass

            sock_dst.sendto(data, dst_addr)

            data, _ = sock_dst.recvfrom(65565)
            logger.debug('received from {1}: {0!r}'.format(data, dst_addr))
            print(data.hex())

            for i in range(30):
                f = BytesIO(data[i:])
                if len(data[i:]) < 8:
                    continue
                try:
                    decrypted = decrypt_blowfish(f)
                    print('UNPACKED', i, decrypted, decrypted.hex())
                    print(decrypted.decode('utf-8', 'ignore'))
                except:
                    pass

            sock_src.sendto(data, addr)

        sock_src.close()
        sock_dst.close()

def recv():
    global BLOWFISH_KEY
    sock_src = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_dst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_addr = (options.bind_address, options.port)
    dst_addr = (options.dst_ip, options.dst_port)
    sock_src.bind(recv_addr)

    while True:
        data, addr = sock_src.recvfrom(65565)
        if not data:
            logger.error('an error occured')
            break
        logger.debug('received from {1}: {0!r}'.format(data, addr))

        if os.name == 'posix':
            rsa_key = RSA.importKey(open("/mnt/d/bigworld/loginapp.privkey").read())
            rsa_pubkey = RSA.importKey(open(CLIENT_PUBLIC_KEY).read())
        else:
            rsa_key = RSA.importKey(open("D:\\bigworld\\loginapp.privkey").read())
            rsa_pubkey = RSA.importKey(open(CLIENT_PUBLIC_KEY).read())
        cipher1 = PKCS1_OAEP.new(rsa_key)
        cipher2 = PKCS1_OAEP.new(rsa_pubkey)
        io = BytesIO(data)
        payload = BytesIO(data)
        payload.write(io.read(16))
        rest = io.read()
        crypted = rest[:-2]
        tail = rest[-2:]
        print(len(crypted))
        decrypted = cipher1.decrypt(crypted)
        encrypted = cipher2.encrypt(decrypted)
        payload.write(encrypted)
        payload.write(tail)
        sock_dst.sendto(payload.getvalue(), dst_addr)

        packet = MercuryPacket().read(BytesIO(payload.getvalue()))

        io = BytesIO(decrypted)
        print(io.tell())
        print(decrypted)
        print(decrypted.hex())
        print(io.read(1))
        l, = struct.unpack('B', io.read(1))
        print(l)
        print(io.read(l))
        l, = struct.unpack('B', io.read(1))
        print(l)
        print(io.read(l))
        # print(io.read().hex())

        l, = struct.unpack('b', io.read(1))
        print(l)
        BLOWFISH_KEY = io.read(l)
        print('blowfish_key', BLOWFISH_KEY.hex())

        print(io.read(16).hex())
        print(io.read(4).hex())

        parse(data)

        data, _ = sock_dst.recvfrom(65565)
        logger.debug('received from {1}: {0!r}'.format(data, dst_addr))


        parse(data)
        io = BytesIO(data)
        packethead = io.read(4)
        try:
            blowfish_random = io.read(8)
            payload = decrypt_blowfish(io)
            print('UNDERBLOWFISH_REAL', payload.hex(), payload)
            payload_io = BytesIO(payload)
            ip = struct.unpack('>BBBB', payload_io.read(4))
            port, = struct.unpack('>H', payload_io.read(2))

            assert payload_io.read(2).hex() == '0000'

            session_id, = struct.unpack('>I', payload_io.read(4))
            json_len, = struct.unpack('>B', payload_io.read(1))
            print(json_len)
            jsonp = payload_io.read(json_len)
            print(jsonp.hex())
            js = json.loads(jsonp)
            unknown = payload_io.read()
            print(ip, port)

            # (92, 223, 32, 20)
            auth_response = AuthServerResponse(
                # base_server_ip=(92, 223, 32, 15),
                # base_server_port=8320,
                # base_server_ip=(92, 223, 32, 170),
                # base_server_ip=ip,
                # base_server_port=port,
                base_server_ip=(192, 168, 0, 105),
                base_server_port=20030,
                session_id=session_id,
                payload=js,
                unknowntail=unknown
            )
            print('blowfish_random', blowfish_random.hex(), blowfish_random)
            print(len(blowfish_random))
            result_data = packethead + \
                          auth_response.\
                              pack(blowfish_random, BLOWFISH_KEY)
            # print(result_data)
            # print(payload)
            # print(payload_io.read().hex())
        except ValueError:
            raise

        print(packethead.hex())
        print(data.hex())
        print(result_data.hex())
        # assert data == result_data

        game_server = GameServerMitm(
            server_ip='.'.join(map(str, (192, 168, 0, 105))),
            server_port=20030,
            real_server_ip='.'.join(map(str, ip)),
            real_server_port=port
        )
        game_server.start()
        sleep(2)

        sock_src.sendto(result_data, addr)
        game_server.join()

        print('=' * 20)

    sock_src.close()
    sock_dst.close()


if __name__ == '__main__':
    parse_args()
    try:
        recv()
    except KeyboardInterrupt:
        exit(0)