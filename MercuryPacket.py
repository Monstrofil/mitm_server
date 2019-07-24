#!/usr/bin/python
# coding=utf-8
import json
import struct
from io import BytesIO
from pprint import pformat

__author__ = "Aleksandr Shyshatsky"


class MercuryPacket(object):
    def __init__(self):
        self.unknown = None
        self.payload_size = None
        self.payload = None
        self.counter = None
        self.session = None
        self.unknown2 = None
        self.payload = None
        self.footer = None

    def read(self, io):
        self.unknown = io.read(3).hex()
        self.payload_size, = struct.unpack('h', io.read(2))
        self.counter = io.read(1).hex()
        self.session = io.read(4)
        self.unknown2 = io.read(1)
        self.payload = io.read(self.payload_size)
        self.footer = io.read()

        return self

    def __str__(self):
        return '<PACKET>:\n~~\n%s\n~~' % pformat(self.__dict__)
