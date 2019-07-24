#!/usr/bin/python
# coding=utf-8
__author__ = "Aleksandr Shyshatsky"

from socket import *

s = socket(AF_INET, SOCK_DGRAM)
s.bind(('192.168.0.105', 20030))
m = s.recvfrom(1024)
print(m[0])
