#!/usr/bin/python
# coding=utf-8
import os
import struct

from StringIO import StringIO

from Crypto.Cipher import Blowfish, PKCS1_OAEP
from Crypto.Cipher.Blowfish import MODE_ECB
from Crypto.PublicKey import RSA

data ='168d7e576b28faddc8f61cd9ce38d0494023b5110ca3d6bf5125ec05e88f7b3929ab88dcaf97fe2c946716556456c3c4212c3de589b7a7f337033eff2cacf2f513d94a8c17f7be2c79e77ed5374d24d4de6c84b43aec8cd63d912bfe64bc1e076794708d83c7102b63447f2e01ba0a0da60eaf5d5c259dbfd92038bfabfdb43901ad28fe0f7bbce533f0a1bfae44287c7cd5c7d387c3511a0fc7bead2573ce13aed612fc7f04a0d6a4184922db3d18e2dbe65365a5c889efdc1cd9eacf1186bbb8d47cab4956cd34aac1a0da7e1357341a78a72144ce8026ed06a7632496cfe75bcc6e21a7f77c400e4b05c96dc74fc77d4c93744d8786dae1c9414281385ce5'.decode('hex')
data ='76a2677c4c0c0cb285ace22646bc3f5fbb905be0c18f4e5246f5f5cd7919634134d31b2c6a603e375404098fc3661ddc8728471927aa950410ef2cc82f338b56fe942529855f1ab44bb38cc680f3ba91e396cd1c38dfe9d6b8b51f46f0d2ac74c52bfa65efb8aefd4fa6311975fd63042981f940123238c786ae4b5ac05a0903e0efd14a55f6c2cc25cb9ebf721d1a3f5dff4ba6b3700932803c415b308a6883d979b61ce9342b011e7758c1cdd6e23e2092a5f9dbd46c52bf78311eb5f74af8dfb19f6de9227eb26e284498454920ce0dfa1615b9d70a667ab4a76e6b68d7bf4eb7574d37e6a6f79de435cea930b47e3774ecae024fc20b7897c308930b7f7d'.decode('hex')
print(len(data))
# data ='19082a13e4dc82acb07631007965f53142ae753166901723ae509115398740fe9de1443fd6591861838b23965f460c1b2e1a8f8489876e3a58f4c1f38f065c47416abbfb1a3934bba1393c589ef96ffc9c1b042c7cc79fd37fc2fd7331c5d03ae02b2f7beed63fcf7915d9e258471f86a664727acdb0e72150f9d571bd319b0c6c4987a3b04d7d1b4b4bf7cf66984dcada013c929ee3d2b410eaaf2284f7fc49601f3d4953007e5aa65c3bc646242a4b798932da8ae7eeae5e0fb18a4e1ea454de2259d2dc72e5c34adcfca7b936ac12b7fa0baa0ebff44a967c5c5108638ca52c516c63192af9555c81806220de35e5b78db174e549bd392579b3b8af39fdb9'.decode('hex')

print(len(data))
# rsa = M2Crypto.RSA.load_key("/mnt/d/bigworld/loginapp.privkey")
if os.name == 'posix':
   rsa_key = RSA.importKey(open("/mnt/d/bigworld/loginapp.privkey").read())
else:
   rsa_key = RSA.importKey(open("D:\\bigworld\\loginapp.privkey").read())
cipher1 = PKCS1_OAEP.new(rsa_key)


i = 0
f = StringIO(data[i:])
print(data[:i].encode('hex'))

try:
   crypted = f.read(256)
   decPremaster = cipher1.decrypt(crypted) # rsa.private_decrypt(crypted, M2Crypto.RSA.pkcs1_oaep_padding)
   io = StringIO(decPremaster)
   print(decPremaster)
   print(decPremaster.encode('hex'))
   print(io.read(1))
   l, = struct.unpack('b', io.read(1))
   print(l)
   print(io.read(l))
   l, = struct.unpack('b', io.read(1))
   print(l)
   print(io.read(l))
   # print(io.read().encode('hex'))

   l, = struct.unpack('b', io.read(1))
   print(l)
   BLOWFISH_KEY = io.read(l)
   print(BLOWFISH_KEY.encode('hex'))

   print(io.read(16).encode('hex'))
   print(io.read(4).encode('hex'))
except M2Crypto.RSA.RSAError as e:
   print(e)

blowfish = Blowfish.new(BLOWFISH_KEY, MODE_ECB)
decrypted_block = blowfish.decrypt('')

