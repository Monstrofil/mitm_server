#!/usr/bin/python
# coding=utf-8
import M2Crypto
from StringIO import StringIO

data ='0000ff9d00000001e6000001359474119e264f719a02d62fa9e5a8574b97bb170e2ecfb4345c183fcb32d589eddd08187513ffef29518758e90bd9f72743ac5b93d5f3fd568c7b98d594e16931ec01878514483bf7961765d1ec01c6e75c592ba0a227fd630aa4ba9bb08fe322868bddf697a9a028b98dcc4327ee4d04854af67aa3870f43082b1443e1cfed863d14cb6c49323d811155df81e3bd4f8eafd5632fe2a4d0'.decode('hex')

print(len(data))
rsa = M2Crypto.RSA.load_pub_key("/mnt/c/Games/World_of_Warships/res_packages/res_unpack/loginapp.pubkey")

print(len(rsa) / 8)

for i in range(30):
    for j in range(len(data)+1, len(data) - 30, -1):
        f = StringIO(data[i: j])
        print(i, j)

        try:
           decPremaster = rsa.public_decrypt(f.read(255), M2Crypto.RSA.pkcs1_padding)

           try:
            # print(decPremaster.encode('hex'))
            print(decPremaster)
           except:
            pass
        except M2Crypto.RSA.RSAError as e:
           print(e)