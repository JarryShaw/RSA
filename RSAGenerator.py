# -*- coding: utf-8 -*-


from __future__ import print_function


import math
import random
import sys


# RSA 密鑰生成器
# 通過大素數生成公／私密鑰對


from jsntlib import ntl as jsntlib


class RSAGenerator:

    def __init__(self, lenBit=32):
        (e, d, n, s) = self._keyGeneration(lenBit)

        self._publicKey  = e
        self._privateKey = d
        self._divisorKey = n
        self._blockSize  = s

        print()
        print('The public key is %d' % self._publicKey)
        print('The private key is %d' % self._privateKey)
        print('The divisor key is %d' % self._divisorKey)
        print('The block size is %d' % self._blockSize)
        print('\n-*- Key Generated -*-\n')

    @property
    def public(a):
        return a._publicKey

    @property
    def private(a):
        return a._privateKey

    @property
    def divisor(a):
        return a._divisorKey

    @property
    def block(a):
        return a._blockSize

    # 獲取公鑰對(e,n)及分區長度
    def getPublicKey(self):
        return self._publicKey, self._divisorKey, self._blockSize

    # 獲取私鑰對(d,n)
    def getPrivateKey(self):
        return self._privateKey, self._divisorKey

    # 生成公／私鑰對及分區長度
    def _keyGeneration(self, _lenBit):
        p = self._cookPrimeNum(_lenBit)
        q = self._cookPrimeNum(_lenBit)

        n = p * q
        phi_n = jsntlib.lcm(p-1, q-1)           # φ(n) = (p-1)*(q-1)

        e = self._cookPublicKey(phi_n)
        d = self._cookPrivateKey(phi_n, e)
        s = self._cookBlockSize(_lenBit)

        return e, d, n, s

    # 獲取隨機大素數p及q
    @staticmethod
    def _cookPrimeNum(_lenBit):
        _lower = 2**_lenBit // 2 + 1
        _upper = 2**_lenBit
        _primeNum = 4
        _primeNumSet = []
        while not jsntlib.isprime(_primeNum):
            _primeNumSet.append(_primeNum)
            while _primeNum in _primeNumSet:
                _primeNum = random.randrange(_lower, _upper, 2)
        return _primeNum

    # 獲取公鑰e
    @staticmethod
    def _cookPublicKey(phi_n):
        # flag = False                          # 紀錄e與φ(n)是否互素
        eSet = []                               # 紀錄曾嘗試過的無效的e
        tmp_e = random.randrange(1, phi_n)      # 隨機生成e，並進行合理性判斷

        while True:
            while tmp_e in eSet:                # 若e紀錄與eSet中，重新生成之
                tmp_e = random.randrange(1, phi_n)
            if jsntlib.coprime(tmp_e, phi_n):   # e與φ(n)互素性質判斷
                break
            else:
                eSet.append(tmp_e)              # 若不互素，則加入eSet紀錄

        return tmp_e

    # 獲取私鑰d
    @staticmethod
    def _cookPrivateKey(phi_n, e):
        d = jsntlib.bezout(e, phi_n)[0]         # e * d ≡ 1 (mod φ(n))

        # print(e, phi_n, e*d%phi_n)
        while d <= 0:
            d += phi_n

        return d

    # 獲取分區長度
    @staticmethod
    def _cookBlockSize(_lenBit):
        size = _lenBit // 8
        return size

if __name__ == '__main__':
    rsaModule = RSAGenerator()
    (e,n,bs) = rsaModule.getPublicKey()
    (d,n)    = rsaModule.getPrivateKey()

    # print('The public key is %d' %e)
    # print('The private key is %d' %d)
    # print('The divisor key is %d' %n)
    # print('The block size is %d' %bs)
