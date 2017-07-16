# -*- coding: utf-8 -*-


from __future__ import print_function


import binascii
import sys


# RSA 加密器
# 利用生成的公鑰進行加密操作


from jsntlib import ntl as jsntlib
from RSAGenerator import RSAGenerator
from RSAMessager import rsachr, rsaord, rsastr, RSAMessager


class RSAEncrytor:

    def __init__(self, plainText):
        _rsacipher = RSAGenerator()
        publicKey  = _rsacipher.public
        privateKey = _rsacipher.private
        divisorKey = _rsacipher.divisor
        blockSize  = _rsacipher.block

        # 對明文進行分塊
        blockText, complement = self._blockSlice(plainText, blockSize)

        # 逐塊加密，並合併得到密文
        self._cipherText = RSAMessager(privateKey, divisorKey)

        for block in blockText[:-1]:
            cipherText= self._msgEncryption(block, publicKey, divisorKey)
            self._cipherText(True, cipherText)

        cipherText = self._msgEncryption(blockText[-1], publicKey, divisorKey)
        self._cipherText(True, cipherText, complement)

        '''
        self.cipherText += str(self.msgEncryption(block, publicKey, divisorKey)).rjust(len(str(divisorKey)),'0')
        '''
        # An alternative for the above line of code:
        # self.cipherText += str(self.repetiveSquareModulo(self.convertUnicode2Number(stringText), publicKey, divisorKey)).rjust(len(str(divisorKey)), '0')

    # 獲取密文
    @property
    def message(self):
        return self._cipherText

    # 明文分塊
    @staticmethod
    def _blockSlice(plainText, blockSize):
        blockText = []
        tmpLength = len(plainText) % blockSize
        complement = 0 if tmpLength == 0 else blockSize - tmpLength

        while len(plainText) > 0:
            blockText.append(plainText[:blockSize].ljust(blockSize, b' '))
            plainText = plainText[blockSize:]

        # print('blockText=', reversed(blockText))
        return blockText, complement

    # 明文加密
    def _msgEncryption(self, stringText, publicKey, divisorKey):
        numberText = self._Unicode2Number(stringText)
        cipherNumb = rsastr(jsntlib.modulo(numberText, publicKey, divisorKey))
        cipherText = self._Number2Unicode(cipherNumb)

        print(stringText, '\t', numberText, '\t', cipherNumb, '\t', cipherText, '\t')
        return cipherText
    
    # 將字串轉化爲數字（Unicode碼）
    @staticmethod
    def _Unicode2Number(stringText):
        numberText = ''

        for letter in stringText:
            # print(type(stringText), letter)
            numberText += rsaord(letter).rjust(3, '0')
            # print(letter, letter)
            # print('numberText=', numberText)

        return int(numberText)

    # 將數字轉化爲字串（Unicode串）
    @staticmethod
    def _Number2Unicode(numberText):
        stringText = ''

        while len(numberText) > 0:
            # print(numberText[-3:])
            stringText = rsachr(int(numberText[-3:])) + stringText
            numberText = numberText[:-3]

        # print('stringText=', stringText)
        return stringText


if __name__ == '__main__':
    import RSAGenerator

    rsa_keys = RSAGenerator.RSAGenerator()
    (publicKey, divisorKey, blockSize) = rsa_keys.getPublicKey()

    # plainText = 'Mathematic Fundation of Information security 20170323 515030910023'
    # plainText = 'Mathmatics'

    rsa_cipher = RSAEncrytor(plainText, publicKey, divisorKey, blockSize)
    cipherText = rsa_cipher.text

    print('The plain text is %s' % plainText)
    print('The cipher text is %s' % ''.join(cipherText))
    '''
    cipherTextFile = open("cipherText.txt","w")
    cipherTextFile.write("\n".join(cipherText))
    cipherTextFile.close()
    '''
