# -*- coding: utf-8 -*-


from __future__ import print_function


import sys


# RSA 解密器
# 利用生成的私鑰進行解密操作


from jsntlib import ntl as jsntlib
from RSAMessager import rsachr, rsastr


class RSADecryter:

    def __init__(self, cipherText):
        '''
        blockText = self.blockSlice(str(cipherText), len(str(divisorKey)))  # 對密文進行分塊
        '''

        cipherList = cipherText.list()
        privateKey = cipherList[0][0]
        divisorKey = cipherList[1][0]
        print('Keys: ', privateKey, divisorKey)

        self._plainText = b''
        for block in cipherList[2:]:     # 逐塊解密，並合併得到明文
            # print('block: ', block)
            self._plainText += self._msgDecryption(block[0], privateKey, divisorKey, block[1])
            
            # An alternative for the above line of code:
            # self.cipherText += str(self.repetiveSquareModulo(self.convertUnicode2Number(stringText), publicKey, divisorKey)).rjust(len(str(divisorKey)), '0')

    # 獲取明文
    @property
    def message(self):
        return self._plainText

    # 密文解密
    def _msgDecryption(self, cipherText, privateKey, divisorKey, complement):
        numberText = self._Unicode2Number(cipherText)
        plainNumb  = rsastr(jsntlib.modulo(numberText, privateKey, divisorKey))
        plainText  = self._Number2Unicode(plainNumb, complement)

        print(cipherText, '\t', numberText, '\t', plainNumb, '\t', plainText)
        return plainText

    # 將字串轉化爲數字（Unicode碼）
    @staticmethod
    def _Unicode2Number(stringText):
        numberText = ''

        # print('string: ', stringText)
        for letter in stringText:
            # print('letter: ', letter)
            numberText += rsastr(ord(letter)).rjust(3, '0')
            # print('numberText=', numberText)

        return int(numberText)

    # 將數字轉化爲字串（Unicode串）
    @staticmethod
    def _Number2Unicode(numberText, complement):
        stringText = b''

        while len(numberText) > 0:
            # print('bytes: ', bytes([int(numberText[-3:])]))
            stringText = bytearray([int(numberText[-3:])]) + stringText
            numberText = numberText[:-3]

        # print('stringText=', stringText)
        if complement > 0:
            return stringText[:-complement]
        else:
            return stringText


if __name__ == '__main__':
    # import RSAGenerator
    import RSAEncryptor

    # rsa_keys = RSAGenerator.RSAGenerator()
    # (publicKey, divisorKey, blockSize) = rsa_keys.getPublicKey()

    # print('\n-*- Key Generated -*-\n')

    plainText = b'Mathematic1'
    # plainText = b'Mathematic Fundation of Information security 20170323 515030910023 Óé¬¬ø ∑ø®¬∂!'
    # plainText = b'The binascii module contains a number of methods to convert between binary and various ASCII-encoded binary representations. Normally, you will not use these functions directly but use wrapper modules like uu, base64, or binhex instead. The binascii module contains low-level functions written in C for greater speed that are used by the higher-level modules.'
    # plainText = u'記得初中化學曾學過，紙的燃點是華氏451度，約合攝氏233度——挺有趣的，是吧？前段時間，有人用404刷爆了朋友圈。其實，從技術上說，404應是「勇敢的新世界」了；現在還僅僅是451的時代，「因法律原因不可用」。而那些高唱讚歌的傢伙，若尚未失智，忘記二十四字核心價值觀的第五個詞（自由），那便是非蠢即壞的。'.encode('utf-8')
    # print(repr(plainText), type(plainText))
    # input()

    # print(type(plainText))
    rsa_cipher = RSAEncryptor.RSAEncrytor(plainText)
    cipherText = rsa_cipher.message
    # print(unicode(cipherText))

    print('\n-*- Text Ciphered -*-\n')

    # (privateKey, divisorKey) = rsa_keys.getPrivateKey()

    rsa_plain = RSADecryter(cipherText)
    plainText = rsa_plain.message
    print(type(plainText))

    print('The original message is \'%s\'' % plainText)
    print()
