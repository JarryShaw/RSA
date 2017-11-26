# -*- coding: utf-8 -*-


from jsntlib import ntl as jsntlib


# RSA 解密器
# 利用生成的私鑰進行解密操作


from .RSAUtilities import rsachr, rsastr


'''Usage sample:

# 1st set:
plainText = b'Mathematic1'

# 2nd set:
plainText = b'Mathematic Fundation of Information security 20170323 515030910023 Óé¬¬ø ∑ø®¬∂!'

# 3rd set:
plainText = b'\
The binascii module contains a number of methods to convert between binary and various \
ASCII-encoded binary representations.Normally, you will not use these functions directly \
but use wrapper modules like uu, base64, or binhex instead.The binascii module contains \
low-level functions written in C for greater speed that are used by the higher-level modules.'

# 4th set:
plainText = u'\
記得初中化學曾學過，紙的燃點是華氏451度，約合攝氏233度——挺有趣的，是吧？前段時間，有人用404刷爆了朋友圈。\
其實，從技術上說，404應是「勇敢的新世界」了；現在還僅僅是451的時代，「因法律原因不可用」。\
而那些高唱讚歌的傢伙，若尚未失智，忘記二十四字核心價值觀的第五個詞（自由），那便是非蠢即壞的。'.encode('utf-8')


##############################################################################

from .RSAEncryptor import RSAEncryptor

rsa_cipher = RSAEncrytor(plainText)
cipherText = rsa_cipher.message

##############################################################################

rsa_plain = RSADecryter(cipherText)
plainText = rsa_plain.message

print('The original message is \'%s\'\n' % plainText)

'''


class RSADecryter:

    def __init__(self, cipherText):
        ctr = 0
        self._plainText = b''

        # 逐塊解密，並合併得到明文
        for block in cipherText:
            ctr += 1

            if ctr == 1:
                privateKey = block[0]
            elif ctr == 2:
                divisorKey = block[0]
            else:
                self._plainText += self._msgDecryption(block[0], privateKey, divisorKey, block[1])

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

        for letter in stringText:
            numberText += rsastr(ord(letter)).rjust(3, '0')

        return int(numberText)

    # 將數字轉化爲字串（Unicode串）
    @staticmethod
    def _Number2Unicode(numberText, complement):
        stringText = b''

        while len(numberText) > 0:
            stringText = bytearray([int(numberText[-3:])]) + stringText
            numberText = numberText[:-3]

        if complement > 0:
            return stringText[:-complement]
        else:
            return stringText
