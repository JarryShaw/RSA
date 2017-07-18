# -*- coding: utf-8 -*-


from jsntlib import ntl as jsntlib


# RSA 加密器
# 利用生成的公鑰進行加密操作


from .RSAGenerator import RSAGenerator
from .RSAMessager  import RSAMessager
from .RSAUtilities import rsachr, rsaord, rsastr


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

rsa_cipher = RSAEncrytor(plainText)
cipherText = rsa_cipher.message

print('The ciphered message is \'%s\'\n' % cipherText)

'''


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

    # 獲取密文
    @property
    def message(self):
        return self._cipherText

    # 獲取密鑰
    @property
    def keys(self):
        return self._rsacipher

    # 明文分塊
    @staticmethod
    def _blockSlice(plainText, blockSize):
        blockText = []
        tmpLength = len(plainText) % blockSize
        complement = 0 if tmpLength == 0 else blockSize - tmpLength

        while len(plainText) > 0:
            blockText.append(plainText[:blockSize].ljust(blockSize, b' '))
            plainText = plainText[blockSize:]

        return blockText, complement

    # 明文加密
    def _msgEncryption(self, stringText, publicKey, divisorKey):
        numberText = self._Unicode2Number(stringText)
        cipherNumb = rsastr(jsntlib.modulo(numberText, publicKey, divisorKey))
        cipherText = self._Number2Unicode(cipherNumb)

        # print(stringText, '\t', numberText, '\t', cipherNumb, '\t', cipherText, '\t')

        return cipherText
    
    # 將字串轉化爲數字（Unicode碼）
    @staticmethod
    def _Unicode2Number(stringText):
        numberText = ''

        for letter in stringText:
            numberText += rsaord(letter).rjust(3, '0')

        return int(numberText)

    # 將數字轉化爲字串（Unicode串）
    @staticmethod
    def _Number2Unicode(numberText):
        stringText = ''

        while len(numberText) > 0:
            stringText = rsachr(int(numberText[-3:])) + stringText
            numberText = numberText[:-3]

        return stringText
