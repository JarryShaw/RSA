#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function


# # 1st set:
# plainText = b'Mathematic1'

# 2nd set:
plainText = 'Mathematic Fundation of Information security 20170323 515030910023 ✐'
# Óé¬¬ø ∑ø®¬∂!'

# # 3rd set:
# plainText_0 = b'The binascii module contains a number of methods to convert between binary and '
# plainText_1 = b'various ASCII-encoded binary representations.Normally, you will not use these '
# plainText_2 = b'functions directly but use wrapper modules like uu, base64, or binhex instead. '
# plainText_3 = b'The binascii module contains low-level functions written in C for greater speed '
# plainText_4 = b'that are used by the higher-level modules.'
# plainText = plainText_0 + plainText_1 + plainText_2 + plainText_3 + plainText_4

# # 4th set:
# plainText = u'\
# 記得初中化學曾學過，紙的燃點是華氏451度，約合攝氏233度——挺有趣的，是吧？前段時間，有人用404刷爆了朋友圈。\
# 其實，從技術上說，404應是「勇敢的新世界」了；現在還僅僅是451的時代，「因法律原因不可用」。\
# 而那些高唱讚歌的傢伙，若尚未失智，忘記二十四字核心價值觀的第五個詞（自由），那便是非蠢即壞的。'.encode('utf-8')


##############################################################################

from rsa import RSAEncryptor

rsa_cipher = RSAEncryptor.RSAEncrytor(plainText)
cipherText = rsa_cipher.message

print('The encrypted message is \n\n\'%s\'' % cipherText)
print('\n-*- TEXT ENCRYPTED -*-\n')

##############################################################################

from rsa import RSADecrypter

print(type(cipherText))
rsa_plain = RSADecrypter.RSADecryter(cipherText)
plainText = rsa_plain.message

print('The original message is \n\n\'%s\'' % plainText)
print('\n-*- TEXT DECRYPTED -*-\n')
