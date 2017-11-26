# -*- coding: utf-8 -*-


import math, sys


# RSA 常用函數
# 一些常用的函數兼容性覆寫


# Python 2.7 -- int(ceil(num)) | Python 3.6 -- ceil(num)
rsaceil = math.ceil if sys.version_info[0] > 2 else lambda x: int(math.ceil(x))


# Python 2.7 -- unichr | Python 3.6 -- chr
rsachr = chr if sys.version_info[0] > 2 else unichr


# Python 2.7 -- int & long | Python 3.6 -- int
rsaint = int if sys.version_info[0] > 2 else (int, long)


# Python 2.7 -- xrange | Python 3.6 -- range
rsarange = range if sys.version_info[0] > 2 else xrange


# Python 2.7 -- unicode | Python 3.6 -- str
rsastr = str if sys.version_info[0] > 2 else unicode


# Python 2.7 -- unicode(ord(letter)) | Python 3.6 -- str(letter)
# rsaord = rsastr if sys.version_info[0] > 2 else lambda x: rsastr(ord(x))
rsaord = lambda x: rsastr(ord(x))
