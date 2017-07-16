# -*- coding: utf-8 -*-


from __future__ import print_function


import math
import sys


# RSA 密文信息
# 保存密文信息並用於解密


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
rsaord = rsastr if sys.version_info[0] > 2 else lambda x: rsastr(ord(x))


class RSAMessager(object):

    '''Data module:

    Public key and divisor will be stored in the first two blocks.

    And of every Messager block,
        * First byte  -- length of the block, except the headers;
        * Second byte -- length of complement characters in the block.

    '''

    @property
    def message(self):
        return self._message

    def __new__(cls, _public, _divisor):
        self = super(RSAMessager, cls).__new__(cls)
        self._message = ''
        self._ceiling = 0
        self._counter = 0
        self._pointer = 0
        return self

    def __init__(self, _private, _divisor):
        self._add_block(_private)
        self._add_block(_divisor)

    def __call__(self, _mode, _block=None, _compt=None):
        if _mode:
            self._add_block(_block, _compt)
        else:
            return self._read_block()

    def __str__(self):
        return self._message

    def __iter__(self):
        yield self(False)

    def list(self):
        _list = []
        for _ctr in rsarange(self._ceiling):
            _text, _comp = self(False)
            if _text is None:
                break
            else:
                _list.append((_text, _comp))
        return _list

    def _add_block(self, _text, _comp=None):
        if isinstance(_text, rsaint):
            _len = rsachr(rsaceil(math.log(_text, 256)))
            _cpm = rsachr(0)
            _txt = self._int2bytes(_text)
            # print(_text, ' \\ ', ord(_len), ' \\ ', ord(_cpm), ' \\ ', _txt, ' \\ ', len(_txt))

        else:
            _len = rsachr(len(_text))
            _cpm = rsachr(0) if _comp is None else rsachr(_comp)
            _txt = _text

        self._ceiling += 1
        self._message += _len + _cpm + _txt

    def _read_block(self):
        _ctr = self._counter
        _ptr = self._pointer

        if _ctr < self._ceiling:
            _len = ord(self._message[_ptr])
            _cpm = ord(self._message[_ptr+1])

            if _ctr >= 2:
                _txt = ''
                for _chr in self._message[_ptr+2 : _ptr+2+_len]:
                    _txt += _chr

            else:
                _txt = 0
                for _mtp in rsarange(_len):
                    _txt += ord(self._message[_ptr+2+_mtp]) * 256**_mtp

            self._counter += 1
            self._pointer += 2 + _len

            return _txt, _cpm

        else:
            return None, None

    @staticmethod
    def _int2bytes(_int):
        _rmd = []
        while _int >= 256:
            _rmd.append(_int % 256)
            _int //= 256
        _rmd.append(_int)

        _txt = ''
        for _hex in _rmd:
            _txt += rsachr(_hex)

        return _txt
