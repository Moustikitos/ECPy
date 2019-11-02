# -*- encoding:utf-8 -*-
# Copyright 2019 THOORENS Bruno
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# python 2 compatibility
import future
from builtins import int
try:
    from builtins import long
except ImportError:
    long = int


class Encoder:
    """
    Naive encoder class.

    Attributes:
        compressed (:class:`bool`):
            a flag to compress encoded point
        length (:class:`int`):
            byte-length used for :class:`int` - :class:`bytes` conversion

    Parameters:
        curve (:class:`ecpy.curves.Curve`): the associated curve
        compressed (:class:`bool`): compression flag
    """

    def __init__(self, curve, compressed=True):
        self.compressed = compressed
        self.length = self._get_length(curve)

    def _get_length(self, curve):
        return curve.size >> 3

    def encode(self, x, y):
        """
        Args:
            x,y (:class:`int`, :class:`int`): curve point to convert

        Returns:
            :class:`bytes`: encoded point
        """
        if x and isinstance(x, long): x = int(x)
        if y and isinstance(y, long): y = int(y)
        return self._encode(x, y)

    def _encode(self, x, y):
        raise NotImplementedError()

    def decode(self, data, curve):
        """
        Args:
            data (:class:`bytes`): encoded point

        Returns:
            (:class:`int`, :class:`int`): point coordinates
        """
        raise NotImplementedError()


class Secp256k1(Encoder):
    """
    Standart point serialisation.
      * ``02|x`` for even x in compressed form
      * ``03|x``  for odd x in compressed form
      * ``04|x|y`` for uncompressed form
    """

    def _get_length(self, curve):
        if curve.type == "twistededward":
            raise Exception("not available within TWISTEDEDWARD curve")
        else:
            return curve.size >> 3

    def _encode(self, x, y):
        length = self.length
        if self.compressed:
            return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(length, "big")
        else:
            return b"\x04" + x.to_bytes(length, "big") + y.to_bytes(length, "big")

    def decode(self, data, curve):
        length = self.length
        xy = bytearray(data)
        x = int.from_bytes(xy[1:1+length], "big")
        if xy[0] in [2, 3]:
            y = curve.y_recover(x, xy[0] == 3)
        elif xy[0] == 4:
            y = int.from_bytes(xy[1+length:], "big")
        else:
            raise Exception("invalid encoded point")
        return x, y


class Rfc87748(Encoder):
    """
    Only valid encoder within ``MONTGOMERY`` curve.
    """

    def _get_length(self, curve):
        if curve.type == "montgomery":
            return curve.size >> 3
        else:
            raise Exception("only available within MONTGOMERY curve")

    def _encode(self, x, y):
        return x.to_bytes(self.length, "little")

    def decode(self, data, curve=None):
        x = bytearray(data)
        x[-1] &= ~0x80
        x = int.from_bytes(x, "little")
        return x, None


class Eddsa04(Encoder):
    """
    Only valid encoder within ``ED25519`` or ``Ed448`` curve.
    """

    def _get_length(self, curve):
        if curve.name == 'Ed25519':
            return 32
        elif curve.name == 'Ed448':
            return 57
        else:
            raise Exception("invalid curve name '%s' (should be 'Ed25519' or 'Ed448')" % curve.name)

    def _encode(self, x, y):
        length = self.length
        y = bytearray(y.to_bytes(length, "little"))
        if x & 1:
            y[len(y)-1] |= 0x80
        return bytes(y)

    def decode(self, data, curve):
        y = bytearray(data)
        sign = y[len(y)-1] & 0x80
        y[len(y)-1] &= ~0x80
        y = int.from_bytes(y, "little")    
        return curve.x_recover(y, sign), y


class P1363_2000(Encoder):
    """
    ``P1363-2000`` point serialisation.
      * ``02|x|sign(y)`` for compressed form
      * ``04|x|y`` for uncompressed form
    """

    def _encode(self, x, y):
        length = self.length
        if self.compressed:
            return b"\x02" + x.to_bytes(length, "big") + (b"\x01" if y&1 else b"\x00")
        else:
            return b"\x04" + x.to_bytes(length, "big") + y.to_bytes(length, "big")

    def decode(self, data, curve):
        length = self.length
        xy = bytearray(data)
        x = int.from_bytes(xy[1:1+length], "big")
        if xy[0] == 2:
            y = curve.y_recover(x, xy[-1])
        elif xy[0] == 4:
            y = int.from_bytes(xy[1+length:], "big")
        else:
            raise Exception("invalid encoded point")
        return x, y


def decode_scalar_25519(data):
    """
    Decode scalar according to ``RF7748`` and ``draft-irtf-cfrg-eddsa``

    Args:
        data (:class:`bytes`): data to decode

    Returns:
        :class:`int`: scalar value
    """
    k = bytearray(data)
    k[0]  &= 0xf8
    k[31] = (k[31] &0x7f) | 0x40
    return int.from_bytes(bytes(k), "little")
