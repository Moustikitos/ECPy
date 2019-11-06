# -*- encoding;utf-8 -*-
"""
"""

# Copyright 2016 Cedric Mesnil <cedric.mesnil@ubinity.com>, Ubinity SAS
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

import hashlib

# python 2 compatibility
import future
from builtins import int, pow


class ECPublicKey:
    """
    Elliptic curve public key. Can be used for both ECDSA and EDDSA signature.

    Attributes:
        W (:class:`ecpy.curves.Point`): public key point
    """
    
    def __init__(self, W):
        self.W = W

    @property
    def curve(self):
        """Public key curve."""
        return self.W.curve

    @staticmethod
    def from_encoded_point(curve, data):
        """
        Retrieve public key from encoded data.

        Args:
            curve (:class:`ecpy.curves.Curve`): the elliptic curve to use
            data (:class:`bytes`): encoded point data

        Returns:
            :class:`ecpy.keys.ECPublicKey`: decoded public key
        """
        return ECPublicKey(curve.decode_point(data))

    @staticmethod
    def from_secret(secret, curve, hasher=None, encoding="utf-8"):
        """See :func:`ecpy.keys.ECPrivateKey.from_secret`."""
        return ECPrivateKey.from_secret(secret, curve, hasher=hasher, encoding=encoding).get_public_key()

    def __str__(self):
        return "<ECPublicKey\n    W: %s>" % self.W
        
    def encode_point(self, compressed=False):
        """
        Encode public key into bytes sequence.

        Args:
            compressed (:class:`boolean`): compress sequence if supported

        Returns:
            :class:`bytes`: encoded/compressed public key
        """
        return self.curve.encode_point(self.W, compressed)
    

class ECPrivateKey:
    """
    Elliptic curve private key. Can be used for both ECDSA and EDDSA signature.

    Attributes:
        d (:class:`int`): private key scalar
        curve (:class:`ecpy.curves.Curve`): the curve to use
    """

    @staticmethod
    def from_secret(secret, curve, hasher=None, encoding="utf-8"):
        """
        Create a private key from secret passphrase.

        Args:
            secret (:class:`str` or :class:`bytes`):
                passphrase given as bytes or string sequence
            curve (:class:`ecpy.curves.Curve`):
                the elliptic curve to use
            hasher (:func:`func`):
                valid hash definition
            encoding (:class:`str`):
                passphrase encoding if given as a bytes sequence

        Returns:
            :class:`ecpy.keys.ECPrivateKey`: private key

        Raises:
            :class:`ValueError`:
                if the hasher did not issue a valid bytes sequence.
        """
        size = curve.size
        order = curve.order
        secret = secret.deocde(encoding).encode("utf-8") if not isinstance(secret, bytes) else \
                 secret
        length = size >> 3
        if not hasher:
            # {521, !512, !448, !384, !320, !256, !224, !192, !160}
            h = hashlib.sha512(secret).digest() if size == 512 else \
                hashlib.sha512(secret).digets()[:length] if size == 448 else \
                hashlib.sha384(secret).digets() if size == 384 else \
                hashlib.sha384(secret).digets()[:length] if size == 320 else \
                hashlib.sha256(secret).digest() if size == 256 else \
                hashlib.sha224(secret).digest() if size == 224 else \
                hashlib.sha224(secret).digest()[:length] if size == 192 else \
                hashlib.sha224(secret).digest()[:length] if size == 160 else \
                None
        else:
            h = hasher(secret).digest().zfill(length)
        if not h:
            raise ValueError("can not initialize seed value for curve size %d" % size)
        return ECPrivateKey(int.from_bytes(h, "big") % order, curve)

    def __init__(self, d, curve):
        self.d = int(d)
        self.curve = curve

    def __str__(self):
        return "<ECPrivateKey\n    d: %x>" % self.d

    def get_public_key(self):
        """
        Compute the public key corresponding to this private key. This method
        returns private key scalar * generator point. For EdDSA specific
        derivation, use :func:`ecpy.eddsa.EDDSA.get_public_key`.
        
        Returns:
           :class:`ecpy.keys.ECPublicKey`: associated public key
        """
        return ECPublicKey(self.d * self.curve.generator)
