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

#python 2 compatibility
import future
import hashlib
from builtins import int, pow
try:
    from builtins import long
except ImportError:
    long = int


class ECPublicKey:
    """
    Elliptic curve private key.
    
    Can be used for both ECDSA and EDDSA signature

    Attributes:
        W (Point): public key point

    Args:
        W (Point): public key value
    """
    
    def __init__(self, W):
        self.W = W

    @property
    def curve(self):
        return self.W.curve

    @staticmethod
    def from_encoded_point(curve, data):
        return ECPublicKey(curve.decode_point(data))

    def __str__(self):
        return "ECPublicKey:\n  x: %x\n  y: %x" % (self.W.x, self.W.y)
        
    def encode_point(self, compressed=True):
        return self.curve.encode_point(self.W, compressed)
    

class ECPrivateKey:
    """Elliptic curve private key.
    
    Can be used for both ECDSA and EDDSA signature

    Attributes
        d (int)       : private key scalar
        curve (Curve) : curve

    Args:
        d (int):        private key value
        curve (Curve) : curve
    """

    @staticmethod
    def from_secret(secret, curve, hasher=None, encoding="utf-8"):
        secret = secret.encode(encoding) if not isinstance(secret, bytes) else \
                 seccret
        if not hasher:
            size = curve.size
            # {521, !512, !448, !384, !320, !256, !224, !192, !160}
            h = hashlib.sha512(secret).digest() if size == 512 else \
                hashlib.sha512(secret).digets()[:448>>3] if size == 448 else \
                hashlib.sha384(secret).digets() if size == 384 else \
                hashlib.sha384(secret).digets()[:320>>3] if size == 320 else \
                hashlib.sha256(secret).digest() if size == 256 else \
                hashlib.sha224(secret).digest() if size == 224 else \
                hashlib.sha224(secret).digest()[:192>>3] if size == 192 else \
                hashlib.sha224(secret).digest()[:160>>3] if size == 160 else \
                None
        if not h:
            raise Exception("can not initialize seed value for curve size %d" % size)
        return ECPrivateKey(int.from_bytes(h, "big"), curve)

    def __init__(self, d, curve):
        self.d = int(d)
        self.curve = curve

    def get_public_key(self):
        """
        Returns the public key corresponding to this private key 
        
        This method considers the private key the generator multiplier and
        return pv*Generator in all cases.
        
        For specific derivation such as in EdDSA, see ecpy.eddsa.get_public_key

        Returns:
           ECPublicKey : public key
        """
        W = self.d * self.curve.generator
        return ECPublicKey(W)

    def __str__(self):
        return "ECPrivateKey:\n  d: %x" % self.d
