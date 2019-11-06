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

# python 2 compatibility
import future
from builtins import int, pow
try:
    from builtins import long
    long = int
except ImportError:
    long = int


FORMATS = ("DER", "BTUPLE", "ITUPLE", "RAW", "EDDSA")

def encode_sig(r, s, fmt="DER", size=0):
    """
    Encore signature according to format.

    Args:
        r (:class:`int`): r value
        s (:class:`int`): s value
        fmt (:class:`str`): ``DER``, ``BTUPLE``, ``ITUPLE``, ``RAW`` or ``EDDSA``

    Returns:
        encoded signature:
            (:class:`bytes`) for ``DER``, ``RAW`` and ``EDDSA`` encoding,
            (:class:`bytes`, :class:`bytes`) for ``BTUPLE`` encoding,
            (:class:`int`, :class:`int`) for ``ITUPLE`` encoding
    """

    r, s = int(r), int(s)

    if fmt == "DER":
        r = r.to_bytes((r.bit_length()+7)//8, 'big')
        s = s.to_bytes((s.bit_length()+7)//8, 'big')
        if (r[0] & 0x80) == 0x80:
            r = b'\0' + r
        if (s[0] & 0x80) == 0x80:
            s = b'\0' + s
        return b'\x30' + int((len(r)+len(s)+4)).to_bytes(1, 'big') + \
               b'\x02' + int(len(r)).to_bytes(1, 'big') + r        + \
               b'\x02' + int(len(s)).to_bytes(1, 'big') + s 

    if fmt == "BTUPLE":
        return (
            r.to_bytes((r.bit_length()+7)//8, 'big'),
            s.to_bytes((s.bit_length()+7)//8, 'big')
        )

    if fmt == "ITUPLE":
        return (r, s)
    
    if fmt == "RAW":
        if size == 0:
            size = (max(r.bit_length(), s.bit_length())+7) // 8
        return r.to_bytes(size, 'big') + s.to_bytes(size, 'big')

    if fmt == "EDDSA":
        if size == 0:
            size = (max(r.bit_length(), s.bit_length())+7) // 8
        return r.to_bytes(size, 'little') + s.to_bytes(size, 'little')


def decode_sig(sig, fmt="DER") :
    """
    Decode signature according to format.

    Args:
        sig:
            (:class:`bytes`) for ``DER``, ``RAW`` and ``EDDSA`` encoding, 
            (:class:`bytes`, :class:`bytes`) for ``BTUPLE`` encoding,
            (:class:`int`, :class:`int`) for ``ITUPLE`` encoding
        fmt (:class:`str`): ``DER``, ``BTUPLE``, ``ITUPLE``, ``RAW`` or ``EDDSA``

    Returns:
        signature part (:class:`int`, :class:`int`): r and s value
    """

    if fmt == "DER":
        sig = bytearray(sig)
        sig_len = sig[1] + 2
        r_offset, r_len = 4, sig[3]
        s_offset, s_len = 4+r_len+2, sig[4+r_len+1]
        if (
            sig[0]  != 0x30          or
            sig_len != r_len+s_len+6 or
            sig[r_offset-2] != 0x02  or
            sig[s_offset-2] != 0x02):
            return None, None
        return (
            int.from_bytes(sig[r_offset:r_offset+r_len], 'big'),
            int.from_bytes(sig[s_offset:s_offset+s_len], 'big')
        )
    
    if fmt == "ITUPLE":
        return sig

    if fmt == "BTUPLE":        
        return (
            int.from_bytes(sig[0], 'big'),
            int.from_bytes(sig[1], 'big')                
        )

    if fmt == "RAW":
        l = len(sig)>>1
        return (
            int.from_bytes(sig[0:l], 'big'),
            int.from_bytes(sig[l:],  'big')
        )

    if fmt == "EDDSA":
        l = len(sig)>>1
        return (
            int.from_bytes(sig[0:l], 'little'),
            int.from_bytes(sig[l:],  'little')
        )

