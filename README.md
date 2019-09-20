# ECPy

ECPy (pronounced ekpy), is a pure python Elliptic Curve library
providing ECDSA, EDDSA (Ed25519), ECSchnorr, Borromean signatures as well as 
elliptic point operations.

**Point sample**

```python
from ecpy.curves import Curve, Point

P  = Point(
    0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b21,
    None,
    curve=Curve.get_curve('secp256k1')
)
k  = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
Q  = k * P
R  = P + Q
```

**ECDSA sample**

```python
from ecpy.curves import Curve
from ecpy.keys   import ECPrivateKey
from ecpy.ecdsa  import ECDSA

signer = ECDSA()
pv_key = ECPrivateKey.from_secret("secret", Curve.get_curve('secp256k1'))
pu_key = pv_key.get_public_key()

sig = signer.sign(b'01234567890123456789012345678912', pv_key)
assert(signer.verify(b'01234567890123456789012345678912', sig, pu_key))
```

# Quick Install

```bash
python -m pip install git+https://github.com/Moustikitos/ecpy.git@schnorr-rfc6979
```
